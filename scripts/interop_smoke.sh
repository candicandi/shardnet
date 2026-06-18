#!/usr/bin/env bash
# Live TAP interop smoke test: runs the interop binary against real Linux peers
# in a fresh netns, so the host firewall can't interfere. Needs root.
set -u
BIN="$(readlink -f "${1:-./zig-out/bin/interop_tap}")"
NS=sn_interop
SHARDNET=10.9.0.2
KERNEL=10.9.0.1
rc=0
in_ns() { ip netns exec "$NS" "$@"; }
pass() { echo "[smoke] PASS: $*"; }
fail() {
    echo "[smoke] FAIL: $*" >&2
    rc=1
}
# wait_for SECONDS CMD...: run CMD until it succeeds, or give up after SECONDS.
wait_for() {
    local n=$(($1 * 5))
    shift
    while [ "$n" -gt 0 ]; do
        "$@" >/dev/null 2>&1 && return 0
        sleep 0.2
        n=$((n - 1))
    done
    return 1
}
cleanup() {
    in_ns pkill -x interop_tap 2>/dev/null
    in_ns pkill -x nc 2>/dev/null
    in_ns pkill -x dnsmasq 2>/dev/null
    ip netns del "$NS" 2>/dev/null
}
trap cleanup EXIT

ip netns del "$NS" 2>/dev/null
ip netns add "$NS"
in_ns ip link set lo up
in_ns ip tuntap add dev tap0 mode tap
in_ns ip addr add "$KERNEL/24" dev tap0
in_ns ip link set tap0 up

# Scenarios 1, 2, 4: kernel to shardnet (ICMP, TCP, HTTP).
in_ns "$BIN" >/tmp/smoke_srv.log 2>&1 &
if wait_for 6 in_ns ping -c1 -W1 "$SHARDNET"; then pass "ICMP ping"; else fail "ICMP ping"; fi
body="$(in_ns curl -s --max-time 5 "http://$SHARDNET:8080/" 2>/dev/null)"
echo "$body" | grep -q "shardnet over TAP" && pass "TCP/HTTP curl" || fail "TCP/HTTP curl (got: $body)"
in_ns pkill -x interop_tap 2>/dev/null
sleep 0.3

# Scenario 3: shardnet to kernel (outbound TCP).
: >/tmp/smoke_nc.txt
in_ns nc -l 9000 >/tmp/smoke_nc.txt 2>&1 &
in_ns "$BIN" client >/tmp/smoke_cli.log 2>&1 &
if wait_for 6 grep -q "shardnet over TAP" /tmp/smoke_nc.txt; then pass "outbound TCP"; else fail "outbound TCP"; fi
in_ns pkill -x interop_tap 2>/dev/null
in_ns pkill -x nc 2>/dev/null
sleep 0.3

# Scenario 5: shardnet leases from a real DHCP server.
in_ns dnsmasq --no-daemon --interface=tap0 --bind-interfaces --no-resolv --port=0 \
    --dhcp-range=10.9.0.50,10.9.0.150,255.255.255.0,2m \
    --dhcp-option=3,"$KERNEL" --dhcp-option=6,8.8.8.8 --dhcp-authoritative \
    >/tmp/smoke_dnsmasq.log 2>&1 &
in_ns "$BIN" dhcp >/tmp/smoke_dhcp.log 2>&1 &
if wait_for 10 grep -q "DHCP bound 10.9.0" /tmp/smoke_dhcp.log; then pass "DHCP lease"; else fail "DHCP lease (got: $(cat /tmp/smoke_dhcp.log))"; fi

[ "$rc" -eq 0 ] && echo "[smoke] all interop scenarios passed"
exit "$rc"
