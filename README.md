<div align="center">

# Shardnet

**A high-performance userspace TCP/IP stack written in Zig**

[![CI](https://github.com/Adel-Ayoub/shardnet/actions/workflows/ci.yml/badge.svg)](https://github.com/Adel-Ayoub/shardnet/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/zig-0.14.x-orange.svg)](https://ziglang.org)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](#platform-support)

</div>

---

Shardnet is a full TCP/IP stack — IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, ARP and DNS — that runs entirely in userspace over pluggable drivers (loopback, TAP, AF_PACKET, AF_XDP). It targets Linux and is built for throughput: modern TCP extensions, CUBIC/BBRv2 congestion control, zero-copy buffers, and a sharded, multi-queue-friendly core — wrapped in a portable, poll-based socket API and hardened against adversarial traffic (bounded state everywhere, fuzz-tested parsers).

## Architecture

### Overall Architecture

<p align="center">
  <img src="assets/architecture-overview.svg" alt="Overall architecture — the shardnet layered stack">
</p>

### System Context

<p align="center">
  <img src="assets/architecture-context.svg" alt="System context — shardnet among external actors">
</p>

## Quick start

```sh
git clone https://github.com/Adel-Ayoub/shardnet.git
cd shardnet

zig build          # static + shared libraries
zig build test     # run the test suite
zig build example  # build example binaries
```

Requires the **Zig 0.14.x** toolchain. Linux has full support; macOS/BSD build with the loopback driver only.

## Features

- **Protocols** — IPv4 and IPv6 with fragment reassembly on both (RFC 5722 overlap rejection on v6), extension header chains, TCP (RFC 793), UDP, ICMP/ICMPv6 (echo, rate limiting, neighbor discovery, SLAAC), ARP (cache change detection), DNS (TTL + negative cache + hosts file).
- **Sockets** — portable high-level socket API (`Socket.tcp`/`Socket.udp`): bind/connect/listen/accept, send/recv, poll-based like smoltcp — the same code runs over any driver on any platform.
- **TCP extensions** — SACK (RFC 2018), timestamps & window scaling (RFC 7323), Nagle / `TCP_NODELAY` (RFC 896), fast retransmit/recovery (RFC 5681), PRR (RFC 6937), early retransmit (RFC 5827), ACK validation (RFC 5961), SYN cookies with rotating secrets, keepalive, full TIME_WAIT/2MSL with RFC 1122 reuse and RFC 1337 assassination protection.
- **Path MTU Discovery** — RFC 1191 (IPv4, DF + Fragmentation Needed with plateau fallback) and RFC 8201 (IPv6 Packet Too Big), feeding a bounded, aging PMTU cache that clamps TCP MSS.
- **Congestion control** — CUBIC (RFC 9438 + HyStart++), BBRv2, and a pluggable interface for custom algorithms.
- **Drivers** — loopback (end-to-end testing with optional latency/loss injection), TAP, AF_PACKET (TPACKET_V3 block mode), AF_XDP (kernel bypass).
- **Performance** — zero-copy cluster buffers, 256-way sharded transport tables, timerfd timer wheel, pre-warmed memory pools, per-layer stats.
- **Hardening** — every per-peer table is bounded with eviction and drop counters (reassembly, ARP/NDP, PMTU, SYN backlog); ICMP errors are validated against locally-sourced packets; parsers are exercised by a deterministic fuzz harness in CI.
- **Operations** — Unix-socket health check (`/tmp/shardnet.sock`), Prometheus metrics, graceful shutdown.

**In progress:** socket options & blocking modes&nbsp;&nbsp;·&nbsp;&nbsp;**Planned:** DHCP client · TSO/GRO · QUIC · Multipath TCP · DPDK driver · eBPF integration

## Usage

Bring up a stack on a driver, then talk through the portable socket API:

```zig
const std = @import("std");
const shardnet = @import("shardnet");
const Socket = shardnet.socket.Socket;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // Registers IPv4/IPv6, ARP, ICMP/ICMPv6, TCP and UDP.
    var stack = try shardnet.init(gpa.allocator());
    defer stack.deinit();

    var tap = try shardnet.drivers.tap.Tap.init("tap0");
    try stack.createNIC(1, tap.linkEndpoint());
    try stack.nics.get(1).?.addAddress(.{
        .protocol = shardnet.tcpip.EtherType.IPv4,
        .address_with_prefix = .{ .address = .{ .v4 = .{ 10, 0, 0, 1 } }, .prefix_len = 24 },
    });

    var server = try Socket.tcp(&stack);
    defer server.close();
    try server.bind(.{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 8080 });
    try server.listen(128);

    // Sockets are poll-based: drive the stack, then retry.
    var conn: ?*Socket = null;
    while (conn == null) {
        // pump your event loop / driver here
        conn = server.accept() catch null;
    }
    defer conn.?.close();

    var buf: [1024]u8 = undefined;
    const n = try conn.?.recv(&buf);
    _ = try conn.?.send(buf[0..n]);
}
```

Run the bundled examples and benchmarks (root required for the real drivers):

```sh
sudo ./setup_veth.sh
sudo zig-out/bin/bench_ping_pong -i tap0 -a 10.0.0.1/24
sudo zig-out/bin/example_unified -d af_packet -i eth0 -a 10.0.0.1/24
```

See [`examples/`](examples) for TCP servers, multi-driver setups, and throughput tests.

## Build

| Target | Description |
|--------|-------------|
| `zig build` | Static and shared libraries |
| `zig build test` | Run all tests |
| `zig build bench` | Benchmark binaries (ReleaseFast) |
| `zig build docs` | Generate documentation |
| `zig build example` | Example binaries |

Options: `-Doptimize=ReleaseFast`, `-Dlog_level=<err|warn|info|debug|none>`.

`zig build test` runs the full suite, including a deterministic parser fuzz harness.
CI builds and tests on Linux and cross-compiles for macOS; macOS runs the
platform-agnostic subset locally (the POSIX layer and real drivers are Linux-only).

## Platform support

| Platform | Support | Notes |
|----------|---------|-------|
| Linux | Full | All drivers, namespaces, cgroups |
| macOS / BSD | Limited | Loopback only |

## Performance

Indicative single-core numbers (Intel Xeon E5-2680 v4, Linux 5.15):

| TCP throughput | UDP throughput | Ping-pong latency | Connections/sec |
|----------------|----------------|-------------------|-----------------|
| ~8 Gbps | ~10 Gbps | ~15 µs | ~100K |

<details>
<summary><strong>RFC compliance</strong></summary>

| RFC | Title |
|-----|-------|
| 791 / 8200 | IPv4 / IPv6 |
| 792 / 4443 | ICMP / ICMPv6 |
| 826 | ARP |
| 793 | TCP |
| 896 | Nagle algorithm |
| 1191 / 8201 | Path MTU Discovery (IPv4 / IPv6) |
| 1337 | TIME_WAIT assassination protection |
| 2018 | TCP SACK |
| 4861 / 4862 | Neighbor Discovery / SLAAC |
| 4987 | TCP SYN cookies |
| 5681 | TCP congestion control |
| 5722 / 6946 | IPv6 overlapping-fragment rejection / atomic fragments |
| 5827 | TCP early retransmit |
| 5961 | TCP ACK validation |
| 6937 | Proportional Rate Reduction |
| 7323 | TCP timestamps & window scaling |
| 9406 | HyStart++ |
| 9438 | CUBIC |

</details>

<details>
<summary><strong>Project layout</strong></summary>

```
src/
├── main.zig            entry point + CLI
├── stack.zig           orchestration, routing, dispatch
├── socket.zig          portable high-level socket API
├── tcpip.zig           core types and vtables
├── buffer.zig          zero-copy buffers
├── header.zig          protocol headers + checksums
├── time.zig            timer wheel
├── event_mux.zig       epoll + timerfd event loop
├── fuzz_test.zig       deterministic parser fuzz harness
├── dns.zig posix.zig stats.zig waiter.zig interface.zig
├── link/eth.zig        Ethernet framing
├── network/            ipv4 · ipv6 · arp · icmp · icmpv6
├── transport/          tcp · udp · congestion/{control,cubic,bbr}
└── drivers/            loopback · linux/{tap,af_packet,af_xdp}
examples/               ping_pong · uperf · main_unified · …
```

</details>

## License

Apache License 2.0 — Copyright (c) 2026 Adel-Ayoub. See [LICENSE](LICENSE).
