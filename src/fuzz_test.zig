//! Parser robustness fuzzing.
//!
//! Every wire parser must tolerate arbitrary attacker-controlled bytes without
//! panicking, reading out of bounds, or leaking. This is driven by a deterministic
//! PRNG so any failure reproduces exactly in CI. The same entry points are pure
//! functions over byte slices, so they can also be driven by `zig build test --fuzz`.

const std = @import("std");
const shardnet = @import("shardnet");
const tcpip = shardnet.tcpip;
const buffer = shardnet.buffer;
const header = shardnet.header;
const stack = shardnet.stack;
const ipv4 = shardnet.network.ipv4;
const ipv6 = shardnet.network.ipv6;
const arp = shardnet.network.arp;
const dns = shardnet.dns;

fn freeRecords(allocator: std.mem.Allocator, records: []dns.ResourceRecord) void {
    if (records.len == 0) return; // empty result allocates nothing
    for (records) |rr| {
        allocator.free(rr.name);
        switch (rr.rdata) {
            .CNAME, .TXT, .NS, .PTR, .unknown => |s| allocator.free(s),
            .SRV => |srv| allocator.free(srv.target),
            .MX => |mx| allocator.free(mx.exchange),
            else => {},
        }
    }
    allocator.free(records);
}

test "fuzz: wire parsers tolerate arbitrary bytes" {
    const allocator = std.testing.allocator;

    var ip4 = ipv4.IPv4Protocol.init();
    const np4 = ip4.protocol();
    var ip6 = ipv6.IPv6Protocol.init();
    const np6 = ip6.protocol();
    var arp_proto = arp.ARPProtocol.init(allocator);
    defer arp_proto.deinit();
    const npa = arp_proto.protocol();

    var prng = std.Random.DefaultPrng.init(0x5EED);
    const rng = prng.random();

    var iter: usize = 0;
    while (iter < 50_000) : (iter += 1) {
        var buf: [1024]u8 = undefined;
        const n = rng.uintAtMost(usize, buf.len);
        rng.bytes(buf[0..n]);
        const slice = buf[0..n];

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = slice }};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(n, &views),
            .header = buffer.Prependable.init(&[_]u8{}),
        };

        // Network address extraction — called by the NIC dispatch before any
        // length validation, so it must be safe on a runt frame.
        _ = np4.parseAddresses(pkt);
        _ = np6.parseAddresses(pkt);
        _ = npa.parseAddresses(pkt);

        // The length-validation gates themselves must never read out of bounds.
        _ = header.IPv4.init(slice).isValid(n);
        _ = header.IPv6.init(slice).isValid(n);
        _ = header.ARP.init(slice).isValid();

        // Variable-length walks.
        _ = ipv6.parseExtensionHeaders(slice, rng.int(u8));

        if (dns.parseResponse(allocator, slice)) |res| {
            freeRecords(allocator, res.answers);
        } else |_| {}
    }
}
