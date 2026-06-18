/// ICMPv4 protocol implementation.
///
/// Handles ICMP echo request/reply, destination unreachable,
/// redirects, and includes rate limiting to prevent amplification.

const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");
const time = @import("../time.zig");
const stats = @import("../stats.zig");
const log = @import("../log.zig").scoped(.icmp);

pub const ProtocolNumber = 1;

/// ICMP message types.
pub const Type = struct {
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACHABLE: u8 = 3;
    pub const REDIRECT: u8 = 5;
    pub const ECHO: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
};

/// Destination Unreachable codes.
pub const DestUnreachableCode = struct {
    pub const NET_UNREACHABLE: u8 = 0;
    pub const HOST_UNREACHABLE: u8 = 1;
    pub const PROTOCOL_UNREACHABLE: u8 = 2;
    pub const PORT_UNREACHABLE: u8 = 3;
    pub const FRAGMENTATION_NEEDED: u8 = 4;
    pub const SOURCE_ROUTE_FAILED: u8 = 5;
};

/// Time Exceeded codes.
pub const TimeExceededCode = struct {
    pub const TTL_EXPIRED: u8 = 0;
    pub const FRAGMENT_REASSEMBLY: u8 = 1;
};

const RateLimiter = @import("../ratelimit.zig").RateLimiter;

/// RTT measurement for echo replies.
pub const RttMeasurement = struct {
    /// Pending echo requests: sequence -> send timestamp (ns).
    pending: std.AutoHashMap(u16, i128),

    pub fn init(allocator: std.mem.Allocator) RttMeasurement {
        return .{
            .pending = std.AutoHashMap(u16, i128).init(allocator),
        };
    }

    pub fn deinit(self: *RttMeasurement) void {
        self.pending.deinit();
    }

    pub fn recordSend(self: *RttMeasurement, seq: u16) void {
        self.pending.put(seq, std.time.nanoTimestamp()) catch {};
    }

    /// Returns RTT in microseconds if matching request found.
    pub fn recordRecv(self: *RttMeasurement, seq: u16) ?u64 {
        if (self.pending.fetchRemove(seq)) |entry| {
            const now = std.time.nanoTimestamp();
            const rtt_ns = now - entry.value;
            return @as(u64, @intCast(@divFloor(rtt_ns, 1000)));
        }
        return null;
    }
};

pub const ICMPv4TransportProtocol = struct {
    owner_allocator: ?std.mem.Allocator = null,

    pub fn init() ICMPv4TransportProtocol {
        return .{};
    }

    pub fn protocol(self: *ICMPv4TransportProtocol) stack.TransportProtocol {
        return .{
            .ptr = self,
            .vtable = &.{
                .number = transportNumber,
                .newEndpoint = newTransportEndpoint,
                .parsePorts = parsePorts,
                .handlePacket = handlePacket_external,
                .deinit = deinit_external,
            },
        };
    }

    fn deinit_external(ptr: *anyopaque) void {
        const self = @as(*ICMPv4TransportProtocol, @ptrCast(@alignCast(ptr)));
        if (self.owner_allocator) |a| a.destroy(self);
    }

    fn transportNumber(ptr: *anyopaque) tcpip.TransportProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn newTransportEndpoint(ptr: *anyopaque, s: *stack.Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
        _ = ptr;
        _ = s;
        _ = net_proto;
        _ = wait_queue;
        return tcpip.Error.NotPermitted;
    }

    fn parsePorts(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.TransportProtocol.PortPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{ .src = 0, .dst = 0 };
        if (v.len >= 8) {
            const id = std.mem.readInt(u16, v[4..6][0..2], .big);
            return .{ .src = id, .dst = 0 };
        }
        return .{ .src = 0, .dst = 0 };
    }

    fn handlePacket_external(ptr: *anyopaque, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        _ = ptr;
        _ = id;
        ICMPv4PacketHandler.handlePacket(r.nic.stack, r, pkt);
    }
};

pub const ICMPv4PacketHandler = struct {
    var rate_limiter: RateLimiter = RateLimiter.init();
    var echo_reply_limiter: RateLimiter = RateLimiter.init();

    pub fn handlePacket(s: *stack.Stack, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        var mut_pkt = pkt;
        const v = mut_pkt.data.first() orelse return;
        const h = header.ICMPv4.init(v);

        stats.global_stats.icmp.rx_packets.inc();

        switch (h.@"type"()) {
            Type.ECHO => {
                stats.global_stats.icmp.rx_echo_requests.inc();
                handleEchoRequest(s, r, &mut_pkt, v);
            },
            Type.ECHO_REPLY => {
                stats.global_stats.icmp.rx_echo_replies.inc();
                // RTT measurement would be handled here
            },
            Type.DEST_UNREACHABLE => {
                handleDestUnreachable(s, r, v);
            },
            Type.REDIRECT => {
                handleRedirect(s, r, v);
            },
            Type.TIME_EXCEEDED => {
                // Informational - log and ignore
                log.debug("Received Time Exceeded from {any}", .{r.remote_address.v4});
            },
            else => {
                log.debug("Unknown ICMP type: {}", .{h.@"type"()});
            },
        }
    }

    fn handleEchoRequest(s: *stack.Stack, r: *const stack.Route, pkt: *tcpip.PacketBuffer, v: []const u8) void {
        _ = pkt;
        if (v.len < header.ICMPv4MinimumSize) return;

        // Bound echo-reply emission so a ping flood cannot make us reflect without
        // limit (mirrors the ICMPv6 echo gate).
        if (!echo_reply_limiter.tryConsume()) {
            stats.global_stats.icmp.echo_replies_throttled.inc();
            return;
        }

        // The whole ICMP message (header + echo data) is the L4 payload; the
        // header Prependable must reserve room for the IP and link headers. A TAP
        // link prepends a 14-byte Ethernet header, which initFull leaves no room for.
        const msg = s.allocator.alloc(u8, v.len) catch return;
        defer s.allocator.free(msg);
        @memcpy(msg, v);

        var reply_h = header.ICMPv4.init(msg[0..header.ICMPv4MinimumSize]);
        reply_h.data[0] = Type.ECHO_REPLY;
        reply_h.setChecksum(0);
        reply_h.setChecksum(reply_h.calculateChecksum(msg[header.ICMPv4MinimumSize..]));

        const hdr_mem = s.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer s.allocator.free(hdr_mem);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = msg }};
        const reply_pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(msg.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        const reply_route = r.*;
        if (r.nic.network_endpoints.get(0x0800)) |ip_ep| {
            stats.global_stats.icmp.tx_echo_replies.inc();
            ip_ep.writePacket(&reply_route, ProtocolNumber, reply_pkt) catch |err| {
                log.debug("ICMP: echo reply tx failed: {}", .{err});
                stats.global_stats.direction.tx_drops.inc();
            };
        }
    }

    // RFC 1191 section 7.1 plateau table, for routers that send MTU=0.
    const mtu_plateaus = [_]u16{ 65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68 };

    fn plateauBelow(total_len: u16) u32 {
        for (mtu_plateaus) |p| {
            if (p < total_len) return p;
        }
        return 68;
    }

    fn handleDestUnreachable(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        if (v.len < 8) return;
        const code = v[1];
        log.debug("Destination Unreachable code {} from {any}", .{ code, r.remote_address.v4 });

        // The error embeds the original IP header + >=8 payload bytes (RFC 792).
        if (v.len < 8 + header.IPv4MinimumSize) return;
        const orig = v[8..];
        if ((orig[0] >> 4) != 4) return;
        const orig_src = tcpip.Address{ .v4 = orig[12..16].* };
        const orig_dst = tcpip.Address{ .v4 = orig[16..20].* };
        // Only honor errors about packets we could actually have sent: the
        // cheap RFC 5927 check against off-path spoofing.
        if (!s.hasLocalAddress(orig_src)) return;

        if (code == DestUnreachableCode.FRAGMENTATION_NEEDED) {
            var mtu_val: u32 = std.mem.readInt(u16, v[6..8], .big);
            if (mtu_val == 0) mtu_val = plateauBelow(std.mem.readInt(u16, orig[2..4], .big));
            mtu_val = @max(mtu_val, 68);
            s.updatePMTU(orig_dst, mtu_val);
            return;
        }

        notifyTransportError(s, orig);
    }

    fn notifyTransportError(s: *stack.Stack, orig: []const u8) void {
        const ihl: usize = @as(usize, orig[0] & 0x0f) * 4;
        if (ihl < header.IPv4MinimumSize or orig.len < ihl + 4) return;
        const ports = orig[ihl..];
        // The embedded packet was outbound, so its source is our local side.
        const id = stack.TransportEndpointID{
            .local_port = std.mem.readInt(u16, ports[0..2], .big),
            .local_address = .{ .v4 = orig[12..16].* },
            .remote_port = std.mem.readInt(u16, ports[2..4], .big),
            .remote_address = .{ .v4 = orig[16..20].* },
        };
        if (s.endpoints.get(id)) |ep| {
            ep.notify(waiter.EventErr);
            ep.decRef();
        }
    }

    fn handleRedirect(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        if (v.len < 8) return;
        const code = v[1];
        _ = code;

        // Extract gateway address from ICMP redirect (bytes 4-7)
        const gateway = tcpip.Address{ .v4 = v[4..8][0..4].* };

        // NOTE: Security consideration - redirects should be validated
        // before updating routing table to prevent route hijacking
        log.debug("Redirect received suggesting gateway {any}", .{gateway.v4});
        _ = s;
        _ = r;
    }

    /// Send Destination Unreachable message.
    pub fn sendDestUnreachable(s: *stack.Stack, r: *const stack.Route, code: u8, original_pkt: []const u8) void {
        if (!rate_limiter.tryConsume()) {
            log.debug("ICMP rate limited", .{});
            stats.global_stats.icmp.errors_throttled.inc();
            return;
        }

        // ICMP error contains: type(1) + code(1) + checksum(2) + unused(4) + original IP header + 8 bytes
        const orig_len = @min(original_pkt.len, 28); // IP header (20 min) + 8 bytes data
        const icmp_len = 8 + orig_len;

        const buf = s.allocator.alloc(u8, icmp_len) catch return;
        defer s.allocator.free(buf);

        buf[0] = Type.DEST_UNREACHABLE;
        buf[1] = code;
        buf[2] = 0; // checksum placeholder
        buf[3] = 0;
        @memset(buf[4..8], 0); // unused
        @memcpy(buf[8..][0..orig_len], original_pkt[0..orig_len]);

        var h = header.ICMPv4.init(buf[0..header.ICMPv4MinimumSize]);
        h.setChecksum(0);
        const c = h.calculateChecksum(buf[header.ICMPv4MinimumSize..]);
        h.setChecksum(c);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const hdr_mem = s.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer s.allocator.free(hdr_mem);

        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        if (r.nic.network_endpoints.get(0x0800)) |ip_ep| {
            stats.global_stats.icmp.tx_dest_unreachable.inc();
            ip_ep.writePacket(r, ProtocolNumber, pkt) catch |err| {
                log.debug("ICMP: error message tx failed: {}", .{err});
                stats.global_stats.direction.tx_drops.inc();
            };
        }
    }

    /// Send Time Exceeded message.
    pub fn sendTimeExceeded(s: *stack.Stack, r: *const stack.Route, code: u8, original_pkt: []const u8) void {
        if (!rate_limiter.tryConsume()) {
            stats.global_stats.icmp.errors_throttled.inc();
            return;
        }

        const orig_len = @min(original_pkt.len, 28);
        const icmp_len = 8 + orig_len;

        const buf = s.allocator.alloc(u8, icmp_len) catch return;
        defer s.allocator.free(buf);

        buf[0] = Type.TIME_EXCEEDED;
        buf[1] = code;
        buf[2] = 0;
        buf[3] = 0;
        @memset(buf[4..8], 0);
        @memcpy(buf[8..][0..orig_len], original_pkt[0..orig_len]);

        var h = header.ICMPv4.init(buf[0..header.ICMPv4MinimumSize]);
        h.setChecksum(0);
        const c = h.calculateChecksum(buf[header.ICMPv4MinimumSize..]);
        h.setChecksum(c);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const hdr_mem = s.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer s.allocator.free(hdr_mem);

        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        if (r.nic.network_endpoints.get(0x0800)) |ip_ep| {
            stats.global_stats.icmp.tx_time_exceeded.inc();
            ip_ep.writePacket(r, ProtocolNumber, pkt) catch |err| {
                log.debug("ICMP: error message tx failed: {}", .{err});
                stats.global_stats.direction.tx_drops.inc();
            };
        }
    }
};

pub const ICMPv4Protocol = struct {
    owner_allocator: ?std.mem.Allocator = null,

    pub fn init() ICMPv4Protocol {
        return .{};
    }

    pub fn protocol(self: *ICMPv4Protocol) stack.NetworkProtocol {
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = stack.NetworkProtocol.VTable{
        .number = number,
        .newEndpoint = newEndpoint,
        .linkAddressRequest = linkAddressRequest,
        .parseAddresses = parseAddresses,
        .deinit = deinit_external,
    };

    fn deinit_external(ptr: *anyopaque) void {
        const self = @as(*ICMPv4Protocol, @ptrCast(@alignCast(ptr)));
        if (self.owner_allocator) |a| a.destroy(self);
    }

    fn number(ptr: *anyopaque) tcpip.NetworkProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn linkAddressRequest(ptr: *anyopaque, addr: tcpip.Address, local_addr: tcpip.Address, nic: *stack.NIC) tcpip.Error!void {
        _ = ptr;
        _ = addr;
        _ = local_addr;
        _ = nic;
        return tcpip.Error.NotPermitted;
    }

    fn parseAddresses(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.NetworkProtocol.AddressPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{
            .src = .{ .v4 = .{ 0, 0, 0, 0 } },
            .dst = .{ .v4 = .{ 0, 0, 0, 0 } },
        };
        const h = header.IPv4.init(v);
        return .{
            .src = .{ .v4 = h.sourceAddress() },
            .dst = .{ .v4 = h.destinationAddress() },
        };
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        const self = @as(*ICMPv4Protocol, @ptrCast(@alignCast(ptr)));
        const ep = nic.stack.allocator.create(ICMPv4Endpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = .{
            .nic = nic,
            .address = addr.address,
            .protocol = self,
        };
        _ = dispatcher;
        return ep.networkEndpoint();
    }
};

pub const ICMPv4Endpoint = struct {
    nic: *stack.NIC,
    address: tcpip.Address,
    protocol: *ICMPv4Protocol,

    pub fn networkEndpoint(self: *ICMPv4Endpoint) stack.NetworkEndpoint {
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = stack.NetworkEndpoint.VTable{
        .writePacket = writePacket,
        .handlePacket = handlePacket,
        .mtu = mtu,
        .close = close,
    };

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*ICMPv4Endpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.IPv4MinimumSize;
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*ICMPv4Endpoint, @ptrCast(@alignCast(ptr)));
        self.nic.stack.allocator.destroy(self);
    }

    fn writePacket(ptr: *anyopaque, r: *const stack.Route, prot: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        _ = ptr;
        _ = r;
        _ = prot;
        _ = pkt;
        return tcpip.Error.NotPermitted;
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        const self = @as(*ICMPv4Endpoint, @ptrCast(@alignCast(ptr)));
        ICMPv4PacketHandler.handlePacket(self.nic.stack, r, pkt);
    }
};

test "ICMP fragmentation needed updates the PMTU cache" {
    const loopback = @import("../drivers/loopback.zig");
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var lo = loopback.Loopback.init(allocator);
    defer lo.deinit();
    try s.createLoopbackNIC(1, lo.linkEndpoint());
    const nic = s.nics.get(1).?;
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = .{ 10, 0, 0, 1 } }, .prefix_len = 24 } });

    const r = stack.Route{
        .local_address = .{ .v4 = .{ 10, 0, 0, 1 } },
        .remote_address = .{ .v4 = .{ 203, 0, 113, 1 } },
        .local_link_address = lo.linkEndpoint().linkAddress(),
        .net_proto = 0x0800,
        .nic = nic,
    };

    var msg = [_]u8{0} ** (8 + 28);
    msg[0] = Type.DEST_UNREACHABLE;
    msg[1] = DestUnreachableCode.FRAGMENTATION_NEEDED;
    msg[8] = 0x45;
    std.mem.writeInt(u16, msg[10..12], 1500, .big); // embedded total length
    msg[20..24].* = .{ 10, 0, 0, 1 }; // embedded src: ours
    msg[24..28].* = .{ 192, 0, 2, 7 }; // embedded dst: the path target
    const path_dst = tcpip.Address{ .v4 = .{ 192, 0, 2, 7 } };

    const feed = struct {
        fn run(st: *stack.Stack, route: *const stack.Route, bytes: []const u8) void {
            var views = [_]buffer.ClusterView{.{ .cluster = null, .view = @constCast(bytes) }};
            const pkt = tcpip.PacketBuffer{
                .data = buffer.VectorisedView.init(bytes.len, &views),
                .header = buffer.Prependable.init(&[_]u8{}),
            };
            ICMPv4PacketHandler.handlePacket(st, route, pkt);
        }
    }.run;

    // MTU field of 0: fall back to the next plateau below the embedded length.
    feed(&s, &r, &msg);
    try std.testing.expectEqual(@as(?u32, 1492), s.pmtuFor(path_dst));

    // Explicit next-hop MTU shrinks the entry.
    std.mem.writeInt(u16, msg[6..8], 1400, .big);
    feed(&s, &r, &msg);
    try std.testing.expectEqual(@as(?u32, 1400), s.pmtuFor(path_dst));

    // An error about a packet we never sent (foreign source) is ignored.
    msg[20..24].* = .{ 10, 0, 0, 99 };
    std.mem.writeInt(u16, msg[6..8], 600, .big);
    feed(&s, &r, &msg);
    try std.testing.expectEqual(@as(?u32, 1400), s.pmtuFor(path_dst));
}

test "ICMPv4 error senders count throttle drops" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    // Drain the shared error limiter so both senders take the throttle path;
    // save/restore it so test ordering does not matter.
    const saved = ICMPv4PacketHandler.rate_limiter;
    defer ICMPv4PacketHandler.rate_limiter = saved;
    ICMPv4PacketHandler.rate_limiter.tokens = 0;

    var r = stack.Route{
        .local_address = .{ .v4 = .{ 10, 0, 0, 1 } },
        .remote_address = .{ .v4 = .{ 10, 0, 0, 2 } },
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = undefined,
    };
    const orig = [_]u8{0} ** 28;

    const before = stats.global_stats.icmp.errors_throttled.load();
    ICMPv4PacketHandler.sendDestUnreachable(&s, &r, 0, &orig);
    ICMPv4PacketHandler.sendTimeExceeded(&s, &r, 0, &orig);
    try std.testing.expectEqual(before + 2, stats.global_stats.icmp.errors_throttled.load());
}

test "RTT measurement" {
    const allocator = std.testing.allocator;
    var rtt = RttMeasurement.init(allocator);
    defer rtt.deinit();

    rtt.recordSend(1234);
    std.time.sleep(1_000_000); // 1ms

    const measured_rtt = rtt.recordRecv(1234);
    try std.testing.expect(measured_rtt != null);
    try std.testing.expect(measured_rtt.? >= 1000); // at least 1000 us
}
