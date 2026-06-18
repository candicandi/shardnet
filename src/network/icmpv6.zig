/// ICMPv6 protocol implementation.
///
/// Handles ICMPv6 echo, Neighbor Discovery Protocol (NDP),
/// Router Solicitation/Advertisement, Duplicate Address Detection (DAD),
/// and Multicast Listener Discovery (MLD).

const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");
const log = @import("../log.zig").scoped(.icmpv6);
const stats = @import("../stats.zig");
const RateLimiter = @import("../ratelimit.zig").RateLimiter;

pub const ProtocolNumber = 58;

/// DAD (Duplicate Address Detection) state.
/// NOTE: RFC 4862 specifies 1 second wait time for DAD.
pub const DADState = struct {
    address: [16]u8,
    retransmit_timer_ms: i64,
    retransmits_left: u8,
    completed: bool,
    conflict: bool,
};

/// MLD (Multicast Listener Discovery) group membership.
pub const MLDGroupEntry = struct {
    group_addr: [16]u8,
    filter_mode: enum { include, exclude },
    /// Timer for query response.
    response_timer_ms: i64,
};

pub const ICMPv6Protocol = struct {
    pub fn init() ICMPv6Protocol {
        return .{};
    }

    pub fn protocol(self: *ICMPv6Protocol) stack.NetworkProtocol {
        return .{
            .ptr = self,
            .vtable = &.{
                .number = number,
                .newEndpoint = newEndpoint,
                .linkAddressRequest = linkAddressRequest,
                .parseAddresses = parseAddresses,
            },
        };
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
        _ = pkt;
        return .{
            .src = .{ .v6 = [_]u8{0} ** 16 },
            .dst = .{ .v6 = [_]u8{0} ** 16 },
        };
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        _ = ptr;
        _ = nic;
        _ = addr;
        _ = dispatcher;
        return tcpip.Error.NotPermitted;
    }
};

pub const ICMPv6TransportProtocol = struct {
    owner_allocator: ?std.mem.Allocator = null,

    pub fn init() ICMPv6TransportProtocol {
        return .{};
    }

    pub fn protocol(self: *ICMPv6TransportProtocol) stack.TransportProtocol {
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
        const self = @as(*ICMPv6TransportProtocol, @ptrCast(@alignCast(ptr)));
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
        ICMPv6PacketHandler.handlePacket(r.nic.stack, r, pkt);
    }
};

pub const ICMPv6PacketHandler = struct {
    // Bound outbound echo replies so a ping flood cannot make us reply without
    // limit. Reuses the ICMPv4 token bucket (ICMPv6 emits no error messages here,
    // so the echo reply is the only floodable response worth gating).
    var rate_limiter: RateLimiter = RateLimiter.init();

    pub fn handlePacket(s: *stack.Stack, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        var mut_pkt = pkt;
        const v = mut_pkt.data.first() orelse return;
        const h = header.ICMPv6.init(v);

        stats.global_stats.icmpv6.rx_packets.inc();

        switch (h.type()) {
            header.ICMPv6PacketTooBigType => {
                handlePacketTooBig(s, v);
            },
            header.ICMPv6EchoRequestType => {
                stats.global_stats.icmpv6.rx_echo_requests.inc();
                handleEchoRequest(s, r, v);
            },
            header.ICMPv6EchoReplyType => {
                stats.global_stats.icmpv6.rx_echo_replies.inc();
            },
            header.ICMPv6NeighborSolicitationType => {
                stats.global_stats.icmpv6.rx_neighbor_solicitations.inc();
                handleNeighborSolicitation(s, r, v);
            },
            header.ICMPv6NeighborAdvertisementType => {
                stats.global_stats.icmpv6.rx_neighbor_advertisements.inc();
                handleNeighborAdvertisement(s, r, v);
            },
            header.ICMPv6RouterSolicitationType => {
                stats.global_stats.icmpv6.rx_router_solicitations.inc();
            },
            header.ICMPv6RouterAdvertisementType => {
                stats.global_stats.icmpv6.rx_router_advertisements.inc();
                handleRouterAdvertisement(s, r, v);
            },
            130 => { // MLD Query
                handleMLDQuery(s, r, v);
            },
            131 => { // MLDv1 Report
                handleMLDReport(s, r, v);
            },
            143 => { // MLDv2 Report
                handleMLDv2Report(s, r, v);
            },
            else => {
                log.debug("Unknown ICMPv6 type: {}", .{h.type()});
            },
        }
    }

    fn handlePacketTooBig(s: *stack.Stack, v: []const u8) void {
        // type(1) code(1) checksum(2) MTU(4), then the original packet (RFC 4443).
        if (v.len < 8 + header.IPv6MinimumSize) return;
        const orig = v[8..];
        if ((orig[0] >> 4) != 6) return;
        const orig_src = tcpip.Address{ .v6 = orig[8..24].* };
        const orig_dst = tcpip.Address{ .v6 = orig[24..40].* };
        // Only honor errors about packets we could actually have sent: the
        // cheap RFC 5927 check against off-path spoofing.
        if (!s.hasLocalAddress(orig_src)) return;
        // RFC 8201: never below the IPv6 minimum link MTU.
        const mtu_val = @max(std.mem.readInt(u32, v[4..8], .big), 1280);
        s.updatePMTU(orig_dst, mtu_val);
    }

    fn handleEchoRequest(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        if (!rate_limiter.tryConsume()) {
            stats.global_stats.icmpv6.echo_replies_throttled.inc();
            return;
        }
        const payload = s.allocator.alloc(u8, v.len) catch return;
        defer s.allocator.free(payload);
        @memcpy(payload, v);

        var reply_h = header.ICMPv6.init(payload);
        reply_h.data[0] = header.ICMPv6EchoReplyType;
        reply_h.setChecksum(0);

        const src = r.local_address.v6;
        const dst = r.remote_address.v6;
        const c = reply_h.calculateChecksum(src, dst, payload[header.ICMPv6MinimumSize..]);
        reply_h.setChecksum(c);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = payload }};
        const hdr_mem = s.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer s.allocator.free(hdr_mem);

        const reply_pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(payload.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        const reply_route = r.*;
        if (r.nic.network_endpoints.get(0x86dd)) |ep| {
            stats.global_stats.icmpv6.tx_echo_replies.inc();
            ep.writePacket(&reply_route, ProtocolNumber, reply_pkt) catch |err| {
                log.debug("ICMPv6: echo reply tx failed: {}", .{err});
                stats.global_stats.direction.tx_drops.inc();
            };
        }
    }

    fn handleNeighborSolicitation(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        if (v.len < header.ICMPv6MinimumSize + 20) return;
        const ns = header.ICMPv6NS.init(@constCast(v[header.ICMPv6MinimumSize..]));
        const target = ns.targetAddress();

        const src_is_unspecified = r.remote_address.eq(.{ .v6 = [_]u8{0} ** 16 });

        // Learn sender's link-layer address from SLLA option
        if (!src_is_unspecified and v.len >= header.ICMPv6MinimumSize + 28) {
            if (v[header.ICMPv6MinimumSize + 20] == header.ICMPv6OptionSourceLinkLayerAddress) {
                var mac: tcpip.LinkAddress = undefined;
                @memcpy(&mac.addr, v[header.ICMPv6MinimumSize + 22 .. header.ICMPv6MinimumSize + 28]);
                s.addLinkAddress(r.remote_address, mac) catch {};
            }
        }

        if (r.nic.hasAddress(.{ .v6 = target })) {
            // NOTE: If source is unspecified (::), this is a DAD probe.
            // We respond with NA but don't add to neighbor cache.
            const is_dad = src_is_unspecified;

            if (is_dad) {
                // NOTE: RFC 4862 Section 5.4.3 - Receiving DAD NS
                // A conflict means someone else is probing for our address.
                log.err("IPv6 DAD Conflict detected for address {any}", .{target});
            }

            sendNeighborAdvertisement(s, r, target, is_dad);
        }
    }

    fn sendNeighborAdvertisement(s: *stack.Stack, r: *const stack.Route, target: [16]u8, is_dad: bool) void {
        const na_buf = s.allocator.alloc(u8, header.ICMPv6MinimumSize + 20 + 8) catch return;
        defer s.allocator.free(na_buf);

        var na_h = header.ICMPv6.init(na_buf[0..header.ICMPv6MinimumSize]);
        na_h.data[0] = header.ICMPv6NeighborAdvertisementType;
        na_h.data[1] = 0;
        na_h.setChecksum(0);

        var na = header.ICMPv6NA.init(na_buf[header.ICMPv6MinimumSize..]);
        na.setFlags(if (is_dad) header.ICMPv6NAFlagsOverride else (header.ICMPv6NAFlagsSolicited | header.ICMPv6NAFlagsOverride));
        na.setTargetAddress(target);

        // TLLA option
        na_buf[header.ICMPv6MinimumSize + 20] = header.ICMPv6OptionTargetLinkLayerAddress;
        na_buf[header.ICMPv6MinimumSize + 21] = 1;
        @memcpy(na_buf[header.ICMPv6MinimumSize + 22 .. header.ICMPv6MinimumSize + 28], &r.nic.linkEP.linkAddress().addr);

        const src = target;
        const dst = if (is_dad) ([_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }) else r.remote_address.v6;

        const c = na_h.calculateChecksum(src, dst, na_buf[header.ICMPv6MinimumSize..]);
        na_h.setChecksum(c);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = na_buf }};
        const hdr_mem = s.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer s.allocator.free(hdr_mem);

        const na_pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(na_buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        var na_route = stack.Route{
            .local_address = .{ .v6 = src },
            .remote_address = .{ .v6 = dst },
            .local_link_address = r.nic.linkEP.linkAddress(),
            .remote_link_address = if (is_dad) tcpip.LinkAddress{ .addr = [_]u8{ 0x33, 0x33, 0, 0, 0, 1 } } else r.remote_link_address,
            .net_proto = 0x86dd,
            .nic = r.nic,
        };

        if (r.nic.network_endpoints.get(0x86dd)) |ep| {
            stats.global_stats.icmpv6.tx_neighbor_advertisements.inc();
            ep.writePacket(&na_route, ProtocolNumber, na_pkt) catch |err| {
                log.debug("ICMPv6: neighbor advertisement tx failed: {}", .{err});
                stats.global_stats.direction.tx_drops.inc();
            };
        }
    }

    fn handleNeighborAdvertisement(s: *stack.Stack, _: *const stack.Route, v: []const u8) void {
        if (v.len < header.ICMPv6MinimumSize + 20) return;
        const na = header.ICMPv6NA.init(@constCast(v[header.ICMPv6MinimumSize..]));
        const target = na.targetAddress();

        // Extract TLLA option
        if (v.len >= header.ICMPv6MinimumSize + 28) {
            if (v[header.ICMPv6MinimumSize + 20] == header.ICMPv6OptionTargetLinkLayerAddress) {
                var mac: tcpip.LinkAddress = undefined;
                @memcpy(&mac.addr, v[header.ICMPv6MinimumSize + 22 .. header.ICMPv6MinimumSize + 28]);
                s.addLinkAddress(.{ .v6 = target }, mac) catch {};
            }
        }
    }

    // RFC 4861 routers are trusted by default, which an attacker on a shared L2
    // can abuse (a rogue RA installs a default route and SLAAC prefix). Honor an
    // RA only when accept_ra is set, and only from an allowlisted source if one
    // is configured.
    fn raAccepted(s: *stack.Stack, src: tcpip.Address) bool {
        if (!s.config.ipv6_accept_ra) return false;
        if (s.config.ipv6_ra_allowlist) |allow| {
            for (allow) |a| {
                if (a.eq(src)) return true;
            }
            return false;
        }
        return true;
    }

    fn handleRouterAdvertisement(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        if (!raAccepted(s, r.remote_address)) {
            stats.global_stats.icmpv6.router_advertisements_ignored.inc();
            return;
        }
        if (v.len < header.ICMPv6MinimumSize + 12) return;
        const ra = header.ICMPv6RA.init(@constCast(v[header.ICMPv6MinimumSize..]));

        // Add default gateway if lifetime > 0
        if (ra.routerLifetime() > 0) {
            s.addRoute(.{
                .destination = .{ .address = .{ .v6 = [_]u8{0} ** 16 }, .prefix = 0 },
                .gateway = r.remote_address,
                .nic = r.nic.id,
                .mtu = r.nic.linkEP.mtu(),
            }) catch {};

            // Learn router's MAC
            if (r.remote_link_address) |mac| {
                s.addLinkAddress(r.remote_address, mac) catch {};
            }
        }

        // Parse Options
        var opt_idx: usize = header.ICMPv6MinimumSize + 12;
        while (opt_idx + 2 <= v.len) {
            const opt_type = v[opt_idx];
            const opt_len = @as(usize, v[opt_idx + 1]) * 8;
            if (opt_len == 0 or opt_idx + opt_len > v.len) break;

            if (opt_type == header.ICMPv6OptionPrefixInformation) {
                if (opt_len >= 32) {
                    handlePrefixOption(s, r, v[opt_idx..][0..opt_len]);
                }
            }
            opt_idx += opt_len;
        }
    }

    fn handlePrefixOption(s: *stack.Stack, r: *const stack.Route, opt: []const u8) void {
        _ = s;
        const pinfo = header.ICMPv6OptionPrefix.init(@constCast(opt));
        const prefix = pinfo.prefix();
        const prefix_len = pinfo.prefixLength();

        // Flags: L=0x80, A=0x40
        const flags = opt[3];
        if (flags & 0x40 != 0) { // Autonomous address-configuration flag
            // SLAAC: Generate address from prefix + interface ID (Modified EUI-64)
            var new_addr = prefix;
            const mac = r.nic.linkEP.linkAddress();
            new_addr[8] = mac.addr[0] ^ 0x02;
            new_addr[9] = mac.addr[1];
            new_addr[10] = mac.addr[2];
            new_addr[11] = 0xff;
            new_addr[12] = 0xfe;
            new_addr[13] = mac.addr[3];
            new_addr[14] = mac.addr[4];
            new_addr[15] = mac.addr[5];

            if (!r.nic.hasAddress(.{ .v6 = new_addr })) {
                r.nic.addAddress(.{
                    .protocol = 0x86dd,
                    .address_with_prefix = .{
                        .address = .{ .v6 = new_addr },
                        .prefix_len = prefix_len,
                    },
                }) catch {};
                log.info("SLAAC: Configured address {any}/{}", .{ new_addr, prefix_len });
            }
        }
    }

    /// Handle MLD Query (type 130).
    fn handleMLDQuery(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        _ = s;
        _ = r;
        if (v.len < header.ICMPv6MinimumSize + 20) return;
        // NOTE: Would schedule MLD report for each joined multicast group
        log.debug("MLD Query received", .{});
    }

    /// Handle MLDv1 Report (type 131).
    fn handleMLDReport(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        _ = s;
        _ = r;
        _ = v;
        // Informational only for hosts
    }

    /// Handle MLDv2 Report (type 143).
    fn handleMLDv2Report(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        _ = s;
        _ = r;
        _ = v;
        // Informational only for hosts
    }

    /// Send MLD Report for joining a multicast group.
    pub fn sendMLDReport(s: *stack.Stack, nic: *stack.NIC, group: [16]u8) void {
        const report_len = header.ICMPv6MinimumSize + 20;
        const buf = s.allocator.alloc(u8, report_len) catch return;
        defer s.allocator.free(buf);

        @memset(buf, 0);
        buf[0] = 131; // MLDv1 Report
        buf[1] = 0;
        // Checksum placeholder
        // Maximum Response Delay (2 bytes) = 0
        // Reserved (2 bytes) = 0
        @memcpy(buf[8..24], &group);

        const src = nic.getLinkLocalAddress() orelse return;
        var h = header.ICMPv6.init(buf[0..header.ICMPv6MinimumSize]);
        const c = h.calculateChecksum(src.v6, group, buf[header.ICMPv6MinimumSize..]);
        h.setChecksum(c);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const hdr_mem = s.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer s.allocator.free(hdr_mem);

        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        const r = stack.Route{
            .local_address = src,
            .remote_address = .{ .v6 = group },
            .local_link_address = nic.linkEP.linkAddress(),
            .remote_link_address = tcpip.LinkAddress{ .addr = [_]u8{ 0x33, 0x33, group[12], group[13], group[14], group[15] } },
            .net_proto = 0x86dd,
            .nic = nic,
        };

        if (nic.network_endpoints.get(0x86dd)) |ep| {
            ep.writePacket(&r, ProtocolNumber, pkt) catch |err| {
                log.debug("ICMPv6: MLD report tx failed: {}", .{err});
                stats.global_stats.direction.tx_drops.inc();
            };
        }
    }
};

test "ICMPv6 Neighbor Discovery" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var ipv6_proto = @import("ipv6.zig").IPv6Protocol.init();
    try s.registerNetworkProtocol(ipv6_proto.protocol());

    var icmpv6_transport = ICMPv6TransportProtocol.init();
    try s.registerTransportProtocol(icmpv6_transport.protocol());

    var fake_link = struct {
        last_pkt: ?[]u8 = null,
        alloc: std.mem.Allocator,

        fn writePacket(ptr: *anyopaque, route: ?*const stack.Route, prot: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = route;
            _ = prot;
            const hdr_view = pkt.header.view();
            const data_len = pkt.data.size;
            if (self.last_pkt) |p| self.alloc.free(p);
            self.last_pkt = self.alloc.alloc(u8, hdr_view.len + data_len) catch return tcpip.Error.NoBufferSpace;
            @memcpy(self.last_pkt.?[0..hdr_view.len], hdr_view);
            var offset = hdr_view.len;
            for (pkt.data.views) |v| {
                @memcpy(self.last_pkt.?[offset .. offset + v.view.len], v.view);
                offset += v.view.len;
            }
            return;
        }
        fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
            _ = ptr;
            _ = dispatcher;
        }
        fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
            _ = ptr;
            return .{ .addr = [_]u8{ 1, 2, 3, 4, 5, 6 } };
        }
        fn getMtu(ptr: *anyopaque) u32 {
            _ = ptr;
            return 1500;
        }
        fn setMTU(ptr: *anyopaque, m: u32) void {
            _ = ptr;
            _ = m;
        }
        fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
            _ = ptr;
            return stack.CapabilityNone;
        }
    }{ .alloc = allocator };
    defer if (fake_link.last_pkt) |p| allocator.free(p);

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_link,
        .vtable = &.{
            .writePacket = @TypeOf(fake_link).writePacket,
            .attach = @TypeOf(fake_link).attach,
            .linkAddress = @TypeOf(fake_link).linkAddress,
            .mtu = @TypeOf(fake_link).getMtu,
            .setMTU = @TypeOf(fake_link).setMTU,
            .capabilities = @TypeOf(fake_link).capabilities,
        },
    };

    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;

    const my_addr = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try nic.addAddress(.{
        .protocol = 0x86dd,
        .address_with_prefix = .{ .address = .{ .v6 = my_addr }, .prefix_len = 64 },
    });

    const sender_addr = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    const sender_mac = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

    var ns_buf = try allocator.alloc(u8, header.ICMPv6MinimumSize + 20 + 8);
    defer allocator.free(ns_buf);

    var icmp_h = header.ICMPv6.init(ns_buf[0..header.ICMPv6MinimumSize]);
    icmp_h.data[0] = header.ICMPv6NeighborSolicitationType;
    icmp_h.data[1] = 0;
    icmp_h.setChecksum(0);

    var ns = header.ICMPv6NS.init(ns_buf[header.ICMPv6MinimumSize..]);
    ns.setTargetAddress(my_addr);

    ns_buf[header.ICMPv6MinimumSize + 20] = header.ICMPv6OptionSourceLinkLayerAddress;
    ns_buf[header.ICMPv6MinimumSize + 21] = 1;
    @memcpy(ns_buf[header.ICMPv6MinimumSize + 22 .. header.ICMPv6MinimumSize + 28], &sender_mac);

    const r = stack.Route{
        .local_address = .{ .v6 = my_addr },
        .remote_address = .{ .v6 = sender_addr },
        .local_link_address = .{ .addr = [_]u8{ 1, 2, 3, 4, 5, 6 } },
        .remote_link_address = .{ .addr = sender_mac },
        .net_proto = 0x86dd,
        .nic = nic,
    };

    var views = [_]buffer.ClusterView{.{ .cluster = null, .view = ns_buf }};
    const ns_pkt = tcpip.PacketBuffer{
        .data = buffer.VectorisedView.init(ns_buf.len, &views),
        .header = buffer.Prependable.init(&[_]u8{}),
    };

    ICMPv6PacketHandler.handlePacket(&s, &r, ns_pkt);

    const learned_mac = s.getLinkAddress(.{ .v6 = sender_addr });
    try std.testing.expect(learned_mac != null);
    try std.testing.expectEqualStrings(&sender_mac, &learned_mac.?.addr);

    try std.testing.expect(fake_link.last_pkt != null);
    const na_pkt_data = fake_link.last_pkt.?;
    try std.testing.expect(na_pkt_data.len >= 40 + 28);
    const na_icmp = header.ICMPv6.init(na_pkt_data[40..]);
    try std.testing.expectEqual(header.ICMPv6NeighborAdvertisementType, na_icmp.type());

    const na = header.ICMPv6NA.init(na_pkt_data[40 + header.ICMPv6MinimumSize ..]);
    try std.testing.expectEqualStrings(&my_addr, &na.targetAddress());
}

test "ICMPv6 echo replies are rate limited" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var ipv6_proto = @import("ipv6.zig").IPv6Protocol.init();
    try s.registerNetworkProtocol(ipv6_proto.protocol());
    var icmpv6_transport = ICMPv6TransportProtocol.init();
    try s.registerTransportProtocol(icmpv6_transport.protocol());

    var fake_link = struct {
        fn writePacket(_: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, _: tcpip.PacketBuffer) tcpip.Error!void {
            return;
        }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
            return .{ .addr = [_]u8{ 1, 2, 3, 4, 5, 6 } };
        }
        fn getMtu(_: *anyopaque) u32 {
            return 1500;
        }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
            return stack.CapabilityNone;
        }
    }{};

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_link,
        .vtable = &.{
            .writePacket = @TypeOf(fake_link).writePacket,
            .attach = @TypeOf(fake_link).attach,
            .linkAddress = @TypeOf(fake_link).linkAddress,
            .mtu = @TypeOf(fake_link).getMtu,
            .setMTU = @TypeOf(fake_link).setMTU,
            .capabilities = @TypeOf(fake_link).capabilities,
        },
    };

    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    const my_addr = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try nic.addAddress(.{ .protocol = 0x86dd, .address_with_prefix = .{ .address = .{ .v6 = my_addr }, .prefix_len = 64 } });

    const sender_addr = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    const r = stack.Route{
        .local_address = .{ .v6 = my_addr },
        .remote_address = .{ .v6 = sender_addr },
        .local_link_address = .{ .addr = [_]u8{ 1, 2, 3, 4, 5, 6 } },
        .remote_link_address = .{ .addr = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff } },
        .net_proto = 0x86dd,
        .nic = nic,
    };

    var echo_buf = [_]u8{0} ** (header.ICMPv6MinimumSize + 8);
    echo_buf[0] = header.ICMPv6EchoRequestType;
    var views = [_]buffer.ClusterView{.{ .cluster = null, .view = &echo_buf }};
    const echo_pkt = tcpip.PacketBuffer{
        .data = buffer.VectorisedView.init(echo_buf.len, &views),
        .header = buffer.Prependable.init(&[_]u8{}),
    };

    // Constrain the shared limiter to a single token, restoring it afterwards so
    // test ordering does not matter.
    const saved = ICMPv6PacketHandler.rate_limiter;
    defer ICMPv6PacketHandler.rate_limiter = saved;
    ICMPv6PacketHandler.rate_limiter = RateLimiter.init();
    ICMPv6PacketHandler.rate_limiter.max_tokens = 1;
    ICMPv6PacketHandler.rate_limiter.tokens = 1;

    const base_tx = stats.global_stats.icmpv6.tx_echo_replies.load();
    const base_throttled = stats.global_stats.icmpv6.echo_replies_throttled.load();

    // First echo request consumes the budget and is answered; the second is
    // throttled (no reply emitted).
    ICMPv6PacketHandler.handlePacket(&s, &r, echo_pkt);
    ICMPv6PacketHandler.handlePacket(&s, &r, echo_pkt);

    try std.testing.expectEqual(base_tx + 1, stats.global_stats.icmpv6.tx_echo_replies.load());
    try std.testing.expectEqual(base_throttled + 1, stats.global_stats.icmpv6.echo_replies_throttled.load());
}

test "ICMPv6 Router Advertisement & SLAAC" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    s.config.ipv6_accept_ra = true;

    var ipv6_proto = @import("ipv6.zig").IPv6Protocol.init();
    try s.registerNetworkProtocol(ipv6_proto.protocol());

    var icmpv6_transport = ICMPv6TransportProtocol.init();
    try s.registerTransportProtocol(icmpv6_transport.protocol());

    var fake_link = struct {
        last_pkt: ?[]u8 = null,
        alloc: std.mem.Allocator,

        fn writePacket(ptr: *anyopaque, route: ?*const stack.Route, prot: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = route;
            _ = prot;
            const hdr_view = pkt.header.view();
            const data_len = pkt.data.size;
            if (self.last_pkt) |p| self.alloc.free(p);
            self.last_pkt = self.alloc.alloc(u8, hdr_view.len + data_len) catch return tcpip.Error.NoBufferSpace;
            @memcpy(self.last_pkt.?[0..hdr_view.len], hdr_view);
            var offset = hdr_view.len;
            for (pkt.data.views) |v| {
                @memcpy(self.last_pkt.?[offset .. offset + v.view.len], v.view);
                offset += v.view.len;
            }
            return;
        }
        fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
            _ = ptr;
            _ = dispatcher;
        }
        fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
            _ = ptr;
            return .{ .addr = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 } };
        }
        fn getMtu(ptr: *anyopaque) u32 {
            _ = ptr;
            return 1500;
        }
        fn setMTU(ptr: *anyopaque, m: u32) void {
            _ = ptr;
            _ = m;
        }
        fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
            _ = ptr;
            return stack.CapabilityNone;
        }
    }{ .alloc = allocator };
    defer if (fake_link.last_pkt) |p| allocator.free(p);

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_link,
        .vtable = &.{
            .writePacket = @TypeOf(fake_link).writePacket,
            .attach = @TypeOf(fake_link).attach,
            .linkAddress = @TypeOf(fake_link).linkAddress,
            .mtu = @TypeOf(fake_link).getMtu,
            .setMTU = @TypeOf(fake_link).setMTU,
            .capabilities = @TypeOf(fake_link).capabilities,
        },
    };

    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;

    const my_ll_addr = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    try nic.addAddress(.{
        .protocol = 0x86dd,
        .address_with_prefix = .{ .address = .{ .v6 = my_ll_addr }, .prefix_len = 64 },
    });

    const router_addr = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const router_mac = [_]u8{ 0xaa, 0x30, 0x75, 0xe0, 0x61, 0x19 };
    const prefix = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    var ra_buf = try allocator.alloc(u8, 48);
    defer allocator.free(ra_buf);
    @memset(ra_buf, 0);

    var icmp_h = header.ICMPv6.init(ra_buf[0..header.ICMPv6MinimumSize]);
    icmp_h.data[0] = header.ICMPv6RouterAdvertisementType;

    const ra = header.ICMPv6RA.init(ra_buf[header.ICMPv6MinimumSize..]);
    _ = ra;
    std.mem.writeInt(u16, ra_buf[header.ICMPv6MinimumSize + 2 .. header.ICMPv6MinimumSize + 4][0..2], 1800, .big);

    const opt_idx = header.ICMPv6MinimumSize + 12;
    ra_buf[opt_idx] = header.ICMPv6OptionPrefixInformation;
    ra_buf[opt_idx + 1] = 4;
    ra_buf[opt_idx + 2] = 64;
    ra_buf[opt_idx + 3] = 0xC0; // L=1, A=1
    @memcpy(ra_buf[opt_idx + 16 .. opt_idx + 32], &prefix);

    const r = stack.Route{
        .local_address = .{ .v6 = my_ll_addr },
        .remote_address = .{ .v6 = router_addr },
        .local_link_address = .{ .addr = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 } },
        .remote_link_address = .{ .addr = router_mac },
        .net_proto = 0x86dd,
        .nic = nic,
    };

    var views = [_]buffer.ClusterView{.{ .cluster = null, .view = ra_buf }};
    const ra_pkt = tcpip.PacketBuffer{
        .data = buffer.VectorisedView.init(ra_buf.len, &views),
        .header = buffer.Prependable.init(&[_]u8{}),
    };

    ICMPv6PacketHandler.handlePacket(&s, &r, ra_pkt);

    var expected_addr = prefix;
    expected_addr[8] = 0x00;
    expected_addr[9] = 0x00;
    expected_addr[10] = 0x00;
    expected_addr[11] = 0xff;
    expected_addr[12] = 0xfe;
    expected_addr[13] = 0x00;
    expected_addr[14] = 0x00;
    expected_addr[15] = 0x02;

    try std.testing.expect(nic.hasAddress(.{ .v6 = expected_addr }));

    const routes = s.getRouteTable();
    var found_default = false;
    for (routes) |re| {
        if (re.destination.prefix == 0 and re.gateway.v6[0] == router_addr[0]) {
            found_default = true;
            break;
        }
    }
    try std.testing.expect(found_default);
}

test "ICMPv6 Router Advertisement guard ignores RAs by default and off-allowlist" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var ipv6_proto = @import("ipv6.zig").IPv6Protocol.init();
    try s.registerNetworkProtocol(ipv6_proto.protocol());

    var fake_link = struct {
        fn writePacket(_: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, _: tcpip.PacketBuffer) tcpip.Error!void {
            return;
        }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
            return .{ .addr = [_]u8{0} ** 6 };
        }
        fn mtu(_: *anyopaque) u32 {
            return 1500;
        }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
            return stack.CapabilityNone;
        }
    }{};
    try s.createNIC(1, .{ .ptr = &fake_link, .vtable = &.{
        .writePacket = @TypeOf(fake_link).writePacket,
        .attach = @TypeOf(fake_link).attach,
        .linkAddress = @TypeOf(fake_link).linkAddress,
        .mtu = @TypeOf(fake_link).mtu,
        .setMTU = @TypeOf(fake_link).setMTU,
        .capabilities = @TypeOf(fake_link).capabilities,
    } });
    const nic = s.nics.get(1).?;

    const router_addr = tcpip.Address{ .v6 = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    // Minimal RA: router lifetime > 0, no options, so it only installs a default route.
    var ra_buf = [_]u8{0} ** (header.ICMPv6MinimumSize + 12);
    ra_buf[0] = header.ICMPv6RouterAdvertisementType;
    std.mem.writeInt(u16, ra_buf[header.ICMPv6MinimumSize + 2 .. header.ICMPv6MinimumSize + 4][0..2], 1800, .big);

    const r = stack.Route{
        .local_address = .{ .v6 = [_]u8{0} ** 16 },
        .remote_address = router_addr,
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x86dd,
        .nic = nic,
    };

    const hasDefault = struct {
        fn f(st: *stack.Stack) bool {
            for (st.getRouteTable()) |re| {
                if (re.destination.prefix == 0) return true;
            }
            return false;
        }
    }.f;

    // Default config: RAs are ignored and counted.
    const ign0 = stats.global_stats.icmpv6.router_advertisements_ignored.load();
    ICMPv6PacketHandler.handleRouterAdvertisement(&s, &r, &ra_buf);
    try std.testing.expect(!hasDefault(&s));
    try std.testing.expectEqual(ign0 + 1, stats.global_stats.icmpv6.router_advertisements_ignored.load());

    // Accepting, but the router is off the allowlist: still ignored.
    const other = tcpip.Address{ .v6 = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 } };
    s.config.ipv6_accept_ra = true;
    s.config.ipv6_ra_allowlist = &[_]tcpip.Address{other};
    ICMPv6PacketHandler.handleRouterAdvertisement(&s, &r, &ra_buf);
    try std.testing.expect(!hasDefault(&s));

    // Router on the allowlist: honored.
    s.config.ipv6_ra_allowlist = &[_]tcpip.Address{router_addr};
    ICMPv6PacketHandler.handleRouterAdvertisement(&s, &r, &ra_buf);
    try std.testing.expect(hasDefault(&s));
}

test "ICMPv6 Packet Too Big updates the PMTU cache" {
    const loopback = @import("../drivers/loopback.zig");
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var lo = loopback.Loopback.init(allocator);
    defer lo.deinit();
    try s.createLoopbackNIC(1, lo.linkEndpoint());
    const nic = s.nics.get(1).?;

    const my_addr = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1};
    const dst_addr = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{2};
    try nic.addAddress(.{ .protocol = 0x86dd, .address_with_prefix = .{ .address = .{ .v6 = my_addr }, .prefix_len = 64 } });

    const r = stack.Route{
        .local_address = .{ .v6 = my_addr },
        .remote_address = .{ .v6 = dst_addr },
        .local_link_address = lo.linkEndpoint().linkAddress(),
        .net_proto = 0x86dd,
        .nic = nic,
    };

    var msg = [_]u8{0} ** (8 + 40);
    msg[0] = header.ICMPv6PacketTooBigType;
    std.mem.writeInt(u32, msg[4..8], 1300, .big);
    msg[8] = 0x60;
    msg[16..32].* = my_addr; // embedded src: ours
    msg[32..48].* = dst_addr; // embedded dst: the path target

    const feed = struct {
        fn run(st: *stack.Stack, route: *const stack.Route, bytes: []const u8) void {
            var views = [_]buffer.ClusterView{.{ .cluster = null, .view = @constCast(bytes) }};
            const pkt = tcpip.PacketBuffer{
                .data = buffer.VectorisedView.init(bytes.len, &views),
                .header = buffer.Prependable.init(&[_]u8{}),
            };
            ICMPv6PacketHandler.handlePacket(st, route, pkt);
        }
    }.run;

    feed(&s, &r, &msg);
    try std.testing.expectEqual(@as(?u32, 1300), s.pmtuFor(.{ .v6 = dst_addr }));

    // Reported MTU below the IPv6 minimum link MTU is clamped to 1280.
    std.mem.writeInt(u32, msg[4..8], 600, .big);
    feed(&s, &r, &msg);
    try std.testing.expectEqual(@as(?u32, 1280), s.pmtuFor(.{ .v6 = dst_addr }));

    // An error about a packet we never sent (foreign source) is ignored:
    // no entry may appear for its destination.
    const other_dst = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{3};
    msg[16..32].* = dst_addr;
    msg[32..48].* = other_dst;
    std.mem.writeInt(u32, msg[4..8], 1400, .big);
    feed(&s, &r, &msg);
    try std.testing.expectEqual(@as(?u32, null), s.pmtuFor(.{ .v6 = other_dst }));
}
