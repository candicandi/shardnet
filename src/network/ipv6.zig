/// IPv6 packet handling.
///
/// Implements IPv6 parsing, validation, extension header chain processing,
/// fragmentation/reassembly, and integration with the network stack.

const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const log = @import("../log.zig").scoped(.ipv6);
const stats = @import("../stats.zig");

pub const ProtocolNumber = 0x86dd;

/// Default Hop Limit for outgoing packets.
pub const DEFAULT_HOP_LIMIT: u8 = 64;

/// Maximum time to hold reassembly fragments before expiry (60 seconds per RFC 8200).
pub const REASSEMBLY_TIMEOUT_MS: i64 = 60_000;

/// Reassembly resource caps (mirrors ipv4.zig): without them a fragment flood
/// exhausts the heap via unique-id contexts or many fragments per datagram.
pub const MAX_REASSEMBLY_CONTEXTS: usize = 256;
pub const MAX_FRAGMENTS_PER_DATAGRAM: usize = 128;
pub const MAX_REASSEMBLY_BYTES: usize = 65_535;

/// Extension header types (Next Header values).
pub const NextHeader = struct {
    pub const HOP_BY_HOP: u8 = 0;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const ICMPV6: u8 = 58;
    pub const NO_NEXT_HEADER: u8 = 59;
    pub const DESTINATION: u8 = 60;
};

/// Fragment reassembly key.
const ReassemblyKey = struct {
    src: [16]u8,
    dst: [16]u8,
    id: u32,
};

/// Fragment reassembly context.
const ReassemblyContext = struct {
    fragments: std.ArrayList(FragmentEntry),
    first_arrival_ms: i64,
    /// Running total of buffered payload bytes, for the per-datagram byte cap.
    total_bytes: usize,
    /// Next Header from the Fragment header: first header of the fragmentable part.
    next_header: u8,

    pub fn init(allocator: std.mem.Allocator, next_header: u8) ReassemblyContext {
        return .{
            .fragments = std.ArrayList(FragmentEntry).init(allocator),
            .first_arrival_ms = std.time.milliTimestamp(),
            .total_bytes = 0,
            .next_header = next_header,
        };
    }

    pub fn deinit(self: *ReassemblyContext, allocator: std.mem.Allocator) void {
        for (self.fragments.items) |f| {
            allocator.free(f.data);
        }
        self.fragments.deinit();
    }

    pub fn isExpired(self: *const ReassemblyContext) bool {
        const now = std.time.milliTimestamp();
        return (now - self.first_arrival_ms) >= REASSEMBLY_TIMEOUT_MS;
    }
};

const FragmentEntry = struct {
    data: []u8,
    /// Byte offset within the fragmentable part (header field is in 8-byte units).
    offset: u32,
    more: bool,
};

/// Parsed extension header result.
pub const ExtensionHeaderResult = struct {
    /// Next header type after all extensions.
    next_header: u8,
    /// Offset in packet where payload begins.
    payload_offset: usize,
    /// Flow label extracted for QoS.
    flow_label: u20 = 0,
    /// Fragment header info if present.
    fragment_offset: ?u16 = null,
    fragment_more: bool = false,
    fragment_id: u32 = 0,
    /// Whether parsing was successful.
    valid: bool = true,
};

/// Parse extension header chain.
/// NOTE: Extension headers must be processed in order. Each header's length
/// is in 8-byte units (except Fragment which is fixed 8 bytes).
pub fn parseExtensionHeaders(data: []const u8, first_next_header: u8) ExtensionHeaderResult {
    var result = ExtensionHeaderResult{
        .next_header = first_next_header,
        .payload_offset = 0,
    };

    var offset: usize = 0;
    var next_hdr = first_next_header;

    while (true) {
        switch (next_hdr) {
            NextHeader.HOP_BY_HOP, NextHeader.DESTINATION, NextHeader.ROUTING => {
                if (offset + 2 > data.len) {
                    result.valid = false;
                    return result;
                }
                next_hdr = data[offset];
                const ext_len = (@as(usize, data[offset + 1]) + 1) * 8;
                if (offset + ext_len > data.len) {
                    result.valid = false;
                    return result;
                }
                offset += ext_len;
            },
            NextHeader.FRAGMENT => {
                if (offset + 8 > data.len) {
                    result.valid = false;
                    return result;
                }
                const frag_off_and_flags = std.mem.readInt(u16, data[offset + 2 ..][0..2], .big);
                result.fragment_offset = frag_off_and_flags >> 3;
                result.fragment_more = (frag_off_and_flags & 0x01) != 0;
                result.fragment_id = std.mem.readInt(u32, data[offset + 4 ..][0..4], .big);
                // Everything after the Fragment header is a slice of the ORIGINAL
                // packet's fragmentable part — for non-first fragments those bytes
                // are mid-stream payload, not headers of this packet. Stop here;
                // reassembly walks the remaining chain on the rebuilt datagram.
                result.next_header = data[offset];
                result.payload_offset = offset + 8;
                return result;
            },
            else => {
                // Upper layer protocol or unknown
                result.next_header = next_hdr;
                result.payload_offset = offset;
                return result;
            },
        }
    }
}

pub const IPv6Protocol = struct {
    owner_allocator: ?std.mem.Allocator = null,

    pub fn init() IPv6Protocol {
        return .{};
    }

    pub fn protocol(self: *IPv6Protocol) stack.NetworkProtocol {
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
        const self = @as(*IPv6Protocol, @ptrCast(@alignCast(ptr)));
        if (self.owner_allocator) |a| a.destroy(self);
    }

    fn number(ptr: *anyopaque) tcpip.NetworkProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn parseAddresses(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.NetworkProtocol.AddressPair {
        _ = ptr;
        const zero = stack.NetworkProtocol.AddressPair{
            .src = .{ .v6 = [_]u8{0} ** 16 },
            .dst = .{ .v6 = [_]u8{0} ** 16 },
        };
        const v = pkt.data.first() orelse return zero;
        // Called from the NIC dispatch before length validation; a runt frame
        // must not drive the address accessors out of bounds.
        if (v.len < header.IPv6MinimumSize) return zero;
        const h = header.IPv6.init(v);
        return .{
            .src = .{ .v6 = h.sourceAddress() },
            .dst = .{ .v6 = h.destinationAddress() },
        };
    }

    fn linkAddressRequest(ptr: *anyopaque, addr: tcpip.Address, local_addr: tcpip.Address, nic: *stack.NIC) tcpip.Error!void {
        _ = ptr;
        if (addr != .v6) return;
        const target = addr.v6;
        const src = local_addr.v6;

        // Solicited-node multicast address
        const dst = addr.toSolicitedNodeMulticast().v6;

        // Build Neighbor Solicitation
        const payload_len = header.ICMPv6MinimumSize + 20 + 8;
        const buf = nic.stack.allocator.alloc(u8, payload_len) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(buf);

        var icmp_h = header.ICMPv6.init(buf[0..header.ICMPv6MinimumSize]);
        icmp_h.data[0] = header.ICMPv6NeighborSolicitationType;
        icmp_h.data[1] = 0;
        icmp_h.setChecksum(0);

        var ns = header.ICMPv6NS.init(buf[header.ICMPv6MinimumSize..]);
        ns.setTargetAddress(target);

        // Option: Source Link-Layer Address
        buf[header.ICMPv6MinimumSize + 20] = header.ICMPv6OptionSourceLinkLayerAddress;
        buf[header.ICMPv6MinimumSize + 21] = 1;
        @memcpy(buf[header.ICMPv6MinimumSize + 22 .. header.ICMPv6MinimumSize + 28], &nic.linkEP.linkAddress().addr);

        const c = icmp_h.calculateChecksum(src, dst, buf[header.ICMPv6MinimumSize..]);
        icmp_h.setChecksum(c);

        const hdr_mem = nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(hdr_mem);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        var r = stack.Route{
            .local_address = .{ .v6 = src },
            .remote_address = .{ .v6 = dst },
            .local_link_address = nic.linkEP.linkAddress(),
            // Ethernet multicast for IPv6: 33:33: + last 32 bits of IPv6 address
            .remote_link_address = tcpip.LinkAddress{ .addr = [_]u8{ 0x33, 0x33, dst[12], dst[13], dst[14], dst[15] } },
            .net_proto = ProtocolNumber,
            .nic = nic,
        };

        if (nic.network_endpoints.get(ProtocolNumber)) |ep| {
            try ep.writePacket(&r, 58, pkt); // ICMPv6 is 58
        }
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        const self = @as(*IPv6Protocol, @ptrCast(@alignCast(ptr)));
        const ep = nic.stack.allocator.create(IPv6Endpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = .{
            .nic = nic,
            .address = addr.address,
            .protocol = self,
            .dispatcher = dispatcher,
            .reassembly_list = std.AutoHashMap(ReassemblyKey, ReassemblyContext).init(nic.stack.allocator),
        };

        // Perform DAD (RFC 4862)
        const target = addr.address.v6;
        const src = [_]u8{0} ** 16;
        const dst = addr.address.toSolicitedNodeMulticast().v6;

        const payload_len = header.ICMPv6MinimumSize + 20;
        const buf = nic.stack.allocator.alloc(u8, payload_len) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(buf);

        var icmp_h = header.ICMPv6.init(buf[0..header.ICMPv6MinimumSize]);
        icmp_h.data[0] = header.ICMPv6NeighborSolicitationType;
        icmp_h.data[1] = 0;
        icmp_h.setChecksum(0);

        var ns = header.ICMPv6NS.init(buf[header.ICMPv6MinimumSize..]);
        ns.setTargetAddress(target);

        const c = icmp_h.calculateChecksum(src, dst, buf[header.ICMPv6MinimumSize..]);
        icmp_h.setChecksum(c);

        const hdr_mem = nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(hdr_mem);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        const r = stack.Route{
            .local_address = .{ .v6 = src },
            .remote_address = .{ .v6 = dst },
            .local_link_address = nic.linkEP.linkAddress(),
            .remote_link_address = tcpip.LinkAddress{ .addr = [_]u8{ 0x33, 0x33, dst[12], dst[13], dst[14], dst[15] } },
            .net_proto = ProtocolNumber,
            .nic = nic,
        };

        // Manual IP header since NetworkEndpoint is not registered yet
        var mut_pkt = pkt;
        const ip_header = mut_pkt.header.prepend(header.IPv6MinimumSize) orelse return tcpip.Error.NoBufferSpace;
        const h = header.IPv6.init(ip_header);
        h.encode(src, dst, 58, @as(u16, @intCast(pkt.data.size)));

        nic.linkEP.writePacket(&r, ProtocolNumber, mut_pkt) catch |err| {
            log.debug("IPv6: solicited-node NS tx failed: {}", .{err});
            stats.global_stats.direction.tx_drops.inc();
        };

        // Also send Router Solicitation to all-routers multicast
        self.sendRouterSolicitation(nic) catch {};

        return ep.networkEndpoint();
    }

    fn sendRouterSolicitation(self: *IPv6Protocol, nic: *stack.NIC) tcpip.Error!void {
        _ = self;
        var src = [_]u8{0} ** 16;
        for (nic.addresses.items) |pa| {
            if (pa.protocol == ProtocolNumber) {
                const addr = pa.address_with_prefix.address.v6;
                if (addr[0] == 0xfe and addr[1] == 0x80) {
                    src = addr;
                    break;
                }
            }
        }

        const dst = [_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }; // All-Routers multicast

        const payload_len = header.ICMPv6MinimumSize + 4 + 8;
        const buf = nic.stack.allocator.alloc(u8, payload_len) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(buf);

        var icmp_h = header.ICMPv6.init(buf[0..header.ICMPv6MinimumSize]);
        icmp_h.data[0] = header.ICMPv6RouterSolicitationType;
        icmp_h.data[1] = 0;
        icmp_h.setChecksum(0);

        // Reserved 4 bytes
        @memset(buf[header.ICMPv6MinimumSize .. header.ICMPv6MinimumSize + 4], 0);

        // Option: Source Link-Layer Address
        buf[header.ICMPv6MinimumSize + 4] = header.ICMPv6OptionSourceLinkLayerAddress;
        buf[header.ICMPv6MinimumSize + 5] = 1;
        @memcpy(buf[header.ICMPv6MinimumSize + 6 .. header.ICMPv6MinimumSize + 12], &nic.linkEP.linkAddress().addr);

        const c = icmp_h.calculateChecksum(src, dst, buf[header.ICMPv6MinimumSize..]);
        icmp_h.setChecksum(c);

        const hdr_mem = nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(hdr_mem);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        const r = stack.Route{
            .local_address = .{ .v6 = src },
            .remote_address = .{ .v6 = dst },
            .local_link_address = nic.linkEP.linkAddress(),
            .remote_link_address = tcpip.LinkAddress{ .addr = [_]u8{ 0x33, 0x33, 0, 0, 0, 2 } },
            .net_proto = ProtocolNumber,
            .nic = nic,
        };

        var mut_pkt = pkt;
        const ip_header = mut_pkt.header.prepend(header.IPv6MinimumSize) orelse return tcpip.Error.NoBufferSpace;
        const h = header.IPv6.init(ip_header);
        h.encode(src, dst, 58, @as(u16, @intCast(pkt.data.size)));

        return nic.linkEP.writePacket(&r, ProtocolNumber, mut_pkt);
    }
};

pub const IPv6Endpoint = struct {
    nic: *stack.NIC,
    address: tcpip.Address,
    protocol: *IPv6Protocol,
    dispatcher: stack.TransportDispatcher,
    reassembly_list: std.AutoHashMap(ReassemblyKey, ReassemblyContext),

    pub fn networkEndpoint(self: *IPv6Endpoint) stack.NetworkEndpoint {
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
        const self = @as(*IPv6Endpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.IPv6MinimumSize;
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*IPv6Endpoint, @ptrCast(@alignCast(ptr)));
        var it = self.reassembly_list.valueIterator();
        while (it.next()) |ctx| {
            ctx.deinit(self.nic.stack.allocator);
        }
        self.reassembly_list.deinit();
        self.nic.stack.allocator.destroy(self);
    }

    fn writePacket(ptr: *anyopaque, r: *const stack.Route, prot: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*IPv6Endpoint, @ptrCast(@alignCast(ptr)));

        var mut_pkt = pkt;
        const ip_header = mut_pkt.header.prepend(header.IPv6MinimumSize) orelse return tcpip.Error.NoBufferSpace;
        const h = header.IPv6.init(ip_header);

        h.encode(r.local_address.v6, r.remote_address.v6, @as(u8, @intCast(prot)), @as(u16, @intCast(pkt.data.size)));

        return self.nic.linkEP.writePacket(r, ProtocolNumber, mut_pkt);
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        const self = @as(*IPv6Endpoint, @ptrCast(@alignCast(ptr)));
        var mut_pkt = pkt;
        const headerView = mut_pkt.data.first() orelse return;
        const h = header.IPv6.init(headerView);
        if (!h.isValid(mut_pkt.data.size)) {
            return;
        }

        // Extract flow label for QoS classification
        const flow_label = h.flowLabel();
        _ = flow_label; // Would be used for traffic classification

        mut_pkt.network_header = headerView[0..header.IPv6MinimumSize];

        const hlen = header.IPv6MinimumSize;
        const plen = h.payloadLength();
        const next_hdr = h.nextHeader();

        // NOTE: Extension headers are processed in chain order.
        // Each extension header contains a Next Header field pointing to
        // the next header type in the chain.
        if (next_hdr == NextHeader.HOP_BY_HOP or
            next_hdr == NextHeader.ROUTING or
            next_hdr == NextHeader.FRAGMENT or
            next_hdr == NextHeader.DESTINATION)
        {
            const ext_data = headerView[hlen..];
            const ext_result = parseExtensionHeaders(ext_data, next_hdr);
            if (!ext_result.valid) {
                log.warn("IPv6: Invalid extension headers", .{});
                return;
            }

            // Handle fragmentation
            if (ext_result.fragment_offset != null) {
                self.handleFragment(r, pkt, h, ext_result);
                return;
            }

            mut_pkt.data.trimFront(hlen + ext_result.payload_offset);
            mut_pkt.data.capLength(plen - ext_result.payload_offset);
            self.dispatcher.deliverTransportPacket(r, ext_result.next_header, mut_pkt);
        } else {
            mut_pkt.data.trimFront(hlen);
            mut_pkt.data.capLength(plen);
            self.dispatcher.deliverTransportPacket(r, next_hdr, mut_pkt);
        }
    }

    fn handleFragment(self: *IPv6Endpoint, r: *const stack.Route, pkt: tcpip.PacketBuffer, h: header.IPv6, ext_result: ExtensionHeaderResult) void {
        const allocator = self.nic.stack.allocator;
        self.expireReassemblyContexts();

        const plen: usize = h.payloadLength();
        const frag_data_off = ext_result.payload_offset;
        if (plen < frag_data_off) return;
        const frag_len = plen - frag_data_off;
        const byte_off = @as(u32, ext_result.fragment_offset.?) * 8;
        const more = ext_result.fragment_more;

        // RFC 8200 4.5: non-final fragments carry a multiple of 8 bytes, and no
        // datagram may exceed 65535 reassembled bytes.
        if (more and frag_len % 8 != 0) {
            stats.global_stats.ip.reassembly_drops.inc();
            return;
        }
        if (byte_off + frag_len > MAX_REASSEMBLY_BYTES) {
            stats.global_stats.ip.reassembly_drops.inc();
            return;
        }

        const key = ReassemblyKey{
            .src = h.sourceAddress(),
            .dst = h.destinationAddress(),
            .id = ext_result.fragment_id,
        };

        var ctx_ptr = self.reassembly_list.getPtr(key);
        if (ctx_ptr == null) {
            if (self.reassembly_list.count() >= MAX_REASSEMBLY_CONTEXTS) {
                self.evictOldestReassembly();
            }
            const ctx = ReassemblyContext.init(allocator, ext_result.next_header);
            self.reassembly_list.put(key, ctx) catch return;
            ctx_ptr = self.reassembly_list.getPtr(key);
        }
        const ctx = ctx_ptr.?;

        if (ctx.fragments.items.len >= MAX_FRAGMENTS_PER_DATAGRAM or
            ctx.total_bytes + frag_len > MAX_REASSEMBLY_BYTES)
        {
            self.poisonReassembly(key);
            return;
        }

        // RFC 5722: a datagram with ANY overlapping fragments must be silently
        // discarded in full (overlap is only ever an attack or a broken stack).
        for (ctx.fragments.items) |f| {
            if (byte_off < f.offset + f.data.len and f.offset < byte_off + frag_len) {
                self.poisonReassembly(key);
                return;
            }
        }

        var payload_pkt = pkt;
        payload_pkt.data.trimFront(header.IPv6MinimumSize + frag_data_off);
        payload_pkt.data.capLength(frag_len);
        const bytes = payload_pkt.data.toView(allocator) catch return;

        ctx.fragments.append(.{ .data = bytes, .offset = byte_off, .more = more }) catch {
            allocator.free(bytes);
            return;
        };
        ctx.total_bytes += frag_len;

        const Sort = struct {
            fn less(_: void, a: FragmentEntry, b: FragmentEntry) bool {
                return a.offset < b.offset;
            }
        };
        std.sort.block(FragmentEntry, ctx.fragments.items, {}, Sort.less);

        var expected: u32 = 0;
        var complete = true;
        var saw_last = false;
        for (ctx.fragments.items) |f| {
            if (saw_last) {
                // Data past the final fragment can never be valid — poison it.
                self.poisonReassembly(key);
                return;
            }
            if (f.offset != expected) {
                complete = false;
                break;
            }
            expected += @intCast(f.data.len);
            if (!f.more) saw_last = true;
        }

        if (complete and saw_last) {
            // Take ownership out of the table first so every exit frees the
            // fragments exactly once and expiry never sees a half-consumed context.
            var owned = (self.reassembly_list.fetchRemove(key) orelse return).value;
            defer owned.deinit(allocator);

            const total_size: usize = expected;
            if (total_size == 0) return;
            const reassembled_buf = allocator.alloc(u8, total_size) catch return;
            defer allocator.free(reassembled_buf);
            var offset: usize = 0;
            for (owned.fragments.items) |f| {
                @memcpy(reassembled_buf[offset .. offset + f.data.len], f.data);
                offset += f.data.len;
            }

            // The fragmentable part may itself begin with extension headers
            // (carried in fragment 0) — walk them to find the transport payload.
            const chain = parseExtensionHeaders(reassembled_buf, owned.next_header);
            if (!chain.valid or chain.fragment_offset != null or chain.payload_offset > total_size) {
                stats.global_stats.ip.reassembly_drops.inc();
                return;
            }

            // Receivers shallow-clone (cloneInPool acquires clusters, not bytes),
            // so the delivered view must be cluster-backed, not this frame's buffer.
            var wire = buffer.VectorisedView.fromSlice(
                reassembled_buf[chain.payload_offset..total_size],
                allocator,
                &self.nic.stack.cluster_pool,
            ) catch return;
            const reassembled_pkt = tcpip.PacketBuffer{
                .data = wire,
                .header = buffer.Prependable.init(&[_]u8{}),
            };

            self.dispatcher.deliverTransportPacket(r, chain.next_header, reassembled_pkt);
            wire.deinit();
        }
    }

    fn poisonReassembly(self: *IPv6Endpoint, key: ReassemblyKey) void {
        stats.global_stats.ip.reassembly_drops.inc();
        if (self.reassembly_list.fetchRemove(key)) |kv| {
            var removed = kv.value;
            removed.deinit(self.nic.stack.allocator);
        }
    }

    fn expireReassemblyContexts(self: *IPv6Endpoint) void {
        var to_remove = std.ArrayList(ReassemblyKey).init(self.nic.stack.allocator);
        defer to_remove.deinit();

        var it = self.reassembly_list.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.reassembly_list.fetchRemove(key)) |kv| {
                var removed = kv.value;
                removed.deinit(self.nic.stack.allocator);
            }
            stats.global_stats.ip.reassembly_drops.inc();
        }
    }

    // Capacity eviction: drop the longest-waiting reassembly. An attacker
    // churning ids mostly evicts their own flood; a legitimate datagram
    // completes in well under the 60s window.
    fn evictOldestReassembly(self: *IPv6Endpoint) void {
        var oldest_key: ?ReassemblyKey = null;
        var oldest_ms: i64 = std.math.maxInt(i64);
        var it = self.reassembly_list.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.first_arrival_ms < oldest_ms) {
                oldest_ms = entry.value_ptr.first_arrival_ms;
                oldest_key = entry.key_ptr.*;
            }
        }
        if (oldest_key) |k| {
            if (self.reassembly_list.fetchRemove(k)) |kv| {
                var ctx = kv.value;
                ctx.deinit(self.nic.stack.allocator);
            }
            stats.global_stats.ip.reassembly_drops.inc();
        }
    }
};

fn buildFragmentPacket(buf: []u8, src: [16]u8, dst: [16]u8, id: u32, nh: u8, off_units: u16, more: bool, chunk: []const u8) usize {
    const total = header.IPv6MinimumSize + 8 + chunk.len;
    const h = header.IPv6.init(buf[0..header.IPv6MinimumSize]);
    h.encode(src, dst, NextHeader.FRAGMENT, @intCast(8 + chunk.len));
    buf[40] = nh;
    buf[41] = 0;
    std.mem.writeInt(u16, buf[42..44], (off_units << 3) | @as(u16, if (more) 1 else 0), .big);
    std.mem.writeInt(u32, buf[44..48], id, .big);
    @memcpy(buf[48..][0..chunk.len], chunk);
    return total;
}

const ReassemblyTestBed = struct {
    s: stack.Stack,
    lo: @import("../drivers/loopback.zig").Loopback,
    nic: *stack.NIC = undefined,
    net_ep: stack.NetworkEndpoint = undefined,
    udp_ep: tcpip.Endpoint = undefined,
    wq: @import("../waiter.zig").Queue = .{},
    route: stack.Route = undefined,

    const my_addr = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1};
    const peer_addr = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{2};

    fn init(self: *ReassemblyTestBed, allocator: std.mem.Allocator, ip6: *IPv6Protocol) !void {
        self.s = try stack.Stack.init(allocator);
        errdefer self.s.deinit();
        try self.s.registerNetworkProtocol(ip6.protocol());
        const udp_proto = @import("../transport/udp.zig").UDPProtocol.init(allocator);
        try self.s.registerTransportProtocol(udp_proto.protocol());

        self.lo = @import("../drivers/loopback.zig").Loopback.init(allocator);
        try self.s.createLoopbackNIC(1, self.lo.linkEndpoint());
        self.nic = self.s.nics.get(1).?;
        try self.nic.addAddress(.{ .protocol = 0x86dd, .address_with_prefix = .{ .address = .{ .v6 = my_addr }, .prefix_len = 64 } });
        self.net_ep = self.nic.network_endpoints.get(0x86dd).?;

        self.udp_ep = try udp_proto.protocol().newEndpoint(&self.s, 0x86dd, &self.wq);
        try self.udp_ep.bind(.{ .nic = 1, .addr = .{ .v6 = my_addr }, .port = 9000 });

        self.route = stack.Route{
            .local_address = .{ .v6 = my_addr },
            .remote_address = .{ .v6 = peer_addr },
            .local_link_address = self.lo.linkEndpoint().linkAddress(),
            .net_proto = 0x86dd,
            .nic = self.nic,
        };
    }

    fn deinit(self: *ReassemblyTestBed) void {
        self.udp_ep.close();
        self.s.deinit();
        self.lo.deinit();
    }

    fn feed(self: *ReassemblyTestBed, bytes: []const u8) void {
        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = @constCast(bytes) }};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(bytes.len, &views),
            .header = buffer.Prependable.init(&[_]u8{}),
        };
        self.net_ep.handlePacket(&self.route, pkt);
    }

    fn recv(self: *ReassemblyTestBed, out: []u8, from: ?*tcpip.FullAddress) tcpip.Error!usize {
        var iov = [_][]u8{out};
        var uio = buffer.Uio.init(&iov);
        return self.udp_ep.readv(&uio, from);
    }
};

test "IPv6 fragment reassembly delivers a UDP datagram (out-of-order arrival)" {
    const allocator = std.testing.allocator;
    var ip6 = IPv6Protocol.init();
    var tb: ReassemblyTestBed = undefined;
    tb.wq = .{};
    try tb.init(allocator, &ip6);
    defer tb.deinit();

    // Original datagram: UDP header (8) + 24 payload bytes = 32 fragmentable bytes.
    var dgram: [32]u8 = undefined;
    std.mem.writeInt(u16, dgram[0..2], 9001, .big);
    std.mem.writeInt(u16, dgram[2..4], 9000, .big);
    std.mem.writeInt(u16, dgram[4..6], 32, .big);
    std.mem.writeInt(u16, dgram[6..8], 0, .big);
    for (dgram[8..], 0..) |*b, idx| b.* = @truncate(idx);

    var f1: [128]u8 = undefined;
    var f2: [128]u8 = undefined;
    const n1 = buildFragmentPacket(&f1, ReassemblyTestBed.peer_addr, ReassemblyTestBed.my_addr, 0x1234, NextHeader.UDP, 0, true, dgram[0..16]);
    const n2 = buildFragmentPacket(&f2, ReassemblyTestBed.peer_addr, ReassemblyTestBed.my_addr, 0x1234, NextHeader.UDP, 2, false, dgram[16..32]);

    // Deliver the tail first to prove offset sorting.
    tb.feed(f2[0..n2]);
    var rbuf: [64]u8 = undefined;
    try std.testing.expectError(tcpip.Error.WouldBlock, tb.recv(&rbuf, null));

    tb.feed(f1[0..n1]);
    var from: tcpip.FullAddress = undefined;
    const n = try tb.recv(&rbuf, &from);
    try std.testing.expectEqualSlices(u8, dgram[8..], rbuf[0..n]);
    try std.testing.expectEqual(@as(u16, 9001), from.port);

    // RFC 6946 atomic fragment (offset 0, M=0) delivers immediately.
    var fa: [128]u8 = undefined;
    const na = buildFragmentPacket(&fa, ReassemblyTestBed.peer_addr, ReassemblyTestBed.my_addr, 0x9999, NextHeader.UDP, 0, false, &dgram);
    tb.feed(fa[0..na]);
    const n_atomic = try tb.recv(&rbuf, null);
    try std.testing.expectEqualSlices(u8, dgram[8..], rbuf[0..n_atomic]);
}

test "IPv6 reassembly drops the whole datagram on overlap (RFC 5722)" {
    const allocator = std.testing.allocator;
    var ip6 = IPv6Protocol.init();
    var tb: ReassemblyTestBed = undefined;
    tb.wq = .{};
    try tb.init(allocator, &ip6);
    defer tb.deinit();

    const drops_before = stats.global_stats.ip.reassembly_drops.load();

    var chunk16 = [_]u8{0xab} ** 16;
    var f1: [128]u8 = undefined;
    var f2: [128]u8 = undefined;
    var f3: [128]u8 = undefined;
    const n1 = buildFragmentPacket(&f1, ReassemblyTestBed.peer_addr, ReassemblyTestBed.my_addr, 0x42, NextHeader.UDP, 0, true, &chunk16);
    // Overlaps bytes 8..16 of the first fragment.
    const n2 = buildFragmentPacket(&f2, ReassemblyTestBed.peer_addr, ReassemblyTestBed.my_addr, 0x42, NextHeader.UDP, 1, false, &chunk16);
    // Would have completed the datagram had the context survived.
    const n3 = buildFragmentPacket(&f3, ReassemblyTestBed.peer_addr, ReassemblyTestBed.my_addr, 0x42, NextHeader.UDP, 2, false, &chunk16);

    tb.feed(f1[0..n1]);
    tb.feed(f2[0..n2]);
    tb.feed(f3[0..n3]);

    var rbuf: [64]u8 = undefined;
    try std.testing.expectError(tcpip.Error.WouldBlock, tb.recv(&rbuf, null));
    try std.testing.expect(stats.global_stats.ip.reassembly_drops.load() > drops_before);
}

test "IPv6 reassembly drops non-final fragments not multiple of 8" {
    const allocator = std.testing.allocator;
    var ip6 = IPv6Protocol.init();
    var tb: ReassemblyTestBed = undefined;
    tb.wq = .{};
    try tb.init(allocator, &ip6);
    defer tb.deinit();

    const drops_before = stats.global_stats.ip.reassembly_drops.load();

    var chunk12 = [_]u8{0xcd} ** 12;
    var f1: [128]u8 = undefined;
    const n1 = buildFragmentPacket(&f1, ReassemblyTestBed.peer_addr, ReassemblyTestBed.my_addr, 0x77, NextHeader.UDP, 0, true, &chunk12);
    tb.feed(f1[0..n1]);

    const ip6_ep: *IPv6Endpoint = @ptrCast(@alignCast(tb.net_ep.ptr));
    try std.testing.expectEqual(@as(usize, 0), ip6_ep.reassembly_list.count());
    try std.testing.expect(stats.global_stats.ip.reassembly_drops.load() > drops_before);
}

test "IPv6 reassembly poisons a datagram with data past the final fragment" {
    const allocator = std.testing.allocator;
    var ip6 = IPv6Protocol.init();
    var tb: ReassemblyTestBed = undefined;
    tb.wq = .{};
    try tb.init(allocator, &ip6);
    defer tb.deinit();

    const drops_before = stats.global_stats.ip.reassembly_drops.load();

    var chunk8 = [_]u8{0xef} ** 8;
    var f1: [128]u8 = undefined;
    var f2: [128]u8 = undefined;
    var f3: [128]u8 = undefined;
    const n1 = buildFragmentPacket(&f1, ReassemblyTestBed.peer_addr, ReassemblyTestBed.my_addr, 0x55, NextHeader.UDP, 0, true, &chunk8);
    // Beyond the final fragment's end (offset 32, final ends at 16).
    const n3 = buildFragmentPacket(&f3, ReassemblyTestBed.peer_addr, ReassemblyTestBed.my_addr, 0x55, NextHeader.UDP, 4, false, &chunk8);
    // Final fragment: bytes 8..16.
    const n2 = buildFragmentPacket(&f2, ReassemblyTestBed.peer_addr, ReassemblyTestBed.my_addr, 0x55, NextHeader.UDP, 1, false, &chunk8);

    tb.feed(f1[0..n1]);
    tb.feed(f3[0..n3]);
    tb.feed(f2[0..n2]);

    var rbuf: [64]u8 = undefined;
    try std.testing.expectError(tcpip.Error.WouldBlock, tb.recv(&rbuf, null));
    try std.testing.expect(stats.global_stats.ip.reassembly_drops.load() > drops_before);
}

test "IPv6 extension header parsing" {
    // Test simple case - no extension headers
    const data = [_]u8{0} ** 8;
    const result = parseExtensionHeaders(&data, NextHeader.TCP);
    try std.testing.expect(result.valid);
    try std.testing.expectEqual(NextHeader.TCP, result.next_header);
    try std.testing.expectEqual(@as(usize, 0), result.payload_offset);
}

test "IPv6 fragment header parsing" {
    // Fragment header: next=TCP, reserved, offset=0x100 (256*8=2048), M=1, id=0x12345678
    var data: [8]u8 = undefined;
    data[0] = NextHeader.TCP; // next header
    data[1] = 0; // reserved
    std.mem.writeInt(u16, data[2..4], (0x100 << 3) | 0x01, .big); // offset + M flag
    std.mem.writeInt(u32, data[4..8], 0x12345678, .big); // identification

    const result = parseExtensionHeaders(&data, NextHeader.FRAGMENT);
    try std.testing.expect(result.valid);
    try std.testing.expectEqual(NextHeader.TCP, result.next_header);
    try std.testing.expectEqual(@as(?u16, 0x100), result.fragment_offset);
    try std.testing.expect(result.fragment_more);
    try std.testing.expectEqual(@as(u32, 0x12345678), result.fragment_id);
}
