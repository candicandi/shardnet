/// ARP (Address Resolution Protocol) implementation for shardnet.
///
/// Handles IPv4-to-MAC address resolution with caching, pending request
/// queuing, gratuitous ARP, and RFC 5227 probe/announcement support.

const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const time = @import("../time.zig");
const stats = @import("../stats.zig");
const log = @import("../log.zig").scoped(.arp);

pub const ProtocolNumber = 0x0806;
pub const ProtocolAddress = "arp";

/// ARP cache entry with TTL-based expiry.
pub const CacheEntry = struct {
    mac: [6]u8,
    timestamp_ms: i64,
    state: State,

    pub const State = enum {
        /// Entry is valid and confirmed.
        reachable,
        /// Entry is stale; refresh needed on next use.
        stale,
        /// Entry is being probed (no reply yet).
        probe,
    };
};

/// Default cache entry TTL in milliseconds (20 minutes).
const CACHE_TTL_MS: i64 = 20 * 60 * 1000;

/// Stale threshold in milliseconds (15 minutes).
const CACHE_STALE_MS: i64 = 15 * 60 * 1000;

/// Maximum pending requests before oldest is dropped.
const MAX_PENDING_REQUESTS = 64;

/// RFC 5227: Number of probe packets to send.
const PROBE_COUNT = 3;

/// RFC 5227: Delay between probes in milliseconds.
const PROBE_INTERVAL_MS = 1000;

/// Policy for handling ARP cache updates that change an existing mapping.
///
/// ARP spoofing/poisoning attacks work by sending unsolicited ARP replies
/// that overwrite legitimate mappings. This policy controls how the stack
/// responds when an incoming ARP packet would change an existing entry.
pub const CacheUpdatePolicy = enum {
    /// Accept all updates (original behaviour, vulnerable to spoofing).
    accept,
    /// Reject updates that change MAC for an existing IP (paranoid mode).
    reject,
    /// Accept but log a warning (recommended for production monitoring).
    alert,
};

pub const ARPProtocol = struct {
    // Secondary ARP cache. NOTE: currently unused by the RX path — passive
    // learning writes to stack.link_addr_cache (the bounded, live cache). Kept
    // for the explicit updateCache/policy API; wire it up or remove it.
    cache: std.AutoHashMap(tcpip.Address, CacheEntry),
    allocator: std.mem.Allocator,
    /// Policy for handling cache updates that would change an existing mapping.
    /// Defaults to .alert which logs potential spoofing but allows the update.
    update_policy: CacheUpdatePolicy = .alert,

    pub fn init(allocator: std.mem.Allocator) ARPProtocol {
        return .{
            .cache = std.AutoHashMap(tcpip.Address, CacheEntry).init(allocator),
            .allocator = allocator,
        };
    }

    /// Initialise with explicit cache update policy.
    pub fn initWithPolicy(allocator: std.mem.Allocator, policy: CacheUpdatePolicy) ARPProtocol {
        return .{
            .cache = std.AutoHashMap(tcpip.Address, CacheEntry).init(allocator),
            .allocator = allocator,
            .update_policy = policy,
        };
    }

    pub fn deinit(self: *ARPProtocol) void {
        self.cache.deinit();
    }

    /// Look up a MAC address in the cache.
    /// Returns null if not found or if the entry has expired.
    pub fn lookup(self: *ARPProtocol, addr: tcpip.Address) ?[6]u8 {
        const entry = self.cache.get(addr) orelse return null;
        const now = std.time.milliTimestamp();

        // Check if entry has expired
        if (now - entry.timestamp_ms > CACHE_TTL_MS) {
            _ = self.cache.remove(addr);
            return null;
        }

        return entry.mac;
    }

    /// Add or update a cache entry.
    ///
    /// When an entry already exists with a different MAC address, the
    /// configured `update_policy` determines behaviour:
    ///   - accept: silently overwrite (vulnerable to ARP spoofing)
    ///   - reject: keep original mapping, ignore the new one
    ///   - alert:  log a warning and then overwrite (recommended)
    ///
    /// NOTE: Frequent MAC changes for the same IP may indicate:
    ///   1. ARP spoofing attack (malicious)
    ///   2. VRRP/HSRP failover (legitimate)
    ///   3. VM migration (legitimate)
    /// Operators should tune the policy based on their environment.
    pub fn updateCache(self: *ARPProtocol, addr: tcpip.Address, mac: [6]u8) void {
        // Check for existing entry with different MAC (potential spoofing)
        if (self.cache.get(addr)) |existing| {
            if (!std.mem.eql(u8, &existing.mac, &mac)) {
                switch (self.update_policy) {
                    .reject => {
                        log.warn("ARP: Rejecting MAC change for {any}: {x}:{x}:{x}:{x}:{x}:{x} -> {x}:{x}:{x}:{x}:{x}:{x} (policy=reject)", .{
                            addr.v4,
                            existing.mac[0], existing.mac[1], existing.mac[2],
                            existing.mac[3], existing.mac[4], existing.mac[5],
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                        });
                        return;
                    },
                    .alert => {
                        log.warn("ARP: MAC changed for {any}: {x}:{x}:{x}:{x}:{x}:{x} -> {x}:{x}:{x}:{x}:{x}:{x} (possible spoofing)", .{
                            addr.v4,
                            existing.mac[0], existing.mac[1], existing.mac[2],
                            existing.mac[3], existing.mac[4], existing.mac[5],
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                        });
                    },
                    .accept => {},
                }
            }
        }

        const entry = CacheEntry{
            .mac = mac,
            .timestamp_ms = std.time.milliTimestamp(),
            .state = .reachable,
        };
        self.cache.put(addr, entry) catch {};
    }

    /// Remove an entry from the cache.
    pub fn invalidate(self: *ARPProtocol, addr: tcpip.Address) void {
        _ = self.cache.remove(addr);
    }

    /// Expire old entries from the cache.
    /// NOTE: Called periodically by the timer; removes entries older than TTL.
    pub fn expireEntries(self: *ARPProtocol) void {
        const now = std.time.milliTimestamp();
        var it = self.cache.iterator();
        var to_remove: [32]tcpip.Address = undefined;
        var remove_count: usize = 0;

        while (it.next()) |entry| {
            if (now - entry.value_ptr.timestamp_ms > CACHE_TTL_MS) {
                if (remove_count < to_remove.len) {
                    to_remove[remove_count] = entry.key_ptr.*;
                    remove_count += 1;
                }
            }
        }

        for (to_remove[0..remove_count]) |addr| {
            _ = self.cache.remove(addr);
        }
    }

    pub fn protocol(self: *ARPProtocol) stack.NetworkProtocol {
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
    };

    fn number(ptr: *anyopaque) tcpip.NetworkProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn parseAddresses(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.NetworkProtocol.AddressPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{
            .src = .{ .v4 = .{ 0, 0, 0, 0 } },
            .dst = .{ .v4 = .{ 0, 0, 0, 0 } },
        };
        const h = header.ARP.init(v);
        return .{
            .src = .{ .v4 = h.protocolAddressSender() },
            .dst = .{ .v4 = h.protocolAddressTarget() },
        };
    }

    fn linkAddressRequest(ptr: *anyopaque, addr: tcpip.Address, local_addr: tcpip.Address, nic: *stack.NIC) tcpip.Error!void {
        _ = ptr;

        const ep_opt = nic.network_endpoints.get(ProtocolNumber);
        if (ep_opt) |ep| {
            const arp_ep = @as(*ARPEndpoint, @ptrCast(@alignCast(ep.ptr)));
            if (!arp_ep.pending_requests.contains(addr)) {
                // Bound the pending table; drop the longest-waiting request to
                // make room (matches the documented "oldest is dropped" policy).
                if (arp_ep.pending_requests.count() >= MAX_PENDING_REQUESTS) {
                    arp_ep.dropOldestPending();
                }
                arp_ep.pending_requests.put(addr, std.time.milliTimestamp()) catch {};
                if (!arp_ep.timer.active) {
                    nic.stack.timer_queue.schedule(&arp_ep.timer, 10);
                }

                const hdr_buf = nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
                defer nic.stack.allocator.free(hdr_buf);

                var pre = buffer.Prependable.init(hdr_buf);
                const arp_hdr = pre.prepend(header.ARPSize).?;
                var h = header.ARP.init(arp_hdr);
                h.setIPv4OverEthernet();
                h.setOp(1); // Request
                @memcpy(h.data[8..14], &nic.linkEP.linkAddress().addr);
                @memcpy(h.data[14..18], &local_addr.v4);
                @memcpy(h.data[24..28], &addr.v4);

                const pb = tcpip.PacketBuffer{
                    .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 },
                    .header = pre,
                };

                const broadcast_hw = tcpip.LinkAddress{ .addr = [_]u8{0xff} ** 6 };
                var r = stack.Route{
                    .local_address = local_addr,
                    .remote_address = addr,
                    .local_link_address = nic.linkEP.linkAddress(),
                    .remote_link_address = broadcast_hw,
                    .net_proto = ProtocolNumber,
                    .nic = nic,
                };

                stats.global_stats.arp.tx_requests.inc();
                return nic.linkEP.writePacket(&r, ProtocolNumber, pb);
            }
        }

        return;
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        _ = ptr;
        _ = addr;
        _ = dispatcher;
        const ep = try nic.stack.allocator.create(ARPEndpoint);
        ep.* = .{
            .nic = nic,
            .pending_requests = std.HashMap(tcpip.Address, i64, stack.Stack.AddressContext, 80).init(nic.stack.allocator),
            .timer = time.Timer.init(ARPEndpoint.handleTimer, ep),
        };
        return ep.networkEndpoint();
    }
};

pub const ARPEndpoint = struct {
    nic: *stack.NIC,
    pending_requests: std.HashMap(tcpip.Address, i64, stack.Stack.AddressContext, 80),
    timer: time.Timer = undefined,

    pub fn networkEndpoint(self: *ARPEndpoint) stack.NetworkEndpoint {
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

    /// Send a gratuitous ARP announcement.
    /// Used when an interface comes up to announce our presence and detect conflicts.
    pub fn sendGratuitousArp(self: *ARPEndpoint, addr: tcpip.Address) !void {
        const hdr_buf = self.nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer self.nic.stack.allocator.free(hdr_buf);

        var pre = buffer.Prependable.init(hdr_buf);
        const arp_hdr = pre.prepend(header.ARPSize).?;
        var h = header.ARP.init(arp_hdr);
        h.setIPv4OverEthernet();
        h.setOp(1); // Request (gratuitous ARP uses request with target = sender)
        @memcpy(h.data[8..14], &self.nic.linkEP.linkAddress().addr);
        @memcpy(h.data[14..18], &addr.v4);
        @memset(h.data[18..24], 0); // Target hardware address = 0
        @memcpy(h.data[24..28], &addr.v4); // Target protocol address = our address

        const pb = tcpip.PacketBuffer{
            .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 },
            .header = pre,
        };

        const broadcast_hw = tcpip.LinkAddress{ .addr = [_]u8{0xff} ** 6 };
        var r = stack.Route{
            .local_address = addr,
            .remote_address = addr,
            .local_link_address = self.nic.linkEP.linkAddress(),
            .remote_link_address = broadcast_hw,
            .net_proto = ProtocolNumber,
            .nic = self.nic,
        };

        self.nic.linkEP.writePacket(&r, ProtocolNumber, pb) catch |err| {
            log.debug("ARP: announcement/probe tx failed: {}", .{err});
            stats.global_stats.direction.tx_drops.inc();
        };
    }

    /// Send an RFC 5227 ARP probe.
    /// Sender IP is 0.0.0.0, target IP is the address being probed.
    pub fn sendProbe(self: *ARPEndpoint, target_addr: tcpip.Address) !void {
        const hdr_buf = self.nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer self.nic.stack.allocator.free(hdr_buf);

        var pre = buffer.Prependable.init(hdr_buf);
        const arp_hdr = pre.prepend(header.ARPSize).?;
        var h = header.ARP.init(arp_hdr);
        h.setIPv4OverEthernet();
        h.setOp(1); // Request
        @memcpy(h.data[8..14], &self.nic.linkEP.linkAddress().addr);
        @memset(h.data[14..18], 0); // Sender IP = 0.0.0.0 (probe)
        @memset(h.data[18..24], 0); // Target hardware = 0
        @memcpy(h.data[24..28], &target_addr.v4);

        const pb = tcpip.PacketBuffer{
            .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 },
            .header = pre,
        };

        const broadcast_hw = tcpip.LinkAddress{ .addr = [_]u8{0xff} ** 6 };
        const zero_addr = tcpip.Address{ .v4 = .{ 0, 0, 0, 0 } };
        var r = stack.Route{
            .local_address = zero_addr,
            .remote_address = target_addr,
            .local_link_address = self.nic.linkEP.linkAddress(),
            .remote_link_address = broadcast_hw,
            .net_proto = ProtocolNumber,
            .nic = self.nic,
        };

        self.nic.linkEP.writePacket(&r, ProtocolNumber, pb) catch |err| {
            log.debug("ARP: announcement/probe tx failed: {}", .{err});
            stats.global_stats.direction.tx_drops.inc();
        };
    }

    /// Send an RFC 5227 ARP announcement.
    /// Both sender and target IP are set to our address.
    pub fn sendAnnouncement(self: *ARPEndpoint, addr: tcpip.Address) !void {
        // Announcement is same as gratuitous ARP
        try self.sendGratuitousArp(addr);
    }

    /// Evict the longest-waiting pending resolution to keep the table bounded.
    fn dropOldestPending(self: *ARPEndpoint) void {
        var oldest_key: ?tcpip.Address = null;
        var oldest_ms: i64 = std.math.maxInt(i64);
        var it = self.pending_requests.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* < oldest_ms) {
                oldest_ms = entry.value_ptr.*;
                oldest_key = entry.key_ptr.*;
            }
        }
        if (oldest_key) |k| {
            _ = self.pending_requests.remove(k);
            stats.global_stats.arp.pending_drops.inc();
        }
    }

    pub fn handleTimer(ptr: *anyopaque) void {
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        var it = self.pending_requests.iterator();
        const now = std.time.milliTimestamp();
        var has_pending = false;

        while (it.next()) |entry| {
            if (now - entry.value_ptr.* >= 10) {
                const proto_opt = self.nic.stack.network_protocols.get(ProtocolNumber);
                if (proto_opt) |p| {
                    const proto = @as(*ARPProtocol, @ptrCast(@alignCast(p.ptr)));
                    var local_addr: ?tcpip.Address = null;
                    const addrs = self.nic.addresses.items;
                    if (addrs.len > 0) local_addr = addrs[0].address_with_prefix.address;

                    if (local_addr) |la| {
                        ARPProtocol.linkAddressRequest(proto, entry.key_ptr.*, la, self.nic) catch {};
                        entry.value_ptr.* = now;
                    }
                }
            }
            has_pending = true;
        }

        if (has_pending) {
            self.nic.stack.timer_queue.schedule(&self.timer, 10);
        }
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.ARPSize;
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        self.nic.stack.timer_queue.cancel(&self.timer);
        self.pending_requests.deinit();
        self.nic.stack.allocator.destroy(self);
    }

    fn writePacket(ptr: *anyopaque, r: *const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        _ = ptr;
        _ = r;
        _ = protocol;
        _ = pkt;
        return tcpip.Error.NotPermitted;
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        _ = r;
        const v = pkt.data.first() orelse return;
        const h = header.ARP.init(v);
        if (!h.isValid()) return;

        const sender_proto_addr = tcpip.Address{ .v4 = h.protocolAddressSender() };
        const sender_hw_addr = h.hardwareAddressSender();

        // NOTE: Update cache on any valid ARP packet from this sender.
        // This implements passive learning to reduce ARP traffic.
        _ = self.pending_requests.remove(sender_proto_addr);
        self.nic.stack.addLinkAddress(sender_proto_addr, .{ .addr = sender_hw_addr }) catch {};

        const target_proto_addr = tcpip.Address{ .v4 = h.protocolAddressTarget() };
        if (h.op() == 1) { // Request
            stats.global_stats.arp.rx_requests.inc();
            if (self.nic.hasAddress(target_proto_addr)) {
                const hdr_buf = self.nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
                defer self.nic.stack.allocator.free(hdr_buf);

                var pre = buffer.Prependable.init(hdr_buf);
                const arp_hdr = pre.prepend(header.ARPSize).?;
                var reply_h = header.ARP.init(arp_hdr);
                reply_h.setIPv4OverEthernet();
                reply_h.setOp(2); // Reply
                @memcpy(reply_h.data[8..14], &self.nic.linkEP.linkAddress().addr);
                @memcpy(reply_h.data[14..18], h.data[24..28]);
                @memcpy(reply_h.data[18..24], h.data[8..14]);
                @memcpy(reply_h.data[24..28], h.data[14..18]);

                const reply_pkt = tcpip.PacketBuffer{
                    .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 },
                    .header = pre,
                };

                const remote_link_address = tcpip.LinkAddress{ .addr = sender_hw_addr };
                var reply_route = stack.Route{
                    .local_address = target_proto_addr,
                    .remote_address = sender_proto_addr,
                    .local_link_address = self.nic.linkEP.linkAddress(),
                    .remote_link_address = remote_link_address,
                    .net_proto = ProtocolNumber,
                    .nic = self.nic,
                };

                stats.global_stats.arp.tx_replies.inc();
                self.nic.linkEP.writePacket(&reply_route, ProtocolNumber, reply_pkt) catch |err| {
                    log.debug("ARP: reply tx failed: {}", .{err});
                    stats.global_stats.direction.tx_drops.inc();
                };
            }
        } else if (h.op() == 2) { // Reply
            stats.global_stats.arp.rx_replies.inc();
        }
    }
};

test "ARP pending-request cap and link-address cache bound" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var fake_link = struct {
        fn writePacket(_: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, _: tcpip.PacketBuffer) tcpip.Error!void {
            return;
        }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
            return .{ .addr = [_]u8{0} ** 6 };
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

    // Register an ARP endpoint on the NIC; NIC.deinit closes it.
    const ep = try allocator.create(ARPEndpoint);
    ep.* = .{
        .nic = nic,
        .pending_requests = std.HashMap(tcpip.Address, i64, stack.Stack.AddressContext, 80).init(allocator),
        .timer = time.Timer.init(ARPEndpoint.handleTimer, ep),
    };
    try nic.network_endpoints.put(ProtocolNumber, ep.networkEndpoint());

    var proto = ARPProtocol.init(allocator);
    defer proto.deinit();
    const local = tcpip.Address{ .v4 = .{ 10, 0, 0, 1 } };

    // Pending cap: one past MAX_PENDING_REQUESTS drops the longest-waiting entry.
    const base_pending = stats.global_stats.arp.pending_drops.load();
    var i: usize = 0;
    while (i < MAX_PENDING_REQUESTS) : (i += 1) {
        const target = tcpip.Address{ .v4 = .{ 10, 0, 1, @intCast(i) } };
        try ARPProtocol.linkAddressRequest(&proto, target, local, nic);
    }
    try std.testing.expectEqual(MAX_PENDING_REQUESTS, @as(usize, ep.pending_requests.count()));

    const overflow_target = tcpip.Address{ .v4 = .{ 10, 0, 2, 0 } };
    try ARPProtocol.linkAddressRequest(&proto, overflow_target, local, nic);
    try std.testing.expectEqual(MAX_PENDING_REQUESTS, @as(usize, ep.pending_requests.count()));
    try std.testing.expect(ep.pending_requests.contains(overflow_target));
    try std.testing.expectEqual(base_pending + 1, stats.global_stats.arp.pending_drops.load());

    // Cache bound: one past MAX_LINK_ADDR_CACHE evicts an entry instead of growing.
    const base_evict = stats.global_stats.arp.cache_evictions.load();
    const mac = tcpip.LinkAddress{ .addr = [_]u8{ 1, 2, 3, 4, 5, 6 } };
    var j: usize = 0;
    while (j < stack.MAX_LINK_ADDR_CACHE) : (j += 1) {
        const a = tcpip.Address{ .v4 = .{ 172, 16, @intCast(j >> 8), @intCast(j & 0xff) } };
        try s.addLinkAddress(a, mac);
    }
    try std.testing.expectEqual(stack.MAX_LINK_ADDR_CACHE, @as(usize, s.link_addr_cache.count()));
    try std.testing.expectEqual(base_evict, stats.global_stats.arp.cache_evictions.load());

    try s.addLinkAddress(.{ .v4 = .{ 10, 9, 9, 9 } }, mac);
    try std.testing.expectEqual(stack.MAX_LINK_ADDR_CACHE, @as(usize, s.link_addr_cache.count()));
    try std.testing.expectEqual(base_evict + 1, stats.global_stats.arp.cache_evictions.load());
    try std.testing.expect(s.link_addr_cache.get(.{ .v4 = .{ 10, 9, 9, 9 } }) != null);
}
