/// Network stack with configuration, routing, and protocol dispatch.
///
/// Provides longest-prefix routing, transport demultiplexing with
/// sharded endpoint tables, graceful shutdown support, and health check
/// endpoint via Unix domain socket.
///
/// // NOTE: The health check uses a Unix socket rather than an HTTP endpoint
/// // because: (1) no HTTP layer dependency, (2) accessible even when the
/// // network stack itself is unhealthy, (3) simple local-only access control.

const std = @import("std");
const tcpip = @import("tcpip.zig");
const buffer = @import("buffer.zig");
const header = @import("header.zig");
const waiter = @import("waiter.zig");
const time = @import("time.zig");
const log = @import("log.zig").scoped(.stack);
const stats = @import("stats.zig");

pub const LinkEndpointCapabilities = u32;
pub const CapabilityNone: LinkEndpointCapabilities = 0;
pub const CapabilityLoopback: LinkEndpointCapabilities = 1 << 0;
pub const CapabilityResolutionRequired: LinkEndpointCapabilities = 1 << 1;

/// Upper bound on the link-address (ARP/NDP) cache to resist spoofed-reply floods.
pub const MAX_LINK_ADDR_CACHE: usize = 4096;

/// Upper bound on the PMTU cache; ICMP errors are off-path forgeable, so the
/// per-destination state they create must be bounded.
pub const MAX_PMTU_CACHE: usize = 4096;

/// RFC 1191 section 6.3: age PMTU entries out after ~10 minutes so the path
/// gets re-probed at larger sizes.
pub const PMTU_TTL_MS: i64 = 10 * 60 * 1000;

pub const PMTUEntry = struct {
    mtu: u32,
    updated_ms: i64,
};

/// Stack configuration.
pub const Config = struct {
    /// Maximum Segment Lifetime for TCP (milliseconds).
    tcp_msl: u64 = 30000,
    /// Enable TCP timestamps (RFC 7323).
    tcp_timestamps: bool = true,
    /// Enable TCP window scaling (RFC 7323).
    tcp_window_scaling: bool = true,
    /// Enable TCP SACK (RFC 2018).
    tcp_sack: bool = true,
    /// Default congestion control algorithm.
    congestion_control: tcpip.CongestionControlAlgorithm = .cubic,
    /// Ephemeral port range start.
    ephemeral_port_start: u16 = 32768,
    /// Ephemeral port range end.
    ephemeral_port_end: u16 = 65535,
    /// Maximum ARP pending queue entries.
    arp_pending_max: usize = 64,
    /// ARP pending timeout (milliseconds).
    arp_pending_timeout_ms: i64 = 1000,
    /// Cluster pool prewarm count.
    cluster_pool_prewarm: usize = 1024,
    // Hard cap on total clusters (16 KiB each) the cluster pool will allocate;
    // acquire backpressures (drops) past it. cluster_pool_max_free caps idle
    // clusters retained so a burst does not leave the pool permanently inflated.
    cluster_pool_max: usize = 65536,
    cluster_pool_max_free: usize = 8192,
    // Hard cap on live transport endpoints (TCP connections, listeners, UDP).
    // Registrations past it are rejected so the table cannot grow without bound.
    max_endpoints: usize = 65536,
    /// Path MTU discovery: set DF on IPv4 egress and honor ICMP
    /// Fragmentation Needed / Packet Too Big (RFC 1191 / RFC 8201).
    ip_pmtud: bool = true,
    /// Unix socket path for health check endpoint (null to disable).
    /// // NOTE: Unix socket provides health monitoring without HTTP dependency.
    health_check_socket: ?[]const u8 = "/tmp/shardnet.sock",
};

/// Health check response structure.
pub const HealthStatus = struct {
    uptime_seconds: i64,
    nic_count: usize,
    tcp_connections: usize,
    arp_cache_size: usize,
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_drops: u64,

    pub fn toJson(self: HealthStatus, buf: []u8) ![]u8 {
        return try std.fmt.bufPrint(buf,
            \\{{"uptime_seconds":{d},"nic_count":{d},"tcp_connections":{d},"arp_cache_size":{d},"rx_packets":{d},"tx_packets":{d},"rx_bytes":{d},"tx_bytes":{d},"rx_drops":{d}}}
        , .{
            self.uptime_seconds,
            self.nic_count,
            self.tcp_connections,
            self.arp_cache_size,
            self.rx_packets,
            self.tx_packets,
            self.rx_bytes,
            self.tx_bytes,
            self.rx_drops,
        });
    }
};

pub const LinkEndpoint = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        writePacket: *const fn (ptr: *anyopaque, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void,
        writePackets: ?*const fn (ptr: *anyopaque, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void = null,
        flush: ?*const fn (ptr: *anyopaque) void = null,
        attach: *const fn (ptr: *anyopaque, dispatcher: *NetworkDispatcher) void,
        linkAddress: *const fn (ptr: *anyopaque) tcpip.LinkAddress,
        mtu: *const fn (ptr: *anyopaque) u32,
        setMTU: *const fn (ptr: *anyopaque, mtu: u32) void,
        capabilities: *const fn (ptr: *anyopaque) LinkEndpointCapabilities,
        close: ?*const fn (ptr: *anyopaque) void = null,
    };

    pub fn writePacket(self: LinkEndpoint, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        return self.vtable.writePacket(self.ptr, r, protocol, pkt);
    }

    pub fn writePackets(self: LinkEndpoint, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void {
        if (self.vtable.writePackets) |f| {
            return f(self.ptr, r, protocol, packets);
        }
        for (packets) |p| {
            try self.vtable.writePacket(self.ptr, r, protocol, p);
        }
    }

    pub fn attach(self: LinkEndpoint, dispatcher: *NetworkDispatcher) void {
        return self.vtable.attach(self.ptr, dispatcher);
    }

    pub fn linkAddress(self: LinkEndpoint) tcpip.LinkAddress {
        return self.vtable.linkAddress(self.ptr);
    }

    pub fn mtu(self: LinkEndpoint) u32 {
        return self.vtable.mtu(self.ptr);
    }

    pub fn setMTU(self: LinkEndpoint, m: u32) void {
        self.vtable.setMTU(self.ptr, m);
    }

    pub fn capabilities(self: LinkEndpoint) LinkEndpointCapabilities {
        return self.vtable.capabilities(self.ptr);
    }

    pub fn close(self: LinkEndpoint) void {
        if (self.vtable.close) |f| f(self.ptr);
    }

    pub fn flush(self: LinkEndpoint) void {
        if (self.vtable.flush) |f| f(self.ptr);
    }
};

pub const NetworkDispatcher = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        deliverNetworkPacket: *const fn (ptr: *anyopaque, remote: *const tcpip.LinkAddress, local: *const tcpip.LinkAddress, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) void,
    };

    pub fn deliverNetworkPacket(self: NetworkDispatcher, remote: *const tcpip.LinkAddress, local: *const tcpip.LinkAddress, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) void {
        return self.vtable.deliverNetworkPacket(self.ptr, remote, local, protocol, pkt);
    }
};

pub const NetworkEndpoint = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        writePacket: *const fn (ptr: *anyopaque, r: *const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void,
        writePackets: ?*const fn (ptr: *anyopaque, r: *const Route, protocol: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void = null,
        handlePacket: *const fn (ptr: *anyopaque, r: *const Route, pkt: tcpip.PacketBuffer) void,
        mtu: *const fn (ptr: *anyopaque) u32,
        close: ?*const fn (ptr: *anyopaque) void = null,
    };

    pub fn writePacket(self: NetworkEndpoint, r: *const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        return self.vtable.writePacket(self.ptr, r, protocol, pkt);
    }

    pub fn writePackets(self: NetworkEndpoint, r: *const Route, protocol: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void {
        if (self.vtable.writePackets) |f| {
            return f(self.ptr, r, protocol, packets);
        }
        for (packets) |p| {
            try self.vtable.writePacket(self.ptr, r, protocol, p);
        }
    }

    pub fn handlePacket(self: NetworkEndpoint, r: *const Route, pkt: tcpip.PacketBuffer) void {
        return self.vtable.handlePacket(self.ptr, r, pkt);
    }

    pub fn mtu(self: NetworkEndpoint) u32 {
        return self.vtable.mtu(self.ptr);
    }

    pub fn close(self: NetworkEndpoint) void {
        if (self.vtable.close) |f| f(self.ptr);
    }
};

pub const NetworkProtocol = struct {
    pub const AddressPair = struct { src: tcpip.Address, dst: tcpip.Address };

    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        number: *const fn (ptr: *anyopaque) tcpip.NetworkProtocolNumber,
        newEndpoint: *const fn (ptr: *anyopaque, nic: *NIC, addr: tcpip.AddressWithPrefix, dispatcher: TransportDispatcher) tcpip.Error!NetworkEndpoint,
        linkAddressRequest: *const fn (ptr: *anyopaque, addr: tcpip.Address, local_addr: tcpip.Address, nic: *NIC) tcpip.Error!void,
        parseAddresses: *const fn (ptr: *anyopaque, pkt: tcpip.PacketBuffer) AddressPair,
        deinit: ?*const fn (ptr: *anyopaque) void = null,
    };

    pub fn deinit(self: NetworkProtocol) void {
        if (self.vtable.deinit) |f| f(self.ptr);
    }

    pub fn number(self: NetworkProtocol) tcpip.NetworkProtocolNumber {
        return self.vtable.number(self.ptr);
    }

    pub fn newEndpoint(self: NetworkProtocol, nic: *NIC, addr: tcpip.AddressWithPrefix, dispatcher: TransportDispatcher) tcpip.Error!NetworkEndpoint {
        return self.vtable.newEndpoint(self.ptr, nic, addr, dispatcher);
    }

    pub fn linkAddressRequest(self: NetworkProtocol, addr: tcpip.Address, local_addr: tcpip.Address, nic: *NIC) tcpip.Error!void {
        return self.vtable.linkAddressRequest(self.ptr, addr, local_addr, nic);
    }

    pub fn parseAddresses(self: NetworkProtocol, pkt: tcpip.PacketBuffer) AddressPair {
        return self.vtable.parseAddresses(self.ptr, pkt);
    }
};

pub const TransportEndpointID = struct {
    local_port: u16,
    local_address: tcpip.Address,
    remote_port: u16,
    remote_address: tcpip.Address,

    pub fn hash(self: TransportEndpointID) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(std.mem.asBytes(&self.local_port));
        switch (self.local_address) {
            .v4 => |v| h.update(&v),
            .v6 => |v| h.update(&v),
        }
        h.update(std.mem.asBytes(&self.remote_port));
        switch (self.remote_address) {
            .v4 => |v| h.update(&v),
            .v6 => |v| h.update(&v),
        }
        return h.final();
    }

    pub fn eq(self: TransportEndpointID, other: TransportEndpointID) bool {
        return self.local_port == other.local_port and
            self.local_address.eq(other.local_address) and
            self.remote_port == other.remote_port and
            self.remote_address.eq(other.remote_address);
    }
};

pub const TransportEndpoint = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        handlePacket: *const fn (ptr: *anyopaque, r: *const Route, id: TransportEndpointID, pkt: tcpip.PacketBuffer) void,
        close: *const fn (ptr: *anyopaque) void,
        incRef: *const fn (ptr: *anyopaque) void,
        decRef: *const fn (ptr: *anyopaque) void,
        notify: ?*const fn (ptr: *anyopaque, mask: waiter.EventMask) void = null,
        // Stack-owned teardown: release refs the protocol state machine holds on
        // behalf of the stack (not the app's ref). Called by Stack.deinit on
        // endpoints still registered when the stack goes away.
        abort: ?*const fn (ptr: *anyopaque) void = null,
    };

    pub fn handlePacket(self: TransportEndpoint, r: *const Route, id: TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        return self.vtable.handlePacket(self.ptr, r, id, pkt);
    }

    pub fn close(self: TransportEndpoint) void {
        return self.vtable.close(self.ptr);
    }

    pub fn incRef(self: TransportEndpoint) void {
        return self.vtable.incRef(self.ptr);
    }

    pub fn decRef(self: TransportEndpoint) void {
        return self.vtable.decRef(self.ptr);
    }

    pub fn notify(self: TransportEndpoint, mask: waiter.EventMask) void {
        if (self.vtable.notify) |f| {
            return f(self.ptr, mask);
        }
    }

    pub fn abort(self: TransportEndpoint) void {
        if (self.vtable.abort) |f| {
            return f(self.ptr);
        }
    }
};

pub const TransportProtocol = struct {
    pub const PortPair = struct { src: u16, dst: u16 };

    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        number: *const fn (ptr: *anyopaque) tcpip.TransportProtocolNumber,
        newEndpoint: *const fn (ptr: *anyopaque, stack: *Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint,
        parsePorts: *const fn (ptr: *anyopaque, pkt: tcpip.PacketBuffer) PortPair,
        handlePacket: ?*const fn (ptr: *anyopaque, r: *const Route, id: TransportEndpointID, pkt: tcpip.PacketBuffer) void = null,
        deinit: ?*const fn (ptr: *anyopaque) void = null,
    };

    pub fn deinit(self: TransportProtocol) void {
        if (self.vtable.deinit) |f| f(self.ptr);
    }

    pub fn number(self: TransportProtocol) tcpip.TransportProtocolNumber {
        return self.vtable.number(self.ptr);
    }

    pub fn newEndpoint(self: TransportProtocol, s: *Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
        return self.vtable.newEndpoint(self.ptr, s, net_proto, wait_queue);
    }

    pub fn parsePorts(self: TransportProtocol, pkt: tcpip.PacketBuffer) PortPair {
        return self.vtable.parsePorts(self.ptr, pkt);
    }
};

pub const TransportDispatcher = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        deliverTransportPacket: *const fn (ptr: *anyopaque, r: *const Route, protocol: tcpip.TransportProtocolNumber, pkt: tcpip.PacketBuffer) void,
    };

    pub fn deliverTransportPacket(self: TransportDispatcher, r: *const Route, protocol: tcpip.TransportProtocolNumber, pkt: tcpip.PacketBuffer) void {
        return self.vtable.deliverTransportPacket(self.ptr, r, protocol, pkt);
    }
};

pub const NIC = struct {
    stack: *Stack,
    id: tcpip.NICID,
    name: []const u8,
    linkEP: LinkEndpoint,
    loopback: bool,
    addresses: std.ArrayList(tcpip.ProtocolAddress),
    network_endpoints: std.AutoHashMap(tcpip.NetworkProtocolNumber, NetworkEndpoint),
    dispatcher: NetworkDispatcher = undefined,

    pub fn init(stack_ptr: *Stack, id: tcpip.NICID, name: []const u8, ep: LinkEndpoint, loopback: bool) NIC {
        return .{
            .stack = stack_ptr,
            .id = id,
            .name = name,
            .linkEP = ep,
            .loopback = loopback,
            .addresses = std.ArrayList(tcpip.ProtocolAddress).init(stack_ptr.allocator),
            .network_endpoints = std.AutoHashMap(tcpip.NetworkProtocolNumber, NetworkEndpoint).init(stack_ptr.allocator),
        };
    }

    pub fn deinit(self: *NIC) void {
        var it = self.network_endpoints.valueIterator();
        while (it.next()) |ep| {
            ep.close();
        }
        self.linkEP.close();
        self.addresses.deinit();
        self.network_endpoints.deinit();
    }

    pub fn addAddress(self: *NIC, addr: tcpip.ProtocolAddress) !void {
        try self.addresses.append(addr);
        if (self.stack.network_protocols.get(addr.protocol)) |proto| {
            const ep = try proto.newEndpoint(self, addr.address_with_prefix, self.stack.transportDispatcher());
            if (self.network_endpoints.get(addr.protocol)) |old_ep| {
                old_ep.close();
            }
            try self.network_endpoints.put(addr.protocol, ep);
        }
    }

    // Register an address while reusing an existing per-protocol endpoint
    // instead of rebuilding it. addAddress() recreates the endpoint on every
    // call (IPv6 depends on that to run DAD per address), but DHCP applies its
    // leased IPv4 address from inside packet dispatch, and recreating there would
    // free the very endpoint still on the call stack. Safe only where the
    // endpoint does not key off its stored address (IPv4).
    pub fn addAddressReusingEndpoint(self: *NIC, addr: tcpip.ProtocolAddress) !void {
        if (self.network_endpoints.get(addr.protocol) == null) {
            return self.addAddress(addr);
        }
        try self.addresses.append(addr);
    }

    pub fn hasAddress(self: *NIC, addr: tcpip.Address) bool {
        for (self.addresses.items) |pa| {
            if (pa.address_with_prefix.address.eq(addr)) return true;
        }
        return false;
    }

    // The per-protocol network endpoint is shared across a protocol's addresses,
    // so it is left intact, and only the address entry is dropped (used by DHCP on
    // lease release/expiry to relinquish a leased address).
    pub fn removeAddress(self: *NIC, addr: tcpip.Address) void {
        var i: usize = 0;
        while (i < self.addresses.items.len) {
            if (self.addresses.items[i].address_with_prefix.address.eq(addr)) {
                _ = self.addresses.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    pub fn attach(self: *NIC) void {
        self.dispatcher = NetworkDispatcher{
            .ptr = self,
            .vtable = &.{
                .deliverNetworkPacket = deliverNetworkPacket,
            },
        };
        self.linkEP.attach(&self.dispatcher);
    }

    // NOTE: Dispatch order matters. ARP (0x0806) frames are processed before IP
    // to ensure link-layer address resolution completes before dependent packets.
    // This prevents deadlock where IP packets wait for ARP that never completes.
    fn deliverNetworkPacket(ptr: *anyopaque, remote: *const tcpip.LinkAddress, local: *const tcpip.LinkAddress, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) void {
        const start_processing: i64 = @intCast(std.time.nanoTimestamp());
        defer {
            const end_processing: i64 = @intCast(std.time.nanoTimestamp());
            if (pkt.timestamp_ns != 0) {
                stats.global_stats.latency.link_layer.record(@as(i64, @intCast(start_processing - pkt.timestamp_ns)));
                stats.global_stats.latency.network_layer.record(@as(i64, @intCast(end_processing - start_processing)));
            }
        }
        const self = @as(*NIC, @ptrCast(@alignCast(ptr)));

        // A real NIC hears its own link-layer broadcasts and must drop them; a
        // loopback NIC delivers self-addressed traffic by design.
        if (!self.loopback and remote.eq(self.linkEP.linkAddress())) return;

        const proto_opt = self.stack.network_protocols.get(protocol);
        if (proto_opt == null) return;
        const proto = proto_opt.?;

        const ep_opt = self.network_endpoints.get(protocol);
        if (ep_opt == null) return;
        const ep = ep_opt.?;

        const addrs = proto.parseAddresses(pkt);
        if (!addrs.src.isAny()) {
            if (self.stack.link_addr_cache.get(addrs.src)) |prev| {
                if (!prev.eq(remote.*)) {
                    self.stack.addLinkAddress(addrs.src, remote.*) catch {};
                }
            } else {
                self.stack.addLinkAddress(addrs.src, remote.*) catch {};
            }
        }

        const r = Route{
            .local_address = addrs.dst,
            .remote_address = addrs.src,
            .local_link_address = local.*,
            .remote_link_address = remote.*,
            .net_proto = protocol,
            .nic = self,
        };

        ep.handlePacket(&r, pkt);
    }
};

pub const Route = struct {
    remote_address: tcpip.Address,
    local_address: tcpip.Address,
    local_link_address: tcpip.LinkAddress,
    remote_link_address: ?tcpip.LinkAddress = null,
    next_hop: ?tcpip.Address = null,
    net_proto: tcpip.NetworkProtocolNumber,
    nic: *NIC,
    route_entry: ?*const RouteEntry = null,

    pub fn writePacket(self: *Route, protocol: tcpip.TransportProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const next_hop = self.next_hop orelse self.remote_address;

        if (self.remote_link_address == null) {
            const link_addr_opt = self.nic.stack.link_addr_cache.get(next_hop);

            if (link_addr_opt) |link_addr| {
                self.remote_link_address = link_addr;
            } else {
                // The caller releases pkt's header/payload on this WouldBlock
                // return, so deep-copy into the queue; addLinkAddress retransmits
                // once the next hop resolves. OOM just drops it (the upper layer
                // retransmits), so the copy failure is not fatal.
                self.nic.stack.arp_pending.enqueue(self, protocol, next_hop, pkt, self.nic.stack.allocator, &self.nic.stack.cluster_pool) catch {};

                var it = self.nic.stack.network_protocols.valueIterator();
                while (it.next()) |proto| {
                    proto.linkAddressRequest(next_hop, self.local_address, self.nic) catch {};
                }
                return tcpip.Error.WouldBlock;
            }
        }

        const net_ep = self.nic.network_endpoints.get(self.net_proto) orelse return tcpip.Error.NoRoute;
        return net_ep.writePacket(self, protocol, pkt);
    }
};

// A packet held while its next hop is resolved by ARP/NDP. The enqueued copy is
// deep (its own header buffer + cluster-backed payload): the originating sender
// frees pkt's buffers as soon as writePacket returns WouldBlock, so a shallow
// copy would dangle.
const ArpPendingEntry = struct {
    pkt: tcpip.PacketBuffer,
    route: Route,
    trans_proto: tcpip.TransportProtocolNumber,
    next_hop: tcpip.Address,
    timestamp_ms: i64,
    allocator: std.mem.Allocator,

    fn deinit(self: *ArpPendingEntry) void {
        self.pkt.data.deinit();
        self.allocator.free(self.pkt.header.buf);
        self.* = undefined;
    }
};

const ArpPendingQueue = struct {
    entries: std.ArrayList(ArpPendingEntry),
    max_entries: usize,
    timeout_ms: i64,

    fn init(allocator: std.mem.Allocator, max_entries: usize, timeout_ms: i64) ArpPendingQueue {
        return .{
            .entries = std.ArrayList(ArpPendingEntry).init(allocator),
            .max_entries = max_entries,
            .timeout_ms = timeout_ms,
        };
    }

    fn deinit(self: *ArpPendingQueue) void {
        for (self.entries.items) |*e| e.deinit();
        self.entries.deinit();
    }

    fn enqueue(self: *ArpPendingQueue, route: *const Route, trans_proto: tcpip.TransportProtocolNumber, next_hop: tcpip.Address, pkt: tcpip.PacketBuffer, allocator: std.mem.Allocator, cluster_pool: *buffer.ClusterPool) !void {
        if (self.entries.items.len >= self.max_entries) {
            var evicted = self.entries.orderedRemove(0);
            evicted.deinit();
            stats.global_stats.arp.pending_drops.inc();
        }
        // Reserve the slot up front so no fallible step remains after the deep
        // copy owns its buffers (otherwise an append failure would leak them).
        try self.entries.ensureUnusedCapacity(1);

        const hbuf = try allocator.alloc(u8, pkt.header.buf.len);
        errdefer allocator.free(hbuf);
        @memcpy(hbuf, pkt.header.buf);

        const new_data = if (pkt.data.size == 0)
            buffer.VectorisedView.empty()
        else blk: {
            const tmp = try pkt.data.toView(allocator);
            defer allocator.free(tmp);
            break :blk try buffer.VectorisedView.fromSlice(tmp, allocator, cluster_pool);
        };

        self.entries.appendAssumeCapacity(.{
            .pkt = .{ .data = new_data, .header = .{ .buf = hbuf, .usedIdx = pkt.header.usedIdx } },
            .route = route.*,
            .trans_proto = trans_proto,
            .next_hop = next_hop,
            .timestamp_ms = std.time.milliTimestamp(),
            .allocator = allocator,
        });
    }

    // Remove and return entries waiting on `addr`; the caller retransmits each
    // (the next hop is now known) and then deinits it.
    fn drainForAddress(self: *ArpPendingQueue, addr: tcpip.Address) std.ArrayList(ArpPendingEntry) {
        var result = std.ArrayList(ArpPendingEntry).init(self.entries.allocator);
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (self.entries.items[i].next_hop.eq(addr)) {
                const removed = self.entries.orderedRemove(i);
                result.append(removed) catch {
                    var e = removed;
                    e.deinit();
                };
            } else i += 1;
        }
        return result;
    }

    fn expireOld(self: *ArpPendingQueue, now_ms: i64) usize {
        var removed: usize = 0;
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (now_ms - self.entries.items[i].timestamp_ms > self.timeout_ms) {
                var e = self.entries.orderedRemove(i);
                e.deinit();
                removed += 1;
            } else i += 1;
        }
        return removed;
    }
};

pub const RouteEntry = struct {
    destination: tcpip.Subnet,
    gateway: tcpip.Address,
    nic: tcpip.NICID,
    mtu: u32,
};

const RouteTable = struct {
    routes: std.ArrayList(RouteEntry),

    pub fn init(allocator: std.mem.Allocator) RouteTable {
        return .{
            .routes = std.ArrayList(RouteEntry).init(allocator),
        };
    }

    pub fn deinit(self: *RouteTable) void {
        self.routes.deinit();
    }

    pub fn addRoute(self: *RouteTable, route: RouteEntry) !void {
        var i: usize = 0;
        for (self.routes.items) |r| {
            if (r.destination.gt(route.destination.prefix)) {
                break;
            }
            i += 1;
        }
        try self.routes.insert(i, route);
    }

    pub fn removeRoutes(self: *RouteTable, match: *const fn (route: RouteEntry) bool) usize {
        var count: usize = 0;
        var i: usize = 0;
        while (i < self.routes.items.len) {
            if (match(self.routes.items[i])) {
                _ = self.routes.swapRemove(i);
                count += 1;
            } else {
                i += 1;
            }
        }
        return count;
    }

    pub fn findRoute(self: *RouteTable, dest: tcpip.Address, _: tcpip.NICID) ?*RouteEntry {
        var best_route: ?*RouteEntry = null;
        for (self.routes.items) |*route_entry| {
            if (route_entry.destination.contains(dest)) {
                if (best_route == null or route_entry.destination.gt(best_route.?.destination.prefix)) {
                    best_route = route_entry;
                }
            }
        }
        return best_route;
    }

    pub fn getRoutes(self: *RouteTable) []const RouteEntry {
        return self.routes.items;
    }
};

/// PERF: Sharded transport table reduces lock contention on multi-queue NICs.
pub const TransportTable = struct {
    shards: [256]std.HashMap(TransportEndpointID, TransportEndpoint, TransportContext, 80),

    const TransportContext = struct {
        pub fn hash(_: TransportContext, key: TransportEndpointID) u64 {
            return key.hash();
        }
        pub fn eql(_: TransportContext, a: TransportEndpointID, b: TransportEndpointID) bool {
            return a.eq(b);
        }
    };

    pub fn init(allocator: std.mem.Allocator) TransportTable {
        var self: TransportTable = undefined;
        for (&self.shards) |*shard| {
            shard.* = std.HashMap(TransportEndpointID, TransportEndpoint, TransportContext, 80).init(allocator);
        }
        return self;
    }

    pub fn deinit(self: *TransportTable) void {
        for (&self.shards) |*shard| {
            shard.deinit();
        }
    }

    pub fn getShard(self: *TransportTable, id: TransportEndpointID) *std.HashMap(TransportEndpointID, TransportEndpoint, TransportContext, 80) {
        return &self.shards[id.hash() % 256];
    }

    pub fn put(self: *TransportTable, id: TransportEndpointID, ep: TransportEndpoint) !void {
        try self.getShard(id).put(id, ep);
    }

    pub fn fetchRemove(self: *TransportTable, id: TransportEndpointID) ?std.HashMap(TransportEndpointID, TransportEndpoint, TransportContext, 80).KV {
        return self.getShard(id).fetchRemove(id);
    }

    pub fn remove(self: *TransportTable, id: TransportEndpointID) bool {
        return self.getShard(id).remove(id);
    }

    pub fn get(self: *TransportTable, id: TransportEndpointID) ?TransportEndpoint {
        const ep = self.getShard(id).get(id);
        if (ep) |e| e.incRef();
        return ep;
    }
};

pub const Stack = struct {
    allocator: std.mem.Allocator,
    config: Config,
    nics: std.AutoHashMap(tcpip.NICID, *NIC),
    endpoints: TransportTable,
    link_addr_cache: std.HashMap(tcpip.Address, tcpip.LinkAddress, AddressContext, 80),
    pmtu_cache: std.HashMap(tcpip.Address, PMTUEntry, AddressContext, 80),
    transport_protocols: std.AutoHashMap(tcpip.TransportProtocolNumber, TransportProtocol),
    network_protocols: std.AutoHashMap(tcpip.NetworkProtocolNumber, NetworkProtocol),
    route_table: RouteTable,
    timer_queue: time.TimerQueue,
    cluster_pool: buffer.ClusterPool,
    arp_pending: ArpPendingQueue,
    ephemeral_port: u16,
    tcp_msl: u64,
    running: std.atomic.Value(bool),
    start_time_ms: i64,

    pub const AddressContext = struct {
        pub fn hash(_: AddressContext, key: tcpip.Address) u64 {
            return key.hash();
        }
        pub fn eql(_: AddressContext, a: tcpip.Address, b: tcpip.Address) bool {
            return a.eq(b);
        }
    };

    pub fn init(allocator: std.mem.Allocator) !Stack {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: Config) !Stack {
        var cluster_pool = buffer.ClusterPool.init(allocator);
        cluster_pool.max_clusters = config.cluster_pool_max;
        cluster_pool.max_free = config.cluster_pool_max_free;
        try cluster_pool.prewarm(config.cluster_pool_prewarm);
        return .{
            .allocator = allocator,
            .config = config,
            .nics = std.AutoHashMap(tcpip.NICID, *NIC).init(allocator),
            .endpoints = TransportTable.init(allocator),
            .link_addr_cache = std.HashMap(tcpip.Address, tcpip.LinkAddress, AddressContext, 80).init(allocator),
            .pmtu_cache = std.HashMap(tcpip.Address, PMTUEntry, AddressContext, 80).init(allocator),
            .transport_protocols = std.AutoHashMap(tcpip.TransportProtocolNumber, TransportProtocol).init(allocator),
            .network_protocols = std.AutoHashMap(tcpip.NetworkProtocolNumber, NetworkProtocol).init(allocator),
            .route_table = RouteTable.init(allocator),
            .timer_queue = .{},
            .cluster_pool = cluster_pool,
            .arp_pending = ArpPendingQueue.init(allocator, config.arp_pending_max, config.arp_pending_timeout_ms),
            .ephemeral_port = config.ephemeral_port_start,
            .tcp_msl = config.tcp_msl,
            .running = std.atomic.Value(bool).init(false),
            .start_time_ms = std.time.milliTimestamp(),
        };
    }

    pub fn deinit(self: *Stack) void {
        var shard_idx: usize = 0;
        while (shard_idx < 256) : (shard_idx += 1) {
            var shard = &self.endpoints.shards[shard_idx];
            var it = shard.valueIterator();
            while (it.next()) |ep| {
                // abort drops the protocol's stack-side ref; decRef drops the
                // table's. Together they destroy endpoints whose connections
                // never reached a terminal state.
                ep.abort();
                ep.decRef();
            }
            shard.clearAndFree();
        }
        self.endpoints.deinit();
        // Before the cluster pool: draining entries release clusters back to it.
        self.arp_pending.deinit();
        self.cluster_pool.deinit();
        var nic_it = self.nics.valueIterator();
        while (nic_it.next()) |nic| {
            nic.*.deinit();
            self.allocator.destroy(nic.*);
        }
        self.nics.deinit();
        self.link_addr_cache.deinit();
        self.pmtu_cache.deinit();

        var transport_it = self.transport_protocols.valueIterator();
        while (transport_it.next()) |proto| {
            proto.deinit();
        }
        self.transport_protocols.deinit();

        var network_it = self.network_protocols.valueIterator();
        while (network_it.next()) |proto| {
            proto.deinit();
        }
        self.network_protocols.deinit();

        self.route_table.deinit();
    }

    /// Run the stack event loop until shutdown() is called.
    pub fn run(self: *Stack) void {
        self.running.store(true, .release);

        while (self.running.load(.acquire)) {
            // Process timers
            _ = self.timer_queue.tick();

            // Expire old ARP pending entries
            _ = self.arp_pending.expireOld(std.time.milliTimestamp());

            // Sleep until next timer or 10ms max (avoids busy-wait while
            // staying responsive to shutdown and new events).
            const sleep_ns: u64 = if (self.timer_queue.nextExpiration()) |ticks|
                @min(ticks * std.time.ns_per_ms, 10 * std.time.ns_per_ms)
            else
                10 * std.time.ns_per_ms;
            std.time.sleep(sleep_ns);
        }
    }

    /// Signal graceful shutdown.
    pub fn shutdown(self: *Stack) void {
        self.running.store(false, .release);
    }

    pub fn isRunning(self: *Stack) bool {
        return self.running.load(.acquire);
    }

    // -- Health check endpoint -----------------------------------------------

    /// Get current health status.
    pub fn getHealthStatus(self: *Stack) HealthStatus {
        const now_ms = std.time.milliTimestamp();
        const uptime_sec = @divFloor(now_ms - self.start_time_ms, 1000);

        const tcp_conn_count = self.liveEndpointCount();

        const link = &stats.global_link_stats;

        return .{
            .uptime_seconds = uptime_sec,
            .nic_count = self.nics.count(),
            .tcp_connections = tcp_conn_count,
            .arp_cache_size = self.link_addr_cache.count(),
            .rx_packets = link.rx_packets.load(),
            .tx_packets = link.tx_packets.load(),
            .rx_bytes = link.rx_bytes.load(),
            .tx_bytes = link.tx_bytes.load(),
            .rx_drops = stats.global_stats.direction.rx_drops.load(),
        };
    }

    /// Write health status as JSON to a buffer.
    pub fn writeHealthJson(self: *Stack, buf: []u8) ![]u8 {
        const status = self.getHealthStatus();
        return status.toJson(buf);
    }

    pub fn registerNetworkProtocol(self: *Stack, proto: NetworkProtocol) !void {
        try self.network_protocols.put(proto.number(), proto);
    }

    pub fn registerTransportProtocol(self: *Stack, proto: TransportProtocol) !void {
        try self.transport_protocols.put(proto.number(), proto);
    }

    pub fn getLinkAddress(self: *Stack, addr: tcpip.Address) ?tcpip.LinkAddress {
        return self.link_addr_cache.get(addr);
    }

    pub fn addLinkAddress(self: *Stack, addr: tcpip.Address, link_addr: tcpip.LinkAddress) !void {
        var is_new = false;
        if (self.link_addr_cache.get(addr)) |prev| {
            if (prev.eq(link_addr)) return;
        } else {
            is_new = true;
        }

        // Bound the cache: ARP/NDP passive learning writes here on every valid
        // packet, so spoofed replies from many source IPs would grow it without
        // limit. Entries carry no timestamp, so evict an arbitrary one; under a
        // flood it is most likely attacker junk, and a legitimate peer is
        // re-learned on its next packet.
        if (is_new and self.link_addr_cache.count() >= MAX_LINK_ADDR_CACHE) {
            var it = self.link_addr_cache.keyIterator();
            if (it.next()) |victim| {
                const victim_key = victim.*;
                _ = self.link_addr_cache.remove(victim_key);
                stats.global_stats.arp.cache_evictions.inc();
            }
        }

        try self.link_addr_cache.put(addr, link_addr);

        // Retransmit packets that were waiting on this next hop, now that its
        // link address is known, then release their queue-owned buffers.
        var pending = self.arp_pending.drainForAddress(addr);
        defer pending.deinit();

        for (pending.items) |*entry| {
            entry.route.remote_link_address = link_addr;
            entry.route.writePacket(entry.trans_proto, entry.pkt) catch {};
            entry.deinit();
        }

        if (is_new) {
            for (&self.endpoints.shards) |*shard| {
                var it = shard.valueIterator();
                while (it.next()) |ep| {
                    ep.notify(waiter.EventOut);
                }
            }
        }
    }

    pub fn hasLocalAddress(self: *Stack, addr: tcpip.Address) bool {
        var it = self.nics.valueIterator();
        while (it.next()) |nic| {
            if (nic.*.hasAddress(addr)) return true;
        }
        return false;
    }

    pub fn updatePMTU(self: *Stack, dest: tcpip.Address, new_mtu: u32) void {
        if (!self.config.ip_pmtud) return;
        const now = std.time.milliTimestamp();
        if (self.pmtu_cache.getPtr(dest)) |entry| {
            // A fresh entry only ever shrinks; growth happens by aging out
            // and re-probing (RFC 1191 section 6.3).
            if (now - entry.updated_ms <= PMTU_TTL_MS and new_mtu >= entry.mtu) return;
            entry.* = .{ .mtu = new_mtu, .updated_ms = now };
            stats.global_stats.ip.pmtu_updates.inc();
            return;
        }
        // Entries carry their own freshness, so an arbitrary victim is fine:
        // a still-active path is re-learned by the next ICMP error.
        if (self.pmtu_cache.count() >= MAX_PMTU_CACHE) {
            var it = self.pmtu_cache.keyIterator();
            if (it.next()) |victim| {
                const victim_key = victim.*;
                _ = self.pmtu_cache.remove(victim_key);
            }
        }
        self.pmtu_cache.put(dest, .{ .mtu = new_mtu, .updated_ms = now }) catch return;
        stats.global_stats.ip.pmtu_updates.inc();
    }

    pub fn pmtuFor(self: *Stack, dest: tcpip.Address) ?u32 {
        const entry = self.pmtu_cache.get(dest) orelse return null;
        if (std.time.milliTimestamp() - entry.updated_ms > PMTU_TTL_MS) {
            _ = self.pmtu_cache.remove(dest);
            return null;
        }
        return entry.mtu;
    }

    fn liveEndpointCount(self: *Stack) usize {
        var n: usize = 0;
        for (&self.endpoints.shards) |*shard| n += shard.count();
        return n;
    }

    pub fn registerTransportEndpoint(self: *Stack, id: TransportEndpointID, ep: TransportEndpoint) !void {
        const shard = self.endpoints.getShard(id);
        // Only a brand-new id grows the table; re-registering an existing id (bind
        // then listen reuse it) does not, so only new ids are capped.
        if (!shard.contains(id) and self.liveEndpointCount() >= self.config.max_endpoints) {
            stats.global_stats.tcp.endpoints_dropped.inc();
            return tcpip.Error.NoBufferSpace;
        }
        ep.incRef();
        errdefer ep.decRef();
        // fetchPut returns the entry it replaced; decRef it so re-registering an
        // id (bind then listen) does not strand the previous endpoint's ref.
        const old = try shard.fetchPut(id, ep);
        if (old) |kv| kv.value.decRef();
    }

    pub fn unregisterTransportEndpoint(self: *Stack, id: TransportEndpointID) void {
        const ep_opt = self.endpoints.fetchRemove(id);
        if (ep_opt) |kv| {
            kv.value.decRef();
        }
    }

    pub fn getNextEphemeralPort(self: *Stack) u16 {
        const port = self.ephemeral_port;
        if (self.ephemeral_port >= self.config.ephemeral_port_end) {
            self.ephemeral_port = self.config.ephemeral_port_start;
        } else {
            self.ephemeral_port += 1;
        }
        return port;
    }

    pub fn findRoute(self: *Stack, nic_id: tcpip.NICID, local_addr: tcpip.Address, remote_addr: tcpip.Address, net_proto: tcpip.NetworkProtocolNumber) !Route {
        if (nic_id != 0) {
            const nic_opt = self.nics.get(nic_id);
            const next_hop = remote_addr;
            const link_addr_opt = self.link_addr_cache.get(next_hop);

            const nic = nic_opt orelse return tcpip.Error.UnknownNICID;

            return Route{
                .local_address = local_addr,
                .remote_address = remote_addr,
                .local_link_address = nic.linkEP.linkAddress(),
                .remote_link_address = link_addr_opt,
                .net_proto = net_proto,
                .nic = nic,
                .next_hop = null,
                .route_entry = null,
            };
        }

        const route_entry = self.route_table.findRoute(remote_addr, nic_id) orelse return tcpip.Error.NoRoute;

        const nic_opt = self.nics.get(route_entry.nic);
        const next_hop = route_entry.gateway;
        const link_addr_opt = if (next_hop.isAny()) self.link_addr_cache.get(remote_addr) else self.link_addr_cache.get(next_hop);

        const nic = nic_opt orelse return tcpip.Error.UnknownNICID;

        var final_local_addr = local_addr;
        if (final_local_addr.isAny()) {
            for (nic.addresses.items) |addr| {
                if (addr.protocol == net_proto) {
                    final_local_addr = addr.address_with_prefix.address;
                    break;
                }
            }
        }

        return Route{
            .local_address = final_local_addr,
            .remote_address = remote_addr,
            .local_link_address = nic.linkEP.linkAddress(),
            .remote_link_address = link_addr_opt,
            .net_proto = net_proto,
            .nic = nic,
            .next_hop = if (next_hop.isAny()) null else next_hop,
            .route_entry = route_entry,
        };
    }

    pub fn addRoute(self: *Stack, route: RouteEntry) !void {
        try self.route_table.addRoute(route);
    }

    pub fn removeRoute(self: *Stack, route: RouteEntry) bool {
        for (self.route_table.routes.items, 0..) |r, i| {
            if (r.nic == route.nic and
                r.destination.prefix == route.destination.prefix and
                r.destination.address.eq(route.destination.address) and
                r.gateway.eq(route.gateway))
            {
                _ = self.route_table.routes.swapRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn setRouteTable(self: *Stack, routes: []const RouteEntry) !void {
        self.route_table.routes.clearRetainingCapacity();
        for (routes) |route| {
            try self.route_table.routes.append(route);
        }
    }

    pub fn removeRoutes(self: *Stack, match: *const fn (route: RouteEntry) bool) usize {
        return self.route_table.removeRoutes(match);
    }

    pub fn getRouteTable(self: *Stack) []const RouteEntry {
        return self.route_table.getRoutes();
    }

    pub fn flush(self: *Stack) void {
        var it = self.nics.valueIterator();
        while (it.next()) |nic| {
            nic.*.linkEP.flush();
        }
    }

    pub fn createNIC(self: *Stack, id: tcpip.NICID, ep: LinkEndpoint) !void {
        return self.createNICEx(id, ep, false);
    }

    /// Create a loopback NIC, which delivers self-addressed traffic (the NIC
    /// dispatch skips the "drop our own link-layer broadcast" guard).
    pub fn createLoopbackNIC(self: *Stack, id: tcpip.NICID, ep: LinkEndpoint) !void {
        return self.createNICEx(id, ep, true);
    }

    pub fn createNICEx(self: *Stack, id: tcpip.NICID, ep: LinkEndpoint, loopback: bool) !void {
        const nic = try self.allocator.create(NIC);
        nic.* = NIC.init(self, id, "", ep, loopback);

        try self.nics.put(id, nic);

        nic.attach();
    }

    pub fn transportDispatcher(self: *Stack) TransportDispatcher {
        return .{
            .ptr = self,
            .vtable = &.{
                .deliverTransportPacket = deliverTransportPacket,
            },
        };
    }

    pub fn deliverTransportPacket(ptr: *anyopaque, r: *const Route, protocol: tcpip.TransportProtocolNumber, pkt: tcpip.PacketBuffer) void {
        defer {
            const end_processing: i64 = @intCast(std.time.nanoTimestamp());
            if (pkt.timestamp_ns != 0) {
                stats.global_stats.latency.transport_dispatch.record(end_processing - pkt.timestamp_ns);
            }
        }
        const self = @as(*Stack, @ptrCast(@alignCast(ptr)));

        const proto_opt = self.transport_protocols.get(protocol);

        const proto = proto_opt orelse return;
        const ports = proto.parsePorts(pkt);

        const id = TransportEndpointID{
            .local_port = ports.dst,
            .local_address = r.local_address,
            .remote_port = ports.src,
            .remote_address = r.remote_address,
        };

        const ep_opt = self.endpoints.get(id);

        if (ep_opt) |ep| {
            ep.handlePacket(r, id, pkt);
            ep.decRef();
        } else {
            if (proto.vtable.handlePacket) |handle| {
                handle(proto.ptr, r, id, pkt);
                return;
            }

            const listener_id = TransportEndpointID{
                .local_port = ports.dst,
                .local_address = r.local_address,
                .remote_port = 0,
                .remote_address = switch (r.local_address) {
                    .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                    .v6 => .{ .v6 = [_]u8{0} ** 16 },
                },
            };

            const listener_opt = self.endpoints.get(listener_id);

            if (listener_opt) |ep| {
                ep.handlePacket(r, id, pkt);
                ep.decRef();
            } else {
                const any_addr = switch (r.local_address) {
                    .v4 => tcpip.Address{ .v4 = .{ 0, 0, 0, 0 } },
                    .v6 => tcpip.Address{ .v6 = [_]u8{0} ** 16 },
                };

                const any_id = TransportEndpointID{
                    .local_port = ports.dst,
                    .local_address = any_addr,
                    .remote_port = 0,
                    .remote_address = switch (r.local_address) {
                        .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                        .v6 => .{ .v6 = [_]u8{0} ** 16 },
                    },
                };

                if (self.endpoints.get(any_id)) |ep| {
                    ep.handlePacket(r, id, pkt);
                    ep.decRef();
                } else {
                    if (protocol == 17) {
                        log.warn("Stack: No endpoint for UDP port {}. Looked for exact: {}, listener: {}, any: {}", .{ ports.dst, id.hash(), listener_id.hash(), any_id.hash() });
                        log.debug("Exact: local={any}:{} remote={any}:{}", .{ id.local_address, id.local_port, id.remote_address, id.remote_port });
                        log.debug("Any: local={any}:{} remote={any}:{}", .{ any_id.local_address, any_id.local_port, any_id.remote_address, any_id.remote_port });
                    }
                }
            }
        }
    }
};

test "Stack.init with config" {
    const allocator = std.testing.allocator;
    var s = try Stack.initWithConfig(allocator, .{
        .tcp_msl = 60000,
        .ephemeral_port_start = 49152,
    });
    defer s.deinit();

    try std.testing.expectEqual(@as(u64, 60000), s.tcp_msl);
    try std.testing.expectEqual(@as(u16, 49152), s.ephemeral_port);
}

test "health status serializes to valid JSON with the expected fields" {
    const allocator = std.testing.allocator;
    var s = try Stack.init(allocator);
    defer s.deinit();

    var buf: [512]u8 = undefined;
    const json = try s.writeHealthJson(&buf);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expect(obj.contains("uptime_seconds"));
    try std.testing.expect(obj.contains("tcp_connections"));
    try std.testing.expect(obj.contains("rx_packets"));
    try std.testing.expect(obj.contains("rx_drops"));
}

test "Stack PMTU cache: shrink-only while fresh, aging, bounded" {
    const allocator = std.testing.allocator;
    var s = try Stack.init(allocator);
    defer s.deinit();

    const dst = tcpip.Address{ .v4 = .{ 192, 0, 2, 1 } };
    try std.testing.expectEqual(@as(?u32, null), s.pmtuFor(dst));

    s.updatePMTU(dst, 1400);
    try std.testing.expectEqual(@as(?u32, 1400), s.pmtuFor(dst));

    // A fresh entry must not grow from a (possibly forged) ICMP error.
    s.updatePMTU(dst, 1500);
    try std.testing.expectEqual(@as(?u32, 1400), s.pmtuFor(dst));

    s.updatePMTU(dst, 1000);
    try std.testing.expectEqual(@as(?u32, 1000), s.pmtuFor(dst));

    // An aged entry is dropped on lookup so the path re-probes larger MTUs.
    s.pmtu_cache.getPtr(dst).?.updated_ms -= PMTU_TTL_MS + 1;
    try std.testing.expectEqual(@as(?u32, null), s.pmtuFor(dst));
    try std.testing.expectEqual(@as(usize, 0), s.pmtu_cache.count());

    // The cache never exceeds its bound.
    var i: u32 = 0;
    while (i < MAX_PMTU_CACHE + 10) : (i += 1) {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, i, .big);
        s.updatePMTU(.{ .v4 = bytes }, 1280);
    }
    try std.testing.expectEqual(MAX_PMTU_CACHE, s.pmtu_cache.count());
}

test "Stack PMTU cache: disabled by config" {
    const allocator = std.testing.allocator;
    var s = try Stack.initWithConfig(allocator, .{ .ip_pmtud = false });
    defer s.deinit();

    const dst = tcpip.Address{ .v4 = .{ 192, 0, 2, 1 } };
    s.updatePMTU(dst, 1400);
    try std.testing.expectEqual(@as(?u32, null), s.pmtuFor(dst));
}

test "Stack graceful shutdown" {
    const allocator = std.testing.allocator;
    var s = try Stack.init(allocator);
    defer s.deinit();

    try std.testing.expect(!s.isRunning());
    s.running.store(true, .release);
    try std.testing.expect(s.isRunning());
    s.shutdown();
    try std.testing.expect(!s.isRunning());
}
