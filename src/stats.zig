/// Runtime statistics with atomic counters for thread-safe Rx/Tx updates.
/// Capture point-in-time Snapshot for logging or Prometheus export.
const std = @import("std");

const Atomic = std.atomic.Value;

/// Lock-free monotonic counter backed by an atomic u64.
pub const Counter = struct {
    raw: Atomic(u64) = Atomic(u64).init(0),

    pub fn inc(self: *Counter) void {
        _ = self.raw.fetchAdd(1, .monotonic);
    }

    pub fn dec(self: *Counter) void {
        _ = self.raw.fetchSub(1, .monotonic);
    }

    pub fn add(self: *Counter, value: u64) void {
        _ = self.raw.fetchAdd(value, .monotonic);
    }

    pub fn load(self: *const Counter) u64 {
        return self.raw.load(.monotonic);
    }

    pub fn store(self: *Counter, value: u64) void {
        self.raw.store(value, .monotonic);
    }
};

// Direction counters (atomic, lock-free)
pub const DirectionStats = struct {
    rx_bytes: Counter = .{},
    tx_bytes: Counter = .{},
    rx_packets: Counter = .{},
    tx_packets: Counter = .{},
    rx_drops: Counter = .{},
    tx_drops: Counter = .{},

    pub fn recordRx(self: *DirectionStats, bytes: u64) void {
        self.rx_packets.inc();
        self.rx_bytes.add(bytes);
    }

    pub fn recordTx(self: *DirectionStats, bytes: u64) void {
        self.tx_packets.inc();
        self.tx_bytes.add(bytes);
    }

    pub fn recordRxDrop(self: *DirectionStats) void {
        self.rx_drops.inc();
    }

    pub fn recordTxDrop(self: *DirectionStats) void {
        self.tx_drops.inc();
    }

    pub fn reset(self: *DirectionStats) void {
        self.rx_bytes.store(0);
        self.tx_bytes.store(0);
        self.rx_packets.store(0);
        self.tx_packets.store(0);
        self.rx_drops.store(0);
        self.tx_drops.store(0);
    }
};

// Snapshot -- immutable copy for logging or export
pub const Snapshot = struct {
    ip: IPStatsSnapshot,
    tcp: TCPStatsSnapshot,
    arp: ARPStatsSnapshot,
    link: LinkStatsSnapshot,
    direction: DirectionStatsSnapshot,
};

pub const DirectionStatsSnapshot = struct {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_drops: u64,
    tx_drops: u64,
};

pub const IPStatsSnapshot = struct {
    rx_packets: u64,
    tx_packets: u64,
    dropped_packets: u64,
    invalid_checksum: u64,
    no_route: u64,
    reassembly_drops: u64,
    pmtu_updates: u64,
};

pub const TCPStatsSnapshot = struct {
    rx_segments: u64,
    tx_segments: u64,
    retransmits: u64,
    active_opens: u64,
    passive_opens: u64,
    failed_connections: u64,
    established: u64,
    resets_sent: u64,
    resets_received: u64,
    active_endpoints: u64,
};

pub const ARPStatsSnapshot = struct {
    rx_requests: u64,
    rx_replies: u64,
    tx_requests: u64,
    tx_replies: u64,
    cache_evictions: u64,
    pending_drops: u64,
    requests_throttled: u64,
};

pub const LinkStatsSnapshot = struct {
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_errors: u64,
    tx_errors: u64,
};

// Protocol-level stats (atomic)

pub const IPStats = struct {
    rx_packets: Counter = .{},
    tx_packets: Counter = .{},
    dropped_packets: Counter = .{},
    invalid_checksum: Counter = .{},
    no_route: Counter = .{},
    reassembly_drops: Counter = .{},
    pmtu_updates: Counter = .{},

    pub fn snapshot(self: *const IPStats) IPStatsSnapshot {
        return .{
            .rx_packets = self.rx_packets.load(),
            .tx_packets = self.tx_packets.load(),
            .dropped_packets = self.dropped_packets.load(),
            .invalid_checksum = self.invalid_checksum.load(),
            .no_route = self.no_route.load(),
            .reassembly_drops = self.reassembly_drops.load(),
            .pmtu_updates = self.pmtu_updates.load(),
        };
    }

    pub fn reset(self: *IPStats) void {
        self.rx_packets.store(0);
        self.tx_packets.store(0);
        self.dropped_packets.store(0);
        self.invalid_checksum.store(0);
        self.no_route.store(0);
        self.reassembly_drops.store(0);
        self.pmtu_updates.store(0);
    }
};

pub const TCPStats = struct {
    rx_segments: Counter = .{},
    tx_segments: Counter = .{},
    retransmits: Counter = .{},
    active_opens: Counter = .{},
    passive_opens: Counter = .{},
    failed_connections: Counter = .{},
    established: Counter = .{},
    resets_sent: Counter = .{},
    resets_received: Counter = .{},
    active_endpoints: Counter = .{},
    pool_exhausted: Counter = .{},
    syncache_dropped: Counter = .{},
    syncache_searches: Counter = .{},
    syncache_max_size: Counter = .{},
    ooo_dropped: Counter = .{},
    endpoints_dropped: Counter = .{},

    // TCP flags stats.
    rx_syn: Counter = .{},
    rx_syn_ack: Counter = .{},
    rx_ack: Counter = .{},
    rx_psh: Counter = .{},
    rx_fin: Counter = .{},
    tx_syn: Counter = .{},
    tx_syn_ack: Counter = .{},
    tx_ack: Counter = .{},
    tx_psh: Counter = .{},
    tx_fin: Counter = .{},

    // Keepalive and recovery stats
    tx_keepalive_probes: Counter = .{},
    prr_recovery_entries: Counter = .{},
    early_retransmits: Counter = .{},

    pub fn snapshot(self: *const TCPStats) TCPStatsSnapshot {
        return .{
            .rx_segments = self.rx_segments.load(),
            .tx_segments = self.tx_segments.load(),
            .retransmits = self.retransmits.load(),
            .active_opens = self.active_opens.load(),
            .passive_opens = self.passive_opens.load(),
            .failed_connections = self.failed_connections.load(),
            .established = self.established.load(),
            .resets_sent = self.resets_sent.load(),
            .resets_received = self.resets_received.load(),
            .active_endpoints = self.active_endpoints.load(),
        };
    }

    pub fn reset(self: *TCPStats) void {
        self.rx_segments.store(0);
        self.tx_segments.store(0);
        self.retransmits.store(0);
        self.active_opens.store(0);
        self.passive_opens.store(0);
        self.failed_connections.store(0);
        self.established.store(0);
        self.resets_sent.store(0);
        self.resets_received.store(0);
        self.active_endpoints.store(0);
        self.pool_exhausted.store(0);
        self.syncache_dropped.store(0);
        self.syncache_searches.store(0);
        self.syncache_max_size.store(0);
        self.ooo_dropped.store(0);
        self.endpoints_dropped.store(0);
        self.rx_syn.store(0);
        self.rx_syn_ack.store(0);
        self.rx_ack.store(0);
        self.rx_psh.store(0);
        self.rx_fin.store(0);
        self.tx_syn.store(0);
        self.tx_syn_ack.store(0);
        self.tx_ack.store(0);
        self.tx_psh.store(0);
        self.tx_fin.store(0);
    }
};

pub const ARPStats = struct {
    rx_requests: Counter = .{},
    rx_replies: Counter = .{},
    tx_requests: Counter = .{},
    tx_replies: Counter = .{},
    cache_evictions: Counter = .{},
    pending_drops: Counter = .{},
    requests_throttled: Counter = .{},

    pub fn snapshot(self: *const ARPStats) ARPStatsSnapshot {
        return .{
            .rx_requests = self.rx_requests.load(),
            .rx_replies = self.rx_replies.load(),
            .tx_requests = self.tx_requests.load(),
            .tx_replies = self.tx_replies.load(),
            .cache_evictions = self.cache_evictions.load(),
            .pending_drops = self.pending_drops.load(),
            .requests_throttled = self.requests_throttled.load(),
        };
    }

    pub fn reset(self: *ARPStats) void {
        self.rx_requests.store(0);
        self.rx_replies.store(0);
        self.tx_requests.store(0);
        self.tx_replies.store(0);
        self.cache_evictions.store(0);
        self.pending_drops.store(0);
        self.requests_throttled.store(0);
    }
};

pub const PoolStats = struct {
    cluster_fallback: Counter = .{},
    buffer_fallback: Counter = .{},
    generic_fallback: Counter = .{},
    cluster_exhausted: Counter = .{},
    view_exhausted: Counter = .{},
    generic_exhausted: Counter = .{},

    pub fn reset(self: *PoolStats) void {
        self.cluster_fallback.store(0);
        self.buffer_fallback.store(0);
        self.generic_fallback.store(0);
        self.cluster_exhausted.store(0);
        self.view_exhausted.store(0);
        self.generic_exhausted.store(0);
    }
};

pub const ICMPStats = struct {
    rx_packets: Counter = .{},
    rx_echo_requests: Counter = .{},
    rx_echo_replies: Counter = .{},
    tx_echo_replies: Counter = .{},
    tx_dest_unreachable: Counter = .{},
    tx_time_exceeded: Counter = .{},
};

pub const ICMPv6Stats = struct {
    rx_packets: Counter = .{},
    rx_echo_requests: Counter = .{},
    rx_echo_replies: Counter = .{},
    tx_echo_replies: Counter = .{},
    rx_neighbor_solicitations: Counter = .{},
    rx_neighbor_advertisements: Counter = .{},
    rx_router_solicitations: Counter = .{},
    rx_router_advertisements: Counter = .{},
    tx_neighbor_advertisements: Counter = .{},
};

pub const UDPStats = struct {
    rx_packets: Counter = .{},
    tx_packets: Counter = .{},
    rx_bytes: Counter = .{},
    tx_bytes: Counter = .{},
};

pub const LinkStats = struct {
    rx_packets: Counter = .{},
    tx_packets: Counter = .{},
    rx_bytes: Counter = .{},
    tx_bytes: Counter = .{},
    rx_errors: Counter = .{},
    tx_errors: Counter = .{},
    rx_syscalls: Counter = .{},
    tx_syscalls: Counter = .{},

    pub fn snapshot(self: *const LinkStats) LinkStatsSnapshot {
        return .{
            .rx_packets = self.rx_packets.load(),
            .tx_packets = self.tx_packets.load(),
            .rx_bytes = self.rx_bytes.load(),
            .tx_bytes = self.tx_bytes.load(),
            .rx_errors = self.rx_errors.load(),
            .tx_errors = self.tx_errors.load(),
        };
    }

    pub fn reset(self: *LinkStats) void {
        self.rx_packets.store(0);
        self.tx_packets.store(0);
        self.rx_bytes.store(0);
        self.tx_bytes.store(0);
        self.rx_errors.store(0);
        self.tx_errors.store(0);
        self.rx_syscalls.store(0);
        self.tx_syscalls.store(0);
    }

    pub fn dump(self: *const LinkStats) void {
        const s = self.snapshot();
        std.debug.print("\n--- Link Statistics ---\n", .{});
        std.debug.print("  Rx: {d} packets, {d} bytes\n", .{ s.rx_packets, s.rx_bytes });
        std.debug.print("  Tx: {d} packets, {d} bytes\n", .{ s.tx_packets, s.tx_bytes });
        std.debug.print("  Rx Errors: {d}, Tx Errors: {d}\n", .{ s.rx_errors, s.tx_errors });
        std.debug.print("-------------------------\n\n", .{});
    }
};

// Latency tracking

pub const LatencyMetric = struct {
    count: u64 = 0,
    sum_ns: i64 = 0,
    min_ns: i64 = std.math.maxInt(i64),
    max_ns: i64 = 0,

    pub fn record(self: *@This(), ns: i64) void {
        self.count += 1;
        self.sum_ns += ns;
        if (ns < self.min_ns) self.min_ns = ns;
        if (ns > self.max_ns) self.max_ns = ns;
    }

    pub fn average(self: @This()) f64 {
        if (self.count == 0) return 0;
        return @as(f64, @floatFromInt(self.sum_ns)) / @as(f64, @floatFromInt(self.count));
    }
};

pub const LatencyStats = struct {
    link_layer: LatencyMetric = .{},
    network_layer: LatencyMetric = .{},
    transport_dispatch: LatencyMetric = .{},
    tcp_endpoint: LatencyMetric = .{},
    udp_endpoint: LatencyMetric = .{},
    driver_rx: LatencyMetric = .{},
    driver_tx: LatencyMetric = .{},

    pub fn dump(self: @This()) void {
        std.debug.print("\n--- Latency Statistics (ns) ---\n", .{});
        printMetric("Driver RX       ", self.driver_rx);
        printMetric("Driver TX       ", self.driver_tx);
        printMetric("Link Layer      ", self.link_layer);
        printMetric("Network Layer   ", self.network_layer);
        printMetric("Transport Disp  ", self.transport_dispatch);
        printMetric("TCP Endpoint    ", self.tcp_endpoint);
        printMetric("UDP Endpoint    ", self.udp_endpoint);
        std.debug.print("-------------------------------\n\n", .{});
    }

    fn printMetric(name: []const u8, m: LatencyMetric) void {
        if (m.count == 0) return;
        std.debug.print("{s}: avg={d:.2}, min={d}, max={d}, count={d}\n", .{ name, m.average(), m.min_ns, m.max_ns, m.count });
    }
};

// Aggregate stack stats

pub const StackStats = struct {
    ip: IPStats = .{},
    tcp: TCPStats = .{},
    arp: ARPStats = .{},
    icmp: ICMPStats = .{},
    icmpv6: ICMPv6Stats = .{},
    udp: UDPStats = .{},
    latency: LatencyStats = .{},
    pool: PoolStats = .{},
    direction: DirectionStats = .{},

    /// Capture a point-in-time immutable copy of all counters.
    pub fn snapshot(self: *const StackStats) Snapshot {
        return .{
            .ip = self.ip.snapshot(),
            .tcp = self.tcp.snapshot(),
            .arp = self.arp.snapshot(),
            .link = .{
                .rx_packets = 0,
                .tx_packets = 0,
                .rx_bytes = 0,
                .tx_bytes = 0,
                .rx_errors = 0,
                .tx_errors = 0,
            },
            .direction = .{
                .rx_bytes = self.direction.rx_bytes.load(),
                .tx_bytes = self.direction.tx_bytes.load(),
                .rx_packets = self.direction.rx_packets.load(),
                .tx_packets = self.direction.tx_packets.load(),
                .rx_drops = self.direction.rx_drops.load(),
                .tx_drops = self.direction.tx_drops.load(),
            },
        };
    }

    /// Reset all counters to zero.
    pub fn reset(self: *StackStats) void {
        self.ip.reset();
        self.tcp.reset();
        self.arp.reset();
        self.latency = .{};
        self.pool.reset();
        self.direction.reset();
    }

    pub fn dump(self: *const StackStats) void {
        const s = self.snapshot();
        std.debug.print("\n--- Stack Statistics ---\n", .{});
        std.debug.print("IP:\n", .{});
        std.debug.print("  Rx: {d}, Tx: {d}, Dropped: {d}\n", .{ s.ip.rx_packets, s.ip.tx_packets, s.ip.dropped_packets });
        std.debug.print("ARP:\n", .{});
        std.debug.print("  Rx Req: {d}, Rx Rep: {d}, Tx Req: {d}, Tx Rep: {d}\n", .{ s.arp.rx_requests, s.arp.rx_replies, s.arp.tx_requests, s.arp.tx_replies });
        std.debug.print("TCP:\n", .{});
        std.debug.print("  Rx Seg: {d}, Tx Seg: {d}, Retrans: {d}\n", .{ s.tcp.rx_segments, s.tcp.tx_segments, s.tcp.retransmits });
        std.debug.print("Direction:\n", .{});
        std.debug.print("  Rx: {d} pkts / {d} bytes, Tx: {d} pkts / {d} bytes\n", .{ s.direction.rx_packets, s.direction.rx_bytes, s.direction.tx_packets, s.direction.tx_bytes });
        std.debug.print("  Rx Drops: {d}, Tx Drops: {d}\n", .{ s.direction.rx_drops, s.direction.tx_drops });
        std.debug.print("-------------------------\n", .{});
        self.latency.dump();
    }

    /// Write all counters in Prometheus exposition format.
    pub fn format(self: *const StackStats, writer: anytype, iface: []const u8) !void {
        const s = self.snapshot();
        const label = if (iface.len > 0) iface else "default";

        // IP metrics
        try writer.print("net_ip_rx_packets_total{{iface=\"{s}\"}} {d}\n", .{ label, s.ip.rx_packets });
        try writer.print("net_ip_tx_packets_total{{iface=\"{s}\"}} {d}\n", .{ label, s.ip.tx_packets });
        try writer.print("net_ip_dropped_packets_total{{iface=\"{s}\"}} {d}\n", .{ label, s.ip.dropped_packets });
        try writer.print("net_ip_invalid_checksum_total{{iface=\"{s}\"}} {d}\n", .{ label, s.ip.invalid_checksum });
        try writer.print("net_ip_no_route_total{{iface=\"{s}\"}} {d}\n", .{ label, s.ip.no_route });
        try writer.print("net_ip_reassembly_drops_total{{iface=\"{s}\"}} {d}\n", .{ label, s.ip.reassembly_drops });
        try writer.print("net_ip_pmtu_updates_total{{iface=\"{s}\"}} {d}\n", .{ label, s.ip.pmtu_updates });

        // TCP metrics
        try writer.print("net_tcp_rx_segments_total{{iface=\"{s}\"}} {d}\n", .{ label, s.tcp.rx_segments });
        try writer.print("net_tcp_tx_segments_total{{iface=\"{s}\"}} {d}\n", .{ label, s.tcp.tx_segments });
        try writer.print("net_tcp_retransmits_total{{iface=\"{s}\"}} {d}\n", .{ label, s.tcp.retransmits });
        try writer.print("net_tcp_active_opens_total{{iface=\"{s}\"}} {d}\n", .{ label, s.tcp.active_opens });
        try writer.print("net_tcp_passive_opens_total{{iface=\"{s}\"}} {d}\n", .{ label, s.tcp.passive_opens });
        try writer.print("net_tcp_failed_connections_total{{iface=\"{s}\"}} {d}\n", .{ label, s.tcp.failed_connections });
        try writer.print("net_tcp_established{{iface=\"{s}\"}} {d}\n", .{ label, s.tcp.established });
        try writer.print("net_tcp_resets_sent_total{{iface=\"{s}\"}} {d}\n", .{ label, s.tcp.resets_sent });
        try writer.print("net_tcp_resets_received_total{{iface=\"{s}\"}} {d}\n", .{ label, s.tcp.resets_received });

        // ARP metrics
        try writer.print("net_arp_rx_requests_total{{iface=\"{s}\"}} {d}\n", .{ label, s.arp.rx_requests });
        try writer.print("net_arp_rx_replies_total{{iface=\"{s}\"}} {d}\n", .{ label, s.arp.rx_replies });
        try writer.print("net_arp_tx_requests_total{{iface=\"{s}\"}} {d}\n", .{ label, s.arp.tx_requests });
        try writer.print("net_arp_tx_replies_total{{iface=\"{s}\"}} {d}\n", .{ label, s.arp.tx_replies });
        try writer.print("net_arp_cache_evictions_total{{iface=\"{s}\"}} {d}\n", .{ label, s.arp.cache_evictions });
        try writer.print("net_arp_pending_drops_total{{iface=\"{s}\"}} {d}\n", .{ label, s.arp.pending_drops });

        // Direction metrics
        try writer.print("net_rx_bytes_total{{iface=\"{s}\"}} {d}\n", .{ label, s.direction.rx_bytes });
        try writer.print("net_tx_bytes_total{{iface=\"{s}\"}} {d}\n", .{ label, s.direction.tx_bytes });
        try writer.print("net_rx_packets_total{{iface=\"{s}\"}} {d}\n", .{ label, s.direction.rx_packets });
        try writer.print("net_tx_packets_total{{iface=\"{s}\"}} {d}\n", .{ label, s.direction.tx_packets });
        try writer.print("net_rx_drops_total{{iface=\"{s}\"}} {d}\n", .{ label, s.direction.rx_drops });
        try writer.print("net_tx_drops_total{{iface=\"{s}\"}} {d}\n", .{ label, s.direction.tx_drops });
    }
};

// Per-interface stats

pub const InterfaceStats = struct {
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    link: LinkStats = .{},
    direction: DirectionStats = .{},

    pub fn setName(self: *InterfaceStats, iface: []const u8) void {
        const len = @min(iface.len, 16);
        @memcpy(self.name[0..len], iface[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn getName(self: *const InterfaceStats) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn format(self: *const InterfaceStats, writer: anytype) !void {
        const label = self.getName();
        const s = self.link.snapshot();

        try writer.print("net_link_rx_packets_total{{iface=\"{s}\"}} {d}\n", .{ label, s.rx_packets });
        try writer.print("net_link_tx_packets_total{{iface=\"{s}\"}} {d}\n", .{ label, s.tx_packets });
        try writer.print("net_link_rx_bytes_total{{iface=\"{s}\"}} {d}\n", .{ label, s.rx_bytes });
        try writer.print("net_link_tx_bytes_total{{iface=\"{s}\"}} {d}\n", .{ label, s.tx_bytes });
        try writer.print("net_link_rx_errors_total{{iface=\"{s}\"}} {d}\n", .{ label, s.rx_errors });
        try writer.print("net_link_tx_errors_total{{iface=\"{s}\"}} {d}\n", .{ label, s.tx_errors });
    }
};

// Globals

pub var global_stats: StackStats = .{};
pub var global_link_stats: LinkStats = .{};
pub var interface_stats: [8]InterfaceStats = [_]InterfaceStats{.{}} ** 8;
