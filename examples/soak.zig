// In-process soak / load harness. Drives sustained TCP connection churn (with a
// small echo per connection) through the stack over loopback for a fixed duration,
// sampling RSS and pool/endpoint usage to surface slow leaks, accounting drift, and
// cap behaviour that the unit suite (short single flows) cannot catch.
//
//   zig build soak -Dlog_level=err      # err/none: the stack logs per packet at debug
//   ./zig-out/bin/soak [--seconds N] [--concurrency N] [--payload N]
//
// After a warmup it records a baseline, prints a sample line each second, then on
// exit compares pool/endpoint usage to the baseline and prints a PASS/FAIL leak
// verdict: outstanding pool objects and live endpoints must return to baseline.

const std = @import("std");
const shardnet = @import("shardnet");

const Stack = shardnet.stack.Stack;
const Socket = shardnet.socket.Socket;
const Loopback = shardnet.drivers.loopback.Loopback;
const IPv4Protocol = shardnet.network.ipv4.IPv4Protocol;
const TCPProtocol = shardnet.transport.tcp.TCPProtocol;
const tcpip = shardnet.tcpip;

const SERVER_PORT: u16 = 8080;

const Config = struct {
    seconds: u64 = 30,
    concurrency: usize = 64,
    payload: usize = 256,
};

fn fa(port: u16) tcpip.FullAddress {
    return .{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = port };
}

// Current resident set size in bytes (Linux /proc/self/statm field 2 = pages).
fn rssBytes() usize {
    const f = std.fs.openFileAbsolute("/proc/self/statm", .{}) catch return 0;
    defer f.close();
    var buf: [128]u8 = undefined;
    const n = f.readAll(&buf) catch return 0;
    var it = std.mem.tokenizeScalar(u8, buf[0..n], ' ');
    _ = it.next(); // total program size
    const resident = it.next() orelse return 0;
    const pages = std.fmt.parseInt(usize, std.mem.trim(u8, resident, " \n"), 10) catch return 0;
    return pages * 4096; // statm reports pages; 4 KiB on x86_64 (RSS growth is what matters)
}

const Sample = struct {
    endpoints: usize,
    view_outstanding: usize,
    node_outstanding: usize,
    clusters: usize,
    rss: usize,
};

fn sample(s: *Stack, tcp_proto: *const TCPProtocol) Sample {
    return .{
        .endpoints = s.getHealthStatus().tcp_connections,
        .view_outstanding = tcp_proto.view_pool.outstanding,
        .node_outstanding = tcp_proto.packet_node_pool.outstanding,
        .clusters = s.cluster_pool.allocated,
        .rss = rssBytes(),
    };
}

fn pump(s: *Stack, lo: *Loopback, rounds: usize) void {
    var k: usize = 0;
    while (k < rounds) : (k += 1) {
        lo.tick();
        _ = s.timer_queue.tick();
    }
}

// Sleep + pump so the (short, soak-configured) TIME_WAIT timers actually fire and
// closed endpoints are reclaimed; otherwise they linger and look like a leak.
fn drain(s: *Stack, lo: *Loopback) void {
    var d: usize = 0;
    while (d < 12) : (d += 1) {
        std.time.sleep(30 * std.time.ns_per_ms);
        pump(s, lo, 300);
    }
}

// Open `concurrency` clients, accept them server-side, run one echo each, then close
// everything and drain. Returns the number of bytes successfully echoed back.
fn runBatch(allocator: std.mem.Allocator, s: *Stack, lo: *Loopback, server: *Socket, cfg: Config, payload: []const u8) !usize {
    const clients = try allocator.alloc(?*Socket, cfg.concurrency);
    defer allocator.free(clients);
    const conns = try allocator.alloc(?*Socket, cfg.concurrency);
    defer allocator.free(conns);
    @memset(clients, null);
    @memset(conns, null);
    // Belt-and-suspenders: close anything still open if we bail early.
    defer for (clients) |c| {
        if (c) |sock| sock.close();
    };
    defer for (conns) |c| {
        if (c) |sock| sock.close();
    };

    const max_rounds = cfg.concurrency * 8 + 200;

    for (clients) |*c| {
        const sock = Socket.tcp(s) catch continue;
        sock.bind(fa(0)) catch {
            sock.close();
            continue;
        };
        sock.connect(fa(SERVER_PORT)) catch {
            sock.close();
            continue;
        };
        c.* = sock;
    }

    var accepted: usize = 0;
    var rounds: usize = 0;
    while (accepted < cfg.concurrency and rounds < max_rounds) : (rounds += 1) {
        pump(s, lo, 1);
        while (accepted < cfg.concurrency) {
            const conn = server.accept() catch break;
            conns[accepted] = conn;
            accepted += 1;
        }
    }

    for (clients) |c| {
        if (c) |sock| _ = sock.send(payload) catch {};
    }
    pump(s, lo, max_rounds);

    var bytes: usize = 0;
    var rbuf: [4096]u8 = undefined;
    for (conns[0..accepted]) |c| {
        if (c) |sock| {
            const n = sock.recv(&rbuf) catch continue;
            _ = sock.send(rbuf[0..n]) catch {};
        }
    }
    pump(s, lo, max_rounds);

    for (clients) |c| {
        if (c) |sock| {
            const n = sock.recv(&rbuf) catch continue;
            bytes += n;
        }
    }

    for (clients) |*c| {
        if (c.*) |sock| sock.close();
        c.* = null;
    }
    for (conns[0..accepted]) |*c| {
        if (c.*) |sock| sock.close();
        c.* = null;
    }
    pump(s, lo, 400); // drain FINs / TIME_WAIT transitions so endpoints free
    return bytes;
}

fn parseArgs(allocator: std.mem.Allocator) !Config {
    var cfg = Config{};
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--seconds") and i + 1 < args.len) {
            i += 1;
            cfg.seconds = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, a, "--concurrency") and i + 1 < args.len) {
            i += 1;
            cfg.concurrency = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, a, "--payload") and i + 1 < args.len) {
            i += 1;
            cfg.payload = try std.fmt.parseInt(usize, args[i], 10);
        }
    }
    if (cfg.concurrency == 0) cfg.concurrency = 1;
    return cfg;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        if (gpa.deinit() == .leak) std.debug.print("LEAK: GPA reported leaked allocations at shutdown\n", .{});
    }
    const allocator = gpa.allocator();

    const cfg = try parseArgs(allocator);
    const out = std.io.getStdOut().writer();

    // Raise the SYN limiter so the harness's own connection churn is not
    // self-throttled (it is a load generator, not a SYN-flood test).
    shardnet.transport.tcp.syn_limiter = .{ .max_tokens = 1 << 30, .tokens = 1 << 30, .refill_rate = 1 << 30 };

    // Short MSL so TIME_WAIT recycles quickly: closed connections drain instead of
    // piling up, which keeps the live-endpoint count a valid leak signal.
    var s = try Stack.initWithConfig(allocator, .{ .tcp_msl = 50 });
    defer s.deinit();

    var ip4 = IPv4Protocol.init();
    try s.registerNetworkProtocol(ip4.protocol());
    const tcp_proto = TCPProtocol.init(allocator);
    try s.registerTransportProtocol(tcp_proto.protocol());

    var lo = Loopback.init(allocator);
    defer lo.deinit();
    try s.createLoopbackNIC(1, lo.linkEndpoint());
    const nic = s.nics.get(1).?;
    const my_ip = tcpip.Address{ .v4 = .{ 10, 0, 0, 1 } };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = my_ip, .prefix_len = 24 } });
    try s.addLinkAddress(my_ip, lo.linkEndpoint().linkAddress());

    var server = try Socket.tcp(&s);
    defer server.close();
    try server.bind(fa(SERVER_PORT));
    try server.listen(@intCast(@min(cfg.concurrency * 2, 1024)));

    const payload = try allocator.alloc(u8, cfg.payload);
    defer allocator.free(payload);
    for (payload, 0..) |*b, idx| b.* = @truncate(idx);

    try out.print("soak: {d}s, concurrency {d}, payload {d}B\n", .{ cfg.seconds, cfg.concurrency, cfg.payload });

    // Warmup: one batch so pools reach steady state, drain it, then snapshot baseline.
    _ = try runBatch(allocator, &s, &lo, server, cfg, payload);
    drain(&s, &lo);
    const base = sample(&s, tcp_proto);
    try out.print("baseline: endpoints={d} view_out={d} node_out={d} clusters={d} rss={d}KiB\n", .{ base.endpoints, base.view_outstanding, base.node_outstanding, base.clusters, base.rss / 1024 });

    var timer = try std.time.Timer.start();
    const deadline_ns = cfg.seconds * std.time.ns_per_s;
    var batches: u64 = 0;
    var conns_done: u64 = 0;
    var bytes_total: u64 = 0;
    var next_sample_ns: u64 = std.time.ns_per_s;

    while (timer.read() < deadline_ns) {
        const echoed = runBatch(allocator, &s, &lo, server, cfg, payload) catch |err| {
            try out.print("batch error: {s}\n", .{@errorName(err)});
            break;
        };
        batches += 1;
        conns_done += cfg.concurrency;
        bytes_total += echoed;

        const now = timer.read();
        if (now >= next_sample_ns) {
            const sec = now / std.time.ns_per_s;
            const cur = sample(&s, tcp_proto);
            const cps = if (sec > 0) conns_done / sec else conns_done;
            try out.print("t={d}s conns={d} ({d}/s) MiB={d} endpoints={d} view_out={d} node_out={d} clusters={d} rss={d}KiB\n", .{ sec, conns_done, cps, bytes_total / (1024 * 1024), cur.endpoints, cur.view_outstanding, cur.node_outstanding, cur.clusters, cur.rss / 1024 });
            next_sample_ns += std.time.ns_per_s;
        }
    }

    // Final drain and verdict.
    drain(&s, &lo);
    const fin = sample(&s, tcp_proto);
    try out.print("\nfinal: batches={d} conns={d} MiB={d} endpoints={d} view_out={d} node_out={d} clusters={d} rss={d}KiB\n", .{ batches, conns_done, bytes_total / (1024 * 1024), fin.endpoints, fin.view_outstanding, fin.node_outstanding, fin.clusters, fin.rss / 1024 });

    var leaked = false;
    if (fin.endpoints > base.endpoints) {
        try out.print("LEAK: live endpoints {d} > baseline {d} (after TIME_WAIT drain)\n", .{ fin.endpoints, base.endpoints });
        leaked = true;
    }
    if (fin.view_outstanding > base.view_outstanding) {
        try out.print("LEAK: view-pool outstanding {d} > baseline {d}\n", .{ fin.view_outstanding, base.view_outstanding });
        leaked = true;
    }
    if (fin.node_outstanding > base.node_outstanding) {
        try out.print("LEAK: packet-node outstanding {d} > baseline {d}\n", .{ fin.node_outstanding, base.node_outstanding });
        leaked = true;
    }
    const rss_growth = if (fin.rss > base.rss) fin.rss - base.rss else 0;
    try out.print("rss growth since baseline: {d}KiB\n", .{rss_growth / 1024});

    if (leaked) {
        try out.print("VERDICT: FAIL (pool/endpoint accounting did not return to baseline)\n", .{});
        std.process.exit(1);
    }
    try out.print("VERDICT: PASS (pools and endpoints returned to baseline)\n", .{});
}
