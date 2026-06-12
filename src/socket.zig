//! High-level, portable socket API over shardnet's transport endpoints.
//!
//! This is the ergonomic surface most users want: `send([]const u8)` /
//! `recv([]u8)` instead of vectorised views and payloaders, `accept()` that
//! returns another `Socket`, and plain lifecycle management. It is portable
//! (unlike `posix.zig`, which is a Linux syscall shim) because it wraps the
//! stack's own endpoints, which run on every platform via loopback.
//!
//! The model is poll-based, like smoltcp: operations are non-blocking and
//! return `error.WouldBlock` when not ready. Drive packet delivery with your
//! event loop (or `loopback.tick()` in tests), then read/write.

const std = @import("std");
const tcpip = @import("tcpip.zig");
const stack = @import("stack.zig");
const buffer = @import("buffer.zig");
const waiter = @import("waiter.zig");

pub const Error = tcpip.Error;

const TCP_PROTO: tcpip.TransportProtocolNumber = 6;
const UDP_PROTO: tcpip.TransportProtocolNumber = 17;
const IPV4: tcpip.NetworkProtocolNumber = 0x0800;
const IPV6: tcpip.NetworkProtocolNumber = 0x86dd;

pub const Socket = struct {
    stack: *stack.Stack,
    ep: tcpip.Endpoint,
    wq: *waiter.Queue,
    allocator: std.mem.Allocator,
    // Accepted sockets get a pool-backed queue owned by the endpoint (released
    // on endpoint destroy), so only sockets we created may destroy their wq.
    owns_wq: bool,

    fn create(s: *stack.Stack, trans: tcpip.TransportProtocolNumber, net: tcpip.NetworkProtocolNumber) !*Socket {
        const proto = s.transport_protocols.get(trans) orelse return Error.NotPermitted;
        const wq = try s.allocator.create(waiter.Queue);
        errdefer s.allocator.destroy(wq);
        wq.* = .{};
        const ep = try proto.newEndpoint(s, net, wq);
        const self = try s.allocator.create(Socket);
        self.* = .{ .stack = s, .ep = ep, .wq = wq, .allocator = s.allocator, .owns_wq = true };
        return self;
    }

    /// Open a TCP (IPv4) socket.
    pub fn tcp(s: *stack.Stack) !*Socket {
        return create(s, TCP_PROTO, IPV4);
    }
    /// Open a UDP (IPv4) socket.
    pub fn udp(s: *stack.Stack) !*Socket {
        return create(s, UDP_PROTO, IPV4);
    }
    /// Open a TCP (IPv6) socket.
    pub fn tcp6(s: *stack.Stack) !*Socket {
        return create(s, TCP_PROTO, IPV6);
    }
    /// Open a UDP (IPv6) socket.
    pub fn udp6(s: *stack.Stack) !*Socket {
        return create(s, UDP_PROTO, IPV6);
    }

    pub fn close(self: *Socket) void {
        self.ep.close();
        if (self.owns_wq) self.allocator.destroy(self.wq);
        self.allocator.destroy(self);
    }

    pub fn bind(self: *Socket, addr: tcpip.FullAddress) Error!void {
        return self.ep.bind(addr);
    }
    pub fn connect(self: *Socket, addr: tcpip.FullAddress) Error!void {
        return self.ep.connect(addr);
    }
    pub fn listen(self: *Socket, backlog: i32) Error!void {
        return self.ep.listen(backlog);
    }

    /// Accept a pending connection as a new owned `Socket`. `error.WouldBlock`
    /// if none is ready yet (drive the stack, then retry).
    pub fn accept(self: *Socket) Error!*Socket {
        const res = try self.ep.accept();
        const child = self.allocator.create(Socket) catch {
            res.ep.close();
            return Error.OutOfMemory;
        };
        child.* = .{ .stack = self.stack, .ep = res.ep, .wq = res.wq, .allocator = self.allocator, .owns_wq = false };
        return child;
    }

    /// Send on a connected (TCP) or default-peer (connected UDP) socket.
    pub fn send(self: *Socket, bytes: []const u8) Error!usize {
        var iov = [_][]u8{@constCast(bytes)};
        var uio = buffer.Uio.init(&iov);
        return self.ep.writev(&uio, .{});
    }

    /// Receive into `buf`, returning the number of bytes copied.
    pub fn recv(self: *Socket, buf: []u8) Error!usize {
        var iov = [_][]u8{buf};
        var uio = buffer.Uio.init(&iov);
        return self.ep.readv(&uio, null);
    }

    /// Send a UDP datagram to an explicit destination.
    pub fn sendTo(self: *Socket, dest: tcpip.FullAddress, bytes: []const u8) Error!usize {
        var iov = [_][]u8{@constCast(bytes)};
        var uio = buffer.Uio.init(&iov);
        return self.ep.writev(&uio, .{ .to = &dest });
    }

    /// Receive a UDP datagram, optionally reporting the sender in `from`.
    pub fn recvFrom(self: *Socket, buf: []u8, from: ?*tcpip.FullAddress) Error!usize {
        var iov = [_][]u8{buf};
        var uio = buffer.Uio.init(&iov);
        return self.ep.readv(&uio, from);
    }

    /// True if a read would return data (or a pending connection, for a listener).
    pub fn readable(self: *Socket) bool {
        return self.ep.ready(waiter.EventIn);
    }
    /// True if a write would accept data.
    pub fn writable(self: *Socket) bool {
        return self.ep.ready(waiter.EventOut);
    }

    pub fn localAddr(self: *Socket) Error!tcpip.FullAddress {
        return self.ep.getLocalAddress();
    }
    pub fn peerAddr(self: *Socket) Error!tcpip.FullAddress {
        return self.ep.getRemoteAddress();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const ipv4 = @import("network/ipv4.zig");
const udp_mod = @import("transport/udp.zig");
const tcp_mod = @import("transport/tcp.zig");
const loopback = @import("drivers/loopback.zig");

fn addr4(nic: tcpip.NICID, a: u8, b: u8, c: u8, d: u8, port: u16) tcpip.FullAddress {
    return .{ .nic = nic, .addr = .{ .v4 = .{ a, b, c, d } }, .port = port };
}

test "socket: UDP datagram round-trip over loopback" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var ip4 = ipv4.IPv4Protocol.init();
    try s.registerNetworkProtocol(ip4.protocol());
    const udp_proto = udp_mod.UDPProtocol.init(allocator); // freed by s.deinit (vtable)
    try s.registerTransportProtocol(udp_proto.protocol());

    var lo = loopback.Loopback.init(allocator);
    defer lo.deinit();
    try s.createLoopbackNIC(1, lo.linkEndpoint());
    const nic = s.nics.get(1).?;

    const my_ip = tcpip.Address{ .v4 = .{ 10, 0, 0, 1 } };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = my_ip, .prefix_len = 24 } });
    // Pre-resolve the link address so the TX path doesn't need ARP.
    try s.addLinkAddress(my_ip, lo.linkEndpoint().linkAddress());

    var server = try Socket.udp(&s);
    defer server.close();
    try server.bind(addr4(1, 10, 0, 0, 1, 9000));

    var client = try Socket.udp(&s);
    defer client.close();
    try client.bind(addr4(1, 10, 0, 0, 1, 9001));

    const sent = try client.sendTo(addr4(1, 10, 0, 0, 1, 9000), "ping");
    try std.testing.expectEqual(@as(usize, 4), sent);

    lo.tick(); // deliver the queued datagram

    var buf: [64]u8 = undefined;
    var from: tcpip.FullAddress = undefined;
    const n = try server.recvFrom(&buf, &from);
    try std.testing.expectEqualStrings("ping", buf[0..n]);
    try std.testing.expectEqual(@as(u16, 9001), from.port);
}

test "socket: TCP connect/accept/echo over loopback" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var ip4 = ipv4.IPv4Protocol.init();
    try s.registerNetworkProtocol(ip4.protocol());
    const tcp_proto = tcp_mod.TCPProtocol.init(allocator); // freed by s.deinit (vtable)
    try s.registerTransportProtocol(tcp_proto.protocol());

    var lo = loopback.Loopback.init(allocator);
    defer lo.deinit();
    try s.createLoopbackNIC(1, lo.linkEndpoint());
    const nic = s.nics.get(1).?;

    const my_ip = tcpip.Address{ .v4 = .{ 10, 0, 0, 1 } };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = my_ip, .prefix_len = 24 } });
    try s.addLinkAddress(my_ip, lo.linkEndpoint().linkAddress());

    var server = try Socket.tcp(&s);
    defer server.close();
    try server.bind(addr4(1, 10, 0, 0, 1, 8080));
    try server.listen(8);

    var client = try Socket.tcp(&s);
    defer client.close();
    try client.bind(addr4(1, 10, 0, 0, 1, 0));
    try client.connect(addr4(1, 10, 0, 0, 1, 8080));

    var conn: ?*Socket = null;
    var i: usize = 0;
    while (conn == null and i < 50) : (i += 1) {
        lo.tick();
        _ = s.timer_queue.tick();
        conn = server.accept() catch null;
    }
    try std.testing.expect(conn != null);
    defer conn.?.close();

    const peer = try conn.?.peerAddr();
    try std.testing.expectEqual((try client.localAddr()).port, peer.port);
    try std.testing.expectEqual(@as(u16, 8080), (try client.peerAddr()).port);

    _ = try client.send("hello");
    var buf: [64]u8 = undefined;
    var n: usize = 0;
    i = 0;
    while (i < 50) : (i += 1) {
        lo.tick();
        _ = s.timer_queue.tick();
        n = conn.?.recv(&buf) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        break;
    }
    try std.testing.expectEqualStrings("hello", buf[0..n]);

    _ = try conn.?.send(buf[0..n]);
    var reply: [64]u8 = undefined;
    var rn: usize = 0;
    i = 0;
    while (i < 50) : (i += 1) {
        lo.tick();
        _ = s.timer_queue.tick();
        rn = client.recv(&reply) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        break;
    }
    try std.testing.expectEqualStrings("hello", reply[0..rn]);
}

test "socket: TCP clamps segments to the discovered path MTU" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var ip4 = ipv4.IPv4Protocol.init();
    try s.registerNetworkProtocol(ip4.protocol());
    const tcp_proto = tcp_mod.TCPProtocol.init(allocator); // freed by s.deinit (vtable)
    try s.registerTransportProtocol(tcp_proto.protocol());

    var lo = loopback.Loopback.init(allocator);
    defer lo.deinit();
    try s.createLoopbackNIC(1, lo.linkEndpoint());
    const nic = s.nics.get(1).?;

    const my_ip = tcpip.Address{ .v4 = .{ 10, 0, 0, 1 } };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = my_ip, .prefix_len = 24 } });
    try s.addLinkAddress(my_ip, lo.linkEndpoint().linkAddress());

    var server = try Socket.tcp(&s);
    defer server.close();
    try server.bind(addr4(1, 10, 0, 0, 1, 8081));
    try server.listen(8);

    var client = try Socket.tcp(&s);
    defer client.close();
    try client.bind(addr4(1, 10, 0, 0, 1, 0));
    try client.connect(addr4(1, 10, 0, 0, 1, 8081));

    var conn: ?*Socket = null;
    var i: usize = 0;
    while (conn == null and i < 50) : (i += 1) {
        lo.tick();
        _ = s.timer_queue.tick();
        conn = server.accept() catch null;
    }
    try std.testing.expect(conn != null);
    defer conn.?.close();

    // As if an ICMP Fragmentation Needed reported a 576-byte path.
    s.updatePMTU(my_ip, 576);
    try client.ep.setOption(.{ .tcp_nodelay = true });

    var big: [2000]u8 = undefined;
    for (&big, 0..) |*b, idx| b.* = @truncate(idx);

    const delivered_before = lo.stats().loopback_rx;

    var sent: usize = 0;
    var got: usize = 0;
    var rbuf: [2048]u8 = undefined;
    i = 0;
    while (got < big.len and i < 200) : (i += 1) {
        if (sent < big.len) {
            sent += client.send(big[sent..]) catch |err| switch (err) {
                error.WouldBlock => 0,
                else => return err,
            };
        }
        lo.tick();
        _ = s.timer_queue.tick();
        got += conn.?.recv(rbuf[got..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
    }
    try std.testing.expectEqualSlices(u8, &big, rbuf[0..got]);

    // The clamp must be visible on the endpoint (576 - 40 = 536) and on the
    // wire: 2000 bytes need at least 4 segments at that MSS.
    const cep: *tcp_mod.TCPEndpoint = @ptrCast(@alignCast(client.ep.ptr));
    try std.testing.expectEqual(@as(u16, 536), cep.max_segment_size);
    try std.testing.expect(lo.stats().loopback_rx - delivered_before >= 4);
}
