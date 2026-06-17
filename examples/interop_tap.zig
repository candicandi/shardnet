// Standalone TAP interop peer. Attaches to a pre-created, user-owned
// tap0 (so no CAP_NET_ADMIN is needed here) and runs shardnet as a host on the
// same L2 segment as the kernel:
//
//   sudo ip tuntap add dev tap0 mode tap user "$USER"
//   sudo ip addr add 10.9.0.1/24 dev tap0   # kernel side
//   sudo ip link set tap0 up
//   zig build interop && ./zig-out/bin/interop_tap   # shardnet side = 10.9.0.2
//
// Then from the host: ping 10.9.0.2 / curl http://10.9.0.2:8080/.
const std = @import("std");
const shardnet = @import("shardnet");

const TUNSETIFF: u32 = 0x400454ca;
const IFF_TAP: u16 = 0x0002;
const IFF_NO_PI: u16 = 0x1000;

const HTTP_RESPONSE =
    "HTTP/1.0 200 OK\r\n" ++
    "Content-Type: text/plain\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "Hello from shardnet over TAP!\n";

const TunIfreq = extern struct {
    name: [16]u8 = [_]u8{0} ** 16,
    flags: i16 = 0,
    _pad: [22]u8 = [_]u8{0} ** 22,
};

// Attach to an existing tap device by name. The device is expected to already
// exist and be owned by this user, so TUNSETIFF needs no privilege.
fn openTap(name: []const u8) !std.posix.fd_t {
    const fd = try std.posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR, .NONBLOCK = true }, 0);
    errdefer std.posix.close(fd);
    var ifr = TunIfreq{};
    const n = @min(name.len, 15);
    @memcpy(ifr.name[0..n], name[0..n]);
    ifr.flags = @bitCast(IFF_TAP | IFF_NO_PI);
    const rc = std.os.linux.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr));
    if (std.posix.errno(rc) != .SUCCESS) return error.TunSetIff;
    return fd;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var s = try shardnet.init(allocator);
    defer s.deinit();

    const fd = try openTap("tap0");
    var tap = shardnet.drivers.tap.Tap.initFromFd(fd);
    var eth = shardnet.link.eth.EthernetEndpoint.init(tap.linkEndpoint(), tap.address);
    try s.createNIC(1, eth.linkEndpoint());

    const nic = s.nics.get(1).?;
    try nic.addAddress(.{ .protocol = shardnet.network.ipv4.ProtocolNumber, .address_with_prefix = .{ .address = .{ .v4 = .{ 10, 9, 0, 2 } }, .prefix_len = 24 } });
    try nic.addAddress(.{ .protocol = shardnet.network.arp.ProtocolNumber, .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 } });
    try nic.addAddress(.{ .protocol = shardnet.network.icmp.ProtocolNumber, .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 } });
    try s.addRoute(.{ .destination = .{ .address = .{ .v4 = .{ 10, 9, 0, 0 } }, .prefix = 24 }, .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, .nic = 1, .mtu = 1500 });

    const listener = try shardnet.socket.Socket.tcp(&s);
    defer listener.close();
    try listener.bind(.{ .nic = 1, .addr = .{ .v4 = .{ 10, 9, 0, 2 } }, .port = 8080 });
    try listener.listen(8);

    std.debug.print("interop: tap0 attached, shardnet = 10.9.0.2/24; HTTP on :8080\n", .{});

    var conns = [_]?*shardnet.socket.Socket{null} ** 16;

    var fds = [_]std.posix.pollfd{.{ .fd = tap.fd, .events = std.posix.POLL.IN, .revents = 0 }};
    while (true) {
        _ = std.posix.poll(&fds, 10) catch continue;
        if (fds[0].revents & std.posix.POLL.IN != 0) {
            while (tap.readPacket() catch false) {}
        }
        _ = s.timer_queue.tick();

        while (listener.readable()) {
            const conn = listener.accept() catch break;
            for (&conns) |*slot| {
                if (slot.* == null) {
                    slot.* = conn;
                    break;
                }
            } else conn.close();
        }

        for (&conns) |*slot| {
            const c = slot.* orelse continue;
            if (c.readable()) {
                var rbuf: [2048]u8 = undefined;
                _ = c.recv(&rbuf) catch {};
                _ = c.send(HTTP_RESPONSE) catch {};
                c.close();
                slot.* = null;
            }
        }
    }
}
