// Wire-format conformance: shardnet's emitted bytes must equal an independent
// oracle's (scapy), byte-for-byte including checksums. Loopback is symmetric, so
// an encoding/checksum/endianness bug cancels out and passes there; only an
// external comparison catches it. golden_* are scapy's bytes, baked in.
const std = @import("std");
const shardnet = @import("shardnet");
const header = shardnet.header;
const tcpip = shardnet.tcpip;
const buffer = shardnet.buffer;
const stack = shardnet.stack;
const waiter = shardnet.waiter;
const ipv4 = shardnet.network.ipv4;
const udp = shardnet.transport.udp;
const tcp = shardnet.transport.tcp;
const dhcp = shardnet.dhcp;

const src4 = [4]u8{ 10, 0, 0, 1 };
const dst4 = [4]u8{ 10, 0, 0, 2 };
const src6 = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const dst6 = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

const golden_tcp_ack = [_]u8{ 0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x50, 0x10, 0xff, 0xff, 0x8a, 0xf8, 0x00, 0x00 };
const golden_udp_hdr = [_]u8{ 0x04, 0xd2, 0x16, 0x2e, 0x00, 0x0d, 0x8c, 0xff };
const golden_icmp4_echo_reply = [_]u8{ 0x00, 0x00, 0x5c, 0x35, 0x12, 0x34, 0x00, 0x01, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
const golden_arp_request = [_]u8{ 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02 };
const golden_ipv6_hdr = [_]u8{ 0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
const golden_icmp6_echo_request = [_]u8{ 0x80, 0x00, 0xde, 0xe5, 0x12, 0x34, 0x00, 0x01, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };

// Stack-capture goldens (full L3 frames).
const golden_udp_dgram = [_]u8{ 0x45, 0x00, 0x00, 0x21, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x26, 0xca, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x04, 0xd2, 0x16, 0x2e, 0x00, 0x0d, 0x8c, 0xff, 0x68, 0x65, 0x6c, 0x6c, 0x6f };
const golden_syn_ip = [_]u8{ 0x45, 0x00, 0x00, 0x34, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x26, 0xc2, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02 };
const golden_syn_tcp = [_]u8{ 0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0x10, 0x00, 0x4a, 0xe9, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x0e, 0x00, 0x00, 0x00, 0x00 };

// DHCP BOOTP payloads (the UDP payload). The test zeroes the random xid and the
// elapsed-time secs field before comparing.
const golden_dhcp_discover = [_]u8{ 0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x01, 0x3d, 0x07, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x37, 0x06, 0x01, 0x03, 0x06, 0x33, 0x3a, 0x3b, 0xff };
const golden_dhcp_request = [_]u8{ 0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x03, 0x3d, 0x07, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x32, 0x04, 0xc0, 0xa8, 0x01, 0x32, 0x36, 0x04, 0xc0, 0xa8, 0x01, 0x01, 0x37, 0x06, 0x01, 0x03, 0x06, 0x33, 0x3a, 0x3b, 0xff };

test "wire: TCP bare ACK header + pseudo-header checksum" {
    var buf = [_]u8{0} ** header.TCPMinimumSize;
    const tcp_hdr = header.TCP.init(&buf);
    tcp_hdr.encode(1234, 80, 1000, 2000, header.TCPFlagAck, 65535);
    tcp_hdr.setChecksum(tcp_hdr.calculateChecksum(src4, dst4, &[_]u8{}));
    try std.testing.expectEqualSlices(u8, &golden_tcp_ack, &buf);
}

test "wire: UDP header + pseudo-header checksum" {
    const payload = "hello";
    var buf = [_]u8{0} ** header.UDPMinimumSize;
    const udp_hdr = header.UDP.init(&buf);
    udp_hdr.setSourcePort(1234);
    udp_hdr.setDestinationPort(5678);
    udp_hdr.setLength(@as(u16, header.UDPMinimumSize + payload.len));
    udp_hdr.setChecksum(udp_hdr.calculateChecksum(src4, dst4, payload));
    try std.testing.expectEqualSlices(u8, &golden_udp_hdr, &buf);
}

test "wire: ICMPv4 echo reply + checksum" {
    const payload = "abcdefgh";
    var buf = [_]u8{0} ** (header.ICMPv4MinimumSize + 8);
    buf[0] = header.ICMPv4EchoReplyType;
    buf[1] = 0;
    std.mem.writeInt(u16, buf[4..6], 0x1234, .big);
    std.mem.writeInt(u16, buf[6..8], 1, .big);
    @memcpy(buf[8..16], payload);
    const icmp = header.ICMPv4.init(&buf);
    icmp.setChecksum(icmp.calculateChecksum(payload));
    try std.testing.expectEqualSlices(u8, &golden_icmp4_echo_reply, &buf);
}

test "wire: ARP request (IPv4 over Ethernet)" {
    var buf = [_]u8{0} ** header.ARPSize;
    const arp = header.ARP.init(&buf);
    arp.setIPv4OverEthernet();
    arp.setOp(1);
    @memcpy(buf[8..14], &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff });
    @memcpy(buf[14..18], &src4);
    @memcpy(buf[24..28], &dst4);
    try std.testing.expectEqualSlices(u8, &golden_arp_request, &buf);
}

test "wire: IPv6 fixed header" {
    var buf = [_]u8{0} ** header.IPv6MinimumSize;
    const ip6 = header.IPv6.init(&buf);
    ip6.encode(src6, dst6, 6, 20);
    try std.testing.expectEqualSlices(u8, &golden_ipv6_hdr, &buf);
}

test "wire: ICMPv6 echo request + pseudo-header checksum" {
    const data = "abcdefgh";
    var buf = [_]u8{0} ** (header.ICMPv6MinimumSize + 4 + 8);
    buf[0] = header.ICMPv6EchoRequestType;
    buf[1] = 0;
    std.mem.writeInt(u16, buf[4..6], 0x1234, .big);
    std.mem.writeInt(u16, buf[6..8], 1, .big);
    @memcpy(buf[8..16], data);
    const icmp6 = header.ICMPv6.init(&buf);
    icmp6.setChecksum(icmp6.calculateChecksum(src6, dst6, buf[4..]));
    try std.testing.expectEqualSlices(u8, &golden_icmp6_echo_request, &buf);
}

// Captures the linearized L3 frame the stack would transmit, instead of sending it.
const Capture = struct {
    last_pkt: ?[]u8 = null,
    allocator: std.mem.Allocator,

    fn writePacket(ptr: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self: *Capture = @ptrCast(@alignCast(ptr));
        const hdr = pkt.header.view();
        if (self.last_pkt) |p| self.allocator.free(p);
        self.last_pkt = self.allocator.alloc(u8, hdr.len + pkt.data.size) catch return tcpip.Error.NoBufferSpace;
        @memcpy(self.last_pkt.?[0..hdr.len], hdr);
        var off = hdr.len;
        for (pkt.data.views) |cv| {
            @memcpy(self.last_pkt.?[off .. off + cv.view.len], cv.view);
            off += cv.view.len;
        }
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
    fn linkEndpoint(self: *Capture) stack.LinkEndpoint {
        return .{ .ptr = self, .vtable = &.{
            .writePacket = writePacket,
            .writePackets = null,
            .attach = attach,
            .linkAddress = linkAddress,
            .mtu = mtu,
            .setMTU = setMTU,
            .capabilities = capabilities,
        } };
    }
    fn deinit(self: *Capture) void {
        if (self.last_pkt) |p| self.allocator.free(p);
    }
};

// Independent (naive, scalar) one's-complement checksum, deliberately not
// shardnet's SIMD routine, to verify a captured TCP segment's checksum field.
fn onesSum(data: []const u8, initial: u32) u32 {
    var sum = initial;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) sum += (@as(u32, data[i]) << 8) | data[i + 1];
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    return sum;
}
fn foldSum(sum: u32) u16 {
    var s = sum;
    while (s > 0xffff) s = (s & 0xffff) + (s >> 16);
    return ~@as(u16, @intCast(s));
}
fn tcpChecksum(src: [4]u8, dst: [4]u8, seg: []const u8) u16 {
    var sum: u32 = 0;
    sum += (@as(u32, src[0]) << 8) | src[1];
    sum += (@as(u32, src[2]) << 8) | src[3];
    sum += (@as(u32, dst[0]) << 8) | dst[1];
    sum += (@as(u32, dst[2]) << 8) | dst[3];
    sum += 6; // TCP
    sum += @as(u32, @intCast(seg.len));
    return foldSum(onesSum(seg, sum));
}

test "wire: UDP datagram over IPv4 (stack assembly)" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const udp_proto = udp.UDPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(udp_proto.protocol());

    var cap = Capture{ .allocator = allocator };
    defer cap.deinit();
    try s.createNIC(1, cap.linkEndpoint());
    const nic = s.nics.get(1).?;

    const local = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = src4 }, .port = 1234 };
    const remote = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = dst4 }, .port = 5678 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = local.addr, .prefix_len = 24 } });
    try s.addLinkAddress(remote.addr, .{ .addr = [_]u8{0} ** 6 });

    var wq = waiter.Queue{};
    const ep = try udp_proto.protocol().newEndpoint(&s, 0x0800, &wq);
    defer ep.close();
    try ep.bind(local);
    const uep: *udp.UDPEndpoint = @ptrCast(@alignCast(ep.ptr));

    var payload = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    var views = [_]buffer.ClusterView{.{ .cluster = null, .view = &payload }};
    const data = buffer.VectorisedView.init(payload.len, &views);
    var route = stack.Route{
        .local_address = local.addr,
        .remote_address = remote.addr,
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .remote_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };
    try uep.write(&route, remote.port, data);

    try std.testing.expect(cap.last_pkt != null);
    try std.testing.expectEqualSlices(u8, &golden_udp_dgram, cap.last_pkt.?);
}

test "wire: TCP SYN over IPv4 (stack assembly, options + checksum)" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = tcp.TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var cap = Capture{ .allocator = allocator };
    defer cap.deinit();
    try s.createNIC(1, cap.linkEndpoint());
    const nic = s.nics.get(1).?;

    const local = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = src4 }, .port = 1234 };
    const remote = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = dst4 }, .port = 80 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = local.addr, .prefix_len = 24 } });
    try s.addLinkAddress(remote.addr, .{ .addr = [_]u8{0} ** 6 });

    var wq = waiter.Queue{};
    const ep = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq);
    const tep: *tcp.TCPEndpoint = @ptrCast(@alignCast(ep.ptr));
    defer tep.close();
    try ep.bind(local);
    try ep.connect(remote);

    try std.testing.expect(cap.last_pkt != null);
    const frame = cap.last_pkt.?;
    try std.testing.expectEqual(@as(usize, 52), frame.len);
    try std.testing.expectEqualSlices(u8, &golden_syn_ip, frame[0..20]);

    // The ISN is time-based: graft the observed seq into the template and
    // recompute the checksum independently, then compare the whole TCP header.
    var expected = golden_syn_tcp;
    @memcpy(expected[4..8], frame[24..28]);
    std.mem.writeInt(u16, expected[16..18], 0, .big);
    std.mem.writeInt(u16, expected[16..18], tcpChecksum(src4, dst4, &expected), .big);
    try std.testing.expectEqualSlices(u8, &expected, frame[20..52]);
}

fn putOpt(buf: []u8, i: *usize, code: u8, data: []const u8) void {
    buf[i.*] = code;
    buf[i.* + 1] = @intCast(data.len);
    @memcpy(buf[i.* + 2 ..][0..data.len], data);
    i.* += 2 + data.len;
}

// Builds a DHCP OFFER the client accepts, so it answers with a select REQUEST.
fn buildOffer(buf: []u8, xid: u32) usize {
    @memset(buf[0..240], 0);
    buf[0] = 2; // BOOTREPLY
    buf[1] = 1;
    buf[2] = 6;
    std.mem.writeInt(u32, buf[4..8], xid, .big);
    @memcpy(buf[16..20], &[_]u8{ 192, 168, 1, 50 }); // yiaddr
    @memcpy(buf[236..240], &[_]u8{ 0x63, 0x82, 0x53, 0x63 });
    var i: usize = 240;
    putOpt(buf, &i, 53, &[_]u8{2}); // message type: offer
    putOpt(buf, &i, 54, &[_]u8{ 192, 168, 1, 1 }); // server id
    putOpt(buf, &i, 1, &[_]u8{ 255, 255, 255, 0 }); // subnet mask
    var lease: [4]u8 = undefined;
    std.mem.writeInt(u32, &lease, 3600, .big);
    putOpt(buf, &i, 51, &lease); // lease time
    buf[i] = 0xff;
    return i + 1;
}

fn injectOffer(nic: *stack.NIC, payload: []const u8) void {
    var frame: [600]u8 = undefined;
    @memset(frame[0..20], 0);
    frame[0] = 0x45;
    std.mem.writeInt(u16, frame[2..4], @intCast(20 + 8 + payload.len), .big);
    frame[8] = 64; // ttl
    frame[9] = 17; // UDP
    @memcpy(frame[12..16], &[_]u8{ 192, 168, 1, 1 }); // src = server
    @memcpy(frame[16..20], &[_]u8{ 255, 255, 255, 255 }); // dst = broadcast
    const iph = header.IPv4.init(frame[0..20]);
    iph.setChecksum(iph.calculateChecksum());
    std.mem.writeInt(u16, frame[20..22], 67, .big); // src port (server)
    std.mem.writeInt(u16, frame[22..24], 68, .big); // dst port (client)
    std.mem.writeInt(u16, frame[24..26], @intCast(8 + payload.len), .big);
    std.mem.writeInt(u16, frame[26..28], 0, .big); // UDP checksum (optional in IPv4)
    @memcpy(frame[28..][0..payload.len], payload);
    const flen = 28 + payload.len;
    var views = [_]buffer.ClusterView{.{ .cluster = null, .view = frame[0..flen] }};
    const pkt = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(flen, &views), .header = buffer.Prependable.init(&[_]u8{}) };
    const remote = tcpip.LinkAddress{ .addr = .{ 0x02, 0, 0, 0, 0, 0x01 } };
    const local = nic.linkEP.linkAddress();
    nic.dispatcher.deliverNetworkPacket(&remote, &local, ipv4.ProtocolNumber, pkt);
}

test "wire: DHCPv4 DISCOVER (BOOTP + magic cookie + options)" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const udp_proto = udp.UDPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(udp_proto.protocol());

    var cap = Capture{ .allocator = allocator };
    defer cap.deinit();
    try s.createNIC(1, cap.linkEndpoint());

    const client = try dhcp.Client.create(&s, 1, .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 });
    defer client.destroy();
    try client.start();

    try std.testing.expect(cap.last_pkt != null);
    const frame = cap.last_pkt.?;
    try std.testing.expectEqual(@as(usize, 28 + golden_dhcp_discover.len), frame.len);
    @memset(frame[32..36], 0); // xid (random)
    @memset(frame[36..38], 0); // secs (elapsed)
    try std.testing.expectEqualSlices(u8, &golden_dhcp_discover, frame[28..]);
}

test "wire: DHCPv4 REQUEST (options 50/54 echoed from OFFER)" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const udp_proto = udp.UDPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(udp_proto.protocol());

    var cap = Capture{ .allocator = allocator };
    defer cap.deinit();
    try s.createNIC(1, cap.linkEndpoint());
    const nic = s.nics.get(1).?;

    const client = try dhcp.Client.create(&s, 1, .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 });
    defer client.destroy();
    try client.start(); // emits DISCOVER

    var offer: [300]u8 = undefined;
    const offer_len = buildOffer(&offer, client.xid);
    injectOffer(nic, offer[0..offer_len]); // client answers synchronously with REQUEST

    try std.testing.expectEqual(dhcp.State.requesting, client.state);
    try std.testing.expect(cap.last_pkt != null);
    const frame = cap.last_pkt.?;
    try std.testing.expectEqual(@as(usize, 28 + golden_dhcp_request.len), frame.len);
    @memset(frame[32..36], 0); // xid (random)
    @memset(frame[36..38], 0); // secs (elapsed)
    try std.testing.expectEqualSlices(u8, &golden_dhcp_request, frame[28..]);
}

// Regression: an ICMP echo reply must transmit through the real assembly path
// (IP header prepended onto the reply). The reply used to be built in a
// zero-headroom Prependable and failed with NoBufferSpace, so no frame was sent.
test "wire: ICMPv4 echo reply transmits through the assembly path" {
    const allocator = std.testing.allocator;
    var s = try shardnet.init(allocator); // full protocol set, incl. ICMP transport
    defer s.deinit();

    var cap = Capture{ .allocator = allocator };
    defer cap.deinit();
    try s.createNIC(1, cap.linkEndpoint());
    const nic = s.nics.get(1).?;
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = .{ 10, 9, 0, 2 } }, .prefix_len = 24 } });
    try nic.addAddress(.{ .protocol = shardnet.network.arp.ProtocolNumber, .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 } });
    try nic.addAddress(.{ .protocol = shardnet.network.icmp.ProtocolNumber, .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 } });
    try s.addLinkAddress(.{ .v4 = .{ 10, 9, 0, 1 } }, .{ .addr = [_]u8{0} ** 6 });

    // IPv4 (proto 1) + ICMP echo request from 10.9.0.1, with valid checksums.
    var frame: [32]u8 = undefined;
    @memset(&frame, 0);
    frame[0] = 0x45;
    std.mem.writeInt(u16, frame[2..4], 32, .big);
    frame[8] = 64; // ttl
    frame[9] = 1; // ICMP
    @memcpy(frame[12..16], &[_]u8{ 10, 9, 0, 1 });
    @memcpy(frame[16..20], &[_]u8{ 10, 9, 0, 2 });
    const iph = header.IPv4.init(frame[0..20]);
    iph.setChecksum(iph.calculateChecksum());
    frame[20] = header.ICMPv4EchoType;
    std.mem.writeInt(u16, frame[24..26], 0x1234, .big);
    std.mem.writeInt(u16, frame[26..28], 1, .big);
    const icmph = header.ICMPv4.init(frame[20..32]);
    icmph.setChecksum(icmph.calculateChecksum(frame[28..32]));

    var views = [_]buffer.ClusterView{.{ .cluster = null, .view = &frame }};
    const pkt = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(frame.len, &views), .header = buffer.Prependable.init(&[_]u8{}) };
    const remote = tcpip.LinkAddress{ .addr = .{ 0x02, 0, 0, 0, 0, 0x01 } };
    const local = nic.linkEP.linkAddress();
    nic.dispatcher.deliverNetworkPacket(&remote, &local, ipv4.ProtocolNumber, pkt);

    try std.testing.expect(cap.last_pkt != null);
    const reply = cap.last_pkt.?;
    try std.testing.expectEqual(@as(usize, 32), reply.len); // IPv4(20) + ICMP(8+4)
    try std.testing.expectEqual(@as(u8, 1), reply[9]); // IP proto ICMP
    try std.testing.expectEqual(header.ICMPv4EchoReplyType, reply[20]); // type 0
}


