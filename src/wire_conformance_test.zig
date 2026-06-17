// Wire-format conformance: assert shardnet's serialized header bytes match an
// independent oracle (scapy) byte-for-byte, checksum included. Loopback is
// symmetric, so an encoding/endianness/checksum/offset bug cancels out there and
// passes; comparing against externally-produced bytes is what catches it.
//
// The golden_* arrays are the bytes scapy (an independent implementation)
// produces for the same logical packet; baking them in keeps this test free of
// any runtime dependency on the oracle.
const std = @import("std");
const shardnet = @import("shardnet");
const header = shardnet.header;

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

test "wire: TCP bare ACK header + pseudo-header checksum" {
    var buf = [_]u8{0} ** header.TCPMinimumSize;
    const tcp = header.TCP.init(&buf);
    tcp.encode(1234, 80, 1000, 2000, header.TCPFlagAck, 65535);
    tcp.setChecksum(tcp.calculateChecksum(src4, dst4, &[_]u8{}));
    try std.testing.expectEqualSlices(u8, &golden_tcp_ack, &buf);
}

test "wire: UDP header + pseudo-header checksum" {
    const payload = "hello";
    var buf = [_]u8{0} ** header.UDPMinimumSize;
    const udp = header.UDP.init(&buf);
    udp.setSourcePort(1234);
    udp.setDestinationPort(5678);
    udp.setLength(@as(u16, header.UDPMinimumSize + payload.len));
    udp.setChecksum(udp.calculateChecksum(src4, dst4, payload));
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
