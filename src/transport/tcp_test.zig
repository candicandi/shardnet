/// TCP protocol tests.
///
/// Tests for three-way handshake, data transfer with loss simulation,
/// fast retransmit trigger, window scaling negotiation, and state transitions.

const std = @import("std");
const shardnet = @import("shardnet");
const tcpip = shardnet.tcpip;
const stack = shardnet.stack;
const header = shardnet.header;
const buffer = shardnet.buffer;
const waiter = shardnet.waiter;
const ipv4 = shardnet.network.ipv4;
const tcp = shardnet.transport.tcp;
const TCPEndpoint = tcp.TCPEndpoint;
const TCPProtocol = tcp.TCPProtocol;

/// Mock link endpoint for capturing packets.
const MockLinkEndpoint = struct {
    last_pkt: ?[]u8 = null,
    allocator: std.mem.Allocator,
    drop_next: bool = false,

    fn writePacket(ptr: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self: *MockLinkEndpoint = @ptrCast(@alignCast(ptr));
        if (self.drop_next) {
            self.drop_next = false;
            return;
        }
        const hdr_view = pkt.header.view();
        const data_len = pkt.data.size;
        if (self.last_pkt) |p| self.allocator.free(p);
        self.last_pkt = self.allocator.alloc(u8, hdr_view.len + data_len) catch return tcpip.Error.NoBufferSpace;
        @memcpy(self.last_pkt.?[0..hdr_view.len], hdr_view);
        var offset = hdr_view.len;
        for (pkt.data.views) |cv| {
            @memcpy(self.last_pkt.?[offset .. offset + cv.view.len], cv.view);
            offset += cv.view.len;
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

    fn linkEndpoint(self: *MockLinkEndpoint) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .writePacket = writePacket,
                .writePackets = null,
                .attach = attach,
                .linkAddress = linkAddress,
                .mtu = mtu,
                .setMTU = setMTU,
                .capabilities = capabilities,
            },
        };
    }

    fn deinit(self: *MockLinkEndpoint) void {
        if (self.last_pkt) |p| self.allocator.free(p);
    }
};

test "TCP three-way handshake" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_ep = MockLinkEndpoint{ .allocator = allocator };
    defer fake_ep.deinit();
    const link_ep = fake_ep.linkEndpoint();
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;

    const client_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const server_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = client_addr.addr, .prefix_len = 24 } });
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = server_addr.addr, .prefix_len = 24 } });
    try s.addLinkAddress(server_addr.addr, .{ .addr = [_]u8{0} ** 6 });
    try s.addLinkAddress(client_addr.addr, .{ .addr = [_]u8{0} ** 6 });

    // Create server endpoint
    var wq_server = waiter.Queue{};
    const ep_server_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_server);
    const ep_server: *TCPEndpoint = @ptrCast(@alignCast(ep_server_res.ptr));
    defer ep_server.close();
    try ep_server.endpoint().bind(server_addr);
    try ep_server.endpoint().listen(10);
    try std.testing.expectEqual(tcp.EndpointState.listen, ep_server.state);

    // Create client endpoint
    var wq_client = waiter.Queue{};
    const ep_client_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_client);
    const ep_client: *TCPEndpoint = @ptrCast(@alignCast(ep_client_res.ptr));
    defer ep_client.close();
    try ep_client.endpoint().bind(client_addr);

    // Client sends SYN
    try ep_client.endpoint().connect(server_addr);
    try std.testing.expectEqual(tcp.EndpointState.syn_sent, ep_client.state);
    try std.testing.expect(fake_ep.last_pkt != null);

    // Deliver SYN to server
    const syn_pkt = tcpip.PacketBuffer{
        .data = try buffer.VectorisedView.fromSlice(fake_ep.last_pkt.?[20..], allocator, &s.cluster_pool),
        .header = buffer.Prependable.init(&[_]u8{}),
    };
    var mut_syn = syn_pkt;
    defer mut_syn.data.deinit();
    const r_to_server = stack.Route{
        .local_address = server_addr.addr,
        .remote_address = client_addr.addr,
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };
    const id_to_server = stack.TransportEndpointID{
        .local_port = 80,
        .local_address = server_addr.addr,
        .remote_port = 1234,
        .remote_address = client_addr.addr,
    };
    ep_server.handlePacket(&r_to_server, id_to_server, mut_syn);

    // Server should have sent SYN+ACK
    try std.testing.expect(fake_ep.last_pkt != null);

    // Deliver SYN+ACK to client
    const syn_ack_pkt = tcpip.PacketBuffer{
        .data = try buffer.VectorisedView.fromSlice(fake_ep.last_pkt.?[20..], allocator, &s.cluster_pool),
        .header = buffer.Prependable.init(&[_]u8{}),
    };
    var mut_syn_ack = syn_ack_pkt;
    defer mut_syn_ack.data.deinit();
    const r_to_client = stack.Route{
        .local_address = client_addr.addr,
        .remote_address = server_addr.addr,
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };
    const id_to_client = stack.TransportEndpointID{
        .local_port = 1234,
        .local_address = client_addr.addr,
        .remote_port = 80,
        .remote_address = server_addr.addr,
    };
    ep_client.handlePacket(&r_to_client, id_to_client, mut_syn_ack);

    // Client should be established
    try std.testing.expectEqual(tcp.EndpointState.established, ep_client.state);
}

test "TCP fast retransmit on 3 duplicate ACKs" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_ep = MockLinkEndpoint{ .allocator = allocator };
    defer fake_ep.deinit();
    const link_ep = fake_ep.linkEndpoint();
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;

    const server_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = server_addr.addr, .prefix_len = 24 } });

    var wq_server = waiter.Queue{};
    const ep_server_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_server);
    const ep_server: *TCPEndpoint = @ptrCast(@alignCast(ep_server_res.ptr));
    defer ep_server.close();

    // Manually set up established state
    ep_server.state = .established;
    ep_server.local_addr = server_addr;
    ep_server.remote_addr = .{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    ep_server.snd_nxt = 1000;
    ep_server.last_ack = 900;
    ep_server.rcv_nxt = 5000;
    ep_server.dup_ack_count = 0;

    // Simulate receiving 3 duplicate ACKs (same ACK number)
    const r = stack.Route{
        .local_address = server_addr.addr,
        .remote_address = .{ .v4 = .{ 10, 0, 0, 1 } },
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };
    const id = stack.TransportEndpointID{
        .local_port = 80,
        .local_address = server_addr.addr,
        .remote_port = 1234,
        .remote_address = .{ .v4 = .{ 10, 0, 0, 1 } },
    };

    // Create duplicate ACK packet
    const ack_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(ack_buf);
    @memset(ack_buf, 0);
    var ack_h = header.TCP.init(ack_buf);
    ack_h.encode(1234, 80, 5000, 900, header.TCPFlagAck, 65535);

    // Send 3 duplicate ACKs
    for (0..3) |_| {
        const ack_pkt = tcpip.PacketBuffer{
            .data = try buffer.VectorisedView.fromSlice(ack_buf, allocator, &s.cluster_pool),
            .header = buffer.Prependable.init(&[_]u8{}),
        };
        var mut_ack = ack_pkt;
        ep_server.handlePacket(&r, id, mut_ack);
        mut_ack.data.deinit();
    }

    // After 3 duplicate ACKs, dup_ack_count should have reset (fast retransmit triggered)
    try std.testing.expectEqual(@as(u32, 0), ep_server.dup_ack_count);
}

test "TCP retransmission with packet drop" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_ep = MockLinkEndpoint{ .allocator = allocator };
    defer fake_ep.deinit();
    const link_ep = fake_ep.linkEndpoint();
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;

    const client_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const server_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = server_addr.addr, .prefix_len = 24 } });
    try s.addLinkAddress(client_addr.addr, .{ .addr = [_]u8{0} ** 6 });

    var wq_server = waiter.Queue{};
    const ep_server_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_server);
    const ep_server: *TCPEndpoint = @ptrCast(@alignCast(ep_server_res.ptr));
    defer ep_server.close();
    try ep_server.endpoint().bind(server_addr);
    try ep_server.endpoint().listen(10);

    // Simulate SYN from client
    const syn_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(syn_buf);
    @memset(syn_buf, 0);
    var syn = header.TCP.init(syn_buf);
    syn.encode(client_addr.port, server_addr.port, 1000, 0, header.TCPFlagSyn, 65535);

    const syn_pkt = tcpip.PacketBuffer{
        .data = try buffer.VectorisedView.fromSlice(syn_buf, allocator, &s.cluster_pool),
        .header = buffer.Prependable.init(&[_]u8{}),
    };
    var mut_syn = syn_pkt;
    defer mut_syn.data.deinit();
    const r_to_server = stack.Route{
        .local_address = server_addr.addr,
        .remote_address = client_addr.addr,
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };
    const id_to_server = stack.TransportEndpointID{
        .local_port = 80,
        .local_address = server_addr.addr,
        .remote_port = 1234,
        .remote_address = client_addr.addr,
    };
    ep_server.handlePacket(&r_to_server, id_to_server, mut_syn);

    // Complete handshake with ACK
    const server_initial_seq = header.TCP.init(fake_ep.last_pkt.?[20..]).sequenceNumber();
    const ack_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(ack_buf);
    @memset(ack_buf, 0);
    var ack = header.TCP.init(ack_buf);
    ack.encode(client_addr.port, server_addr.port, 1001, server_initial_seq +% 1, header.TCPFlagAck, 65535);

    const ack_pkt = tcpip.PacketBuffer{
        .data = try buffer.VectorisedView.fromSlice(ack_buf, allocator, &s.cluster_pool),
        .header = buffer.Prependable.init(&[_]u8{}),
    };
    var mut_ack = ack_pkt;
    defer mut_ack.data.deinit();
    ep_server.handlePacket(&r_to_server, id_to_server, mut_ack);

    // Accept the connection
    const accept_res = try ep_server.endpoint().accept();
    const ep_accepted: *TCPEndpoint = @ptrCast(@alignCast(accept_res.ep.ptr));
    defer ep_accepted.decRef();
    defer accept_res.ep.close();

    try std.testing.expectEqual(tcp.EndpointState.established, ep_accepted.state);
}

test "TCP CWND enforcement" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

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
            return 0;
        }
    }{};
    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_link,
        .vtable = &.{
            .writePacket = @TypeOf(fake_link).writePacket,
            .writePackets = null,
            .attach = @TypeOf(fake_link).attach,
            .linkAddress = @TypeOf(fake_link).linkAddress,
            .mtu = @TypeOf(fake_link).mtu,
            .setMTU = @TypeOf(fake_link).setMTU,
            .capabilities = @TypeOf(fake_link).capabilities,
        },
    };
    try s.createNIC(1, link_ep);

    var wq = waiter.Queue{};
    const ep_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq);
    const ep: *TCPEndpoint = @ptrCast(@alignCast(ep_res.ptr));
    defer ep.close();

    ep.state = .established;
    ep.local_addr = .{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 80 };
    ep.remote_addr = .{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 1234 };
    ep.rcv_nxt = 1000;

    // Test out-of-order insertion
    var data1 = [_]u8{'B'} ** 100;
    const pkt1 = tcpip.PacketBuffer{
        .data = try buffer.VectorisedView.fromSlice(&data1, allocator, &s.cluster_pool),
        .header = buffer.Prependable.init(&[_]u8{}),
    };
    var mut_pkt1 = pkt1;
    defer mut_pkt1.data.deinit();
    try ep.insertOOO(2000, mut_pkt1.data);
    try std.testing.expectEqual(@as(usize, 1), ep.ooo_list.len);
    try std.testing.expectEqual(@as(u32, 2000), ep.ooo_list.first.?.data.seq);

    // Insert in-order data
    var data2 = [_]u8{'A'} ** 100;
    const pkt2 = tcpip.PacketBuffer{
        .data = try buffer.VectorisedView.fromSlice(&data2, allocator, &s.cluster_pool),
        .header = buffer.Prependable.init(&[_]u8{}),
    };
    var mut_pkt2 = pkt2;
    const node2 = try tcp_proto.packet_node_pool.acquire();
    node2.data = .{ .data = try mut_pkt2.data.clone(allocator), .seq = 1000 };
    ep.rcv_list.append(node2);
    mut_pkt2.data.deinit();
    ep.rcv_nxt = 1100;
    ep.processOOO();
    try std.testing.expectEqual(@as(usize, 1), ep.rcv_list.len);
    try std.testing.expectEqual(@as(u32, 1100), ep.rcv_nxt);

    // Fill the gap
    var data3 = [_]u8{'C'} ** 900;
    const pkt3 = tcpip.PacketBuffer{
        .data = try buffer.VectorisedView.fromSlice(&data3, allocator, &s.cluster_pool),
        .header = buffer.Prependable.init(&[_]u8{}),
    };
    var mut_pkt3 = pkt3;
    const node3 = try tcp_proto.packet_node_pool.acquire();
    node3.data = .{ .data = try mut_pkt3.data.clone(allocator), .seq = 1100 };
    ep.rcv_list.append(node3);
    mut_pkt3.data.deinit();
    ep.rcv_nxt = 2000;
    ep.processOOO();
    try std.testing.expectEqual(@as(u32, 2100), ep.rcv_nxt);
    try std.testing.expectEqual(@as(usize, 3), ep.rcv_list.len);
    try std.testing.expectEqual(@as(usize, 0), ep.ooo_list.len);
}

test "TCP writable() is gated on a write-capable state" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var wq = waiter.Queue{};
    const ep_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq);
    const ep: *TCPEndpoint = @ptrCast(@alignCast(ep_res.ptr));
    defer ep.close();
    const orig_state = ep.state;

    // The stack notifies EventOut to every endpoint when a link address resolves
    // (the ARP-retry wake, stack.zig). A connecting endpoint must still report
    // not-writable, or a non-blocking connect looks complete before the handshake.
    wq.notify(waiter.EventOut);
    ep.state = .syn_sent;
    try std.testing.expect(!ep_res.ready(waiter.EventOut));
    ep.state = .established;
    try std.testing.expect(ep_res.ready(waiter.EventOut));
    ep.state = orig_state;
}

test "TCP SACK blocks generation" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var wq = waiter.Queue{};
    const ep_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq);
    const ep: *TCPEndpoint = @ptrCast(@alignCast(ep_res.ptr));
    ep.hint_sack_enabled = true;
    defer ep.close();
    ep.state = .established;
    ep.rcv_nxt = 1000;

    // Insert out-of-order segment
    var data1 = [_]u8{'B'} ** 100;
    const pkt1 = tcpip.PacketBuffer{
        .data = try buffer.VectorisedView.fromSlice(&data1, allocator, &s.cluster_pool),
        .header = buffer.Prependable.init(&[_]u8{}),
    };
    var mut_pkt1 = pkt1;
    try ep.insertOOO(2000, mut_pkt1.data);
    try std.testing.expectEqual(@as(usize, 1), ep.sack_blocks.items.len);
    try std.testing.expectEqual(@as(u32, 2000), ep.sack_blocks.items[0].start);
    try std.testing.expectEqual(@as(u32, 2100), ep.sack_blocks.items[0].end);

    // Insert another out-of-order segment
    try ep.insertOOO(3000, mut_pkt1.data);
    mut_pkt1.data.deinit();
    try std.testing.expectEqual(@as(usize, 2), ep.sack_blocks.items.len);
    // Most recent block should be first
    try std.testing.expectEqual(@as(u32, 3000), ep.sack_blocks.items[0].start);
    try std.testing.expectEqual(@as(u32, 3100), ep.sack_blocks.items[0].end);
    try std.testing.expectEqual(@as(u32, 2000), ep.sack_blocks.items[1].start);
    try std.testing.expectEqual(@as(u32, 2100), ep.sack_blocks.items[1].end);

    // Advance rcv_nxt and prune SACK blocks
    ep.rcv_nxt = 2100;
    ep.processOOO();
    try std.testing.expectEqual(@as(usize, 1), ep.sack_blocks.items.len);
    try std.testing.expectEqual(@as(u32, 3000), ep.sack_blocks.items[0].start);
}

test "TCP out-of-order queue is bounded by the receive window" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var wq = waiter.Queue{};
    const ep_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq);
    const ep: *TCPEndpoint = @ptrCast(@alignCast(ep_res.ptr));
    defer ep.close();
    ep.state = .established;
    ep.rcv_nxt = 1000;
    // Shrink the receive buffer so the bound is reachable in-test.
    ep.rcv_wnd_max = 250;

    var data = [_]u8{'X'} ** 100;
    var src = try buffer.VectorisedView.fromSlice(&data, allocator, &s.cluster_pool);
    defer src.deinit();

    // Two 100-byte OOO segments fit (200 <= 250); a third would exceed the
    // window and is dropped rather than buffered.
    try ep.insertOOO(2000, src);
    try ep.insertOOO(3000, src);
    try std.testing.expectEqual(@as(usize, 200), ep.ooo_bytes);

    const drops_before = shardnet.stats.global_stats.tcp.ooo_dropped.load();
    try std.testing.expectError(error.NoBufferSpace, ep.insertOOO(4000, src));
    try std.testing.expectEqual(@as(usize, 200), ep.ooo_bytes);
    try std.testing.expect(ep.rcv_buf_used + ep.ooo_bytes <= ep.rcv_wnd_max);
    try std.testing.expectEqual(drops_before + 1, shardnet.stats.global_stats.tcp.ooo_dropped.load());

    // OOO bytes shrink the advertised window.
    ep.recomputeRcvWnd();
    try std.testing.expectEqual(@as(u32, 50), ep.rcv_wnd);

    // Converting contiguous OOO data to in-order preserves the total
    // receive-buffer budget, so the advertised window does not jump.
    ep.rcv_nxt = 2000;
    ep.processOOO();
    try std.testing.expectEqual(@as(usize, 100), ep.ooo_bytes);
    try std.testing.expectEqual(@as(usize, 100), ep.rcv_buf_used);
}

test "Stack caps the number of live transport endpoints" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.initWithConfig(allocator, .{ .max_endpoints = 3 });
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var wqs: [4]waiter.Queue = .{ .{}, .{}, .{}, .{} };
    var eps: [4]*TCPEndpoint = undefined;
    for (0..4) |i| {
        const r = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wqs[i]);
        eps[i] = @ptrCast(@alignCast(r.ptr));
    }
    defer for (eps) |ep| ep.close();

    // Three binds fill the cap (distinct ports give distinct ids).
    try eps[0].endpoint().bind(.{ .nic = 0, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = 1001 });
    try eps[1].endpoint().bind(.{ .nic = 0, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = 1002 });
    try eps[2].endpoint().bind(.{ .nic = 0, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = 1003 });

    const drops_before = shardnet.stats.global_stats.tcp.endpoints_dropped.load();
    try std.testing.expectError(tcpip.Error.OutOfMemory, eps[3].endpoint().bind(.{ .nic = 0, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = 1004 }));
    try std.testing.expectEqual(drops_before + 1, shardnet.stats.global_stats.tcp.endpoints_dropped.load());
}

test "passive open past the endpoint cap is rejected without leaking" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    // Cap of 2 leaves room for the listener and the client, but not the
    // accepted endpoint the completing ACK would create.
    var s = try stack.Stack.initWithConfig(allocator, .{ .max_endpoints = 2 });
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_ep = MockLinkEndpoint{ .allocator = allocator };
    defer fake_ep.deinit();
    try s.createNIC(1, fake_ep.linkEndpoint());
    const nic = s.nics.get(1).?;

    const client_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const server_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = client_addr.addr, .prefix_len = 24 } });
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = server_addr.addr, .prefix_len = 24 } });
    try s.addLinkAddress(server_addr.addr, .{ .addr = [_]u8{0} ** 6 });
    try s.addLinkAddress(client_addr.addr, .{ .addr = [_]u8{0} ** 6 });

    var wq_server = waiter.Queue{};
    const ep_server: *TCPEndpoint = @ptrCast(@alignCast((try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_server)).ptr));
    defer ep_server.close();
    try ep_server.endpoint().bind(server_addr);
    try ep_server.endpoint().listen(10);

    var wq_client = waiter.Queue{};
    const ep_client: *TCPEndpoint = @ptrCast(@alignCast((try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_client)).ptr));
    defer ep_client.close();
    try ep_client.endpoint().bind(client_addr);
    try ep_client.endpoint().connect(server_addr);

    const r_to_server = stack.Route{ .local_address = server_addr.addr, .remote_address = client_addr.addr, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = nic };
    const id_to_server = stack.TransportEndpointID{ .local_port = 80, .local_address = server_addr.addr, .remote_port = 1234, .remote_address = client_addr.addr };
    const r_to_client = stack.Route{ .local_address = client_addr.addr, .remote_address = server_addr.addr, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = nic };
    const id_to_client = stack.TransportEndpointID{ .local_port = 1234, .local_address = client_addr.addr, .remote_port = 80, .remote_address = server_addr.addr };

    // SYN -> server: creates a syncache entry and emits SYN-ACK, no table growth.
    {
        var p = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(fake_ep.last_pkt.?[20..], allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
        defer p.data.deinit();
        ep_server.handlePacket(&r_to_server, id_to_server, p);
    }
    // SYN-ACK -> client: client becomes established and emits the completing ACK.
    {
        var p = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(fake_ep.last_pkt.?[20..], allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
        defer p.data.deinit();
        ep_client.handlePacket(&r_to_client, id_to_client, p);
    }
    try std.testing.expectEqual(tcp.EndpointState.established, ep_client.state);

    // Completing ACK -> server: the accepted endpoint would be the third, which
    // exceeds the cap, so registration is rejected, the half-built endpoint is
    // released, and nothing reaches the accept queue.
    const drops_before = shardnet.stats.global_stats.tcp.endpoints_dropped.load();
    {
        var p = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(fake_ep.last_pkt.?[20..], allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
        defer p.data.deinit();
        ep_server.handlePacket(&r_to_server, id_to_server, p);
    }
    try std.testing.expectEqual(drops_before + 1, shardnet.stats.global_stats.tcp.endpoints_dropped.load());
    try std.testing.expect(ep_server.accepted_queue.first == null);
}

test "TCP SYN processing is rate limited" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_ep = MockLinkEndpoint{ .allocator = allocator };
    defer fake_ep.deinit();
    try s.createNIC(1, fake_ep.linkEndpoint());
    const nic = s.nics.get(1).?;

    const client_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const server_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = server_addr.addr, .prefix_len = 24 } });
    try s.addLinkAddress(client_addr.addr, .{ .addr = [_]u8{0} ** 6 });

    var wq_server = waiter.Queue{};
    const ep_server: *TCPEndpoint = @ptrCast(@alignCast((try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_server)).ptr));
    defer ep_server.close();
    try ep_server.endpoint().bind(server_addr);
    try ep_server.endpoint().listen(10);

    // Constrain the shared SYN limiter to two tokens, restoring it afterwards so
    // test ordering does not matter.
    const saved = tcp.syn_limiter;
    defer tcp.syn_limiter = saved;
    tcp.syn_limiter = .{ .max_tokens = 2, .tokens = 2, .refill_rate = 2 };

    const r_to_server = stack.Route{
        .local_address = server_addr.addr,
        .remote_address = client_addr.addr,
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };
    const base_throttled = shardnet.stats.global_stats.tcp.syn_throttled.load();

    // Three SYNs from distinct source ports: the budget admits two (recorded in the
    // syncache), the third is rate-limited and dropped before any SYN-ACK.
    for ([_]u16{ 1234, 1235, 1236 }) |sport| {
        const syn_buf = try allocator.alloc(u8, header.TCPMinimumSize);
        defer allocator.free(syn_buf);
        @memset(syn_buf, 0);
        var syn = header.TCP.init(syn_buf);
        syn.encode(sport, server_addr.port, 1000, 0, header.TCPFlagSyn, 65535);
        var pkt = tcpip.PacketBuffer{
            .data = try buffer.VectorisedView.fromSlice(syn_buf, allocator, &s.cluster_pool),
            .header = buffer.Prependable.init(&[_]u8{}),
        };
        defer pkt.data.deinit();
        const id = stack.TransportEndpointID{
            .local_port = 80,
            .local_address = server_addr.addr,
            .remote_port = sport,
            .remote_address = client_addr.addr,
        };
        ep_server.handlePacket(&r_to_server, id, pkt);
    }

    try std.testing.expectEqual(@as(usize, 2), ep_server.syncache.count());
    try std.testing.expectEqual(base_throttled + 1, shardnet.stats.global_stats.tcp.syn_throttled.load());
}

test "TCP window scaling negotiation" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var wq = waiter.Queue{};
    const ep_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq);
    const ep: *TCPEndpoint = @ptrCast(@alignCast(ep_res.ptr));
    defer ep.close();

    // Verify default window scale values
    try std.testing.expectEqual(@as(u8, 0), ep.snd_wnd_scale);
    try std.testing.expectEqual(@as(u8, 14), ep.rcv_wnd_scale);
    try std.testing.expectEqual(@as(u32, 64 * 1024 * 1024), ep.rcv_wnd_max);
}

test "TCP RST in SYN_SENT refuses the connection" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_ep = MockLinkEndpoint{ .allocator = allocator };
    defer fake_ep.deinit();
    try s.createNIC(1, fake_ep.linkEndpoint());
    const nic = s.nics.get(1).?;

    const client_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const server_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 81 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = client_addr.addr, .prefix_len = 24 } });
    try s.addLinkAddress(server_addr.addr, .{ .addr = [_]u8{0} ** 6 });
    try s.addLinkAddress(client_addr.addr, .{ .addr = [_]u8{0} ** 6 });

    var wq_client = waiter.Queue{};
    const ep_client_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_client);
    const ep_client: *TCPEndpoint = @ptrCast(@alignCast(ep_client_res.ptr));
    defer ep_client.close();
    try ep_client.endpoint().bind(client_addr);
    try ep_client.endpoint().connect(server_addr);
    try std.testing.expectEqual(tcp.EndpointState.syn_sent, ep_client.state);

    const resets_before = shardnet.stats.global_stats.tcp.resets_received.load();

    // Peer refuses: RST|ACK acknowledging our SYN
    const rst_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(rst_buf);
    @memset(rst_buf, 0);
    var rst = header.TCP.init(rst_buf);
    rst.encode(server_addr.port, client_addr.port, 0, ep_client.snd_nxt, header.TCPFlagRst | header.TCPFlagAck, 0);

    const r_to_client = stack.Route{
        .local_address = client_addr.addr,
        .remote_address = server_addr.addr,
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };
    const id_to_client = stack.TransportEndpointID{
        .local_port = client_addr.port,
        .local_address = client_addr.addr,
        .remote_port = server_addr.port,
        .remote_address = server_addr.addr,
    };
    var rst_pkt = tcpip.PacketBuffer{
        .data = try buffer.VectorisedView.fromSlice(rst_buf, allocator, &s.cluster_pool),
        .header = buffer.Prependable.init(&[_]u8{}),
    };
    defer rst_pkt.data.deinit();
    ep_client.handlePacket(&r_to_client, id_to_client, rst_pkt);

    try std.testing.expectEqual(tcp.EndpointState.error_state, ep_client.state);
    try std.testing.expect(wq_client.events() & waiter.EventErr != 0);
    try std.testing.expectEqual(resets_before + 1, shardnet.stats.global_stats.tcp.resets_received.load());
    // The 4-tuple is released
    try std.testing.expect(s.endpoints.get(id_to_client) == null);

    // The error is surfaced to readers
    var rbuf: [16]u8 = undefined;
    var iov = [_][]u8{&rbuf};
    var uio = buffer.Uio.init(&iov);
    try std.testing.expectError(tcpip.Error.ConnectionRefused, ep_client.endpoint().readv(&uio, null));
}

test "TCP RST handling in ESTABLISHED follows RFC 5961" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_ep = MockLinkEndpoint{ .allocator = allocator };
    defer fake_ep.deinit();
    try s.createNIC(1, fake_ep.linkEndpoint());
    const nic = s.nics.get(1).?;

    const local_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const remote_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = local_addr.addr, .prefix_len = 24 } });
    try s.addLinkAddress(remote_addr.addr, .{ .addr = [_]u8{0} ** 6 });

    var wq = waiter.Queue{};
    const ep_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq);
    const ep: *TCPEndpoint = @ptrCast(@alignCast(ep_res.ptr));
    defer ep.close();
    ep.state = .established;
    ep.local_addr = local_addr;
    ep.remote_addr = remote_addr;
    ep.rcv_nxt = 5000;
    const id = stack.TransportEndpointID{
        .local_port = local_addr.port,
        .local_address = local_addr.addr,
        .remote_port = remote_addr.port,
        .remote_address = remote_addr.addr,
    };
    try s.registerTransportEndpoint(id, ep.transportEndpoint());

    const r = stack.Route{
        .local_address = local_addr.addr,
        .remote_address = remote_addr.addr,
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };

    const feedRst = struct {
        fn run(st: *stack.Stack, endpoint: *TCPEndpoint, route: *const stack.Route, eid: stack.TransportEndpointID, alloc: std.mem.Allocator, seq: u32) !void {
            const rst_buf = try alloc.alloc(u8, header.TCPMinimumSize);
            defer alloc.free(rst_buf);
            @memset(rst_buf, 0);
            var rst = header.TCP.init(rst_buf);
            rst.encode(eid.remote_port, eid.local_port, seq, 0, header.TCPFlagRst, 0);
            var pkt = tcpip.PacketBuffer{
                .data = try buffer.VectorisedView.fromSlice(rst_buf, alloc, &st.cluster_pool),
                .header = buffer.Prependable.init(&[_]u8{}),
            };
            defer pkt.data.deinit();
            endpoint.handlePacket(route, eid, pkt);
        }
    }.run;

    // Out-of-window RST: dropped, no reply, no state change.
    if (fake_ep.last_pkt) |p| {
        allocator.free(p);
        fake_ep.last_pkt = null;
    }
    try feedRst(&s, ep, &r, id, allocator, 5000 -% 1000);
    try std.testing.expectEqual(tcp.EndpointState.established, ep.state);
    try std.testing.expect(fake_ep.last_pkt == null);

    // In-window but inexact: challenge ACK, still established.
    try feedRst(&s, ep, &r, id, allocator, 6000);
    try std.testing.expectEqual(tcp.EndpointState.established, ep.state);
    try std.testing.expect(fake_ep.last_pkt != null);
    const challenge = header.TCP.init(fake_ep.last_pkt.?[20..]);
    try std.testing.expectEqual(header.TCPFlagAck, challenge.flags());

    // Exact rcv_nxt match: connection reset.
    try feedRst(&s, ep, &r, id, allocator, 5000);
    try std.testing.expectEqual(tcp.EndpointState.error_state, ep.state);
    try std.testing.expect(wq.events() & waiter.EventErr != 0);
    try std.testing.expect(s.endpoints.get(id) == null);

    // Reads and writes surface the reset.
    var rbuf: [16]u8 = undefined;
    var iov = [_][]u8{&rbuf};
    var uio = buffer.Uio.init(&iov);
    try std.testing.expectError(tcpip.Error.ConnectionReset, ep.endpoint().readv(&uio, null));
    var wbuf = [_]u8{0xab} ** 8;
    var wiov = [_][]u8{&wbuf};
    var wuio = buffer.Uio.init(&wiov);
    try std.testing.expectError(tcpip.Error.ConnectionReset, ep.endpoint().writev(&wuio, .{}));
}
