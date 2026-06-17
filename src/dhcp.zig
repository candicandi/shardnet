// DHCPv4 client (RFC 2131): DISCOVER -> OFFER -> REQUEST -> ACK, with T1/T2
// lease renewal driven by the stack timer wheel and a graceful RELEASE.
// Replies arrive through a waiter callback (no app polling); on ACK the leased
// address, subnet, gateway route, and DNS servers are applied to the interface.

const std = @import("std");
const tcpip = @import("tcpip.zig");
const stack = @import("stack.zig");
const header = @import("header.zig");
const waiter = @import("waiter.zig");
const buffer = @import("buffer.zig");
const time = @import("time.zig");
const ipv4 = @import("network/ipv4.zig");
const log = @import("log.zig").scoped(.dhcp);

const CLIENT_PORT: u16 = 68;
const SERVER_PORT: u16 = 67;

const OP_BOOTREQUEST: u8 = 1;
const OP_BOOTREPLY: u8 = 2;
const HTYPE_ETHERNET: u8 = 1;
const HLEN_ETHERNET: u8 = 6;
const FLAG_BROADCAST: u16 = 0x8000;

// Magic cookie (RFC 2131 §3) preceding the options field.
const MAGIC_COOKIE = [4]u8{ 0x63, 0x82, 0x53, 0x63 };
// op..file fixed region; options begin after the cookie at offset 240.
const BOOTP_FIXED_LEN: usize = 236;
const OPTIONS_OFFSET: usize = BOOTP_FIXED_LEN + 4;

const BROADCAST_V4 = tcpip.Address{ .v4 = .{ 255, 255, 255, 255 } };
const BROADCAST_MAC = tcpip.LinkAddress{ .addr = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };

const MAX_DNS = 4;
const INITIAL_BACKOFF_MS: u32 = 4000;
const MAX_BACKOFF_MS: u32 = 64000;

pub const MessageType = enum(u8) {
    discover = 1,
    offer = 2,
    request = 3,
    decline = 4,
    ack = 5,
    nak = 6,
    release = 7,
    inform = 8,
};

const Opt = struct {
    const subnet_mask: u8 = 1;
    const router: u8 = 3;
    const dns: u8 = 6;
    const requested_ip: u8 = 50;
    const lease_time: u8 = 51;
    const message_type: u8 = 53;
    const server_id: u8 = 54;
    const param_request: u8 = 55;
    const renewal_t1: u8 = 58;
    const rebinding_t2: u8 = 59;
    const client_id: u8 = 61;
    const end: u8 = 255;
    const pad: u8 = 0;
};

pub const State = enum { init, selecting, requesting, bound, renewing, rebinding };

pub const Lease = struct {
    address: [4]u8 = .{ 0, 0, 0, 0 },
    subnet_mask: [4]u8 = .{ 0, 0, 0, 0 },
    prefix_len: u8 = 0,
    gateway: ?[4]u8 = null,
    server_id: [4]u8 = .{ 0, 0, 0, 0 },
    dns: [MAX_DNS][4]u8 = [_][4]u8{.{ 0, 0, 0, 0 }} ** MAX_DNS,
    dns_count: u8 = 0,
    lease_secs: u32 = 0,
    t1_secs: u32 = 0,
    t2_secs: u32 = 0,
};

const ParsedReply = struct {
    msg_type: ?u8 = null,
    yiaddr: [4]u8 = .{ 0, 0, 0, 0 },
    server_id: ?[4]u8 = null,
    subnet_mask: ?[4]u8 = null,
    gateway: ?[4]u8 = null,
    dns: [MAX_DNS][4]u8 = [_][4]u8{.{ 0, 0, 0, 0 }} ** MAX_DNS,
    dns_count: u8 = 0,
    lease_secs: ?u32 = null,
    t1_secs: ?u32 = null,
    t2_secs: ?u32 = null,
};

const SendKind = enum { discover, select_request, renew_request, rebind_request, release };

pub const Client = struct {
    stack: *stack.Stack,
    allocator: std.mem.Allocator,
    nic_id: tcpip.NICID,
    mac: [6]u8,

    state: State = .init,
    xid: u32 = 0,
    secs_start_ms: i64 = 0,

    ep: ?tcpip.Endpoint = null,
    wq: waiter.Queue = .{},
    rx_entry: waiter.Entry = .{},

    lease: Lease = .{},
    applied: bool = false,
    applied_route: ?stack.RouteEntry = null,
    any_addr_added: bool = false,

    retransmit_timer: time.Timer = undefined,
    t1_timer: time.Timer = undefined,
    t2_timer: time.Timer = undefined,
    lease_timer: time.Timer = undefined,

    retries: u32 = 0,
    backoff_ms: u32 = INITIAL_BACKOFF_MS,

    // tx_buf belongs to the (heap, long-lived) client so a datagram queued for
    // ARP resolution on the egress path never references a freed stack frame.
    tx_buf: [576]u8 = undefined,

    // Heap-pinned: the timers and waiter entry store back-pointers to the
    // client, so a by-value return would dangle them.
    pub fn create(s: *stack.Stack, nic_id: tcpip.NICID, mac: [6]u8) !*Client {
        const self = try s.allocator.create(Client);
        self.* = .{
            .stack = s,
            .allocator = s.allocator,
            .nic_id = nic_id,
            .mac = mac,
        };
        self.retransmit_timer = time.Timer.init(onRetransmit, self);
        self.t1_timer = time.Timer.init(onT1, self);
        self.t2_timer = time.Timer.init(onT2, self);
        self.lease_timer = time.Timer.init(onLeaseExpire, self);
        self.rx_entry = waiter.Entry.init(self, onReadable);
        return self;
    }

    // Does not release the lease — call release() first for a graceful shutdown.
    pub fn destroy(self: *Client) void {
        self.stop();
        self.stack.allocator.destroy(self);
    }

    fn stop(self: *Client) void {
        self.stack.timer_queue.cancel(&self.retransmit_timer);
        self.stack.timer_queue.cancel(&self.t1_timer);
        self.stack.timer_queue.cancel(&self.t2_timer);
        self.stack.timer_queue.cancel(&self.lease_timer);
        if (self.ep) |ep| {
            self.wq.eventUnregister(&self.rx_entry);
            ep.close();
            self.ep = null;
        }
    }

    pub fn start(self: *Client) !void {
        const udp_proto = self.stack.transport_protocols.get(header.UDP.ProtocolNumber) orelse
            return tcpip.Error.UnknownProtocol;

        // Bring the interface up for IPv4 with the unspecified address so the
        // network endpoint exists (egress needs it) before a lease is granted.
        const nic = self.stack.nics.get(self.nic_id) orelse return tcpip.Error.UnknownNICID;
        if (!nic.hasAddress(.{ .v4 = .{ 0, 0, 0, 0 } })) {
            try nic.addAddress(.{
                .protocol = ipv4.ProtocolNumber,
                .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 },
            });
            self.any_addr_added = true;
        }

        // The limited broadcast resolves to the broadcast MAC without ARP.
        self.stack.addLinkAddress(BROADCAST_V4, BROADCAST_MAC) catch {};

        const ep = try udp_proto.newEndpoint(self.stack, ipv4.ProtocolNumber, &self.wq);
        errdefer ep.close();
        try ep.bind(.{ .nic = self.nic_id, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = CLIENT_PORT });
        self.ep = ep;
        self.wq.eventRegister(&self.rx_entry, waiter.EventIn);

        self.newTransaction();
        self.state = .selecting;
        self.send(.discover) catch {};
        self.armRetransmit();
    }

    pub fn boundAddress(self: *const Client) ?[4]u8 {
        return if (self.state == .bound) self.lease.address else null;
    }

    pub fn dnsServers(self: *const Client) []const [4]u8 {
        return self.lease.dns[0..self.lease.dns_count];
    }

    // -- Transmit ------------------------------------------------------------

    fn newTransaction(self: *Client) void {
        self.xid = std.crypto.random.int(u32);
        self.secs_start_ms = std.time.milliTimestamp();
        self.retries = 0;
        self.backoff_ms = INITIAL_BACKOFF_MS;
    }

    fn secsElapsed(self: *const Client) u16 {
        const delta = std.time.milliTimestamp() - self.secs_start_ms;
        const secs = @divTrunc(@max(delta, 0), 1000);
        return @intCast(@min(secs, std.math.maxInt(u16)));
    }

    fn putOption(buf: []u8, i: *usize, code: u8, data: []const u8) void {
        buf[i.*] = code;
        buf[i.* + 1] = @intCast(data.len);
        i.* += 2;
        @memcpy(buf[i.*..][0..data.len], data);
        i.* += data.len;
    }

    fn buildMessage(self: *Client, kind: SendKind) usize {
        const buf = &self.tx_buf;
        @memset(buf[0..OPTIONS_OFFSET], 0);

        buf[0] = OP_BOOTREQUEST;
        buf[1] = HTYPE_ETHERNET;
        buf[2] = HLEN_ETHERNET;
        buf[3] = 0;
        std.mem.writeInt(u32, buf[4..8], self.xid, .big);
        std.mem.writeInt(u16, buf[8..10], self.secsElapsed(), .big);

        const broadcast = switch (kind) {
            .discover, .select_request, .rebind_request => true,
            .renew_request, .release => false,
        };
        std.mem.writeInt(u16, buf[10..12], if (broadcast) FLAG_BROADCAST else 0, .big);

        // ciaddr is set only when the client already owns the address (RFC 2131
        // §4.3.2/§4.4.5: renew, rebind, and release carry it; bootstrap does not).
        switch (kind) {
            .renew_request, .rebind_request, .release => @memcpy(buf[12..16], &self.lease.address),
            else => {},
        }
        @memcpy(buf[28..34], &self.mac); // chaddr
        @memcpy(buf[BOOTP_FIXED_LEN..][0..4], &MAGIC_COOKIE);

        var i: usize = OPTIONS_OFFSET;
        const mt: MessageType = switch (kind) {
            .discover => .discover,
            .select_request, .renew_request, .rebind_request => .request,
            .release => .release,
        };
        putOption(buf, &i, Opt.message_type, &.{@intFromEnum(mt)});

        const client_id = [_]u8{HTYPE_ETHERNET} ++ self.mac;
        putOption(buf, &i, Opt.client_id, &client_id);

        // Requesting a specific offer (RFC 2131 §4.3.2) echoes the server id and
        // the offered address; renew/rebind use ciaddr instead and omit both.
        if (kind == .select_request) {
            putOption(buf, &i, Opt.requested_ip, &self.lease.address);
            putOption(buf, &i, Opt.server_id, &self.lease.server_id);
        }
        if (kind == .release) {
            putOption(buf, &i, Opt.server_id, &self.lease.server_id);
        }
        if (kind != .release) {
            putOption(buf, &i, Opt.param_request, &.{
                Opt.subnet_mask, Opt.router, Opt.dns,
                Opt.lease_time,  Opt.renewal_t1, Opt.rebinding_t2,
            });
        }

        buf[i] = Opt.end;
        i += 1;
        return i;
    }

    fn send(self: *Client, kind: SendKind) !void {
        const ep = self.ep orelse return tcpip.Error.InvalidEndpointState;
        const len = self.buildMessage(kind);

        const dest_addr = switch (kind) {
            .discover, .select_request, .rebind_request => BROADCAST_V4,
            .renew_request, .release => tcpip.Address{ .v4 = self.lease.server_id },
        };
        const dest = tcpip.FullAddress{ .nic = self.nic_id, .addr = dest_addr, .port = SERVER_PORT };

        const Payloader = struct {
            data: []const u8,
            pub fn payloader(ctx: *@This()) tcpip.Payloader {
                return .{ .ptr = ctx, .vtable = &.{ .fullPayload = fullPayload } };
            }
            fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
                return @as(*@This(), @ptrCast(@alignCast(ptr))).data;
            }
        };
        var fp = Payloader{ .data = self.tx_buf[0..len] };

        _ = ep.write(fp.payloader(), .{ .to = &dest }) catch |err| {
            // A blocked send (address not yet resolved) is retried by the
            // retransmit timer; nothing else to do here.
            if (err == tcpip.Error.WouldBlock) {
                log.debug("send {s}: would block", .{@tagName(kind)});
                return;
            }
            return err;
        };
        log.debug("sent {s} xid=0x{x}", .{ @tagName(kind), self.xid });
    }

    fn armRetransmit(self: *Client) void {
        self.stack.timer_queue.schedule(&self.retransmit_timer, self.backoff_ms);
    }

    // -- Receive -------------------------------------------------------------

    fn onReadable(e: *waiter.Entry) void {
        const self: *Client = @ptrCast(@alignCast(e.context.?));
        self.service();
    }

    fn service(self: *Client) void {
        const ep = self.ep orelse return;
        while (true) {
            var view = ep.read(null) catch |err| {
                if (err != tcpip.Error.WouldBlock) log.debug("read error: {}", .{err});
                return;
            };
            defer view.deinit();
            const flat = view.toView(self.allocator) catch return;
            defer self.allocator.free(flat);
            self.handleReply(flat);
        }
    }

    fn parseReply(self: *Client, buf: []const u8) ?ParsedReply {
        if (buf.len < OPTIONS_OFFSET) return null;
        if (buf[0] != OP_BOOTREPLY) return null;
        if (!std.mem.eql(u8, buf[BOOTP_FIXED_LEN..][0..4], &MAGIC_COOKIE)) return null;
        if (std.mem.readInt(u32, buf[4..8], .big) != self.xid) return null;

        var r = ParsedReply{};
        @memcpy(&r.yiaddr, buf[16..20]);

        var i: usize = OPTIONS_OFFSET;
        while (i < buf.len) {
            const code = buf[i];
            i += 1;
            if (code == Opt.end) break;
            if (code == Opt.pad) continue;
            if (i >= buf.len) break;
            const len = buf[i];
            i += 1;
            if (i + len > buf.len) break;
            const val = buf[i .. i + len];
            switch (code) {
                Opt.message_type => if (len >= 1) {
                    r.msg_type = val[0];
                },
                Opt.subnet_mask => if (len >= 4) {
                    r.subnet_mask = take4(val);
                },
                Opt.router => if (len >= 4) {
                    r.gateway = take4(val);
                },
                Opt.dns => {
                    var o: usize = 0;
                    while (o + 4 <= len and r.dns_count < MAX_DNS) : (o += 4) {
                        @memcpy(&r.dns[r.dns_count], val[o .. o + 4]);
                        r.dns_count += 1;
                    }
                },
                Opt.lease_time => if (len >= 4) {
                    r.lease_secs = std.mem.readInt(u32, val[0..4], .big);
                },
                Opt.renewal_t1 => if (len >= 4) {
                    r.t1_secs = std.mem.readInt(u32, val[0..4], .big);
                },
                Opt.rebinding_t2 => if (len >= 4) {
                    r.t2_secs = std.mem.readInt(u32, val[0..4], .big);
                },
                Opt.server_id => if (len >= 4) {
                    r.server_id = take4(val);
                },
                else => {},
            }
            i += len;
        }
        return r;
    }

    fn handleReply(self: *Client, buf: []const u8) void {
        const reply = self.parseReply(buf) orelse return;
        const mt = reply.msg_type orelse return;
        switch (self.state) {
            .selecting => if (mt == @intFromEnum(MessageType.offer)) self.handleOffer(reply),
            .requesting, .renewing, .rebinding => {
                if (mt == @intFromEnum(MessageType.ack)) {
                    self.handleAck(reply);
                } else if (mt == @intFromEnum(MessageType.nak)) {
                    self.handleNak();
                }
            },
            else => {},
        }
    }

    fn handleOffer(self: *Client, reply: ParsedReply) void {
        self.lease.address = reply.yiaddr;
        if (reply.server_id) |sid| self.lease.server_id = sid;
        self.state = .requesting;
        log.debug("offer {any} from {any}", .{ reply.yiaddr, self.lease.server_id });
        self.backoff_ms = INITIAL_BACKOFF_MS;
        self.send(.select_request) catch {};
        self.armRetransmit();
    }

    fn handleAck(self: *Client, reply: ParsedReply) void {
        const lease_secs = reply.lease_secs orelse {
            log.warn("ACK without lease time; ignoring", .{});
            return;
        };
        self.lease.address = reply.yiaddr;
        if (reply.server_id) |sid| self.lease.server_id = sid;
        self.lease.subnet_mask = reply.subnet_mask orelse .{ 255, 255, 255, 0 };
        self.lease.prefix_len = maskToPrefix(self.lease.subnet_mask);
        self.lease.gateway = reply.gateway;
        self.lease.dns = reply.dns;
        self.lease.dns_count = reply.dns_count;
        self.lease.lease_secs = lease_secs;
        self.lease.t1_secs = reply.t1_secs orelse (lease_secs / 2);
        self.lease.t2_secs = reply.t2_secs orelse (lease_secs / 8 * 7);

        self.applyLease() catch |err| {
            log.warn("failed to apply lease: {}", .{err});
            return;
        };
        self.state = .bound;
        self.scheduleLeaseTimers();
        self.stack.timer_queue.cancel(&self.retransmit_timer);
        self.retries = 0;
        log.info("bound {any}/{d} gw={any} lease={d}s", .{
            self.lease.address, self.lease.prefix_len, self.lease.gateway, self.lease.lease_secs,
        });
    }

    fn handleNak(self: *Client) void {
        log.debug("NAK; restarting", .{});
        self.removeLease();
        self.newTransaction();
        self.state = .selecting;
        self.send(.discover) catch {};
        self.armRetransmit();
    }

    // -- Lease application ---------------------------------------------------

    fn applyLease(self: *Client) !void {
        const nic = self.stack.nics.get(self.nic_id) orelse return tcpip.Error.UnknownNICID;
        const leased = tcpip.Address{ .v4 = self.lease.address };

        if (!nic.hasAddress(leased)) {
            // Reuse the bootstrap endpoint: this runs inside packet dispatch and
            // recreating the IPv4 endpoint would free the one on the call stack.
            try nic.addAddressReusingEndpoint(.{
                .protocol = ipv4.ProtocolNumber,
                .address_with_prefix = .{ .address = leased, .prefix_len = self.lease.prefix_len },
            });
        }
        // Resolve our own address to the link's MAC so egress from it does not
        // stall on ARP, then drop the unspecified bootstrap address.
        self.stack.addLinkAddress(leased, nic.linkEP.linkAddress()) catch {};
        if (self.any_addr_added) {
            nic.removeAddress(.{ .v4 = .{ 0, 0, 0, 0 } });
            self.any_addr_added = false;
        }

        if (self.applied_route) |old| {
            _ = self.stack.removeRoute(old);
            self.applied_route = null;
        }
        if (self.lease.gateway) |gw| {
            const entry = stack.RouteEntry{
                .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 },
                .gateway = .{ .v4 = gw },
                .nic = self.nic_id,
                .mtu = nic.linkEP.mtu(),
            };
            try self.stack.addRoute(entry);
            self.applied_route = entry;
        }
        self.applied = true;
    }

    fn removeLease(self: *Client) void {
        if (!self.applied) return;
        if (self.stack.nics.get(self.nic_id)) |nic| {
            nic.removeAddress(.{ .v4 = self.lease.address });
        }
        if (self.applied_route) |entry| {
            _ = self.stack.removeRoute(entry);
            self.applied_route = null;
        }
        self.applied = false;
    }

    fn scheduleLeaseTimers(self: *Client) void {
        self.stack.timer_queue.schedule(&self.t1_timer, secsToMs(self.lease.t1_secs));
        self.stack.timer_queue.schedule(&self.t2_timer, secsToMs(self.lease.t2_secs));
        self.stack.timer_queue.schedule(&self.lease_timer, secsToMs(self.lease.lease_secs));
    }

    // RFC 2131 §4.4.6: relinquish the lease and tear down the configuration.
    pub fn release(self: *Client) void {
        switch (self.state) {
            .bound, .renewing, .rebinding => self.send(.release) catch {},
            else => {},
        }
        self.removeLease();
        self.stack.timer_queue.cancel(&self.retransmit_timer);
        self.stack.timer_queue.cancel(&self.t1_timer);
        self.stack.timer_queue.cancel(&self.t2_timer);
        self.stack.timer_queue.cancel(&self.lease_timer);
        self.state = .init;
    }

    // -- Timer callbacks -----------------------------------------------------

    fn onRetransmit(ctx: *anyopaque) void {
        const self: *Client = @ptrCast(@alignCast(ctx));
        const kind: SendKind = switch (self.state) {
            .selecting => .discover,
            .requesting => .select_request,
            .renewing => .renew_request,
            .rebinding => .rebind_request,
            else => return,
        };
        self.retries += 1;
        self.send(kind) catch {};
        self.backoff_ms = @min(self.backoff_ms * 2, MAX_BACKOFF_MS);
        self.armRetransmit();
    }

    fn onT1(ctx: *anyopaque) void {
        const self: *Client = @ptrCast(@alignCast(ctx));
        if (self.state != .bound) return;
        self.state = .renewing;
        self.secs_start_ms = std.time.milliTimestamp();
        self.backoff_ms = INITIAL_BACKOFF_MS;
        log.debug("T1 reached; renewing", .{});
        self.send(.renew_request) catch {};
        self.armRetransmit();
    }

    fn onT2(ctx: *anyopaque) void {
        const self: *Client = @ptrCast(@alignCast(ctx));
        if (self.state != .renewing and self.state != .bound) return;
        self.state = .rebinding;
        self.backoff_ms = INITIAL_BACKOFF_MS;
        log.debug("T2 reached; rebinding", .{});
        self.send(.rebind_request) catch {};
        self.armRetransmit();
    }

    fn onLeaseExpire(ctx: *anyopaque) void {
        const self: *Client = @ptrCast(@alignCast(ctx));
        log.warn("lease expired; reacquiring", .{});
        self.stack.timer_queue.cancel(&self.retransmit_timer);
        self.removeLease();
        self.newTransaction();
        self.state = .selecting;
        self.send(.discover) catch {};
        self.armRetransmit();
    }
};

fn take4(s: []const u8) [4]u8 {
    var out: [4]u8 = undefined;
    @memcpy(&out, s[0..4]);
    return out;
}

fn maskToPrefix(mask: [4]u8) u8 {
    var count: u8 = 0;
    for (mask) |b| count += @popCount(b);
    return count;
}

fn secsToMs(secs: u32) u64 {
    return @as(u64, secs) * 1000;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const loopback = @import("drivers/loopback.zig");

test "maskToPrefix" {
    try std.testing.expectEqual(@as(u8, 24), maskToPrefix(.{ 255, 255, 255, 0 }));
    try std.testing.expectEqual(@as(u8, 16), maskToPrefix(.{ 255, 255, 0, 0 }));
    try std.testing.expectEqual(@as(u8, 0), maskToPrefix(.{ 0, 0, 0, 0 }));
    try std.testing.expectEqual(@as(u8, 30), maskToPrefix(.{ 255, 255, 255, 252 }));
}

const TestServer = struct {
    yiaddr: [4]u8,
    server_id: [4]u8,
    mask: [4]u8 = .{ 255, 255, 255, 0 },
    gateway: ?[4]u8 = .{ 192, 168, 1, 1 },
    dns: ?[4]u8 = .{ 8, 8, 8, 8 },
    lease_secs: u32 = 3600,
    t1_secs: ?u32 = null,
    t2_secs: ?u32 = null,

    fn buildReply(self: TestServer, buf: []u8, xid: u32, mt: MessageType) usize {
        @memset(buf[0..OPTIONS_OFFSET], 0);
        buf[0] = OP_BOOTREPLY;
        buf[1] = HTYPE_ETHERNET;
        buf[2] = HLEN_ETHERNET;
        std.mem.writeInt(u32, buf[4..8], xid, .big);
        @memcpy(buf[16..20], &self.yiaddr);
        @memcpy(buf[BOOTP_FIXED_LEN..][0..4], &MAGIC_COOKIE);

        var i: usize = OPTIONS_OFFSET;
        Client.putOption(buf, &i, Opt.message_type, &.{@intFromEnum(mt)});
        Client.putOption(buf, &i, Opt.server_id, &self.server_id);
        Client.putOption(buf, &i, Opt.subnet_mask, &self.mask);
        var lease_be: [4]u8 = undefined;
        std.mem.writeInt(u32, &lease_be, self.lease_secs, .big);
        Client.putOption(buf, &i, Opt.lease_time, &lease_be);
        if (self.t1_secs) |t1| {
            var t1_be: [4]u8 = undefined;
            std.mem.writeInt(u32, &t1_be, t1, .big);
            Client.putOption(buf, &i, Opt.renewal_t1, &t1_be);
        }
        if (self.t2_secs) |t2| {
            var t2_be: [4]u8 = undefined;
            std.mem.writeInt(u32, &t2_be, t2, .big);
            Client.putOption(buf, &i, Opt.rebinding_t2, &t2_be);
        }
        if (self.gateway) |gw| Client.putOption(buf, &i, Opt.router, &gw);
        if (self.dns) |d| Client.putOption(buf, &i, Opt.dns, &d);
        buf[i] = Opt.end;
        i += 1;
        return i;
    }
};

fn injectReply(nic: *stack.NIC, src_ip: [4]u8, dst_ip: [4]u8, dhcp: []const u8) void {
    var frame: [600]u8 = undefined;
    @memset(frame[0..20], 0);
    frame[0] = 0x45;
    const total: u16 = @intCast(20 + 8 + dhcp.len);
    std.mem.writeInt(u16, frame[2..4], total, .big);
    frame[8] = 64; // ttl
    frame[9] = 17; // UDP
    @memcpy(frame[12..16], &src_ip);
    @memcpy(frame[16..20], &dst_ip);
    const iph = header.IPv4.init(frame[0..20]);
    iph.setChecksum(iph.calculateChecksum());

    std.mem.writeInt(u16, frame[20..22], SERVER_PORT, .big);
    std.mem.writeInt(u16, frame[22..24], CLIENT_PORT, .big);
    std.mem.writeInt(u16, frame[24..26], @intCast(8 + dhcp.len), .big);
    std.mem.writeInt(u16, frame[26..28], 0, .big); // UDP checksum optional in IPv4
    @memcpy(frame[28..][0..dhcp.len], dhcp);

    const flen = 28 + dhcp.len;
    var views = [_]buffer.ClusterView{.{ .cluster = null, .view = frame[0..flen] }};
    const pkt = tcpip.PacketBuffer{
        .data = buffer.VectorisedView.init(flen, &views),
        .header = buffer.Prependable.init(&[_]u8{}),
    };
    const remote = tcpip.LinkAddress{ .addr = .{ 0x02, 0, 0, 0, 0, 0x01 } };
    const local = nic.linkEP.linkAddress();
    nic.dispatcher.deliverNetworkPacket(&remote, &local, ipv4.ProtocolNumber, pkt);
}

fn setupStack(allocator: std.mem.Allocator, s: *stack.Stack, lo: *loopback.Loopback) !*stack.NIC {
    // Heap-allocate so the protocol outlives this helper's return (the stack
    // holds a pointer to it); owner_allocator lets s.deinit() free it.
    const ip4 = try allocator.create(ipv4.IPv4Protocol);
    ip4.* = ipv4.IPv4Protocol.init();
    ip4.owner_allocator = allocator;
    try s.registerNetworkProtocol(ip4.protocol());
    const udp_proto = @import("transport/udp.zig").UDPProtocol.init(allocator);
    try s.registerTransportProtocol(udp_proto.protocol());
    try s.createLoopbackNIC(1, lo.linkEndpoint());
    return s.nics.get(1).?;
}

test "DHCP: DISCOVER/OFFER/REQUEST/ACK binds and configures the interface" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    var lo = loopback.Loopback.init(allocator);
    defer lo.deinit();
    const nic = try setupStack(allocator, &s, &lo);

    const client = try Client.create(&s, 1, .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 });
    defer client.destroy();

    try client.start();
    try std.testing.expectEqual(State.selecting, client.state);

    const srv = TestServer{ .yiaddr = .{ 192, 168, 1, 50 }, .server_id = .{ 192, 168, 1, 1 } };

    // OFFER -> client sends REQUEST synchronously inside delivery.
    var reply_buf: [576]u8 = undefined;
    var n = srv.buildReply(&reply_buf, client.xid, .offer);
    injectReply(nic, srv.server_id, .{ 255, 255, 255, 255 }, reply_buf[0..n]);
    try std.testing.expectEqual(State.requesting, client.state);

    // ACK -> client binds and applies configuration.
    n = srv.buildReply(&reply_buf, client.xid, .ack);
    injectReply(nic, srv.server_id, .{ 255, 255, 255, 255 }, reply_buf[0..n]);

    try std.testing.expectEqual(State.bound, client.state);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 50 }, client.boundAddress().?);
    try std.testing.expect(nic.hasAddress(.{ .v4 = .{ 192, 168, 1, 50 } }));
    try std.testing.expect(!nic.hasAddress(.{ .v4 = .{ 0, 0, 0, 0 } }));
    try std.testing.expectEqual(@as(u8, 24), client.lease.prefix_len);
    try std.testing.expectEqual(@as(usize, 1), client.dnsServers().len);
    try std.testing.expectEqual([4]u8{ 8, 8, 8, 8 }, client.dnsServers()[0]);

    // Default route via the leased gateway is installed.
    var has_default = false;
    for (s.getRouteTable()) |re| {
        if (re.destination.prefix == 0 and re.gateway.eq(.{ .v4 = .{ 192, 168, 1, 1 } })) has_default = true;
    }
    try std.testing.expect(has_default);

    // Lease/renewal timers are armed.
    try std.testing.expect(client.t1_timer.active);
    try std.testing.expect(client.t2_timer.active);
    try std.testing.expect(client.lease_timer.active);

    // Drain any queued egress so the loopback teardown sees a clean queue.
    lo.tick();
}

test "DHCP: T1 triggers renewal and a fresh ACK rebinds" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    var lo = loopback.Loopback.init(allocator);
    defer lo.deinit();
    const nic = try setupStack(allocator, &s, &lo);

    const client = try Client.create(&s, 1, .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x03 });
    defer client.destroy();
    try client.start();

    // Short, explicit timers so the wheel reaches T1 in a bounded tick count.
    const srv = TestServer{
        .yiaddr = .{ 10, 0, 0, 77 },
        .server_id = .{ 10, 0, 0, 1 },
        .mask = .{ 255, 0, 0, 0 },
        .gateway = null,
        .dns = null,
        .lease_secs = 10,
        .t1_secs = 2,
        .t2_secs = 8,
    };
    var reply_buf: [576]u8 = undefined;
    var n = srv.buildReply(&reply_buf, client.xid, .offer);
    injectReply(nic, srv.server_id, .{ 255, 255, 255, 255 }, reply_buf[0..n]);
    n = srv.buildReply(&reply_buf, client.xid, .ack);
    injectReply(nic, srv.server_id, .{ 255, 255, 255, 255 }, reply_buf[0..n]);
    try std.testing.expectEqual(State.bound, client.state);
    const xid_before = client.xid;

    // Advance the wheel past T1 (2s = 2000 ticks); the renew keeps xid (RFC 2131).
    _ = s.timer_queue.tickTo(s.timer_queue.currentTick() + 2000);
    try std.testing.expectEqual(State.renewing, client.state);
    try std.testing.expectEqual(xid_before, client.xid);

    n = srv.buildReply(&reply_buf, client.xid, .ack);
    injectReply(nic, srv.server_id, .{ 10, 0, 0, 77 }, reply_buf[0..n]);
    try std.testing.expectEqual(State.bound, client.state);

    lo.tick();
}

test "DHCP: release tears down the leased configuration" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    var lo = loopback.Loopback.init(allocator);
    defer lo.deinit();
    const nic = try setupStack(allocator, &s, &lo);

    const client = try Client.create(&s, 1, .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x04 });
    defer client.destroy();
    try client.start();

    const srv = TestServer{ .yiaddr = .{ 192, 168, 1, 50 }, .server_id = .{ 192, 168, 1, 1 } };
    var reply_buf: [576]u8 = undefined;
    var n = srv.buildReply(&reply_buf, client.xid, .offer);
    injectReply(nic, srv.server_id, .{ 255, 255, 255, 255 }, reply_buf[0..n]);
    n = srv.buildReply(&reply_buf, client.xid, .ack);
    injectReply(nic, srv.server_id, .{ 255, 255, 255, 255 }, reply_buf[0..n]);
    try std.testing.expect(nic.hasAddress(.{ .v4 = .{ 192, 168, 1, 50 } }));

    client.release();
    try std.testing.expectEqual(State.init, client.state);
    try std.testing.expect(!nic.hasAddress(.{ .v4 = .{ 192, 168, 1, 50 } }));
    try std.testing.expect(!client.t1_timer.active);
    try std.testing.expect(!client.lease_timer.active);

    var has_default = false;
    for (s.getRouteTable()) |re| {
        if (re.destination.prefix == 0) has_default = true;
    }
    try std.testing.expect(!has_default);

    lo.tick();
}
