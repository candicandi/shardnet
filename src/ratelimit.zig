const std = @import("std");
const tcpip = @import("tcpip.zig");

// Token bucket rate limiter shared across protocols (ICMP, ARP, TCP SYN). Allows
// bursts up to max_tokens, then refill_rate tokens per second sustained. Uses the
// millisecond wall clock; forward jumps refill to the cap (clamped so the narrowing
// cannot overflow), backward steps reseed instead of stalling.
pub const RateLimiter = struct {
    max_tokens: u32 = 100,
    tokens: u32 = 100,
    refill_rate: u32 = 100,
    // Zero means "not yet initialised"; refill() lazy-inits on the first call.
    last_refill_ms: i64 = 0,

    pub fn init() RateLimiter {
        return .{};
    }

    pub fn tryConsume(self: *RateLimiter) bool {
        self.refill();
        if (self.tokens == 0) return false;
        self.tokens -= 1;
        return true;
    }

    fn refill(self: *RateLimiter) void {
        const now = std.time.milliTimestamp();
        // milliTimestamp() cannot be called at comptime, so the first refill seeds
        // the clock instead of granting tokens.
        if (self.last_refill_ms == 0) {
            self.last_refill_ms = now;
            return;
        }
        const elapsed_ms = now - self.last_refill_ms;
        if (elapsed_ms < 0) {
            // Wall clock stepped backward; reseed so refills resume promptly.
            self.last_refill_ms = now;
            return;
        }
        if (elapsed_ms >= 1000) {
            // Clamp before narrowing: a long idle gap or a large forward clock jump
            // can drive the refill past u32, which would panic the @intCast.
            const refilled = @divFloor(elapsed_ms * @as(i64, self.refill_rate), 1000);
            const new_tokens: u32 = if (refilled >= self.max_tokens) self.max_tokens else @intCast(refilled);
            self.tokens = @min(self.max_tokens, self.tokens + new_tokens);
            self.last_refill_ms = now;
        }
    }
};

// Approximate per-source token-bucket limiter over a fixed, allocation-free
// table: a source address maps to one bucket by hash, and a hash collision
// evicts the previous source. Bounded by construction (no growth), so a
// spoofed-source flood cannot exhaust it; a global limiter still backstops the
// aggregate rate, while this stops a single source from draining that budget.
//
// NOTE: keying on source address throttles many clients behind one NAT or proxy
// as a group, so keep per-source budgets generous; the rates are tunable.
pub fn PerSourceRateLimiter(comptime size: usize) type {
    return struct {
        const Self = @This();
        const Bucket = struct {
            addr: tcpip.Address = .{ .v4 = .{ 0, 0, 0, 0 } },
            used: bool = false,
            limiter: RateLimiter = .{},
        };
        buckets: [size]Bucket = [_]Bucket{.{}} ** size,
        per_source_tokens: u32 = 256,
        per_source_rate: u32 = 256,

        pub fn tryConsume(self: *Self, src: tcpip.Address) bool {
            const idx: usize = @intCast(src.hash() % size);
            const b = &self.buckets[idx];
            if (!b.used or !b.addr.eq(src)) {
                b.* = .{
                    .addr = src,
                    .used = true,
                    .limiter = .{ .max_tokens = self.per_source_tokens, .tokens = self.per_source_tokens, .refill_rate = self.per_source_rate },
                };
            }
            return b.limiter.tryConsume();
        }
    };
}

test "token bucket allows a burst then refills" {
    var limiter = RateLimiter.init();
    limiter.tokens = 5;

    var allowed: u32 = 0;
    for (0..10) |_| {
        if (limiter.tryConsume()) allowed += 1;
    }
    try std.testing.expectEqual(@as(u32, 5), allowed);
}

test "token bucket survives a huge elapsed gap without overflowing" {
    var limiter = RateLimiter.init();
    limiter.tokens = 0;
    // Far in the past: the next refill sees an astronomically large elapsed gap,
    // as a long-idle limiter or a forward clock jump would. The pre-clamp code
    // narrowed the refill to u32 and panicked here.
    limiter.last_refill_ms = 1;
    try std.testing.expect(limiter.tryConsume());
    try std.testing.expect(limiter.tokens == limiter.max_tokens - 1);
}

test "token bucket reseeds instead of stalling on a backward clock step" {
    var limiter = RateLimiter.init();
    limiter.tokens = 3;
    const future = std.time.milliTimestamp() + 1_000_000;
    limiter.last_refill_ms = future;
    _ = limiter.tryConsume();
    try std.testing.expect(limiter.last_refill_ms < future);
}

test "per-source limiter bounds one source and leaves a distinct source alone" {
    const Limiter = PerSourceRateLimiter(64);
    var psl = Limiter{ .per_source_tokens = 3, .per_source_rate = 3 };

    const a = tcpip.Address{ .v4 = .{ 10, 0, 0, 1 } };
    const idx_a: usize = @intCast(a.hash() % 64);

    // Pick a second source that lands in a different bucket (no collision), so
    // the isolation assertion does not depend on hash luck.
    var b = tcpip.Address{ .v4 = .{ 10, 0, 0, 2 } };
    var n: u8 = 2;
    while (@as(usize, @intCast(b.hash() % 64)) == idx_a and n < 250) : (n += 1) {
        b = .{ .v4 = .{ 10, 0, 0, n } };
    }

    // Source a burns exactly its budget, then is throttled.
    var allowed: u32 = 0;
    for (0..10) |_| {
        if (psl.tryConsume(a)) allowed += 1;
    }
    try std.testing.expectEqual(@as(u32, 3), allowed);
    try std.testing.expect(!psl.tryConsume(a));

    // A distinct source still has its full budget.
    try std.testing.expect(psl.tryConsume(b));
}
