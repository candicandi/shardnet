const std = @import("std");

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
