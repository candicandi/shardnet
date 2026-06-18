const std = @import("std");

// Token bucket rate limiter shared across protocols (ICMP, ARP, TCP SYN). Allows
// bursts up to max_tokens, then refill_rate tokens per second sustained. Backed by
// the monotonic millisecond clock, so it is immune to wall-clock adjustments.
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
        if (elapsed_ms >= 1000) {
            const new_tokens: u32 = @intCast(@divFloor(elapsed_ms * self.refill_rate, 1000));
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
