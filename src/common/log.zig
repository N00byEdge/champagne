const std = @import("std");

var log_lock = std.Thread.Mutex{};

pub fn scoped(comptime tag: anytype) fn (comptime fmt: []const u8, args: anytype) callconv(.Inline) void {
    return struct {
        pub inline fn f(comptime fmt: []const u8, args: anytype) void {
            log_lock.lock();
            defer log_lock.unlock();
            std.debug.print(@tagName(tag) ++ ": " ++ fmt ++ "\n", args);
        }
    }.f;
}
