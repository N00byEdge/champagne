const std = @import("std");

pub fn scoped(comptime tag: anytype) fn (comptime fmt: []const u8, args: anytype) callconv(.Inline) void {
    return struct {
        pub inline fn f(comptime fmt: []const u8, args: anytype) void {
            std.debug.print(@tagName(tag) ++ ": " ++ fmt ++ "\n", args);
        }
    }.f;
}
