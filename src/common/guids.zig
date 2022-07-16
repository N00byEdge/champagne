const std = @import("std");

const rt = @import("rt.zig");

pub const GUID = extern struct {
    data1: rt.ULONG,
    data2: rt.USHORT,
    data3: rt.USHORT,
    data4: [8]u8,

    pub fn format(
        self: GUID,
        comptime layout: []const u8,
        opts: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = layout;
        _ = opts;
        try writer.print("{{{X:0>8}-{X:0>4}-{X:0>4}-{X:0>2}{X:0>2}-{X}}}", .{
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            std.fmt.fmtSliceHexUpper(self.data4[2..]),
        });
        if (@import("guids.zig").lookupName(self)) |guid_name| {
            try writer.print("('{s}')", .{guid_name});
        } else {
            try writer.print("(unknown)", .{});
        }
    }
};

const known_guids = .{
    .{ .{ 0x43E63DA5, 0x41D1, 0x4FBF, .{ 0xAD, 0xED, 0x1B, 0xBE, 0xD9, 0x8F, 0xDD, 0x1D } }, "Microsoft-Windows-Subsys-SMSS" },
    // .{ .{ 0xBDE5A307, 0x3888, 0x46CC, .{ 0x85, 0x1E, 0x5C, 0x15, 0x1F, 0xCE, 0xBD, 0x05 } }, "" },
};

pub fn lookupName(guid: GUID) ?[]const u8 {
    inline for (known_guids) |g| {
        const gg = GUID{
            .data1 = g.@"0".@"0",
            .data2 = g.@"0".@"1",
            .data3 = g.@"0".@"2",
            .data4 = g.@"0".@"3",
        };
        if (std.meta.eql(gg, guid))
            return g.@"1";
    }
    return null;
}
