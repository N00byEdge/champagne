const std = @import("std");
const os = std.os;

const PE = @import("common/PE.zig");
const ntdll = @import("common/ntdll.zig");
const rt = @import("common/rt.zig");
const vfs = @import("common/vfs.zig");

const log_lib = @import("common/log.zig");
const logger = log_lib.scoped(.launcher);

pub fn log(
    comptime level: std.log.Level,
    comptime scope: anytype,
    comptime fmt: []const u8,
    args: anytype,
) void {
    _ = level;
    _ = scope;
    _ = fmt;
    _ = args;
    //log_lib.scoped(scope)(@tagName(level) ++ ": " ++ fmt, args);
}

const ResolveContext = @import("common/symbols.zig").ResolveContext;

var smss_path = std.unicode.utf8ToUtf16LeStringLiteral("C:\\Windows\\system32\\smss.exe").*;
var smss_command_line = std.unicode.utf8ToUtf16LeStringLiteral("C:\\Windows\\system32\\smss.exe").*;

fn setSymlink(path: []const u8, comptime value: []const u8) !void {
    const node = try vfs.resolve8(path, true);
    defer vfs.close(node);
    node.get(.symlink).?.* = std.unicode.utf8ToUtf16LeStringLiteral(value);
}

fn doVfsInit() !void {
    try setSymlink("\\KnownDlls\\KnownDllPath", "C:\\Windows\\System32");
    try setSymlink("\\KnownDlls32\\KnownDllPath", "C:\\Windows\\System32");
}

fn trapHandler(signum: c_int, info: *const std.os.siginfo_t, ctx: ?*const anyopaque) callconv(.C) void {
    const context = @ptrCast(*const std.os.ucontext_t, @alignCast(@alignOf(std.os.ucontext_t), ctx));
    const gregs = context.mcontext.gregs;
    const eax = @truncate(u32, gregs[std.os.REG.RAX]);

    _ = signum;
    _ = info;

    const rip = gregs[std.os.REG.RIP] - 1;
    logger("Trap at addr 0x{X}", .{rip});
    const rbp = gregs[std.os.REG.RBP];
    std.debug.dumpStackTraceFromBase(rbp, rip);

    switch(eax) {
        1 => {
            const unk0 = std.mem.span(@intToPtr([*:0]u8, gregs[std.os.REG.RCX]));
            const unk1 = @truncate(u16, gregs[std.os.REG.RDX]);
            const unk2 = @truncate(u32, gregs[std.os.REG.R8]);
            const unk3 = @truncate(u32, gregs[std.os.REG.R9]);
            logger("DebugPrint('{s}', 0x{X}, 0x{X}, 0x{X})", .{
                std.fmt.fmtSliceEscapeUpper(unk0), unk1, unk2, unk3
            });
        },
        2 => {
            const unk0 = gregs[std.os.REG.RCX];
            const unk1 = @truncate(u16, gregs[std.os.REG.RDX]);
            const unk2 = gregs[std.os.REG.R8];
            const unk3 = @truncate(u16, gregs[std.os.REG.R9]);
            logger("DebugPrompt(0x{X}, 0x{X}, 0x{X}, 0x{X})", .{
                unk0, unk1, unk2, unk3
            });
        },
        else => logger("Unknown debug call 0x{X}", .{eax}),
    }
    std.os.abort();
}

pub fn main() !void {
    try rt.init(&smss_path, &smss_command_line);

    var sa = std.os.Sigaction{
        .handler = .{ .sigaction = trapHandler },
        .flags = 0,
        .mask = std.mem.zeroes([32]u32),
    };

    try std.os.sigaction(std.os.SIG.TRAP, &sa, null);

    var ntdll_file = try std.fs.cwd().openFile("test/Windows/System32/ntdll.dll", .{});
    defer ntdll_file.close();

    const ntdll_entry = try PE.load(ntdll_file, ResolveContext);
    _ = ntdll_entry;

    // launch Smss.exe
    var smss = try std.fs.cwd().openFile("test/Windows/System32/smss.exe", .{});
    defer smss.close();

    try doVfsInit();

    const smss_entry = try PE.load(smss, ResolveContext);
    logger("Calling smss.exe entry @ 0x{X}", .{smss_entry});
    _ = rt.call_entry(smss_entry);
}
