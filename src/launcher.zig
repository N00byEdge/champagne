const std = @import("std");
const os = std.os;

const PE = @import("common/PE.zig");
const ntdll = @import("common/ntdll.zig");
const rt = @import("common/rt.zig");
const vfs = @import("common/vfs.zig");

const log = @import("common/log.zig").scoped(.vfs);

var gpa = std.heap.GeneralPurposeAllocator(.{}){
    .backing_allocator = std.heap.page_allocator,
};

const ResolveContext = struct {
    fn isBuiltinModuleName(module_name: []const u8) bool {
        if (std.mem.eql(u8, module_name, "ntdll.dll")) {
            return true;
        }
        return false;
    }

    fn resolveBuiltinSymbol(symbol_name: []const u8) ?*const anyopaque {
        if (std.mem.eql(u8, symbol_name, "_vsnwprintf_s")) {
            return @extern(*const anyopaque, .{ .name = "_vsnwprintf_s", .linkage = .Strong });
        }
        return ntdll.builtin_symbols.get(symbol_name);
    }

    pub fn findSymbol(module_name: []const u8, symbol_name: []const u8) ?*const anyopaque {
        if (isBuiltinModuleName(module_name)) {
            return resolveBuiltinSymbol(symbol_name);
        }
        return null;
    }
};

var smss_path = rt.toNullTerminatedUTF16Buffer("C:\\Windows\\system32\\smss.exe");
var smss_command_line = rt.toNullTerminatedUTF16Buffer("C:\\Windows\\system32\\smss.exe");

fn setSymlink(path: []const u8, comptime value: []const u8) !void {
    const S = struct {
        const value = rt.toNullTerminatedUTF16Buffer(value);
    };

    const node = try vfs.resolve8(path, true);
    defer vfs.close(node);
    node.get(.symlink).?.* = &S.value;
}

fn doVfsInit() !void {
    try setSymlink("\\KnownDlls\\KnownDllPath", "C:\\Windows\\System32");
    try setSymlink("\\KnownDlls32\\KnownDllPath", "C:\\Windows\\System32");
}

pub fn main() !void {
    try rt.init(&smss_path, &smss_command_line);

    // launch Smss.exe
    var smss = try std.fs.cwd().openFile("test/Windows/system32/smss.exe", .{});
    defer smss.close();

    try doVfsInit();

    const smss_entry = try PE.load(smss, gpa.allocator(), ResolveContext);
    log("Calling smss.exe entry @ 0x{X}", .{smss_entry});
    _ = rt.call_entry(smss_entry);
}
