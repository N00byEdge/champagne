const std = @import("std");
const os = std.os;

const PE = @import("common/PE.zig");
const ntdll = @import("common/ntdll.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){
    .backing_allocator = std.heap.page_allocator,
};

const ResolveContext = struct {
    fn isBuiltinModuleName(module_name: []const u8) bool {
        if(std.mem.eql(u8, module_name, "ntdll.dll")) {
            return true;
        }
        return false;
    }

    fn resolveBuiltinSymbol(symbol_name: []const u8) ?*const anyopaque {
        return ntdll.builtin_symbols.get(symbol_name);
    }

    pub fn findSymbol(module_name: []const u8, symbol_name: []const u8) ?*const anyopaque {
        if(isBuiltinModuleName(module_name)) {
            return resolveBuiltinSymbol(symbol_name);
        }
        return null;
    }
};

fn call_entry(entry_point: usize) c_int {
    const Arg = extern struct {
        unk: [0x20]u8 = undefined,
        normalize_proceess_first_param: u64 = 0x41414141,
    };
    const arg = &Arg{};
    // @TODO: Use `callconv(.Win64)` when available 
    return asm volatile(
        \\ call *%[entry]
        :
          [_] "={rax}" (->c_int)
        :
          [entry] "{rax}" (entry_point),
          [arg] "{rcx}" (arg),
        :
          "memory"
    );
    //return @intToPtr(fn() callconv(.Stdcall) c_int, entry_point)(&.{});
}

const HINSTANCE = ?*anyopaque;
const PWSTR = ?[*:0]u16;

const KSystemTime = extern struct {
    idk: u64 = 0x51515151,
    wtf: u32 = 0x52525252,
};

const KUserSharedData = extern struct {
    TickCountLow: u32 = 0x40404040,
    TickCountMultiplier: u32 = 0x40404041,
    InterruptTime: KSystemTime = .{},
    SystemTime: KSystemTime = .{},
    TimeZoneBias: KSystemTime = .{},
};

pub fn main() !void {
    // Map KUSER_SHARED_DATA
    _ = try std.os.mmap(@intToPtr([*]align(0x1000) u8, 0x7ffe0000), 0x1000, std.os.PROT.READ | std.os.PROT.WRITE, std.os.MAP.FIXED | std.os.MAP.ANONYMOUS | std.os.MAP.PRIVATE, 0, 0);
    const kuser_shared_data = @intToPtr(*const KUserSharedData, 0x7ffe0000);
    _ = kuser_shared_data;

    // launch Smss.exe
    var smss = try std.fs.cwd().openFile("test/smss.exe", .{});
    defer smss.close();

    const smss_entry = try PE.load(smss, gpa.allocator(), ResolveContext);
    std.debug.print("Calling smss.exe entry @ 0x{X}\n", .{smss_entry});
    _ = call_entry(smss_entry);
}
