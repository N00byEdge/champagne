const std = @import("std");

pub const BOOL = i32;
pub const FALSE = @as(BOOL, 0);
pub const TRUE = @as(BOOL, 1);

pub const USHORT = u16;
pub const ULONG = u32;
pub const SIZE_T = u32;

pub const WCHAR = u16;

pub const PVOID = ?*anyopaque;
pub const HINSTANCE = ?*anyopaque;
pub const HANDLE = ?*anyopaque;

pub const PWSTR = ?[*:0]WCHAR;

pub const UnicodeString = extern struct {
    length: USHORT,
    capacity: USHORT,
    buffer: PWSTR,

    pub fn initFromBuffer(buf: [:0]WCHAR) UnicodeString {
        return .{
            .length = @intCast(USHORT, buf.len),
            .capacity = @intCast(USHORT, buf.len),
            .buffer = buf.ptr,
        };
    }
};

pub const ProcessParameters = extern struct {
    reserved1: [16]u8,
    reserved2: [10]PVOID,
    image_path_name: UnicodeString,
    command_line: UnicodeString,
};

pub const PEB = extern struct {
    reserved1: [2]u8 = std.mem.zeroes([2]u8),
    being_debugged: u8 = 0,
    reserved2: [1]u8 = std.mem.zeroes([1]u8),
    reserved3: [2]PVOID = std.mem.zeroes([2]PVOID),
    ldr: PVOID = null, // PPEB_LDR_DATA
    process_parameters: ?*ProcessParameters = null,
    reserved4: [3]PVOID = std.mem.zeroes([3]PVOID),
    atl_thunk_s_list_ptr: PVOID = null,
    reserved5: PVOID = null,
    reserved6: ULONG = 0,
    reserved7: PVOID = null,
    reserved8: ULONG = 0,
    atl_think_s_list_ptr32: ULONG = 0,
    reserved9: [45]PVOID = std.mem.zeroes([45]PVOID),
    reserved10: [96]u8 = std.mem.zeroes([96]u8),
    post_process_init_routine: PVOID = null, // PPS_POST_PROCESS_INIT_ROUTINE
    reserved11: [128]u8 = std.mem.zeroes([128]u8),
    reserved12: [1]PVOID = std.mem.zeroes([1]PVOID),
    session_id: ULONG = 0,
};

comptime {
    std.debug.assert(@offsetOf(PEB, "process_parameters") == 0x20);
}

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

pub var pparam: ProcessParameters = undefined;
pub var peb: PEB = undefined;

const kuser_shared_data_addr = 0x7ffe0000;

pub fn init(image_path_name: [:0]WCHAR, command_line: [:0]WCHAR) !void {
    _ = try std.os.mmap(
        @intToPtr([*]align(0x1000) u8, kuser_shared_data_addr),
        0x1000,
        std.os.PROT.READ | std.os.PROT.WRITE,
        std.os.MAP.FIXED | std.os.MAP.ANONYMOUS | std.os.MAP.PRIVATE,
        0,
        0,
    );
    var kusd = @intToPtr(*KUserSharedData, kuser_shared_data_addr);
    kusd.* = .{};

    pparam.image_path_name = UnicodeString.initFromBuffer(image_path_name);
    pparam.command_line = UnicodeString.initFromBuffer(command_line);
    peb.process_parameters = &pparam;
}

pub fn call_entry(entry_point: usize) c_int {
    return @intToPtr(fn(*PEB) callconv(.Win64) c_int, entry_point)(&peb);
}
