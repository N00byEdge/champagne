const std = @import("std");

pub const BOOL = i32;
pub const LOGICAL = ULONG;
pub const FALSE = 0;
pub const TRUE = 1;

pub const UCHAR = u8;
pub const WORD = u16;
pub const USHORT = u16;
pub const DWORD = u32;
pub const ULONG = u32;
pub const SIZE_T = u32;
pub const ULONGLONG = u64;
pub const KAFFINITY = u64;

pub const WCHAR = u16;

pub const PVOID = ?*anyopaque;
pub const HINSTANCE = ?*anyopaque;
pub const HANDLE = usize;

pub const LPCSTR = ?[*:0]const u8;

pub const PWSTR = ?[*:0]WCHAR;
pub const PCWSTR = ?[*:0]const WCHAR;
pub const LPCWSTR = ?[*:0]const WCHAR;

export fn c_log_impl(function: ?[*:0]u8, file: ?[*:0]u8, line: c_int, msg: ?[*:0]WCHAR) callconv(.Win64) void {
    std.debug.print("{s}: {s}:{d}: {}\n", .{ function, file, line, fmt(msg) });
}

export fn c_panic_impl(function: ?[*:0]u8, file: ?[*:0]u8, line: c_int, msg: ?[*:0]WCHAR) callconv(.Win64) void {
    std.debug.print("{s}: {s}:{d}: {}\n", .{ function, file, line, fmt(msg) });
    @panic("");
}

pub fn Fmt(comptime T: type) type {
    return struct {
        v: T,

        pub fn format(
            self: @This(),
            comptime layout: []const u8,
            opts: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = layout;
            _ = opts;
            switch (T) {
                LPCSTR, PWSTR, LPCWSTR => {
                    if (self.v) |v| {
                        const span = std.mem.span(v);
                        try writer.print("(0x{X}) '", .{@ptrToInt(span.ptr)});
                        for (span) |chr| {
                            if (chr > 0x7F) {
                                try writer.print("\\x{X:0>2}", .{chr});
                            } else {
                                try writer.print("{c}", .{@truncate(u8, chr)});
                            }
                        }
                        try writer.print("'", .{});
                    } else {
                        try writer.print("(null)", .{});
                    }
                },
                BOOL => {
                    if (self.v != FALSE) {
                        try writer.print("TRUE", .{});
                    } else {
                        try writer.print("FALSE", .{});
                    }
                },
                else => @compileError("rt.fmt not implemented for type " ++ @typeName(T) ++ " yet!"),
            }
        }
    };
}

pub fn toNullTerminatedUTF16Buffer(comptime ascii: []const u8) [ascii.len:0]u16 {
    comptime var result: []const u16 = &[_]u16{};
    inline for (ascii) |chr| {
        result = result ++ &[_]u16{chr};
    }
    result = result ++ [_]u16{0};
    return result[0..ascii.len :0].*;
}

pub fn pad(comptime v: anytype, comptime len: usize) [len]@TypeOf(v[0]) {
    return v ++ ([1]@TypeOf(v[0]){0} ** (len - v.len));
}

pub fn fmt(val: anytype) Fmt(@TypeOf(val)) {
    return Fmt(@TypeOf(val)){ .v = val };
}

pub const GUID = @import("guids.zig").GUID;
pub const LPCGUID = ?*const GUID;

pub const EventFilterDescriptor = extern struct {
    ptr: ULONGLONG,
    size: ULONG,
    type: ULONG,
};

pub const EnableCallback = fn (
    source: LPCGUID,
    is_enabled: ULONG,
    level: UCHAR,
    match_any_keyword: ULONGLONG,
    match_all_keyword: ULONGLONG,
    filter_data: ?*EventFilterDescriptor,
    callback_context: PVOID,
) callconv(.Win64) void;

pub const UnicodeString = extern struct {
    length: USHORT,
    capacity: USHORT,
    buffer: ?[*]WCHAR,

    pub fn initFromBuffer(buf: [:0]WCHAR) UnicodeString {
        return .{
            .length = @intCast(USHORT, buf.len << 1),
            .capacity = @intCast(USHORT, buf.len << 1),
            .buffer = buf.ptr,
        };
    }

    pub fn freeCapacity(self: @This()) usize {
        return (self.capacity - self.length) >> 1;
    }

    pub fn makeSpaceFor(self: *@This(), num_chars: usize, alloc: std.mem.Allocator) !void {
        if (self.freeCapacity() < num_chars) {
            const new_capacity = std.math.max(
                (num_chars << 1) + self.length, // new length
                self.capacity << 1, // double capacity
            );
            self.buffer = (try alloc.realloc(self.buffer.?[0 .. self.capacity >> 1], new_capacity >> 1)).ptr;
            self.capacity = @intCast(USHORT, new_capacity);
        }
    }

    pub fn appendAssumeCapacity(self: *@This(), appendage: []const WCHAR) void {
        std.mem.copy(WCHAR, self.buffer.?[self.length >> 1 .. (self.length >> 1) + appendage.len], appendage);
        self.length += @intCast(USHORT, appendage.len << 1);
    }

    pub fn append(self: *@This(), appendage: []const WCHAR, alloc: std.mem.Allocator) !void {
        try self.makeSpaceFor(appendage.len, alloc);
        self.appendAssumeCapacity(appendage);
    }

    pub fn chars(self: @This()) []const WCHAR {
        return self.buffer.?[0 .. self.length >> 1];
    }

    pub fn format(
        self: @This(),
        comptime layout: []const u8,
        opts: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = layout;
        _ = opts;
        if (self.buffer) |buf| {
            const span = buf[0 .. self.length >> 1];
            try writer.print("'", .{});
            for (span) |chr| {
                if (chr > 0x7F) {
                    try writer.print("\\x{X:0>2}", .{chr});
                } else {
                    try writer.print("{c}", .{@truncate(u8, chr)});
                }
            }
            try writer.print("'", .{});
        } else {
            try writer.print("{{ null buf }}", .{});
        }
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
    idk0: u32 = 0x51515151,
    idk1: u32 = 0x53535353,
    wtf: u32 = 0x52525252,
};

const KUserSharedData = extern struct {
    tick_count_low: u32 = 0x40404040,        // 0x0000
    tick_count_multiplier: u32 = 0x40404041, // 0x0004
    interrupt_time: KSystemTime = .{},       // 0x0008
    system_time: KSystemTime = .{},          // 0x0014
    time_zone_bias: KSystemTime = .{},       // 0x0020
    image_number_low: USHORT = 0,            // 0x002C
    image_number_high: USHORT = 42,          // 0x002E
    nt_system_root: [0x104]WCHAR = pad(toNullTerminatedUTF16Buffer("C:\\Windows"), 0x104), // 0x30
    max_stack_trace_depth: ULONG = 20,       // 0x0238
    crypto_exponent: ULONG = 0x10001,        // 0x023C
    time_zone_id: ULONG = 0,                 // 0x0240
    large_page_minimum: ULONG = 0x1000 << 9, // 0x0244
};

pub var pparam: ProcessParameters = undefined;
pub var peb: PEB = undefined;

const TEB = extern struct {
    unk0: [0x30]u8 = undefined, // 0x0000
    self: *TEB,                 // 0x0030
    unk1: [0x8]u8 = undefined,  // 0x0038
    process_id: u32 = 0x5,      // 0x0040
    unk2: [0x1C]u8 = undefined, // 0x0044
    peb: ?*PEB = undefined,     // 0x0060
};

var teb: TEB = .{
    .self = undefined,
};

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

    teb.peb = &peb;
    teb.self = &teb;

    asm volatile ("WRGSBASE %[teb]"
        :
        : [teb] "r" (@ptrToInt(&teb)),
    );

    pparam.image_path_name = UnicodeString.initFromBuffer(image_path_name);
    pparam.command_line = UnicodeString.initFromBuffer(command_line);
    peb.process_parameters = &pparam;
}

pub fn call_entry(entry_point: usize) c_int {
    return @intToPtr(fn (*PEB) callconv(.Win64) c_int, entry_point)(&peb);
}
