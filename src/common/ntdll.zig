const std = @import("std");
const rt = @import("rt.zig");
const guids = @import("guids.zig");
const vfs = @import("vfs.zig");
const tp = @import("tp.zig");

const log = @import("log.zig").scoped(.ntdll);

var rtl_global_heap = std.heap.GeneralPurposeAllocator(.{}){ .backing_allocator = std.heap.page_allocator };

pub fn RtlAllocateHeap(heap_handle: ?*anyopaque, flags: rt.ULONG, size: rt.SIZE_T) callconv(.Win64) ?*anyopaque {
    log("RtlAllocateHeap(handle=0x{X}, flags=0x{X}, size=0x{X})", .{ @ptrToInt(heap_handle), flags, size });
    if (heap_handle) |_| {
        @panic("RtlAllocateHeap with handle");
    }

    const retval = (rtl_global_heap.allocator().alloc(u8, size) catch |err| {
        log("RtlAllocateHeap failed (error.{s})!", .{@errorName(err)});
        return null;
    }).ptr;

    log("RtlAllocateHeap -> 0x{X}", .{@ptrToInt(retval)});
    return retval;
}

pub fn RtlFreeHeap(heap_handle: ?*anyopaque, flags: rt.ULONG, base_addr: ?[*]u8) callconv(.Win64) rt.LOGICAL {
    // TODO: Don't just leak memory here
    log("RtlFreeHeap(handle=0x{X}, flags = 0x{X}, ptr=0x{X})", .{ @ptrToInt(heap_handle), flags, @ptrToInt(base_addr) });
    return rt.TRUE;
}

pub fn NtSetInformationProcess(
    process_handle: rt.HANDLE,
    process_information_class: ProcessInfoClass,
    process_information: rt.PVOID,
    process_information_length: rt.ULONG,
) callconv(.Win64) NTSTATUS {
    log("NtSetInformationProcess(handle=0x{X}, class={s}, info=0x{x}, length={d})", .{ process_handle, @tagName(process_information_class), @ptrToInt(process_information), process_information_length });
    return .SUCCESS;
}

pub fn RtlSetHeapInformation(
    heap_handle: rt.PVOID,
    heap_information_class: HeapInformationClass,
    heap_information: rt.PVOID,
    heap_information_length: rt.SIZE_T,
) callconv(.Win64) NTSTATUS {
    log("RtlSetHeapInformation(handle=0x{X}, class={s}, info=0x{x}, length={d})", .{ @ptrToInt(heap_handle), @tagName(heap_information_class), @ptrToInt(heap_information), heap_information_length });
    return .SUCCESS;
}

const REGHANDLE = u64;

pub fn EtwEventRegister(
    provider_id: rt.LPCGUID,
    callback: rt.EnableCallback,
    callback_context: rt.PVOID,
    result_handle: ?*REGHANDLE,
) callconv(.Win64) Error {
    log("EtwEventRegister(guid={any}, callback=0x{X}, context=0x{x}, result_out=0x{X})", .{ provider_id, @ptrToInt(callback), @ptrToInt(callback_context), @ptrToInt(result_handle) });
    return .SUCCESS;
}

const WmidPRequestCode = enum(u32) {
    GetAllData = 0,
    GetSingleInstance = 1,
    SetSingleInstance = 2,
    SetSingleItem = 3,
    EnableEvents = 4,
    DisableEvents = 5,
    EnableCollection = 6,
    DisableCollection = 7,
    RegInfo = 8,
    ExecuteMethod = 9,
};

const WMidPRequest = *const fn (
    request_code: WmidPRequestCode,
    request_context: rt.PVOID,
    buffer_size: ?*rt.ULONG,
    buffer: rt.PVOID,
) callconv(.Win64) rt.ULONG;

const TraceGuidRegistration = extern struct {
    guid: rt.LPCGUID,
    handle: rt.HANDLE,
};

const TraceHandle = rt.HANDLE;

pub fn EtwRegisterTraceGuidsW(
    request_address: WMidPRequest,
    request_context: rt.PVOID,
    control_guid: rt.LPCGUID,
    guid_count: rt.ULONG,
    trace_guid_registration: ?*TraceGuidRegistration,
    m_of_image_path: rt.LPCWSTR,
    m_of_resource_name: rt.LPCWSTR,
    registration_handle: ?*TraceHandle,
) callconv(.Win64) Error {
    log("EtwRegisterTraceGuidsW(req_addr=0x{X}, req_cont=0x{X}, cguid={any}, guidcnt={}, tguid={any}, imgp={}, mrname={}, rhandle=0x{X})", .{
        @ptrToInt(request_address),
        @ptrToInt(request_context),
        control_guid,
        guid_count,
        trace_guid_registration,
        rt.fmt(m_of_image_path),
        rt.fmt(m_of_resource_name),
        @ptrToInt(registration_handle),
    });
    return .SUCCESS;
}

pub fn TpAllocPool(
    opt_result: ?**tp.ThreadPool,
    reserved: rt.PVOID,
) callconv(.Win64) NTSTATUS {
    const result = opt_result orelse return .INVALID_PARAMETER;
    result.* = tp.allocPool() catch return .NO_MEMORY;
    log("TpAllocPool(0x{X}) -> 0x{X}", .{@ptrToInt(result), @ptrToInt(result.*)});
    _ = reserved;
    return .SUCCESS;
}

pub fn TpAllocWork(
    out_opt: ?**tp.TPWork,
    work_opt: ?tp.Work,
    context: tp.Context,
    env: tp.Environment,
) callconv(.Win64) NTSTATUS {
    log("TpAllocWork(0x{X}, 0x{X})", .{@ptrToInt(out_opt), @ptrToInt(work_opt)});
    const out = out_opt orelse return .INVALID_PARAMETER;
    const work = work_opt orelse return .INVALID_PARAMETER;
    out.* = tp.allocWork(work, context, env) catch return .NO_MEMORY;
    return .SUCCESS;
}

pub fn TpPostWork(
    work_opt: ?*tp.TPWork,
) callconv(.Win64) NTSTATUS {
    const work = work_opt orelse return .INVALID_PARAMETER;
    const env = work.env;
    const pool = env.pool.?;
    pool.addWork(work) catch return .NO_MEMORY;
    return .SUCCESS;
}

pub fn TpWaitForWork(
    work_opt: ?*tp.TPWork,
) callconv(.Win64) NTSTATUS {
    log("TpWaitForWork(0x{X})", .{@ptrToInt(work_opt)});
    (work_opt orelse return .INVALID_PARAMETER).finish_sema.wait();
    return .SUCCESS;
}

pub fn TpReleaseWork(
    work_opt: ?*tp.TPWork,
) callconv(.Win64) NTSTATUS {
    log("TpReleaseWork(0x{X})", .{@ptrToInt(work_opt)});
    if(false) tp.releaseWork(work_opt orelse return .INVALID_PARAMETER);
    return .SUCCESS;
}

pub fn TpSetPoolMinThreads(
    pool: ?*tp.ThreadPool,
    min_threads: rt.ULONG,
) callconv(.Win64) NTSTATUS {
    const p = pool orelse return .INVALID_PARAMETER;
    const num_threads = std.math.max(min_threads, 1);
    log("TpSetPoolMinThreads(0x{X}, {d} (treated as {d}))", .{
        @ptrToInt(p),
        min_threads,
        num_threads,
    });
    p.setNumThreads(num_threads) catch return .NO_MEMORY;
    return .SUCCESS;
}

const JobObjectInfoClass = enum(u32) {
    BasicAccountingInformation = 1,
    BasicLimitInformation = 2,
    BasicProcessIdList = 3,
    BasicUIRestrictions = 4,
    SecurityLimitInformation = 5,
    EndOfJobTimeInformation = 6,
    AssociateCompletionPortInformation = 7,
    BasicAndIoAccountingInformation = 8,
    ExtendedLimitInformation = 9,
    JobSetInformation = 10,
    GroupInformation = 11,
    NotificationLimitInformation = 12,
    LimitViolationInformation = 13,
    GroupInformationEx = 14,
    CpuRateControlInformation = 15,
    CompletionFilter = 16,
    CompletionCounter = 17,

    NetRateControlInformation = 32,
    JobObjectNotificationLimitInformation2 = 33,
    JobObjectLimitViolationInformation2 = 34,
    JobObjectCreateSilo = 35,
    JobObjectSiloBasicInformation = 36,

    Unk_39 = 39,
};

pub fn NtQueryInformationJobObject(
    handle: rt.HANDLE,
    class: JobObjectInfoClass,
    len: rt.ULONG,
    ret_len: ?*rt.ULONG,
) callconv(.Win64) NTSTATUS {
    log("NtQueryInformationJobObject(handle=0x{X}, class={s}, len=0x{x}, ret_len={any})", .{ handle, @tagName(class), len, ret_len });
    return .SUCCESS;
}

var rtl_unicode_string_heap = std.heap.GeneralPurposeAllocator(.{}){ .backing_allocator = std.heap.page_allocator };

pub fn RtlInitUnicodeStringEx(
    dest: ?*rt.UnicodeString,
    src: rt.PCWSTR,
) callconv(.Win64) NTSTATUS {
    log("RtlInitUnicodeStringEx({})", .{rt.fmt(src)});
    const str = src orelse {
        var buf = [_]u16{};
        (dest orelse return .INVALID_PARAMETER).* = rt.UnicodeString.initFromBuffer(&buf);
        return .SUCCESS;
    };
    (dest orelse return .INVALID_PARAMETER).* =
        rt.UnicodeString.initFromBuffer(rtl_unicode_string_heap.allocator().dupeZ(u16, std.mem.span(str)) catch return .NO_MEMORY);
    return .SUCCESS;
}

pub fn RtlInitUnicodeString(
    dest: ?*rt.UnicodeString,
    src: rt.PCWSTR,
) callconv(.Win64) void {
    if (RtlInitUnicodeStringEx(dest, src) != .SUCCESS) {
        log("RtlInitUnicodeString: RtlInitUnicodeStringEx failed!", .{});
    }
}

pub fn RtlGetNtSystemRoot(
) callconv(.Win64) [*:0]const u16 {
    return std.unicode.utf8ToUtf16LeStringLiteral("C:\\");
}

pub fn RtlSetThreadIsCritical(
    new_value: rt.BOOL,
    old_value: ?*rt.BOOL,
    check_flag: rt.BOOL,
) callconv(.Win64) NTSTATUS {
    if (old_value) |o| o.* = rt.FALSE;
    log("RtlSetThreadIsCritical({},check_flag={})", .{ rt.fmt(new_value), rt.fmt(check_flag) });
    return .SUCCESS;
}

pub fn RtlCreateTagHeap(
    heap_handle: rt.HANDLE,
    flags: rt.ULONG,
    tag_name: rt.PWSTR,
    tag_sub_name: rt.PWSTR,
) callconv(.Win64) Error {
    log("RtlCreateTagHeap(handle=0x{X}, flags=0x{X}, tag_name={}, tag_sub_name={})", .{ heap_handle, flags, rt.fmt(tag_name), rt.fmt(tag_sub_name) });
    return .SUCCESS;
}

fn giveSystemInfo(ret_ptr: rt.PVOID, ret_max_size: rt.ULONG, ret_out_size: ?*rt.ULONG, comptime T: type) NTSTATUS {
    const copy_size = std.math.min(@sizeOf(T), ret_max_size);
    if (ret_out_size) |out|
        out.* = @intCast(rt.ULONG, @sizeOf(T));

    if (ret_ptr) |p| {
        @memcpy(@ptrCast([*]u8, p), @intToPtr([*]const u8, @ptrToInt(&T{})), copy_size);
    }

    if (ret_max_size < @sizeOf(T)) {
        return .INFO_LENGTH_MISMATCH;
    } else {
        return .SUCCESS;
    }
}

var manufacturer_profile_name = std.unicode.utf8ToUtf16LeStringLiteral("Champagne-SYSTEM").*;

pub fn NtQuerySystemInformation(
    class: SystemInformationClass,
    ret_ptr: rt.PVOID,
    ret_max_size: rt.ULONG,
    ret_out_size: ?*rt.ULONG,
) callconv(.Win64) NTSTATUS {
    log("NtQuerySystemInformation(class=0x{X})", .{@enumToInt(class)});
    log("NtQuerySystemInformation(class=0x{X} ('{s}'), max_size=0x{X})", .{ @enumToInt(class), @tagName(class), ret_max_size });
    return switch (class) {
        .Basic => giveSystemInfo(ret_ptr, ret_max_size, ret_out_size, extern struct {
            reserved: rt.ULONG = 0,
            timer_resolution: rt.ULONG = 1_000_000_000,
            page_size: rt.ULONG = 0x1000,
            number_of_physical_pages: rt.ULONG = 1729,
            lowest_physical_page_number: rt.ULONG = 1,
            highest_physical_page_number: rt.ULONG = 1729,
            allocation_granularity: rt.ULONG = 8,
            minimum_user_mode_address: usize = 0x10000,
            maximum_user_mode_address: usize = 0x7ff80000,
            active_processors_affinity_mask: usize = 1 << 0,
            number_of_processors: usize = 1,
        }),
        .Processor => giveSystemInfo(ret_ptr, ret_max_size, ret_out_size, extern struct {
            architecture: enum(u16) {
                intel = 0,
                i286 = 2,
                i386 = 3,
                i486 = 4,
                i586_pentium = 5,

                amd = 9,
            } = .i586_pentium,

            level: u16 = 0xD0,
            revision: u16 = 5,
            maximum_processors: u16 = 1,
            feature_bits: u32 = 0,
        }),
        .NumaProcessorMap => giveSystemInfo(ret_ptr, ret_max_size, ret_out_size, extern struct {
            const MAXIMUM_NODE_COUNT = 0x40;

            const GroupAffinity = extern struct {
                mask: rt.KAFFINITY = 1,
                group: rt.WORD = 0,
                reserved: [3]rt.WORD = undefined,
            };

            highest_node_number: rt.ULONG = 1,
            reserved: rt.ULONG = undefined,
            aff: [MAXIMUM_NODE_COUNT]GroupAffinity = [1]GroupAffinity{.{}} ++ ([1]GroupAffinity{undefined} ** (MAXIMUM_NODE_COUNT - 1)),

            comptime {
                if (@sizeOf(@This()) != 0x408) @compileError("wtf");
            }
        }),
        .FirmwareTableInformation => giveSystemInfo(ret_ptr, ret_max_size, ret_out_size, extern struct {
            provider: [4]u8 = "CHMP".*, // Champagne
            action: u32 = 0,
            table_id: [4]u8 = "XSDT".*,
            table_buffer_len: rt.ULONG = 4,
            table_buffer: [4]u8 = "XSDT".*,
        }),
        .SystemManufacturingInformation => giveSystemInfo(ret_ptr, ret_max_size, ret_out_size, extern struct {
            options: rt.ULONG = 0,
            profile_name: rt.UnicodeString = rt.UnicodeString.initFromBuffer(&manufacturer_profile_name),
        }),
    };
}

const ConditionVariable = std.Thread.Condition;
const Mutex = std.Thread.Mutex;

comptime {
    std.debug.assert(@sizeOf(Mutex) <= 8);
    std.debug.assert(@sizeOf(ConditionVariable) <= 8);
}

pub fn RtlInitializeSRWLock(
    lock: ?*Mutex,
) callconv(.Win64) void {
    //log("RtlInitializeSRWLock(0x{X})", .{@ptrToInt(lock)});
    lock.?.* = .{};
}

pub fn RtlAcquireSRWLockExclusive(
    lock: ?*Mutex,
) callconv(.Win64) void {
    log("RtlAcquireSRWLockExclusive(0x{X})", .{@ptrToInt(lock)});
    lock.?.lock();
}

pub fn RtlReleaseSRWLockExclusive(
    lock: ?*Mutex,
) callconv(.Win64) void {
    log("RtlReleaseSRWLockExclusive(0x{X})", .{@ptrToInt(lock)});
    lock.?.unlock();
}

pub fn RtlAcquireSRWLockShared(
    lock: ?*Mutex,
) callconv(.Win64) void {
    log("RtlAcquireSRWLockShared(0x{X})", .{@ptrToInt(lock)});
    lock.?.lock();
}

pub fn RtlReleaseSRWLockShared(
    lock: ?*Mutex,
) callconv(.Win64) void {
    log("RtlReleaseSRWLockShared(0x{X})", .{@ptrToInt(lock)});
    lock.?.unlock();
}

pub fn RtlInitializeConditionVariable(
    out_cvar: ?*ConditionVariable,
) callconv(.Win64) void {
    log("RtlInitializeConditionVariable(0x{X})", .{@ptrToInt(out_cvar)});
    out_cvar.?.* = .{};
}

pub fn RtlSleepConditionVariableSRW(
    condvar: ?*ConditionVariable,
    lock: ?*Mutex,
    timeout: rt.LARGEINT,
    flags: rt.ULONG,
) callconv(.Win64) NTSTATUS {
    log("RtlSleepConditionVariableSRW({d})", .{timeout});
    _ = flags;
    if(timeout == 0) {
        condvar.?.timedWait(lock.?, ~@as(usize, 0)) catch return .INVALID_PARAMETER;
    } else {
        condvar.?.timedWait(lock.?, @intCast(usize, timeout)) catch return .INVALID_PARAMETER;
    }
    return .SUCCESS;
}

pub fn RtlWakeAllConditionVariable(
    condvar: ?*ConditionVariable,
) callconv(.Win64) NTSTATUS {
    (condvar orelse return .INVALID_PARAMETER).broadcast();
    return .SUCCESS;
}

pub fn RtlAdjustPrivilege(
    priv: Privilege,
    enable: rt.BOOL,
    current_thread: rt.BOOL,
    enabled: ?*rt.BOOL,
) callconv(.Win64) NTSTATUS {
    log("RtlAdjustPrivilege(priv={s}, enable=0x{X})", .{ @tagName(priv), enable });
    _ = current_thread;
    if (enabled) |e| e.* = rt.TRUE;
    switch (priv) {
        .Shutdown => return .SUCCESS,
        else => return .INVALID_PARAMETER,
    }
}

pub fn NtRaiseHardError(
    error_status: NTSTATUS,
    num_params: rt.ULONG,
    unicode_string_parameter_mask: ?*rt.UnicodeString,
    params: rt.PVOID,
    response_option: HardErrorResponseOption,
    response: ?*HardErrorResponse,
) callconv(.Win64) NTSTATUS {
    _ = params;
    _ = unicode_string_parameter_mask;
    log("NtRaiseHardError(status=0x{X}, ropt=0x{X})", .{ @enumToInt(error_status), @enumToInt(response_option) });
    log("NtRaiseHardError(status={s}, params={d}, ropt={s})", .{ @tagName(error_status), num_params, @tagName(response_option) });
    if (response) |r| r.* = .NotHandled;
    return .SUCCESS;
}

pub fn NtTerminateProcess(
    process_handle: rt.HANDLE,
    exit_status: NTSTATUS,
) callconv(.Win64) NTSTATUS {
    log("NtTerminateProcess(handle=0x{X}, status='{s}')", .{ process_handle, @tagName(exit_status) });
    std.os.exit(0);
}

pub fn RtlNormalizeProcessParams(
) callconv(.Win64) NTSTATUS {
    log("RtlNormalizeProcessParams: Nothing to do under champagne", .{});
    return .SUCCESS;
}

pub fn NtAlpcCreatePort(
    opt_port_handle: ?*rt.HANDLE,
    opt_object_attributes: ?*ObjectAttributes,
    opt_port_attributes: rt.PVOID, // ?*PortAttributes,
) callconv(.Win64) NTSTATUS {
    log("STUB: NtAlpcCreatePort({any})", .{opt_object_attributes});
    _ = opt_port_attributes;
    const port_handle = opt_port_handle orelse return .INVALID_PARAMETER;
    _ = port_handle;
    return .SUCCESS;
}

pub fn NtOpenDirectoryObject(
    opt_dir_handle: ?*rt.HANDLE,
    desired_access: AccessMask,
    opt_object_attributes: ?*ObjectAttributes,
) callconv(.Win64) NTSTATUS {
    log("NtOpenDirectoryObject({any})", .{opt_object_attributes});
    const n = resovleAttrs(opt_object_attributes, true) orelse return .INVALID_PARAMETER;
    defer vfs.close(n);
    if(opt_dir_handle) |handle_out| {
        handle_out.* = vfs.handle(n);
    }
    _ = desired_access;
    return .SUCCESS;
}

pub fn NtCreateMutant(
    opt_handle: ?*rt.HANDLE,
    desired_access: AccessMask,
    opt_object_attributes: ?*ObjectAttributes,
    initial_owner: rt.BOOL,
) callconv(.Win64) NTSTATUS {
    const n = resovleAttrs(opt_object_attributes, true) orelse return .INVALID_PARAMETER;
    defer vfs.close(n);
    const mutex = n.get(.mutex) orelse return .INVALID_PARAMETER;
    if(initial_owner != 0) {
        mutex.lock();
    }
    if(opt_handle) |out| {
        out.* = vfs.handle(n);
    }
    _ = desired_access;
    return .SUCCESS;
}

pub fn NtOpenKey(
    opt_handle: ?*rt.HANDLE,
    desired_access: AccessMask,
    opt_object_attributes: ?*ObjectAttributes,
) callconv(.Win64) NTSTATUS {
    log("STUB: NtOpenKey({any})", .{opt_object_attributes});
    const n = resovleAttrs(opt_object_attributes, true) orelse return .INVALID_PARAMETER;
    defer vfs.close(n);
    _ = n.get(.dir);
    if(opt_handle) |out| {
        out.* = vfs.handle(n);
    }
    _ = desired_access;
    return .SUCCESS;
}

pub fn NtCreateKey(
    opt_handle: ?*rt.HANDLE,
    desired_access: AccessMask,
    opt_object_attributes: ?*ObjectAttributes,
    title_index: rt.ULONG,
    class: ?*rt.UnicodeString,
    create_options: rt.ULONG,
    disposition: ?*rt.ULONG,
) callconv(.Win64) NTSTATUS {
    log("STUB: NtCreateKey({any})", .{opt_object_attributes});
    const n = resovleAttrs(opt_object_attributes, true) orelse return .INVALID_PARAMETER;
    defer vfs.close(n);
    _ = n.get(.dir);
    if(opt_handle) |out| {
        out.* = vfs.handle(n);
    }
    _ = desired_access;
    _ = title_index;
    _ = class;
    _ = create_options;
    _ = disposition;
    return .SUCCESS;
}

pub fn NtCreateDirectoryObject(
    opt_handle: ?*rt.HANDLE,
    desired_access: AccessMask,
    opt_object_attributes: ?*ObjectAttributes,
) callconv(.Win64) NTSTATUS {
    log("STUB: NtCreateDirectoryObject({any})", .{opt_object_attributes});
    const n = resovleAttrs(opt_object_attributes, true) orelse return .INVALID_PARAMETER;
    defer vfs.close(n);
    _ = n.get(.dir);
    if(opt_handle) |out| {
        out.* = vfs.handle(n);
    }
    _ = desired_access;
    return .SUCCESS;
}

pub fn NtCreateFile(
    opt_handle: ?*rt.HANDLE,
    desired_access: AccessMask,
    opt_object_attributes: ?*ObjectAttributes,
    io_status_block: rt.PVOID,
    allocation_size: ?*rt.LARGEINT,
    file_attrs: rt.ULONG,
    share_access: rt.ULONG,
    create_disposition: rt.ULONG,
    create_options: rt.ULONG,
    ea_buffer: rt.PVOID,
    ea_length: rt.ULONG,
) callconv(.Win64) NTSTATUS {
    _ = opt_handle;
    _ = desired_access;
    log("STUB: NtCreateFile({any})", .{opt_object_attributes});
    _ = io_status_block;
    _ = allocation_size;
    _ = file_attrs;
    _ = share_access;
    _ = create_disposition;
    _ = create_options;
    _ = ea_buffer;
    _ = ea_length;
    return .SUCCESS;
}

pub fn NtOpenFile(
    opt_handle: ?*rt.HANDLE,
    desired_access: AccessMask,
    opt_object_attributes: ?*ObjectAttributes,
    io_status_block: rt.PVOID,
    share_access: rt.ULONG,
    open_options: rt.ULONG,
) callconv(.Win64) NTSTATUS {
    _ = opt_handle;
    _ = desired_access;
    log("STUB: NtOpenFile({any})", .{opt_object_attributes});
    _ = io_status_block;
    _ = share_access;
    _ = open_options;
    return .SUCCESS;
}

pub fn NtCreateSection(
    opt_handle: ?*rt.HANDLE,
    desired_access: AccessMask,
    opt_object_attributes: ?*ObjectAttributes,
    max_size: ?*rt.LARGEINT,
    section_page_protection: rt.ULONG,
    allocation_attributes: rt.ULONG,
    file_handle: rt.ULONG,
) callconv(.Win64) NTSTATUS {
    const size = @intCast(usize, (max_size orelse return .INVALID_PARAMETER).*);
    _ = desired_access;
    _ = section_page_protection;
    _ = allocation_attributes;
    log("STUB: NtCreateSection({any}, 0x{X}, 0x{X})", .{opt_object_attributes, file_handle, size});
    std.debug.assert(opt_object_attributes == null or opt_object_attributes.?.name == null);
    std.debug.assert(file_handle == 0);
    if(opt_handle) |h| {
        h.* = @intCast(rt.HANDLE, std.os.memfd_createZ("NtCreateSection", 0) catch return .NO_MEMORY);
        log("-> Returning linux memfd {d} with size 0x{X}", .{h.*, size});
        std.os.ftruncate(@intCast(i32, h.*), size) catch unreachable;
        h.* |= @intCast(rt.HANDLE, size << 32);
    } else {
        unreachable;
    }
    return .SUCCESS;
}

var section_view_map: std.AutoHashMapUnmanaged(usize, usize) = .{};
var section_view_alloc = std.heap.GeneralPurposeAllocator(.{}){ .backing_allocator = std.heap.page_allocator };

pub fn NtAllocateVirtualMemory(
    process_handle: rt.HANDLE,
    base_addr: *usize,
    zero_bits: usize,
    region_size: *usize,
    allocation_type: rt.ULONG,
    protection: rt.ULONG,
) callconv(.Win64) NTSTATUS {
    _ = process_handle;
    _ = allocation_type;
    _ = protection;
    log("NtAllocateVirtualMemory(baddr=0x{X}, zero_bits={d}, region_size=0x{X})", .{
        base_addr.*,
        zero_bits,
        region_size.*,
    });
    std.debug.assert(zero_bits == 0);

    base_addr.* = rt.alignPageUp(base_addr.*);

    const result = std.os.mmap(
        @intToPtr(?[*]align(0x1000) u8, base_addr.*),
        region_size.*,
        std.os.PROT.READ | std.os.PROT.WRITE,
        std.os.MAP.ANONYMOUS | std.os.MAP.PRIVATE,
        -1,
        0,
    ) catch return .NO_MEMORY;

    region_size.* = result.len;
    base_addr.* = @ptrToInt(result.ptr);

    log("NtAllocateVirtualMemory -> 0x{}", .{base_addr.*});

    return .SUCCESS;
}

pub fn NtMapViewOfSection(
    section_handle: rt.HANDLE,
    process_handle: rt.HANDLE,
    base_addr_opt: ?*?[*]align(0x1000) u8,
    zero_bits: rt.ULONG,
    commit_size: rt.ULONG,
    section_offset_opt: ?*rt.LARGEINT,
    view_size_opt: ?*rt.ULONG,
    inherit_dispotision: c_int,
    allocation_type: rt.ULONG,
    protect: rt.ULONG,
) callconv(.Win64) NTSTATUS {
    const base_addr = base_addr_opt orelse return .INVALID_PARAMETER;
    const section_offset_value = if(section_offset_opt) |so| so.* else 0;

    _ = process_handle;

    const fd = @truncate(u32, section_handle);
    const view_size_value = rt.alignPageUp(@truncate(u32, section_handle >> 32));

    log("NtMapViewOfSection(fd=0x{X}, base=0x{X}, size=0x{X}, offset=0x{X})", .{
        fd,
        @ptrToInt(base_addr.*),
        view_size_value,
        section_offset_value,
    });

    const mem = std.os.mmap(
        base_addr.*,
        view_size_value,
        std.os.PROT.READ | std.os.PROT.WRITE,
        std.os.MAP.SHARED,
        @intCast(i32, fd),
        @intCast(usize, section_offset_value),
    ) catch return .NO_MEMORY;

    section_view_map.putNoClobber(
        section_view_alloc.allocator(),
        @ptrToInt(mem.ptr),
        view_size_value,
    ) catch {
        std.os.munmap(mem);
        return .NO_MEMORY;
    };

    log("-> returning mmap ptr 0x{x}", .{@ptrToInt(mem.ptr)});
    base_addr.* = mem.ptr;
    if(section_offset_opt) |so| {
        so.* = section_offset_value;
    }
    if(view_size_opt) |sz| {
        sz.* = @intCast(u32, view_size_value);
    }

    _ = protect;
    _ = allocation_type;
    _ = inherit_dispotision;
    _ = commit_size;
    _ = zero_bits;

    return .SUCCESS;
}

pub fn NtUnmapViewOfSection(
    process_handle: rt.HANDLE,
    base_addr: usize,
) callconv(.Win64) NTSTATUS {
    _ = process_handle;
    log("NtUnmapViewOfSection(0x{X})", .{base_addr});
    if(section_view_map.get(base_addr)) |size| {
        log("-> Mapping of size 0x{X} found", .{size});
        std.debug.assert(section_view_map.remove(base_addr));
        std.os.munmap(@intToPtr([*]align(0x1000)u8, base_addr)[0..size]);
        return .SUCCESS;
    }
    log("-> No mapping found!!", .{});
    return .INVALID_PARAMETER;
}

pub fn NtDeleteValueKey(
    key_handle: rt.HANDLE,
    value_name: ?*rt.UnicodeString,
) callconv(.Win64) NTSTATUS {
    log("STUB: NtDeleteValueKey(0x{X}, {any})", .{key_handle, value_name});
    return .SUCCESS;
}

pub fn NtSetValueKey(
    key_handle: rt.HANDLE,
    value_name_opt: ?*rt.UnicodeString,
    index: rt.ULONG,
    kind: RegistryValueKind,
    data: rt.PVOID,
    data_size: rt.ULONG,
) callconv(.Win64) NTSTATUS {
    log("STUB: NtSetValueKey(0x{X}, {any}, {s})", .{key_handle, value_name_opt, @tagName(kind)});
    const key = vfs.openHandle(key_handle);
    defer vfs.close(key);
    const dir = key.get(.dir) orelse return .INVALID_PARAMETER;
    const value_name = value_name_opt orelse return .INVALID_PARAMETER;
    const value = vfs.resolve16In(dir, value_name.chars() orelse return .INVALID_PARAMETER, true) catch return .NO_MEMORY;
    var u8dbgbuf: [4096]u8 = undefined;
    _ = u8dbgbuf;

    switch(kind) {
        .Symlink => {
            const data16 = @ptrCast([*]const u16, @alignCast(2, data))[0..@divExact(data_size, 2)];
            //log("-> Link value: '{s}'", .{u8dbgbuf[0..std.unicode.utf16leToUtf8(&u8dbgbuf, data16) catch unreachable]});
            value.setSymlinkDyn(data16) catch return .NO_MEMORY;
        },
        .String => {
            const data16 = @ptrCast([*]const u16, @alignCast(2, data))[0..@divExact(data_size, 2)];
            //log("-> String value: '{s}'", .{u8dbgbuf[0..std.unicode.utf16leToUtf8(&u8dbgbuf, data16) catch unreachable]});
            value.setStringDyn(data16) catch return .NO_MEMORY;
        },
        else => @panic("Bad key type!"),
    }
    _ = index;
    return .SUCCESS;
}

pub fn NtQueryValueKey(
    key_handle: rt.HANDLE,
    value_name_opt: ?*rt.UnicodeString,
    information_class: ValueInformationClass,
    info: rt.PVOID,
    info_capacity: rt.ULONG,
    result_len: *rt.ULONG,
) callconv(.Win64) NTSTATUS {
    _ = info;
    _ = info_capacity;
    _ = result_len;
    log("STUB: NtQueryValueKey(0x{X}, {any}, {s})", .{key_handle, value_name_opt, @tagName(information_class)});
    return .SUCCESS;
}

fn resovleAttrs(attrs_opt: ?*ObjectAttributes, create_deep: bool) ?*vfs.DirectoryEntry {
    const attrs = attrs_opt orelse return null;
    const name = attrs.name orelse return null;
    const path = name.chars() orelse return null;
    if(attrs.root_dir == 0) {
        return vfs.resolve16(path, create_deep) catch return null;
    } else {
        const root = vfs.openHandle(attrs.root_dir);
        const root_dir = root.get(.dir) orelse {
            vfs.close(root);
            return null;
        };
        return vfs.resolve16In(root_dir, path, create_deep) catch {
            vfs.close(root);
            return null;
        };
    }
}

pub fn NtOpenSymbolicLinkObject(
    opt_handle: ?*rt.HANDLE,
    desired_access: AccessMask,
    opt_object_attributes: ?*ObjectAttributes,
) callconv(.Win64) NTSTATUS {
    log("STUB: NtOpenSymbolicLinkObject({any})", .{opt_object_attributes});
    const link = resovleAttrs(opt_object_attributes, true) orelse return .INVALID_PARAMETER;
    defer vfs.close(link);
    _ = link.get(.symlink);
    if(opt_handle) |oh| {
        oh.* = vfs.handle(link);
    }
    _ = desired_access;
    return .SUCCESS;
}

pub fn NtQuerySymbolicLinkObject(
    link_handle: rt.HANDLE,
    link_target_opt: ?*rt.UnicodeString,
    out_length: ?*rt.ULONG,
) callconv(.Win64) NTSTATUS {
    log("NtQuerySymbolicLinkObject(0x{X})", .{link_handle});
    const link_dirent = vfs.openHandle(link_handle);
    defer vfs.close(link_dirent);
    const link = link_dirent.get(.symlink) orelse @panic("Not a symlink!");
    const buf_len = if(link_target_opt) |target| target.capacity else 0;

    log("-> Valid symlink of length {d}, buffer size is {d}", .{link.len, buf_len});

    if(out_length) |ol| ol.* = @intCast(rt.ULONG, link.len);
    if(link.len > buf_len) return .BUFFER_TOO_SMALL;

    const link_target = link_target_opt orelse return .INVALID_PARAMETER;
    const data_ptr = link_target.buffer orelse return .INVALID_PARAMETER;
    std.mem.copy(u16, data_ptr[0..link.len], link.*);
    link_target.length = @intCast(u16, link.len);
    return .SUCCESS;
}

var utf16_buffer: [2048]u16 = undefined;

pub fn NtQueryDirectoryObject(
    dir_handle: rt.HANDLE,
    buffer: ?*u16,
    buf_len: rt.ULONG,
    return_single_entry: rt.BOOL,
    restart_scan: rt.BOOL,
    context_opt: ?*rt.ULONG,
    return_length: ?*rt.ULONG,
) callconv(.Win64) NTSTATUS {
    std.debug.assert(return_single_entry != 0);
    const context = context_opt orelse return .INVALID_PARAMETER;

    log("NtQueryDirectoryObject(0x{X}, 0x{X})", .{dir_handle, @ptrToInt(return_length)});

    const dh = vfs.openHandle(dir_handle);
    defer vfs.close(dh);

    if(restart_scan != 0) context.* = 0;
    var idx = context.*;

    var dirent = dh.next;
    while(idx != 0) : (idx -= 1) {
        std.debug.assert(dirent != -1);
        dirent = vfs.dirents.items[@intCast(usize, dirent)].next;
    }

    if(dirent == -1) {
        return .INFO_NO_MORE_ENTRIES;
    }

    if(true) @panic("TODO: NtQueryDirectoryObject ents");

    _ = buffer;
    _ = buf_len;

    context.* += 1;
    return .MORE_ENTRIES;
}

pub fn NtOpenEvent(
    opt_handle: ?*rt.HANDLE,
    desired_access: AccessMask,
    opt_object_attributes: ?*ObjectAttributes,
) callconv(.Win64) NTSTATUS {
    log("STUB: NtOpenEvent({any})", .{opt_object_attributes});
    _ = opt_handle;
    _ = desired_access;
    return .SUCCESS;
}

pub fn NtCreateEvent(
    opt_handle: ?*rt.HANDLE,
    desired_access: AccessMask,
    opt_object_attributes: ?*ObjectAttributes,
    event_type: rt.ULONG,
    initial_state: rt.BOOL,
) callconv(.Win64) NTSTATUS {
    log("STUB: NtCreateEvent({any})", .{opt_object_attributes});
    _ = opt_handle;
    _ = desired_access;
    _ = event_type;
    _ = initial_state;
    return .SUCCESS;
}

pub fn NtClose(
    handle: rt.HANDLE,
) callconv(.Win64) NTSTATUS {
    log("STUB: NtClose(0x{X})", .{handle});
    return .SUCCESS;
}

pub fn NtDuplicateObject(
    source_process: rt.HANDLE,
    source_handle: rt.HANDLE,
    target_process: rt.HANDLE,
    target_handle_opt: ?*rt.HANDLE,
    desired_access: AccessMask,
    inherit_handle: rt.BOOL,
    options: rt.ULONG,
) callconv(.Win64) NTSTATUS {
    log("STUB: NtDuplicateObject(0x{X})", .{source_handle});
    _ = source_process;
    _ = target_process;

    _ = desired_access;
    _ = inherit_handle;
    _ = options;

    const target_handle = target_handle_opt orelse return .INVALID_PARAMETER;
    target_handle.* = source_handle;
    return .SUCCESS;
}

pub fn RtlCreateEnvironment(
    inherit: rt.BOOL,
    env: ?*rt.PCWSTR,
) callconv(.Win64) NTSTATUS {
    _ = inherit;
    _ = env;
    // log("STUB: RtlCreateEnvironment({}, {s})", .{inherit != 0, env});
    return .SUCCESS;
}

const ObjectAttributes = extern struct {
    length: rt.ULONG,
    root_dir: rt.HANDLE,
    name: ?*rt.UnicodeString,
    attributes: rt.ULONG,
    security_descriptor: ?*SecurityDescriptor,
    security_qos: rt.PVOID,

    pub fn format(
        self: @This(),
        comptime layout: []const u8,
        opts: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = layout;
        _ = opts;
        try writer.print("Attribs{{ .root_dir=0x{X}, name={any} }}", .{
            self.root_dir,
            self.name,
        });
    }
};

const Error = enum(rt.ULONG) {
    SUCCESS = 0x00000000,
};

pub const NTSTATUS = enum(u32) {
    SUCCESS = 0x00000000,
    MORE_ENTRIES = 0x00000105,

    INFO_NO_MORE_ENTRIES = 0x8000001A,

    INFO_LENGTH_MISMATCH = 0xC0000004,
    INVALID_PARAMETER = 0xC000000D,
    NO_MEMORY = 0xC0000017,
    BUFFER_TOO_SMALL = 0xC0000023,
    SYSTEM_PROCESS_TERMINATED = 0xC000021A,
};

const AccessMask = rt.DWORD;

const SecurityDescriptor = extern struct {
    revision: u8,
    sbz1: u8 = 0,
    control: SecurityDescriptorControl = 0,
    owner: ?*SecurityIdentifier = null,
    group: ?*SecurityIdentifier = null,
    sacl: ?*AccessControlList = null,
    dacl: ?*AccessControlList = null,
};

const SecurityDescriptorControl = rt.WORD;

const SecurityIdentifier = extern struct {
    revision: u8,
    sub_authority_count: u8 = 0,
    identifier_authority: SecurityIdentifierAuthority = undefined,
    sub_authorities: [8]rt.ULONG = undefined,

    pub fn size(self: @This()) u8 {
        return @offsetOf(@This(), "sub_authorities") + @sizeOf(rt.ULONG) * self.sub_authority_count;
    }

    pub fn format(
        self: @This(),
        comptime layout: []const u8,
        opts: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = layout;
        _ = opts;
        try writer.print("SecurityIdentifier{{ .revision = {d}, .identifier_authority = {any}, .sub = {any}", .{
            self.revision,
            self.identifier_authority,
            self.sub_authorities[0..self.sub_authority_count],
        });
    }
};

const SecurityIdentifierAuthority = [6]u8;

const AccessControlList = extern struct {
    revision: u8,
    sbz1: u8,
    acl_size: rt.WORD,
    ace_count: rt.WORD,
    sbz2: rt.WORD,
};

const AccessControlListEntry = extern struct {
    const Type = enum(u8) {
        allowed = 0,
        // denied = 1,
        // system_audit = 2,
        // system_alarm = 3,
        // allowed_compound = 4,
        // allowed_object = 5,
        // denied_object = 6,
        // system_audit_object = 7,
        // system_alarm_object = 8,
        allowed_callback = 9,
        // denied_callback = 10,
        allowed_callback_object = 11,
        // denied_callback_object = 12,
        // system_audit_callback = 13,
        // system_alarm_callback = 14,
        // system_audit_callback_object = 15,
        // system_alarm_callback_object = 16,
    };

    type: Type,
    num_bytes: u8,
    flags: rt.DWORD,

    u: extern union {
        allowed: extern struct {
            mask: AccessMask,
            sid: SecurityIdentifier,
        },
        allowed_callback: extern struct {
            mask: AccessMask,
            sid: SecurityIdentifier,
        },
        allowed_callback_object: extern struct {
            mask: AccessMask,
            flags: rt.DWORD,
            object_type: rt.GUID,
            inherited_object_type: rt.GUID,
            sid: SecurityIdentifier,
        },
    },

    pub fn size(self: *@This()) u8 {
        inline for (@typeInfo(Type).Enum.fields) |f| {
            if (@enumToInt(self.type) == f.value) {
                return @offsetOf(@This(), "u") + @sizeOf(@TypeOf(@field(self.u, f.name))) - @sizeOf(SecurityIdentifier) + @field(self.u, f.name).sid.size();
            }
            unreachable;
        }
    }

    pub fn format(
        self: @This(),
        comptime layout: []const u8,
        opts: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = layout;
        _ = opts;
        try writer.print("AccessControlListEntry{{ .flags = 0x{X}, .type = {d} }}", .{ self.flags, @enumToInt(self.type) });
    }
};

const HardErrorResponseOption = enum(u32) {
    AbortRetryIgnore,
    Ok,
    OkCancel,
    RetryCancel,
    YesNo,
    YesNoCancel,
    ShutdownSystem,
};

const HardErrorResponse = enum(u32) {
    ReturnToCaller,
    NotHandled,
    Abort,
    Cancel,
    Ignore,
    No,
    Ok,
    Retry,
    Yes,
};

const RegistryValueKind = enum(rt.ULONG) {
    Unknown = 0,
    String = 1,
    ExpandString = 2,
    Binary = 3,
    DWord = 4,
    DWordBigEndian = 5,
    Symlink = 6,
    MultiString = 7,
    ResourceList = 8,
    FullResourceDescription = 9,
    ResourceRequirementsList = 10,
    QWord = 11,
    None = ~@as(rt.ULONG, 0),
};

const ValueInformationClass = enum(rt.ULONG) {
    Basic = 0,
    Full = 1,
    Partial = 2,
    FullAlign64 = 3,
    PartialAlign64 = 4,
    Layer = 5,
};

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/class.htm
// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/basic.htm?ts=0,200
const SystemInformationClass = enum(u32) {
    Basic = 0x00,
    Processor = 0x01,
    //Performance = 2,
    NumaProcessorMap = 0x37,
    FirmwareTableInformation = 0x4C,
    SystemManufacturingInformation = 0x9D,
};

const Privilege = enum(rt.ULONG) {
    CreateToken = 1,
    AssignPrimaryToken = 2,
    LockMemory = 3,
    IncreaseQuota = 4,
    UnsolicitedInput = 5,
    MachineAccount = 6,
    Tcb = 7,
    Security = 8,
    TakeOwnership = 9,
    LoadDriver = 10,
    SystemProfile = 11,
    Systemtime = 12,
    ProfileSingleProcess = 13,
    IncreaseBasePriority = 14,
    CreatePagefile = 15,
    CreatePermanent = 16,
    Backup = 17,
    Restore = 18,
    Shutdown = 19,
    Debug = 20,
    Audit = 21,
    SystemEnvironment = 22,
    ChangeNotify = 23,
    RemoteShutdown = 24,
    Undock = 25,
    SyncAgent = 26,
    EnableDelegation = 27,
    ManageVolume = 28,
    Impersonate = 29,
    CreateGlobal = 30,
    TrustedCredManAccess = 31,
    Relabel = 32,
    IncreaseWorkingSet = 33,
    TimeZone = 34,
    CreateSymbolicLink = 35,
};

const HeapInformationClass = enum(u32) { HeapCompatibilityInformation = 0, HeapEnableTerminationOnCorruption = 1, HeapOptimizeResources = 3, HeapTag };

const ProcessInfoClass = enum(i32) {
    ProcessBasicInformation = 0x00,
    ProcessQuotaLimits = 0x01,
    ProcessIoCounters = 0x02,
    ProcessVmCounters = 0x03,
    ProcessTimes = 0x04,
    ProcessBasePriority = 0x05,
    ProcessRaisePriority = 0x06,
    ProcessDebugPort = 0x07,
    ProcessExceptionPort = 0x08,
    ProcessAccessToken = 0x09,
    ProcessLdtInformation = 0x0A,
    ProcessLdtSize = 0x0B,
    ProcessDefaultHardErrorMode = 0x0C,
    ProcessIoPortHandlers = 0x0D,
    ProcessPooledUsageAndLimits = 0x0E,
    ProcessWorkingSetWatch = 0x0F,
    ProcessUserModeIOPL = 0x10,
    ProcessEnableAlignmentFaultFixup = 0x11,
    ProcessPriorityClass = 0x12,
    ProcessWx86Information = 0x13,
    ProcessHandleCount = 0x14,
    ProcessAffinityMask = 0x15,
    ProcessPriorityBoost = 0x16,
    ProcessDeviceMap = 0x17,
    ProcessSessionInformation = 0x18,
    ProcessForegroundInformation = 0x19,
    ProcessWow64Information = 0x1A,
    ProcessImageFileName = 0x1B,
    ProcessLUIDDeviceMapsEnabled = 0x1C,
    ProcessBreakOnTermination = 0x1D,
    ProcessDebugObjectHandle = 0x1E,
    ProcessDebugFlags = 0x1F,
    ProcessHandleTracing = 0x20,
    ProcessIoPriority = 0x21,
    ProcessExecuteFlags = 0x22,
    ProcessResourceManagement = 0x23,
    ProcessCookie = 0x24,
    ProcessImageInformation = 0x25,
    ProcessCycleTime = 0x26,
    ProcessPagePriority = 0x27,
    ProcessInstrumentationCallback = 0x28,
    ProcessThreadStackAllocation = 0x29,
    ProcessWorkingSetWatchEx = 0x2A,
    ProcessImageFileNameWin32 = 0x2B,
    ProcessImageFileMapping = 0x2C,
    ProcessAffinityUpdateMode = 0x2D,
    ProcessMemoryAllocationMode = 0x2E,
    ProcessGroupInformation = 0x2F,
    ProcessTokenVirtualizationEnabled = 0x30,
    ProcessConsoleHostProcess = 0x31,
    ProcessWindowInformation = 0x32,
    ProcessHandleInformation = 0x33,
    ProcessMitigationPolicy = 0x34,
    ProcessDynamicFunctionTableInformation = 0x35,
    ProcessHandleCheckingMode = 0x36,
    ProcessKeepAliveCount = 0x37,
    ProcessRevokeFileHandles = 0x38,
    ProcessWorkingSetControl = 0x39,
    ProcessHandleTable = 0x3A,
    ProcessCheckStackExtentsMode = 0x3B,
    ProcessCommandLineInformation = 0x3C,
    ProcessProtectionInformation = 0x3D,
    ProcessMemoryExhaustion = 0x3E,
    ProcessFaultInformation = 0x3F,
    ProcessTelemetryIdInformation = 0x40,
    ProcessCommitReleaseInformation = 0x41,
    ProcessDefaultCpuSetsInformation = 0x42,
    ProcessAllowedCpuSetsInformation = 0x43,
    ProcessSubsystemProcess = 0x44,
    ProcessJobMemoryInformation = 0x45,
    ProcessInPrivate = 0x46,
    ProcessRaiseUMExceptionOnInvalidHandleClose = 0x47,
    ProcessIumChallengeResponse = 0x48,
    ProcessChildProcessInformation = 0x49,
    ProcessHighGraphicsPriorityInformation = 0x4A,
    ProcessSubsystemInformation = 0x4B,
    ProcessEnergyValues = 0x4C,
    ProcessActivityThrottleState = 0x4D,
    ProcessActivityThrottlePolicy = 0x4E,
    ProcessWin32kSyscallFilterInformation = 0x4F,
    ProcessDisableSystemAllowedCpuSets = 0x50,
    ProcessWakeInformation = 0x51,
    ProcessEnergyTrackingState = 0x52,
    ProcessManageWritesToExecutableMemory = 0x53,
    ProcessCaptureTrustletLiveDump = 0x54,
    ProcessTelemetryCoverage = 0x55,
    ProcessEnclaveInformation = 0x56,
    ProcessEnableReadWriteVmLogging = 0x57,
    ProcessUptimeInformation = 0x58,
    ProcessImageSection = 0x59,
    ProcessDebugAuthInformation = 0x5A,
    ProcessSystemResourceManagement = 0x5B,
    ProcessSequenceNumber = 0x5C,
    ProcessLoaderDetour = 0x5D,
    ProcessSecurityDomainInformation = 0x5E,
    ProcessCombineSecurityDomainsInformation = 0x5F,
    ProcessEnableLogging = 0x60,
    ProcessLeapSecondInformation = 0x61,
    ProcessFiberShadowStackAllocation = 0x62,
    ProcessFreeFiberShadowStackAllocation = 0x63,
    MaxProcessInfoClass = 0x64,
};
