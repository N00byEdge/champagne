const std = @import("std");
const rt = @import("rt.zig");
const guids = @import("guids.zig");

const log = std.log.scoped(.ntdll);

// @TODO: https://github.com/ziglang/zig/issues/11585

fn stub(comptime str: []const u8) *const anyopaque {
    return @ptrCast(*const anyopaque, struct {
        fn f() callconv(.Win64) noreturn {
            @panic("ntdll stub: " ++ str);
        }
    }.f);
}

fn RtlNormalizeProcessParams(params: ?*rt.ProcessParameters) callconv(.Win64) void {
    log.info("Normalizing params", .{});
    if(params != &rt.pparam) {
        @panic("Wrong pparams passed in!");
    }
}

fn iswspace(chr: rt.WCHAR) callconv(.Win64) rt.BOOL {
    //log.info("iswspace 0x{X} ('{c}')", .{chr, if(chr <= 0x7F) @truncate(u8, chr) else '!'});
    if(chr > 0x7F) {
        @panic("TODO: non-ascii");
    }
    if(std.ascii.isSpace(@intCast(u8, chr))) {
        return rt.TRUE;
    }
    return rt.FALSE;
}

var rtl_global_heap = std.heap.GeneralPurposeAllocator(.{}){.backing_allocator = std.heap.page_allocator};

fn RtlAllocateHeap(heap_handle: ?*anyopaque, flags: rt.ULONG, size: rt.SIZE_T) callconv(.Win64) ?*anyopaque {
    log.info("RtlAllocateHeap(handle=0x{X}, flags=0x{X}, size=0x{X})", .{@ptrToInt(heap_handle), flags, size});
    if(heap_handle) |_| {
        @panic("RtlAllocateHeap with handle");
    }

    const retval = (rtl_global_heap.allocator().alloc(u8, size) catch |err| {
        log.err("RtlAllocateHeap failed (error.{s})!", .{@errorName(err)});
        return null;
    }).ptr;

    log.info("RtlAllocateHeap -> 0x{X}", .{@ptrToInt(retval)});
    return retval;
}

fn RtlFreeHeap(heap_handle: ?*anyopaque, flags: rt.ULONG, base_addr: ?[*]u8) callconv(.Win64) rt.LOGICAL {
    // TODO: Don't just leak memory here
    log.info("RtlFreeHeap(handle=0x{X}, flags = 0x{X}, ptr=0x{X})", .{@ptrToInt(heap_handle), flags, @ptrToInt(base_addr)});
    return rt.TRUE;
}

fn NtSetInformationProcess(
    process_handle: rt.HANDLE,
    process_information_class: ProcessInfoClass,
    process_information: rt.PVOID,
    process_information_length: rt.ULONG,
) callconv(.Win64) NTSTATUS {
    log.info("NtSetInformationProcess(handle=0x{X}, class={s}, info=0x{x}, length={d})", .{@ptrToInt(process_handle), @tagName(process_information_class), @ptrToInt(process_information), process_information_length});
    return .SUCCESS;
}

fn RtlSetHeapInformation(
    heap_handle: rt.PVOID,
    heap_information_class: HeapInformationClass,
    heap_information: rt.PVOID,
    heap_information_length: rt.SIZE_T
) callconv(.Win64) NTSTATUS {
    log.info("RtlSetHeapInformation(handle=0x{X}, class={s}, info=0x{x}, length={d})", .{@ptrToInt(heap_handle), @tagName(heap_information_class), @ptrToInt(heap_information), heap_information_length});
    return .SUCCESS;
}

const REGHANDLE = u64;

fn EtwEventRegister(
    provider_id: rt.LPCGUID,
    callback: rt.EnableCallback,
    callback_context: rt.PVOID,
    result_handle: ?*REGHANDLE,
) callconv(.Win64) Error {
    log.info("EtwEventRegister(guid={}, callback=0x{X}, context=0x{x}, result_out=0x{X})", .{provider_id, @ptrToInt(callback), @ptrToInt(callback_context), @ptrToInt(result_handle)});
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

const WMidPRequest = fn(
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

fn EtwRegisterTraceGuidsW(
    request_address: WMidPRequest,
    request_context: rt.PVOID,
    control_guid: rt.LPCGUID,
    guid_count: rt.ULONG,
    trace_guid_registration: ?*TraceGuidRegistration,
    m_of_image_path: rt.LPCWSTR,
    m_of_resource_name: rt.LPCWSTR,
    registration_handle: ?*TraceHandle,
) callconv(.Win64) Error {
    log.info("EtwRegisterTraceGuidsW(req_addr=0x{X}, req_cont=0x{X}, cguid={}, guidcnt={}, tguid={}, imgp={}, mrname={}, rhandle=0x{X})", .{
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

fn TpAllocPool(
    opt_result: ?[*]rt.PVOID,
    reserved: rt.PVOID,
) callconv(.Win64) NTSTATUS {
    const result = opt_result orelse return .INVALID_PARAMETER;
    log.info("TpAllocPool(0x{X}) -> 0x41414141", .{@ptrToInt(result)});
    result.* = @intToPtr(rt.PVOID, 0x41414141);
    _ = reserved;
    return .SUCCESS;
}

fn TpSetPoolMinThreads(
    tp: rt.PVOID,
    min_threads: rt.ULONG,
) callconv(.Win64) NTSTATUS {
    log.info("TpSetPoolMinThreads(0x{X}, {d})", .{@ptrToInt(tp orelse return .INVALID_PARAMETER), min_threads});
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

fn NtQueryInformationJobObject(
    handle: rt.HANDLE,
    class: JobObjectInfoClass,
    len: rt.ULONG,
    ret_len: ?*rt.ULONG,
) callconv(.Win64) NTSTATUS {
    log.info("NtQueryInformationJobObject(handle=0x{X}, class={s}, len=0x{x}, ret_len={d})", .{@ptrToInt(handle), @tagName(class), len, ret_len});
    return .SUCCESS;
}

var rtl_unicode_string_ex_heap = std.heap.GeneralPurposeAllocator(.{}){.backing_allocator = std.heap.page_allocator};

fn RtlInitUnicodeStringEx(
    dest: ?*rt.UnicodeString,
    src: rt.PCWSTR,
) callconv(.Win64) NTSTATUS {
    log.info("RtlInitUnicodeStringEx({})", .{rt.fmt(src)});
    const str = src orelse return .INVALID_PARAMETER;
    (dest orelse return .INVALID_PARAMETER).* =
        rt.UnicodeString.initFromBuffer(
            rtl_unicode_string_ex_heap.allocator().dupeZ(u16, std.mem.span(str)) catch return .NO_MEMORY
        );
    return .SUCCESS;
}

fn RtlSetThreadIsCritical(
    new_value: rt.BOOL,
    old_value: ?*rt.BOOL,
    check_flag: rt.BOOL,
) callconv(.Win64) NTSTATUS {
    if(old_value) |o| o.* = rt.FALSE;
    log.info("RtlSetThreadIsCritical({},check_flag={})", .{rt.fmt(new_value), rt.fmt(check_flag)});
    return .SUCCESS;
}

const RtlSrwLock = extern struct {
    ptr: rt.PVOID,
};

fn RtlInitializeSRWLock(
    lock: ?*RtlSrwLock,
) callconv(.Win64) void {
    log.info("RtlInitializeSRWLock(0x{X})", .{@ptrToInt(lock)});
}

fn RtlCreateTagHeap(
    heap_handle: rt.HANDLE,
    flags: rt.ULONG,
    tag_name: rt.PWSTR,
    tag_sub_name: rt.PWSTR,
) callconv(.Win64) Error {
    log.info("RtlCreateTagHeap(handle=0x{X}, flags=0x{X}, tag_name={}, tag_sub_name={})", .{@ptrToInt(heap_handle), flags, rt.fmt(tag_name), rt.fmt(tag_sub_name)});
    return .SUCCESS;
}

fn giveSystemInfo(ret_ptr: rt.PVOID, ret_max_size: rt.ULONG, ret_out_size: ?*rt.ULONG, comptime T: type) NTSTATUS {
    const copy_size = std.math.min(@sizeOf(T), ret_max_size);
    if(ret_out_size) |out|
        out.* = @intCast(rt.ULONG, copy_size);
    @memcpy(@ptrCast([*]u8, ret_ptr orelse return .INVALID_PARAMETER), @intToPtr([*]const u8, @ptrToInt(&T{})), copy_size);
    return .SUCCESS;
}

var manufacturer_profile_name = rt.toNullTerminatedUTF16Buffer("Champagne-SYSTEM");

fn NtQuerySystemInformation(
    class: SystemInformationClass,
    ret_ptr: rt.PVOID,
    ret_max_size: rt.ULONG,
    ret_out_size: ?*rt.ULONG,
) callconv(.Win64) NTSTATUS {
    _ = ret_ptr;
    _ = ret_max_size;
    _ = ret_out_size;
    log.info("NtQuerySystemInformation(class=0x{X} ('{s}'), max_size=0x{X})", .{@enumToInt(class), @tagName(class), ret_max_size});
    return switch(class) {
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
        .SystemManufacturingInformation => giveSystemInfo(ret_ptr, ret_max_size, ret_out_size, extern struct {
            options: rt.ULONG = 0,
            profile_name: rt.UnicodeString = rt.UnicodeString.initFromBuffer(&manufacturer_profile_name),
        }),
    };
}

const ConditionVariable = rt.PVOID;

fn RtlInitializeConditionVariable(
    out_cvar: ?*ConditionVariable,
) callconv(.Win64) void {
    log.info("RtlInitializeConditionVariable(0x{X})", .{@ptrToInt(out_cvar)});
}

const Error = enum(rt.ULONG) {
    SUCCESS = 0x00000000,
};

const NTSTATUS = enum(u32) {
    SUCCESS = 0x00000000,

    INVALID_PARAMETER = 0xC000000D,
    NO_MEMORY = 0xC0000017,
};

const SystemInformationClass = enum(u32) {
    Basic = 0x00,
    //Processor = 1,
    //Performance = 2,
    SystemManufacturingInformation = 0x9D,
};

const HeapInformationClass = enum(u32) {
  HeapCompatibilityInformation = 0,
  HeapEnableTerminationOnCorruption = 1,
  HeapOptimizeResources = 3,
  HeapTag
};

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
  MaxProcessInfoClass = 0x64
};

pub const builtin_symbols = blk: {
    @setEvalBranchQuota(200000);

    break :blk std.ComptimeStringMap(*const anyopaque, .{
        .{"RtlComputeCrc32", stub("RtlComputeCrc32") },
        .{"RtlUpcaseUnicodeChar", stub("RtlUpcaseUnicodeChar") },
        .{"NtOpenKey", stub("NtOpenKey") },
        .{"RtlGetVersion", stub("RtlGetVersion") },
        .{"NtClose", stub("NtClose") },
        .{"TpAllocTimer", stub("TpAllocTimer") },
        .{"TpSetTimer", stub("TpSetTimer") },
        .{"NtQuerySystemInformation", NtQuerySystemInformation },
        .{"RtlAllocateHeap", RtlAllocateHeap },
        .{"RtlFreeHeap", RtlFreeHeap },
        .{"NtSetValueKey", stub("NtSetValueKey") },
        .{"RtlFreeUnicodeString", stub("RtlFreeUnicodeString") },
        .{"NtDeviceIoControlFile", stub("NtDeviceIoControlFile") },
        .{"NtQueryValueKey", stub("NtQueryValueKey") },
        .{"RtlInitUnicodeString", stub("RtlInitUnicodeString") },
        .{"RtlPrefixUnicodeString", stub("RtlPrefixUnicodeString") },
        .{"NtOpenFile", stub("NtOpenFile") },
        .{"NtQueryVolumeInformationFile", stub("NtQueryVolumeInformationFile") },
        .{"NtQueryInformationProcess", stub("NtQueryInformationProcess") },
        .{"RtlInitUnicodeStringEx", RtlInitUnicodeStringEx },
        .{"_vsnwprintf_s", stub("_vsnwprintf_s") },
        .{"NtCreatePagingFile", stub("NtCreatePagingFile") },
        .{"NtSetSystemInformation", stub("NtSetSystemInformation") },
        .{"RtlAppendUnicodeToString", stub("RtlAppendUnicodeToString") },
        .{"RtlSecondsSince1970ToTime", stub("RtlSecondsSince1970ToTime") },
        .{"qsort", stub("qsort") },
        .{"NtSetInformationFile", stub("NtSetInformationFile") },
        .{"NtQueryInformationFile", stub("NtQueryInformationFile") },
        .{"NtFsControlFile", stub("NtFsControlFile") },
        .{"RtlCompareUnicodeString", stub("RtlCompareUnicodeString") },
        .{"RtlAppendUnicodeStringToString", stub("RtlAppendUnicodeStringToString") },
        .{"RtlCompareMemory", stub("RtlCompareMemory") },
        .{"NtDeleteValueKey", stub("NtDeleteValueKey") },
        .{"NtFlushKey", stub("NtFlushKey") },
        .{"NtUpdateWnfStateData", stub("NtUpdateWnfStateData") },
        .{"NtSerializeBoot", stub("NtSerializeBoot") },
        .{"RtlUnicodeStringToInteger", stub("RtlUnicodeStringToInteger") },
        .{"RtlAllocateAndInitializeSid", stub("RtlAllocateAndInitializeSid") },
        .{"RtlCreateSecurityDescriptor", stub("RtlCreateSecurityDescriptor") },
        .{"RtlCreateAcl", stub("RtlCreateAcl") },
        .{"RtlAddAccessAllowedAce", stub("RtlAddAccessAllowedAce") },
        .{"RtlSetDaclSecurityDescriptor", stub("RtlSetDaclSecurityDescriptor") },
        .{"RtlSetOwnerSecurityDescriptor", stub("RtlSetOwnerSecurityDescriptor") },
        .{"NtSetSecurityObject", stub("NtSetSecurityObject") },
        .{"RtlExpandEnvironmentStrings_U", stub("RtlExpandEnvironmentStrings_U") },
        .{"RtlDosPathNameToNtPathName_U", stub("RtlDosPathNameToNtPathName_U") },
        .{"NtCreateFile", stub("NtCreateFile") },
        .{"NtReadFile", stub("NtReadFile") },
        .{"NtCreateKey", stub("NtCreateKey") },
        .{"NtAllocateVirtualMemory", stub("NtAllocateVirtualMemory") },
        .{"NtWriteFile", stub("NtWriteFile") },
        .{"NtFreeVirtualMemory", stub("NtFreeVirtualMemory") },
        .{"RtlCreateUnicodeString", stub("RtlCreateUnicodeString") },
        .{"EtwEventWrite", stub("EtwEventWrite") },
        .{"EtwEventEnabled", stub("EtwEventEnabled") },
        .{"_vsnwprintf", stub("_vsnwprintf") },
        .{"RtlCopyUnicodeString", stub("RtlCopyUnicodeString") },
        .{"RtlAddMandatoryAce", stub("RtlAddMandatoryAce") },
        .{"RtlSetSaclSecurityDescriptor", stub("RtlSetSaclSecurityDescriptor") },
        .{"RtlAdjustPrivilege", stub("RtlAdjustPrivilege") },
        .{"RtlFreeSid", stub("RtlFreeSid") },
        .{"RtlLengthSid", stub("RtlLengthSid") },
        .{"NtCreateMutant", stub("NtCreateMutant") },
        .{"RtlCreateTagHeap", RtlCreateTagHeap },
        .{"NtSetInformationProcess", NtSetInformationProcess },
        .{"NtAlpcCreatePort", stub("NtAlpcCreatePort") },
        .{"RtlInitializeBitMap", stub("RtlInitializeBitMap") },
        .{"RtlClearAllBits", stub("RtlClearAllBits") },
        .{"RtlSetBits", stub("RtlSetBits") },
        .{"NtOpenEvent", stub("NtOpenEvent") },
        .{"RtlCreateEnvironment", stub("RtlCreateEnvironment") },
        .{"RtlSetCurrentEnvironment", stub("RtlSetCurrentEnvironment") },
        .{"RtlQueryRegistryValuesEx", stub("RtlQueryRegistryValuesEx") },
        .{"NtCreateDirectoryObject", stub("NtCreateDirectoryObject") },
        .{"RtlEqualUnicodeString", stub("RtlEqualUnicodeString") },
        .{"NtSetEvent", stub("NtSetEvent") },
        .{"NtInitializeRegistry", stub("NtInitializeRegistry") },
        .{"NtResumeThread", stub("NtResumeThread") },
        .{"NtWaitForSingleObject", stub("NtWaitForSingleObject") },
        .{"NtTerminateProcess", stub("NtTerminateProcess") },
        .{"TpAllocWork", stub("TpAllocWork") },
        .{"TpPostWork", stub("TpPostWork") },
        .{"TpWaitForWork", stub("TpWaitForWork") },
        .{"TpReleaseWork", stub("TpReleaseWork") },
        .{"_wcsupr_s", stub("_wcsupr_s") },
        .{"NtOpenDirectoryObject", stub("NtOpenDirectoryObject") },
        .{"NtCreateSymbolicLinkObject", stub("NtCreateSymbolicLinkObject") },
        .{"NtMakeTemporaryObject", stub("NtMakeTemporaryObject") },
        .{"_stricmp", stub("_stricmp") },
        .{"RtlInitAnsiString", stub("RtlInitAnsiString") },
        .{"RtlAnsiStringToUnicodeString", stub("RtlAnsiStringToUnicodeString") },
        .{"NtOpenSymbolicLinkObject", stub("NtOpenSymbolicLinkObject") },
        .{"NtQuerySymbolicLinkObject", stub("NtQuerySymbolicLinkObject") },
        .{"RtlDosPathNameToNtPathName_U_WithStatus", stub("RtlDosPathNameToNtPathName_U_WithStatus") },
        .{"RtlRandomEx", stub("RtlRandomEx") },
        .{"qsort_s", stub("qsort_s") },
        .{"LdrVerifyImageMatchesChecksumEx", stub("LdrVerifyImageMatchesChecksumEx") },
        .{"RtlAppxIsFileOwnedByTrustedInstaller", stub("RtlAppxIsFileOwnedByTrustedInstaller") },
        .{"NtQueryAttributesFile", stub("NtQueryAttributesFile") },
        .{"NtQueryDirectoryFile", stub("NtQueryDirectoryFile") },
        .{"RtlDeleteRegistryValue", stub("RtlDeleteRegistryValue") },
        .{"RtlWriteRegistryValue", stub("RtlWriteRegistryValue") },
        .{"_wcsicmp", stub("_wcsicmp") },
        .{"RtlSetEnvironmentVariable", stub("RtlSetEnvironmentVariable") },
        .{"NtCreateSection", stub("NtCreateSection") },
        .{"NtMapViewOfSection", stub("NtMapViewOfSection") },
        .{"NtUnmapViewOfSection", stub("NtUnmapViewOfSection") },
        .{"NtDuplicateObject", stub("NtDuplicateObject") },
        .{"NtQueryInformationJobObject", NtQueryInformationJobObject },
        .{"iswctype", stub("iswctype") },
        .{"RtlQueryEnvironmentVariable_U", stub("RtlQueryEnvironmentVariable_U") },
        .{"RtlDosSearchPath_U", stub("RtlDosSearchPath_U") },
        .{"RtlTestBit", stub("RtlTestBit") },
        .{"RtlInterlockedSetBitRun", stub("RtlInterlockedSetBitRun") },
        .{"RtlFindSetBits", stub("RtlFindSetBits") },
        .{"RtlCreateProcessParametersEx", stub("RtlCreateProcessParametersEx") },
        .{"RtlCreateUserProcess", stub("RtlCreateUserProcess") },
        .{"RtlDestroyProcessParameters", stub("RtlDestroyProcessParameters") },
        .{"NtDisplayString", stub("NtDisplayString") },
        .{"RtlAddProcessTrustLabelAce", stub("RtlAddProcessTrustLabelAce") },
        .{"RtlGetAce", stub("RtlGetAce") },
        .{"NtQueryDirectoryObject", stub("NtQueryDirectoryObject") },
        .{"RtlTimeToTimeFields", stub("RtlTimeToTimeFields") },
        .{"NtDeleteFile", stub("NtDeleteFile") },
        .{"RtlAcquireSRWLockExclusive", stub("RtlAcquireSRWLockExclusive") },
        .{"NtAlpcDisconnectPort", stub("NtAlpcDisconnectPort") },
        .{"RtlReleaseSRWLockExclusive", stub("RtlReleaseSRWLockExclusive") },
        .{"RtlAcquireSRWLockShared", stub("RtlAcquireSRWLockShared") },
        .{"RtlReleaseSRWLockShared", stub("RtlReleaseSRWLockShared") },
        .{"NtAlpcImpersonateClientOfPort", stub("NtAlpcImpersonateClientOfPort") },
        .{"NtOpenThreadToken", stub("NtOpenThreadToken") },
        .{"NtQueryInformationToken", stub("NtQueryInformationToken") },
        .{"NtSetInformationThread", stub("NtSetInformationThread") },
        .{"TpSetPoolMinThreads", TpSetPoolMinThreads },
        .{"RtlSetThreadIsCritical", RtlSetThreadIsCritical },
        .{"AlpcInitializeMessageAttribute", stub("AlpcInitializeMessageAttribute") },
        .{"NtAlpcSendWaitReceivePort", stub("NtAlpcSendWaitReceivePort") },
        .{"AlpcGetMessageAttribute", stub("AlpcGetMessageAttribute") },
        .{"NtAlpcCancelMessage", stub("NtAlpcCancelMessage") },
        .{"NtAlpcOpenSenderProcess", stub("NtAlpcOpenSenderProcess") },
        .{"RtlInitializeSRWLock", RtlInitializeSRWLock },
        .{"NtAlpcAcceptConnectPort", stub("NtAlpcAcceptConnectPort") },
        .{"NtConnectPort", stub("NtConnectPort") },
        .{"NtRequestWaitReplyPort", stub("NtRequestWaitReplyPort") },
        .{"NtCreateEvent", stub("NtCreateEvent") },
        .{"RtlDeleteNoSplay", stub("RtlDeleteNoSplay") },
        .{"RtlSleepConditionVariableSRW", stub("RtlSleepConditionVariableSRW") },
        .{"RtlWakeAllConditionVariable", stub("RtlWakeAllConditionVariable") },
        .{"NtAssignProcessToJobObject", stub("NtAssignProcessToJobObject") },
        .{"EtwGetTraceLoggerHandle", stub("EtwGetTraceLoggerHandle") },
        .{"EtwGetTraceEnableLevel", stub("EtwGetTraceEnableLevel") },
        .{"EtwGetTraceEnableFlags", stub("EtwGetTraceEnableFlags") },
        .{"EtwRegisterTraceGuidsW", EtwRegisterTraceGuidsW },
        .{"NtDelayExecution", stub("NtDelayExecution") },
        .{"RtlSetHeapInformation", RtlSetHeapInformation },
        .{"EtwEventRegister", EtwEventRegister },
        .{"TpAllocPool", TpAllocPool },
        .{"TpAllocAlpcCompletion", stub("TpAllocAlpcCompletion") },
        .{"NtWaitForMultipleObjects", stub("NtWaitForMultipleObjects") },
        .{"NtRaiseHardError", stub("NtRaiseHardError") },
        .{"RtlInitializeConditionVariable", RtlInitializeConditionVariable },
        .{"NtClearEvent", stub("NtClearEvent") },
        .{"RtlUnicodeStringToAnsiString", stub("RtlUnicodeStringToAnsiString") },
        .{"NtQueryEvent", stub("NtQueryEvent") },
        .{"wcstoul", stub("wcstoul") },
        .{"LdrQueryImageFileExecutionOptions", stub("LdrQueryImageFileExecutionOptions") },
        .{"RtlAcquirePrivilege", stub("RtlAcquirePrivilege") },
        .{"RtlReleasePrivilege", stub("RtlReleasePrivilege") },
        .{"RtlCaptureContext", stub("RtlCaptureContext") },
        .{"RtlLookupFunctionEntry", stub("RtlLookupFunctionEntry") },
        .{"RtlVirtualUnwind", stub("RtlVirtualUnwind") },
        .{"RtlUnhandledExceptionFilter", stub("RtlUnhandledExceptionFilter") },
        .{"RtlCompareUnicodeStrings", stub("RtlCompareUnicodeStrings") },
        .{"RtlNormalizeProcessParams", RtlNormalizeProcessParams },
        .{"iswspace", iswspace },
        .{"RtlConnectToSm", stub("RtlConnectToSm") },
        .{"RtlSendMsgToSm", stub("RtlSendMsgToSm") },
        .{"NtQueryKey", stub("NtQueryKey") },
        .{"NtDeleteKey", stub("NtDeleteKey") },
        .{"__chkstk", stub("__chkstk") },
        .{"memcpy", stub("memcpy") },
        .{"memset", stub("memset") },
        .{"__C_specific_handler", stub("__C_specific_handler") },
    });
};
