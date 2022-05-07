const std = @import("std");
const rt = @import("rt.zig");

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
    heap_information_class: HEAP_INFORMATION_CLASS,
    heap_information: rt.PVOID,
    heap_information_length: rt.SIZE_T
) callconv(.Win64) NTSTATUS {
    log.info("RtlSetHeapInformation(handle={},class={s},info=0x{x},length={d})", .{heap_handle, @tagName(heap_information_class), heap_information, heap_information_length});
    return .SUCCESS;
}

const NTSTATUS = enum(u32) {
    SUCCESS = 0x00000000,
};

const HEAP_INFORMATION_CLASS = enum(u32) {
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
        .{"NtQuerySystemInformation", stub("NtQuerySystemInformation") },
        .{"RtlAllocateHeap", RtlAllocateHeap },
        .{"RtlFreeHeap", stub("RtlFreeHeap") },
        .{"NtSetValueKey", stub("NtSetValueKey") },
        .{"RtlFreeUnicodeString", stub("RtlFreeUnicodeString") },
        .{"NtDeviceIoControlFile", stub("NtDeviceIoControlFile") },
        .{"NtQueryValueKey", stub("NtQueryValueKey") },
        .{"RtlInitUnicodeString", stub("RtlInitUnicodeString") },
        .{"RtlPrefixUnicodeString", stub("RtlPrefixUnicodeString") },
        .{"NtOpenFile", stub("NtOpenFile") },
        .{"NtQueryVolumeInformationFile", stub("NtQueryVolumeInformationFile") },
        .{"NtQueryInformationProcess", stub("NtQueryInformationProcess") },
        .{"RtlInitUnicodeStringEx", stub("RtlInitUnicodeStringEx") },
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
        .{"RtlCreateTagHeap", stub("RtlCreateTagHeap") },
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
        .{"NtQueryInformationJobObject", stub("NtQueryInformationJobObject") },
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
        .{"TpSetPoolMinThreads", stub("TpSetPoolMinThreads") },
        .{"RtlSetThreadIsCritical", stub("RtlSetThreadIsCritical") },
        .{"AlpcInitializeMessageAttribute", stub("AlpcInitializeMessageAttribute") },
        .{"NtAlpcSendWaitReceivePort", stub("NtAlpcSendWaitReceivePort") },
        .{"AlpcGetMessageAttribute", stub("AlpcGetMessageAttribute") },
        .{"NtAlpcCancelMessage", stub("NtAlpcCancelMessage") },
        .{"NtAlpcOpenSenderProcess", stub("NtAlpcOpenSenderProcess") },
        .{"RtlInitializeSRWLock", stub("RtlInitializeSRWLock") },
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
        .{"EtwRegisterTraceGuidsW", stub("EtwRegisterTraceGuidsW") },
        .{"NtDelayExecution", stub("NtDelayExecution") },
        .{"RtlSetHeapInformation", RtlSetHeapInformation },
        .{"EtwEventRegister", stub("EtwEventRegister") },
        .{"TpAllocPool", stub("TpAllocPool") },
        .{"TpAllocAlpcCompletion", stub("TpAllocAlpcCompletion") },
        .{"NtWaitForMultipleObjects", stub("NtWaitForMultipleObjects") },
        .{"NtRaiseHardError", stub("NtRaiseHardError") },
        .{"RtlInitializeConditionVariable", stub("RtlInitializeConditionVariable") },
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