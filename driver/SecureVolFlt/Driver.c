#include "Driver.h"

SECUREVOL_GLOBALS Globals;

FLT_PREOP_CALLBACK_STATUS
SecureVolPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

static NTSTATUS SecureVolGetOrCreateInstanceContext(_In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_ PSECUREVOL_INSTANCE_CONTEXT *Context);
static NTSTATUS SecureVolQueryVolumeGuid(_In_ PFLT_VOLUME Volume, _Out_ PUNICODE_STRING VolumeGuid, _Out_writes_(SECUREVOL_MAX_VOLUME_CHARS) PWCHAR Buffer);
static VOID SecureVolNormalizeVolumeString(_Inout_updates_(SECUREVOL_MAX_VOLUME_CHARS) PWCHAR Buffer);
static BOOLEAN SecureVolIsProtectedVolume(_In_ PSECUREVOL_INSTANCE_CONTEXT Context);
static BOOLEAN SecureVolShouldBypass(_In_ HANDLE ProcessId);
static NTSTATUS SecureVolQueryProcessMetadata(_In_ HANDLE ProcessId, _Out_ PULONGLONG CreateTime, _Out_writes_bytes_(16) PCHAR ImageName);
static ULONG SecureVolHashCacheKey(_In_ HANDLE ProcessId, _In_ ULONGLONG CreateTime);
static BOOLEAN SecureVolCacheLookup(_In_ HANDLE ProcessId, _In_ ULONGLONG CreateTime, _Out_ PULONG Verdict, _Out_ PULONG Reason, _Out_writes_(SECUREVOL_MAX_PATH_CHARS) PWCHAR ImagePath);
static VOID SecureVolCacheInsert(_In_ HANDLE ProcessId, _In_ ULONGLONG CreateTime, _In_ ULONG PolicyGeneration, _In_ ULONG Verdict, _In_ ULONG Reason, _In_opt_ PCWSTR ImagePath);
static VOID SecureVolCacheFlush(VOID);
static VOID SecureVolCacheFlushLocked(VOID);
static VOID SecureVolRecordDeny(_In_ HANDLE ProcessId, _In_ ULONG Reason, _In_reads_bytes_(16) PCCHAR ImageName);
static VOID SecureVolTraceDenyRateLimited(_In_ HANDLE ProcessId, _In_ ULONG Reason, _In_reads_bytes_(16) PCCHAR ImageName);
static FLT_PREOP_CALLBACK_STATUS SecureVolDeny(_Inout_ PFLT_CALLBACK_DATA Data, _In_ ULONG Reason, _In_reads_bytes_(16) PCCHAR ImageName, _In_ HANDLE ProcessId);
static NTSTATUS SecureVolReplyState(_Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer, _In_ ULONG OutputBufferLength, _Out_ PULONG ReturnOutputBufferLength);
static NTSTATUS SecureVolReplyDenies(_Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer, _In_ ULONG OutputBufferLength, _Out_ PULONG ReturnOutputBufferLength);

CONST FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    {
        FLT_INSTANCE_CONTEXT,
        0,
        SecureVolInstanceContextCleanup,
        sizeof(SECUREVOL_INSTANCE_CONTEXT),
        SECUREVOL_INSTANCE_TAG
    },
    { FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, SecureVolPreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    ContextRegistration,
    Callbacks,
    SecureVolUnload,
    SecureVolInstanceSetup,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING portName;
    ULONG index;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&Globals, sizeof(Globals));
    ExInitializePushLock(&Globals.PolicyLock);
    ExInitializePushLock(&Globals.CacheLock);
    ExInitializePushLock(&Globals.DenyLock);

    for (index = 0; index < RTL_NUMBER_OF(Globals.CacheBuckets); index++) {
        InitializeListHead(&Globals.CacheBuckets[index]);
    }

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &Globals.Filter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(Globals.Filter);
        Globals.Filter = NULL;
        return status;
    }

    RtlInitUnicodeString(&portName, SECUREVOL_PORT_NAME);
    InitializeObjectAttributes(&objectAttributes, &portName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, securityDescriptor);

    status = FltCreateCommunicationPort(
        Globals.Filter,
        &Globals.ServerPort,
        &objectAttributes,
        NULL,
        SecureVolPortConnect,
        SecureVolPortDisconnect,
        SecureVolPortMessage,
        SECUREVOL_MAX_PORT_CONNECTIONS);

    FltFreeSecurityDescriptor(securityDescriptor);
    securityDescriptor = NULL;

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(Globals.Filter);
        Globals.Filter = NULL;
        return status;
    }

    status = FltStartFiltering(Globals.Filter);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(Globals.ServerPort);
        Globals.ServerPort = NULL;
        FltUnregisterFilter(Globals.Filter);
        Globals.Filter = NULL;
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "SecureVolFlt: loaded in disabled state; waiting for service policy.\n");
    return STATUS_SUCCESS;
}

NTSTATUS
SecureVolUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    PFLT_PORT clientPort = NULL;

    UNREFERENCED_PARAMETER(Flags);

    ExAcquirePushLockExclusive(&Globals.PolicyLock);
    Globals.ProtectionEnabled = FALSE;
    Globals.Unloading = TRUE;
    clientPort = Globals.ClientPort;
    Globals.ClientPort = NULL;
    Globals.ServiceProcessId = NULL;
    ExReleasePushLockExclusive(&Globals.PolicyLock);

    if (Globals.ServerPort != NULL) {
        FltCloseCommunicationPort(Globals.ServerPort);
        Globals.ServerPort = NULL;
    }

    if (clientPort != NULL) {
        FltCloseClientPort(Globals.Filter, &clientPort);
    }

    SecureVolCacheFlush();

    if (Globals.Filter != NULL) {
        FltUnregisterFilter(Globals.Filter);
        Globals.Filter = NULL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SecureVolInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    NTSTATUS status;
    PSECUREVOL_INSTANCE_CONTEXT context = NULL;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    status = FltAllocateContext(Globals.Filter, FLT_INSTANCE_CONTEXT, sizeof(SECUREVOL_INSTANCE_CONTEXT), NonPagedPoolNx, &context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->VolumeGuid.Buffer = context->VolumeGuidBuffer;
    context->VolumeGuid.Length = 0;
    context->VolumeGuid.MaximumLength = sizeof(context->VolumeGuidBuffer);

    status = SecureVolQueryVolumeGuid(FltObjects->Volume, &context->VolumeGuid, context->VolumeGuidBuffer);
    if (NT_SUCCESS(status)) {
        status = FltSetInstanceContext(FltObjects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, NULL);
    }

    FltReleaseContext(context);
    return status;
}

VOID
SecureVolInstanceContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
{
    PSECUREVOL_INSTANCE_CONTEXT instanceContext = (PSECUREVOL_INSTANCE_CONTEXT)Context;

    UNREFERENCED_PARAMETER(ContextType);

    if (instanceContext->VolumeGuid.Buffer != NULL) {
        RtlZeroMemory(instanceContext->VolumeGuid.Buffer, instanceContext->VolumeGuid.MaximumLength);
    }
}

NTSTATUS
SecureVolPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    )
{
    PSECUREVOL_PORT_CONTEXT portContext;
    ULONG role = SECUREVOL_PORT_ROLE_QUERY;
    ULONG serviceProcessId = 0;

    UNREFERENCED_PARAMETER(ServerPortCookie);

    if (ConnectionPortCookie == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ConnectionPortCookie = NULL;

    if (ConnectionContext != NULL && SizeOfContext >= sizeof(SECUREVOL_CONNECTION_CONTEXT)) {
        PSECUREVOL_CONNECTION_CONTEXT connectionContext = (PSECUREVOL_CONNECTION_CONTEXT)ConnectionContext;
        serviceProcessId = connectionContext->ServiceProcessId;
        role = connectionContext->Role;
    }
    else if (ConnectionContext != NULL && SizeOfContext >= sizeof(ULONG)) {
        serviceProcessId = *(PULONG)ConnectionContext;
        role = SECUREVOL_PORT_ROLE_QUERY;
    }

    if (role != SECUREVOL_PORT_ROLE_QUERY && role != SECUREVOL_PORT_ROLE_CONTROL) {
        return STATUS_INVALID_PARAMETER;
    }

    portContext = (PSECUREVOL_PORT_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SECUREVOL_PORT_CONTEXT),
        SECUREVOL_TAG);

    if (portContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(portContext, sizeof(*portContext));
    portContext->ClientPort = ClientPort;
    portContext->IsQueryPort = (role == SECUREVOL_PORT_ROLE_QUERY);

    if (role == SECUREVOL_PORT_ROLE_CONTROL) {
        *ConnectionPortCookie = portContext;
        return STATUS_SUCCESS;
    }

    ExAcquirePushLockExclusive(&Globals.PolicyLock);
    if (Globals.ClientPort != NULL) {
        ExReleasePushLockExclusive(&Globals.PolicyLock);
        ExFreePoolWithTag(portContext, SECUREVOL_TAG);
        return STATUS_CONNECTION_ACTIVE;
    }

    Globals.ClientPort = ClientPort;
    Globals.ServiceProcessId = serviceProcessId != 0 ? UlongToHandle(serviceProcessId) : NULL;
    *ConnectionPortCookie = portContext;

    ExReleasePushLockExclusive(&Globals.PolicyLock);
    return STATUS_SUCCESS;
}

VOID
SecureVolPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
    )
{
    PSECUREVOL_PORT_CONTEXT portContext = (PSECUREVOL_PORT_CONTEXT)ConnectionCookie;
    PFLT_PORT portToClose = NULL;

    if (portContext == NULL) {
        return;
    }

    ExAcquirePushLockExclusive(&Globals.PolicyLock);
    if (portContext->IsQueryPort && Globals.ClientPort == portContext->ClientPort) {
        Globals.ServiceProcessId = NULL;
        Globals.ClientPort = NULL;
    }

    if (!Globals.Unloading && portContext->ClientPort != NULL) {
        portToClose = portContext->ClientPort;
        portContext->ClientPort = NULL;
    }
    ExReleasePushLockExclusive(&Globals.PolicyLock);

    if (portToClose != NULL) {
        FltCloseClientPort(Globals.Filter, &portToClose);
    }

    ExFreePoolWithTag(portContext, SECUREVOL_TAG);
}

NTSTATUS
SecureVolPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSECUREVOL_MESSAGE_HEADER header;
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(PortCookie);

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(SECUREVOL_MESSAGE_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    header = (PSECUREVOL_MESSAGE_HEADER)InputBuffer;
    switch (header->MessageType) {
    case SecureVolMessageTypeSetPolicy:
    {
        PSECUREVOL_SET_POLICY setPolicy;

        if (InputBufferLength < sizeof(SECUREVOL_SET_POLICY)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        setPolicy = (PSECUREVOL_SET_POLICY)InputBuffer;

        ExAcquirePushLockExclusive(&Globals.PolicyLock);
        Globals.ProtectionEnabled = setPolicy->ProtectionEnabled ? TRUE : FALSE;
        Globals.PolicyGeneration = setPolicy->PolicyGeneration;
        RtlZeroMemory(Globals.ProtectedVolumeGuid, sizeof(Globals.ProtectedVolumeGuid));
        RtlStringCchCopyW(Globals.ProtectedVolumeGuid, RTL_NUMBER_OF(Globals.ProtectedVolumeGuid), setPolicy->ProtectedVolumeGuid);
        SecureVolNormalizeVolumeString(Globals.ProtectedVolumeGuid);
        ExReleasePushLockExclusive(&Globals.PolicyLock);

        SecureVolCacheFlush();
        status = SecureVolReplyState(OutputBuffer, OutputBufferLength, ReturnOutputBufferLength);
        break;
    }

    case SecureVolMessageTypeGetState:
        status = SecureVolReplyState(OutputBuffer, OutputBufferLength, ReturnOutputBufferLength);
        break;

    case SecureVolMessageTypeGetRecentDenies:
        status = SecureVolReplyDenies(OutputBuffer, OutputBufferLength, ReturnOutputBufferLength);
        break;

    case SecureVolMessageTypeFlushCache:
        SecureVolCacheFlush();
        status = SecureVolReplyState(OutputBuffer, OutputBufferLength, ReturnOutputBufferLength);
        break;

    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    return status;
}

FLT_PREOP_CALLBACK_STATUS
SecureVolPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PSECUREVOL_INSTANCE_CONTEXT instanceContext = NULL;
    HANDLE processId;
    ULONGLONG createTime = 0;
    CHAR imageName[16] = { 0 };
    ULONG verdict = SecureVolVerdictUnknown;
    ULONG reason = SecureVolReasonNone;
    WCHAR imagePath[SECUREVOL_MAX_PATH_CHARS] = { 0 };
    SECUREVOL_PROCESS_QUERY query;
    SECUREVOL_PROCESS_REPLY reply;
    ULONG replyLength;
    LARGE_INTEGER timeout;
    BOOLEAN protectionEnabled;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->Iopb->TargetFileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FlagOn(Data->Iopb->TargetFileObject->Flags, FO_VOLUME_OPEN) ||
        FlagOn(Data->Iopb->TargetFileObject->Flags, FO_STREAM_FILE) ||
        FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    processId = UlongToHandle(FltGetRequestorProcessId(Data));
    if (SecureVolShouldBypass(processId)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = SecureVolGetOrCreateInstanceContext(FltObjects, &instanceContext);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!SecureVolIsProtectedVolume(instanceContext)) {
        FltReleaseContext(instanceContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = SecureVolQueryProcessMetadata(processId, &createTime, imageName);
    if (!NT_SUCCESS(status)) {
        FltReleaseContext(instanceContext);
        return SecureVolDeny(Data, SecureVolReasonProcessLookupFailed, "unknown", processId);
    }

    if (SecureVolCacheLookup(processId, createTime, &verdict, &reason, imagePath)) {
        FltReleaseContext(instanceContext);

        if (verdict == SecureVolVerdictAllow || verdict == SecureVolVerdictBypass) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        return SecureVolDeny(Data, reason, imageName, processId);
    }

    ExAcquirePushLockShared(&Globals.PolicyLock);
    protectionEnabled = Globals.ProtectionEnabled;
    ExReleasePushLockShared(&Globals.PolicyLock);

    if (!protectionEnabled) {
        FltReleaseContext(instanceContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Globals.ClientPort == NULL) {
        FltReleaseContext(instanceContext);
        return SecureVolDeny(Data, SecureVolReasonServiceUnavailable, imageName, processId);
    }

    RtlZeroMemory(&query, sizeof(query));
    RtlZeroMemory(&reply, sizeof(reply));

    query.Header.MessageType = SecureVolMessageTypeProcessQuery;
    query.Header.Size = sizeof(query);
    query.PolicyGeneration = Globals.PolicyGeneration;
    query.ProcessId = HandleToULong(processId);
    query.ProcessCreateTime = createTime;
    query.DesiredAccess = (Data->Iopb->Parameters.Create.SecurityContext != NULL)
        ? Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess
        : 0;
    query.CreateOptions = Data->Iopb->Parameters.Create.Options;
    RtlStringCchCopyW(query.VolumeGuid, RTL_NUMBER_OF(query.VolumeGuid), instanceContext->VolumeGuidBuffer);

    timeout.QuadPart = -(LONGLONG)SECUREVOL_QUERY_TIMEOUT_MS * 10000;
    replyLength = sizeof(reply);

    status = FltSendMessage(
        Globals.Filter,
        &Globals.ClientPort,
        &query,
        sizeof(query),
        &reply,
        &replyLength,
        &timeout);

    FltReleaseContext(instanceContext);

    if (!NT_SUCCESS(status) || reply.Header.MessageType != SecureVolMessageTypeProcessQuery) {
        return SecureVolDeny(Data, SecureVolReasonServiceUnavailable, imageName, processId);
    }

    if (reply.Verdict == SecureVolVerdictAllow || reply.Verdict == SecureVolVerdictBypass) {
        SecureVolCacheInsert(processId, createTime, reply.PolicyGeneration, reply.Verdict, reply.Reason, reply.ImagePath);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SecureVolCacheInsert(processId, createTime, reply.PolicyGeneration, reply.Verdict, reply.Reason, reply.ImagePath);
    return SecureVolDeny(Data, reply.Reason, imageName, processId);
}

static NTSTATUS
SecureVolGetOrCreateInstanceContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_ PSECUREVOL_INSTANCE_CONTEXT *Context
    )
{
    NTSTATUS status;
    PSECUREVOL_INSTANCE_CONTEXT context = NULL;
    PSECUREVOL_INSTANCE_CONTEXT oldContext = NULL;

    status = FltGetInstanceContext(FltObjects->Instance, &context);
    if (status == STATUS_NOT_FOUND) {
        status = FltAllocateContext(Globals.Filter, FLT_INSTANCE_CONTEXT, sizeof(SECUREVOL_INSTANCE_CONTEXT), NonPagedPoolNx, &context);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        RtlZeroMemory(context, sizeof(*context));
        context->VolumeGuid.Buffer = context->VolumeGuidBuffer;
        context->VolumeGuid.Length = 0;
        context->VolumeGuid.MaximumLength = sizeof(context->VolumeGuidBuffer);

        status = SecureVolQueryVolumeGuid(FltObjects->Volume, &context->VolumeGuid, context->VolumeGuidBuffer);
        if (!NT_SUCCESS(status)) {
            FltReleaseContext(context);
            return status;
        }

        status = FltSetInstanceContext(FltObjects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, &oldContext);
        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED && oldContext != NULL) {
            FltReleaseContext(context);
            context = oldContext;
            status = STATUS_SUCCESS;
        }
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }

    *Context = context;
    return STATUS_SUCCESS;
}

static NTSTATUS
SecureVolQueryVolumeGuid(
    _In_ PFLT_VOLUME Volume,
    _Out_ PUNICODE_STRING VolumeGuid,
    _Out_writes_(SECUREVOL_MAX_VOLUME_CHARS) PWCHAR Buffer
    )
{
    NTSTATUS status;

    RtlZeroMemory(Buffer, sizeof(WCHAR) * SECUREVOL_MAX_VOLUME_CHARS);
    VolumeGuid->Buffer = Buffer;
    VolumeGuid->Length = 0;
    VolumeGuid->MaximumLength = sizeof(WCHAR) * SECUREVOL_MAX_VOLUME_CHARS;

    status = FltGetVolumeGuidName(Volume, VolumeGuid, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    SecureVolNormalizeVolumeString(Buffer);
    VolumeGuid->Length = (USHORT)(wcslen(Buffer) * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

static VOID
SecureVolNormalizeVolumeString(
    _Inout_updates_(SECUREVOL_MAX_VOLUME_CHARS) PWCHAR Buffer
    )
{
    SIZE_T length;

    if (Buffer == NULL || Buffer[0] == UNICODE_NULL) {
        return;
    }

    if (Buffer[0] == L'\\' &&
        Buffer[1] == L'?' &&
        Buffer[2] == L'?' &&
        Buffer[3] == L'\\') {
        Buffer[1] = L'\\';
    }

    length = wcslen(Buffer);
    while (length > 0 && Buffer[length - 1] == L'\\') {
        Buffer[length - 1] = UNICODE_NULL;
        length--;
    }
}

static BOOLEAN
SecureVolIsProtectedVolume(
    _In_ PSECUREVOL_INSTANCE_CONTEXT Context
    )
{
    BOOLEAN result;

    ExAcquirePushLockShared(&Globals.PolicyLock);
    result = (Globals.ProtectedVolumeGuid[0] != UNICODE_NULL &&
              Globals.ProtectionEnabled &&
              (_wcsicmp(Context->VolumeGuidBuffer, Globals.ProtectedVolumeGuid) == 0));
    ExReleasePushLockShared(&Globals.PolicyLock);

    return result;
}

static BOOLEAN
SecureVolShouldBypass(
    _In_ HANDLE ProcessId
    )
{
    ExAcquirePushLockShared(&Globals.PolicyLock);
    if (Globals.ServiceProcessId != NULL && Globals.ServiceProcessId == ProcessId) {
        ExReleasePushLockShared(&Globals.PolicyLock);
        return TRUE;
    }
    ExReleasePushLockShared(&Globals.PolicyLock);

    return FALSE;
}

static NTSTATUS
SecureVolQueryProcessMetadata(
    _In_ HANDLE ProcessId,
    _Out_ PULONGLONG CreateTime,
    _Out_writes_bytes_(16) PCHAR ImageName
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *CreateTime = PsGetProcessCreateTimeQuadPart(process);
    RtlZeroMemory(ImageName, 16);
    RtlStringCbCopyA(ImageName, 16, "unknown");

    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

static ULONG
SecureVolHashCacheKey(
    _In_ HANDLE ProcessId,
    _In_ ULONGLONG CreateTime
    )
{
    ULONGLONG key = (ULONGLONG)(ULONG_PTR)ProcessId ^ CreateTime;
    return (ULONG)(key % SECUREVOL_CACHE_BUCKET_COUNT);
}

static BOOLEAN
SecureVolCacheLookup(
    _In_ HANDLE ProcessId,
    _In_ ULONGLONG CreateTime,
    _Out_ PULONG Verdict,
    _Out_ PULONG Reason,
    _Out_writes_(SECUREVOL_MAX_PATH_CHARS) PWCHAR ImagePath
    )
{
    ULONG bucketIndex;
    PLIST_ENTRY entry;
    BOOLEAN found = FALSE;

    bucketIndex = SecureVolHashCacheKey(ProcessId, CreateTime);

    ExAcquirePushLockShared(&Globals.CacheLock);
    for (entry = Globals.CacheBuckets[bucketIndex].Flink;
         entry != &Globals.CacheBuckets[bucketIndex];
         entry = entry->Flink) {
        PSECUREVOL_CACHE_ENTRY cacheEntry = CONTAINING_RECORD(entry, SECUREVOL_CACHE_ENTRY, ListEntry);

        if (cacheEntry->ProcessId == ProcessId &&
            cacheEntry->ProcessCreateTime == CreateTime &&
            cacheEntry->PolicyGeneration == Globals.PolicyGeneration) {
            *Verdict = cacheEntry->Verdict;
            *Reason = cacheEntry->Reason;
            RtlStringCchCopyW(ImagePath, SECUREVOL_MAX_PATH_CHARS, cacheEntry->ImagePath);
            found = TRUE;
            break;
        }
    }
    ExReleasePushLockShared(&Globals.CacheLock);

    return found;
}

static VOID
SecureVolCacheInsert(
    _In_ HANDLE ProcessId,
    _In_ ULONGLONG CreateTime,
    _In_ ULONG PolicyGeneration,
    _In_ ULONG Verdict,
    _In_ ULONG Reason,
    _In_opt_ PCWSTR ImagePath
    )
{
    PSECUREVOL_CACHE_ENTRY entry;
    ULONG bucketIndex;

    bucketIndex = SecureVolHashCacheKey(ProcessId, CreateTime);

    ExAcquirePushLockExclusive(&Globals.CacheLock);

    if (Globals.CacheEntryCount >= SECUREVOL_CACHE_MAX_ENTRIES) {
        SecureVolCacheFlushLocked();
    }

    entry = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*entry), SECUREVOL_TAG);
    if (entry != NULL) {
        RtlZeroMemory(entry, sizeof(*entry));
        entry->ProcessId = ProcessId;
        entry->ProcessCreateTime = CreateTime;
        entry->PolicyGeneration = PolicyGeneration;
        entry->Verdict = Verdict;
        entry->Reason = Reason;

        if (ImagePath != NULL && ImagePath[0] != UNICODE_NULL) {
            RtlStringCchCopyW(entry->ImagePath, RTL_NUMBER_OF(entry->ImagePath), ImagePath);
        }

        InsertHeadList(&Globals.CacheBuckets[bucketIndex], &entry->ListEntry);
        Globals.CacheEntryCount++;
    }

    ExReleasePushLockExclusive(&Globals.CacheLock);
}

static VOID
SecureVolCacheFlush(
    VOID
    )
{
    ExAcquirePushLockExclusive(&Globals.CacheLock);
    SecureVolCacheFlushLocked();
    ExReleasePushLockExclusive(&Globals.CacheLock);
}

static VOID
SecureVolCacheFlushLocked(
    VOID
    )
{
    ULONG bucketIndex;
    for (bucketIndex = 0; bucketIndex < RTL_NUMBER_OF(Globals.CacheBuckets); bucketIndex++) {
        while (!IsListEmpty(&Globals.CacheBuckets[bucketIndex])) {
            PLIST_ENTRY listEntry = RemoveHeadList(&Globals.CacheBuckets[bucketIndex]);
            PSECUREVOL_CACHE_ENTRY cacheEntry = CONTAINING_RECORD(listEntry, SECUREVOL_CACHE_ENTRY, ListEntry);
            ExFreePoolWithTag(cacheEntry, SECUREVOL_TAG);
        }
    }
    Globals.CacheEntryCount = 0;
}

static VOID
SecureVolRecordDeny(
    _In_ HANDLE ProcessId,
    _In_ ULONG Reason,
    _In_reads_bytes_(16) PCCHAR ImageName
    )
{
    ULONG index;

    ExAcquirePushLockExclusive(&Globals.DenyLock);

    index = Globals.DenyEventNextIndex % SECUREVOL_MAX_DENY_EVENTS;
    RtlZeroMemory(&Globals.DenyEvents[index], sizeof(Globals.DenyEvents[index]));
    KeQuerySystemTimePrecise(&Globals.DenyEvents[index].TimestampUtc);
    Globals.DenyEvents[index].ProcessId = HandleToULong(ProcessId);
    Globals.DenyEvents[index].Reason = Reason;
    RtlStringCbCopyNA(Globals.DenyEvents[index].ImageName, sizeof(Globals.DenyEvents[index].ImageName), ImageName, 15);

    Globals.DenyEventNextIndex++;
    if (Globals.DenyEventCount < SECUREVOL_MAX_DENY_EVENTS) {
        Globals.DenyEventCount++;
    }

    ExReleasePushLockExclusive(&Globals.DenyLock);
}

static VOID
SecureVolTraceDenyRateLimited(
    _In_ HANDLE ProcessId,
    _In_ ULONG Reason,
    _In_reads_bytes_(16) PCCHAR ImageName
    )
{
    LARGE_INTEGER now;
    LONGLONG delta;
    BOOLEAN shouldTrace = FALSE;

    KeQuerySystemTimePrecise(&now);

    ExAcquirePushLockExclusive(&Globals.DenyLock);
    delta = now.QuadPart - Globals.LastDenyTraceTime.QuadPart;
    if (delta > 10 * 1000 * 1000) {
        Globals.LastDenyTraceTime = now;
        shouldTrace = TRUE;
    }
    ExReleasePushLockExclusive(&Globals.DenyLock);

    if (shouldTrace) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "SecureVolFlt: denied pid=%lu image=%s reason=%lu\n",
            HandleToULong(ProcessId),
            ImageName,
            Reason);
    }
}

static FLT_PREOP_CALLBACK_STATUS
SecureVolDeny(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG Reason,
    _In_reads_bytes_(16) PCCHAR ImageName,
    _In_ HANDLE ProcessId
    )
{
    SecureVolRecordDeny(ProcessId, Reason, ImageName);
    SecureVolTraceDenyRateLimited(ProcessId, Reason, ImageName);

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static NTSTATUS
SecureVolReplyState(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSECUREVOL_DRIVER_STATE state;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(SECUREVOL_DRIVER_STATE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    state = (PSECUREVOL_DRIVER_STATE)OutputBuffer;
    RtlZeroMemory(state, sizeof(*state));

    ExAcquirePushLockShared(&Globals.PolicyLock);
    state->Header.MessageType = SecureVolMessageTypeGetState;
    state->Header.Size = sizeof(*state);
    state->PolicyGeneration = Globals.PolicyGeneration;
    state->ProtectionEnabled = Globals.ProtectionEnabled;
    state->ClientConnected = (Globals.ClientPort != NULL);
    state->CacheEntryCount = Globals.CacheEntryCount;
    RtlStringCchCopyW(state->ProtectedVolumeGuid, RTL_NUMBER_OF(state->ProtectedVolumeGuid), Globals.ProtectedVolumeGuid);
    ExReleasePushLockShared(&Globals.PolicyLock);

    *ReturnOutputBufferLength = sizeof(*state);
    return STATUS_SUCCESS;
}

static NTSTATUS
SecureVolReplyDenies(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSECUREVOL_DENY_EVENT_LIST denyList;
    ULONG count;
    ULONG start;
    ULONG index;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(SECUREVOL_DENY_EVENT_LIST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    denyList = (PSECUREVOL_DENY_EVENT_LIST)OutputBuffer;
    RtlZeroMemory(denyList, sizeof(*denyList));
    denyList->Header.MessageType = SecureVolMessageTypeGetRecentDenies;
    denyList->Header.Size = sizeof(*denyList);

    ExAcquirePushLockShared(&Globals.DenyLock);
    count = Globals.DenyEventCount;
    denyList->Count = count;

    start = (Globals.DenyEventCount == SECUREVOL_MAX_DENY_EVENTS)
        ? (Globals.DenyEventNextIndex % SECUREVOL_MAX_DENY_EVENTS)
        : 0;

    for (index = 0; index < count; index++) {
        denyList->Events[index] = Globals.DenyEvents[(start + index) % SECUREVOL_MAX_DENY_EVENTS];
    }
    ExReleasePushLockShared(&Globals.DenyLock);

    *ReturnOutputBufferLength = sizeof(*denyList);
    return STATUS_SUCCESS;
}
