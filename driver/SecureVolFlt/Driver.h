#pragma once

#include <fltKernel.h>
#include <ntstrsafe.h>
#include <dontuse.h>
#include <suppress.h>
#include "..\..\common\include\SecureVolProtocol.h"

#define SECUREVOL_TAG                         'VceS'
#define SECUREVOL_INSTANCE_TAG                'IceS'
#define SECUREVOL_CACHE_MAX_ENTRIES           1024
#define SECUREVOL_CACHE_BUCKET_COUNT          61
#define SECUREVOL_QUERY_TIMEOUT_MS            300
#define SECUREVOL_MAX_PORT_CONNECTIONS        8
#define SECUREVOL_PORT_ROLE_QUERY             1
#define SECUREVOL_PORT_ROLE_CONTROL           2

typedef struct _SECUREVOL_INSTANCE_CONTEXT {
    UNICODE_STRING VolumeGuid;
    WCHAR VolumeGuidBuffer[SECUREVOL_MAX_VOLUME_CHARS];
} SECUREVOL_INSTANCE_CONTEXT, *PSECUREVOL_INSTANCE_CONTEXT;

typedef struct _SECUREVOL_CONNECTION_CONTEXT {
    ULONG ServiceProcessId;
    ULONG Role;
} SECUREVOL_CONNECTION_CONTEXT, *PSECUREVOL_CONNECTION_CONTEXT;

typedef struct _SECUREVOL_PORT_CONTEXT {
    PFLT_PORT ClientPort;
    BOOLEAN IsQueryPort;
} SECUREVOL_PORT_CONTEXT, *PSECUREVOL_PORT_CONTEXT;

typedef struct _SECUREVOL_CACHE_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    ULONGLONG ProcessCreateTime;
    ULONG PolicyGeneration;
    ULONG Verdict;
    ULONG Reason;
    WCHAR ImagePath[SECUREVOL_MAX_PATH_CHARS];
} SECUREVOL_CACHE_ENTRY, *PSECUREVOL_CACHE_ENTRY;

typedef struct _SECUREVOL_GLOBALS {
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    EX_PUSH_LOCK PolicyLock;
    EX_PUSH_LOCK CacheLock;
    EX_PUSH_LOCK DenyLock;
    BOOLEAN ProtectionEnabled;
    BOOLEAN Unloading;
    ULONG PolicyGeneration;
    ULONG CacheEntryCount;
    HANDLE ServiceProcessId;
    WCHAR ProtectedVolumeGuid[SECUREVOL_MAX_VOLUME_CHARS];
    LIST_ENTRY CacheBuckets[SECUREVOL_CACHE_BUCKET_COUNT];
    SECUREVOL_DENY_EVENT DenyEvents[SECUREVOL_MAX_DENY_EVENTS];
    ULONG DenyEventCount;
    ULONG DenyEventNextIndex;
    LARGE_INTEGER LastDenyTraceTime;
} SECUREVOL_GLOBALS, *PSECUREVOL_GLOBALS;

extern SECUREVOL_GLOBALS Globals;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
SecureVolInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
SecureVolInstanceContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    );

NTSTATUS
SecureVolUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
SecureVolPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

NTSTATUS
SecureVolPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    );

VOID
SecureVolPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
    );

NTSTATUS
SecureVolPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );
