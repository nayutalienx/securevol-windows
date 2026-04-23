#pragma once

#include <fltKernel.h>

#define SECUREVOL_PORT_NAME                 L"\\SecureVolPort"
#define SECUREVOL_MAX_VOLUME_CHARS          96
#define SECUREVOL_MAX_PATH_CHARS            512
#define SECUREVOL_MAX_USER_CHARS            128
#define SECUREVOL_MAX_PUBLISHER_CHARS       128
#define SECUREVOL_MAX_DENY_EVENTS           64

typedef enum _SECUREVOL_MESSAGE_TYPE {
    SecureVolMessageTypeInvalid = 0,
    SecureVolMessageTypeProcessQuery = 1,
    SecureVolMessageTypeSetPolicy = 2,
    SecureVolMessageTypeGetState = 3,
    SecureVolMessageTypeGetRecentDenies = 4,
    SecureVolMessageTypeFlushCache = 5
} SECUREVOL_MESSAGE_TYPE;

typedef enum _SECUREVOL_VERDICT {
    SecureVolVerdictUnknown = 0,
    SecureVolVerdictAllow = 1,
    SecureVolVerdictDeny = 2,
    SecureVolVerdictBypass = 3
} SECUREVOL_VERDICT;

typedef enum _SECUREVOL_REASON {
    SecureVolReasonNone = 0,
    SecureVolReasonAllowedByRule = 1,
    SecureVolReasonPolicyDisabled = 2,
    SecureVolReasonUnprotectedVolume = 3,
    SecureVolReasonKernelRequest = 4,
    SecureVolReasonCachedAllow = 5,
    SecureVolReasonCachedDeny = 6,
    SecureVolReasonServiceUnavailable = 7,
    SecureVolReasonProcessLookupFailed = 8,
    SecureVolReasonNoMatchingRule = 9,
    SecureVolReasonPathMismatch = 10,
    SecureVolReasonHashMismatch = 11,
    SecureVolReasonUserMismatch = 12,
    SecureVolReasonSignatureRequired = 13,
    SecureVolReasonPublisherMismatch = 14,
    SecureVolReasonPolicyNotLoaded = 15,
    SecureVolReasonEmergencyBypass = 16,
    SecureVolReasonInternalError = 17
} SECUREVOL_REASON;

typedef struct _SECUREVOL_MESSAGE_HEADER {
    ULONG MessageType;
    ULONG Size;
} SECUREVOL_MESSAGE_HEADER, *PSECUREVOL_MESSAGE_HEADER;

typedef struct _SECUREVOL_PROCESS_QUERY {
    SECUREVOL_MESSAGE_HEADER Header;
    ULONG PolicyGeneration;
    ULONG ProcessId;
    ULONGLONG ProcessCreateTime;
    ACCESS_MASK DesiredAccess;
    ULONG CreateOptions;
    WCHAR VolumeGuid[SECUREVOL_MAX_VOLUME_CHARS];
} SECUREVOL_PROCESS_QUERY, *PSECUREVOL_PROCESS_QUERY;

typedef struct _SECUREVOL_PROCESS_REPLY {
    SECUREVOL_MESSAGE_HEADER Header;
    ULONG PolicyGeneration;
    ULONG Verdict;
    ULONG Reason;
    WCHAR ImagePath[SECUREVOL_MAX_PATH_CHARS];
} SECUREVOL_PROCESS_REPLY, *PSECUREVOL_PROCESS_REPLY;

typedef struct _SECUREVOL_SET_POLICY {
    SECUREVOL_MESSAGE_HEADER Header;
    ULONG PolicyGeneration;
    ULONG ProtectionEnabled;
    WCHAR ProtectedVolumeGuid[SECUREVOL_MAX_VOLUME_CHARS];
} SECUREVOL_SET_POLICY, *PSECUREVOL_SET_POLICY;

typedef struct _SECUREVOL_DRIVER_STATE {
    SECUREVOL_MESSAGE_HEADER Header;
    ULONG PolicyGeneration;
    ULONG ProtectionEnabled;
    ULONG ClientConnected;
    ULONG CacheEntryCount;
    WCHAR ProtectedVolumeGuid[SECUREVOL_MAX_VOLUME_CHARS];
} SECUREVOL_DRIVER_STATE, *PSECUREVOL_DRIVER_STATE;

typedef struct _SECUREVOL_DENY_EVENT {
    LARGE_INTEGER TimestampUtc;
    ULONG ProcessId;
    ULONG Reason;
    CHAR ImageName[16];
} SECUREVOL_DENY_EVENT, *PSECUREVOL_DENY_EVENT;

typedef struct _SECUREVOL_DENY_EVENT_LIST {
    SECUREVOL_MESSAGE_HEADER Header;
    ULONG Count;
    ULONG Reserved;
    SECUREVOL_DENY_EVENT Events[SECUREVOL_MAX_DENY_EVENTS];
} SECUREVOL_DENY_EVENT_LIST, *PSECUREVOL_DENY_EVENT_LIST;
