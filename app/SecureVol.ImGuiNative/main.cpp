// Native SecureVol shell built on official upstream Dear ImGui (ocornut/imgui)
// using the canonical Win32 + DirectX 11 backends.

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include <d3d11.h>
#include <shellapi.h>
#include <shlobj.h>
#include <commdlg.h>
#include <tchar.h>
#include <winrt/base.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Data.Json.h>

#include <array>
#include <algorithm>
#include <cctype>
#include <cfloat>
#include <cstdio>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <numeric>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

using namespace std::chrono_literals;
using namespace winrt;
using namespace Windows::Data::Json;

namespace fs = std::filesystem;

struct ScopedHandle
{
    HANDLE Value{ INVALID_HANDLE_VALUE };

    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE value) noexcept : Value(value) {}

    ScopedHandle(ScopedHandle const&) = delete;
    ScopedHandle& operator=(ScopedHandle const&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept : Value(other.Value)
    {
        other.Value = INVALID_HANDLE_VALUE;
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept
    {
        if (this != &other)
        {
            Reset();
            Value = other.Value;
            other.Value = INVALID_HANDLE_VALUE;
        }

        return *this;
    }

    ~ScopedHandle()
    {
        Reset();
    }

    bool IsValid() const noexcept
    {
        return Value != INVALID_HANDLE_VALUE && Value != nullptr;
    }

    void Reset(HANDLE replacement = INVALID_HANDLE_VALUE) noexcept
    {
        if (IsValid())
        {
            CloseHandle(Value);
        }

        Value = replacement;
    }
};

struct ScopedServiceHandle
{
    SC_HANDLE Value{ nullptr };

    ScopedServiceHandle() = default;
    explicit ScopedServiceHandle(SC_HANDLE value) noexcept : Value(value) {}

    ScopedServiceHandle(ScopedServiceHandle const&) = delete;
    ScopedServiceHandle& operator=(ScopedServiceHandle const&) = delete;

    ~ScopedServiceHandle()
    {
        if (Value)
        {
            CloseServiceHandle(Value);
        }
    }
};

struct AllowRule
{
    std::string Name;
    std::string ImagePath;
    std::string Publisher;
    std::string User;
    std::string Sha256;
    bool RequireSignature{ false };
};

struct DenyEvent
{
    std::string TimestampUtc;
    std::string ImageName;
    std::string Reason;
    uint32_t ProcessId{ 0 };
};

struct DashboardSnapshot
{
    bool HasPolicy{ false };
    bool LiveBackend{ false };
    bool PipeUp{ false };
    bool ProtectionEnabled{ false };
    bool DriverConnected{ false };
    uint32_t PolicyGeneration{ 0 };
    uint32_t CacheEntryCount{ 0 };
    std::string ProtectedVolume;
    std::string DefaultExpectedUser;
    std::string ServiceStatus{ "Unknown" };
    std::string DriverStatus{ "Unknown" };
    std::string BackendLabel{ "cached" };
    std::string BackendError;
    std::vector<AllowRule> Rules;
    std::vector<DenyEvent> RecentDenies;
};

struct OperationResult
{
    bool Success{ false };
    std::string Message;
    DashboardSnapshot Snapshot;
    bool HasSnapshot{ false };
};

struct PendingOperation
{
    std::future<OperationResult> Future;
    std::string BusyText;
    bool BlocksControls{ true };
    uint64_t Epoch{ 0 };
};

static std::optional<JsonObject> TryAdminCommand(JsonObject const& request, std::string& error, DWORD timeoutMs);
static OperationResult RefreshDashboard();

struct AddRuleDraft
{
    std::array<char, 128> Name{};
    std::array<char, 520> ImagePath{};
    std::array<char, 256> Publisher{};
    std::array<char, 256> User{};
    std::array<char, 128> Sha256{};
    bool RequireSignature{ true };

    void Reset(std::string_view defaultUser)
    {
        Name.fill('\0');
        ImagePath.fill('\0');
        Publisher.fill('\0');
        User.fill('\0');
        Sha256.fill('\0');
        RequireSignature = true;
        std::snprintf(User.data(), User.size(), "%s", std::string(defaultUser).c_str());
    }
};

struct AppState
{
    DashboardSnapshot Snapshot;
    std::optional<PendingOperation> PendingAction;
    std::optional<PendingOperation> PendingSync;
    std::string StatusLine{ "Loaded local snapshot. Click Sync to verify the live backend." };
    std::array<char, 16> MountedDrive{ "A:" };
    AddRuleDraft Draft;
    int SelectedRuleIndex{ -1 };
    uint64_t OperationEpoch{ 0 };
    bool OpenAddRulePopup{ false };
    bool OpenMorePopup{ false };
};

static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static bool g_SwapChainOccluded = false;
static UINT g_ResizeWidth = 0;
static UINT g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static std::string WideToUtf8(std::wstring_view value)
{
    if (value.empty())
    {
        return {};
    }

    auto required = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string output(static_cast<size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), output.data(), required, nullptr, nullptr);
    return output;
}

static std::wstring Utf8ToWide(std::string_view value)
{
    if (value.empty())
    {
        return {};
    }

    auto required = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring output(static_cast<size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), output.data(), required);
    return output;
}

static std::string Trim(std::string value)
{
    auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

static std::string FormatWin32Error(DWORD error)
{
    LPWSTR buffer = nullptr;
    auto flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    auto length = FormatMessageW(flags, nullptr, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring message = length > 0 && buffer != nullptr ? std::wstring(buffer, buffer + length) : L"Unknown error";
    if (buffer)
    {
        LocalFree(buffer);
    }

    return Trim(WideToUtf8(message));
}

static fs::path ProgramDataRoot()
{
    wchar_t* raw = nullptr;
    size_t len = 0;
    if (_wdupenv_s(&raw, &len, L"ProgramData") == 0 && raw != nullptr)
    {
        std::wstring value(raw);
        free(raw);
        return fs::path(value) / L"SecureVol";
    }

    return fs::path(LR"(C:\ProgramData\SecureVol)");
}

static fs::path ConfigDirectory()
{
    return ProgramDataRoot() / L"config";
}

static fs::path PolicyPath()
{
    return ConfigDirectory() / L"policy.json";
}

static fs::path StatusPath()
{
    return ConfigDirectory() / L"status.json";
}

static std::string StripUtf8Bom(std::string text)
{
    if (text.size() >= 3 &&
        static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF)
    {
        text.erase(0, 3);
    }

    return text;
}

static std::optional<std::string> ReadUtf8File(fs::path const& path, std::string& error)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream)
    {
        error = "Unable to read " + WideToUtf8(path.wstring()) + ".";
        return std::nullopt;
    }

    std::string content((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    return StripUtf8Bom(content);
}

static std::optional<JsonObject> ParseJsonObject(std::string const& text, std::string& error)
{
    try
    {
        return JsonObject::Parse(to_hstring(text));
    }
    catch (hresult_error const& ex)
    {
        error = WideToUtf8(ex.message().c_str());
        return std::nullopt;
    }
}

static std::optional<JsonObject> LoadJsonFile(fs::path const& path, std::string& error)
{
    auto content = ReadUtf8File(path, error);
    if (!content)
    {
        return std::nullopt;
    }

    return ParseJsonObject(*content, error);
}

static bool SaveJsonFile(fs::path const& path, JsonObject const& object, std::string& error)
{
    try
    {
        fs::create_directories(path.parent_path());
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        if (!stream)
        {
            error = "Unable to open " + WideToUtf8(path.wstring()) + " for writing.";
            return false;
        }

        auto payload = to_string(object.Stringify());
        stream.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        stream.flush();
        if (!stream)
        {
            error = "Unable to flush " + WideToUtf8(path.wstring()) + ".";
            return false;
        }

        return true;
    }
    catch (std::exception const& ex)
    {
        error = ex.what();
        return false;
    }
}

static std::optional<JsonObject> TryGetObject(JsonObject const& object, wchar_t const* key)
{
    if (!object.HasKey(key))
    {
        return std::nullopt;
    }

    auto value = object.Lookup(key);
    if (value.ValueType() != JsonValueType::Object)
    {
        return std::nullopt;
    }

    return value.GetObject();
}

static std::optional<JsonArray> TryGetArray(JsonObject const& object, wchar_t const* key)
{
    if (!object.HasKey(key))
    {
        return std::nullopt;
    }

    auto value = object.Lookup(key);
    if (value.ValueType() != JsonValueType::Array)
    {
        return std::nullopt;
    }

    return value.GetArray();
}

static std::string JsonString(JsonObject const& object, wchar_t const* key, std::string_view fallback = {})
{
    if (!object.HasKey(key))
    {
        return std::string(fallback);
    }

    auto value = object.Lookup(key);
    switch (value.ValueType())
    {
    case JsonValueType::String:
        return to_string(value.GetString());
    case JsonValueType::Number:
    {
        auto number = static_cast<long long>(value.GetNumber());
        return std::to_string(number);
    }
    case JsonValueType::Boolean:
        return value.GetBoolean() ? "true" : "false";
    default:
        return std::string(fallback);
    }
}

static bool JsonBool(JsonObject const& object, wchar_t const* key, bool fallback = false)
{
    if (!object.HasKey(key))
    {
        return fallback;
    }

    auto value = object.Lookup(key);
    return value.ValueType() == JsonValueType::Boolean ? value.GetBoolean() : fallback;
}

static uint32_t JsonUint(JsonObject const& object, wchar_t const* key, uint32_t fallback = 0)
{
    if (!object.HasKey(key))
    {
        return fallback;
    }

    auto value = object.Lookup(key);
    if (value.ValueType() != JsonValueType::Number)
    {
        return fallback;
    }

    return static_cast<uint32_t>(value.GetNumber());
}

static std::string DecisionReasonName(uint32_t reason)
{
    switch (reason)
    {
    case 1: return "AllowedByRule";
    case 2: return "PolicyDisabled";
    case 3: return "UnprotectedVolume";
    case 4: return "KernelRequest";
    case 5: return "CachedAllow";
    case 6: return "CachedDeny";
    case 7: return "ServiceUnavailable";
    case 8: return "ProcessLookupFailed";
    case 9: return "NoMatchingRule";
    case 10: return "PathMismatch";
    case 11: return "HashMismatch";
    case 12: return "UserMismatch";
    case 13: return "SignatureRequired";
    case 14: return "PublisherMismatch";
    case 15: return "PolicyNotLoaded";
    case 16: return "EmergencyBypass";
    case 17: return "InternalError";
    default: return "None";
    }
}

static std::string JoinCsv(std::vector<std::string> const& values)
{
    if (values.empty())
    {
        return {};
    }

    std::string joined = values.front();
    for (size_t index = 1; index < values.size(); ++index)
    {
        joined += ", ";
        joined += values[index];
    }

    return joined;
}

static std::string QueryServiceStatusText(std::wstring const& serviceName)
{
    ScopedServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.Value)
    {
        return "Unknown";
    }

    ScopedServiceHandle service(OpenServiceW(scm.Value, serviceName.c_str(), SERVICE_QUERY_STATUS));
    if (!service.Value)
    {
        auto error = GetLastError();
        return error == ERROR_SERVICE_DOES_NOT_EXIST ? "NotInstalled" : "Unknown";
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(
            service.Value,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytesNeeded))
    {
        return "Unknown";
    }

    switch (status.dwCurrentState)
    {
    case SERVICE_RUNNING: return "Running";
    case SERVICE_STOPPED: return "Stopped";
    case SERVICE_START_PENDING: return "StartPending";
    case SERVICE_STOP_PENDING: return "StopPending";
    case SERVICE_PAUSED: return "Paused";
    default: return "Other";
    }
}

static std::vector<AllowRule> ParseAllowRules(JsonObject const& policy)
{
    std::vector<AllowRule> rules;
    auto array = TryGetArray(policy, L"allowRules");
    if (!array)
    {
        return rules;
    }

    for (auto const& value : *array)
    {
        if (value.ValueType() != JsonValueType::Object)
        {
            continue;
        }

        auto item = value.GetObject();
        rules.push_back(AllowRule{
            JsonString(item, L"name"),
            JsonString(item, L"imagePath"),
            JsonString(item, L"publisher", "<any>"),
            JsonString(item, L"expectedUser", "<any>"),
            JsonString(item, L"sha256", "<not pinned>"),
            JsonBool(item, L"requireSignature", false)
        });
    }

    return rules;
}

static std::vector<DenyEvent> ParseRecentDenies(JsonArray const& array)
{
    std::vector<DenyEvent> denies;
    for (auto const& value : array)
    {
        if (value.ValueType() != JsonValueType::Object)
        {
            continue;
        }

        auto item = value.GetObject();
        denies.push_back(DenyEvent{
            JsonString(item, L"timestampUtc"),
            JsonString(item, L"imageName"),
            DecisionReasonName(JsonUint(item, L"reason", 0)),
            JsonUint(item, L"processId", 0)
        });
    }

    return denies;
}

static DashboardSnapshot LoadLocalSnapshot()
{
    DashboardSnapshot snapshot;
    snapshot.ServiceStatus = QueryServiceStatusText(L"SecureVolSvc");
    snapshot.DriverStatus = QueryServiceStatusText(L"SecureVolFlt");
    snapshot.BackendLabel = "cached";
    snapshot.LiveBackend = false;
    snapshot.PipeUp = false;

    std::string error;
    if (auto policy = LoadJsonFile(PolicyPath(), error))
    {
        snapshot.HasPolicy = true;
        snapshot.ProtectionEnabled = JsonBool(*policy, L"protectionEnabled", false);
        snapshot.ProtectedVolume = JsonString(*policy, L"protectedVolume");
        snapshot.DefaultExpectedUser = JsonString(*policy, L"defaultExpectedUser");
        snapshot.Rules = ParseAllowRules(*policy);
    }
    else
    {
        snapshot.BackendError = error;
    }

    error.clear();
    if (auto status = LoadJsonFile(StatusPath(), error))
    {
        snapshot.DriverConnected = JsonBool(*status, L"driverConnected", false);
        snapshot.PolicyGeneration = JsonUint(*status, L"policyGeneration", 0);
        if (snapshot.ProtectedVolume.empty())
        {
            snapshot.ProtectedVolume = JsonString(*status, L"protectedVolume");
        }
    }

    return snapshot;
}

static DashboardSnapshot SnapshotFromDashboardResponse(JsonObject const& response)
{
    DashboardSnapshot snapshot;
    snapshot.ServiceStatus = QueryServiceStatusText(L"SecureVolSvc");
    snapshot.DriverStatus = QueryServiceStatusText(L"SecureVolFlt");
    snapshot.LiveBackend = true;
    snapshot.PipeUp = true;
    snapshot.BackendLabel = "live";

    if (auto policy = TryGetObject(response, L"policy"))
    {
        snapshot.HasPolicy = true;
        snapshot.ProtectionEnabled = JsonBool(*policy, L"protectionEnabled", false);
        snapshot.ProtectedVolume = JsonString(*policy, L"protectedVolume");
        snapshot.DefaultExpectedUser = JsonString(*policy, L"defaultExpectedUser");
        snapshot.Rules = ParseAllowRules(*policy);
    }

    if (auto state = TryGetObject(response, L"state"))
    {
        snapshot.DriverConnected = JsonBool(*state, L"clientConnected", false);
        snapshot.PolicyGeneration = JsonUint(*state, L"policyGeneration", 0);
        snapshot.CacheEntryCount = JsonUint(*state, L"cacheEntryCount", 0);
        auto stateVolume = JsonString(*state, L"protectedVolumeGuid");
        if (!stateVolume.empty())
        {
            snapshot.ProtectedVolume = stateVolume;
        }
    }

    if (auto denies = TryGetArray(response, L"recentDenies"))
    {
        snapshot.RecentDenies = ParseRecentDenies(*denies);
    }

    return snapshot;
}

static bool TryRunProcess(std::wstring fileName, std::wstring arguments, DWORD timeoutMs, std::string& error, std::initializer_list<DWORD> successExitCodes = { 0 })
{
    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION processInfo{};
    std::wstring commandLine = L"\"" + fileName + L"\"";
    if (!arguments.empty())
    {
        commandLine.append(L" ");
        commandLine.append(arguments);
    }

    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    if (!CreateProcessW(
            nullptr,
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo))
    {
        error = FormatWin32Error(GetLastError());
        return false;
    }

    ScopedHandle process(processInfo.hProcess);
    ScopedHandle thread(processInfo.hThread);

    auto waitResult = WaitForSingleObject(process.Value, timeoutMs);
    if (waitResult == WAIT_TIMEOUT)
    {
        TerminateProcess(process.Value, 1);
        error = WideToUtf8(fileName) + " timed out.";
        return false;
    }

    DWORD exitCode = 1;
    if (!GetExitCodeProcess(process.Value, &exitCode))
    {
        error = FormatWin32Error(GetLastError());
        return false;
    }

    if (std::find(successExitCodes.begin(), successExitCodes.end(), exitCode) != successExitCodes.end())
    {
        return true;
    }

    error = WideToUtf8(fileName) + " exited with code " + std::to_string(exitCode) + ".";
    return false;
}

static bool WaitForServiceStatusConfirmation(bool enabled, DWORD timeoutMs)
{
    auto deadline = GetTickCount64() + timeoutMs;
    while (GetTickCount64() < deadline)
    {
        std::string error;
        if (auto status = LoadJsonFile(StatusPath(), error))
        {
            auto policyEnabled = JsonBool(*status, L"policyProtectionEnabled", !enabled);
            auto driverConnected = JsonBool(*status, L"driverConnected", false);
            if (policyEnabled == enabled && (!enabled || driverConnected))
            {
                return true;
            }
        }

        Sleep(250);
    }

    return false;
}

static bool ApplyLocalProtectionSetting(bool enabled, DashboardSnapshot const& baseline, std::string& error)
{
    JsonObject policy;
    if (auto loaded = LoadJsonFile(PolicyPath(), error))
    {
        policy = *loaded;
    }
    else
    {
        error.clear();
        policy = JsonObject{};
        policy.Insert(L"protectedVolume", JsonValue::CreateStringValue(to_hstring(baseline.ProtectedVolume)));
        if (baseline.DefaultExpectedUser.empty())
        {
            policy.Insert(L"defaultExpectedUser", JsonValue::CreateNullValue());
        }
        else
        {
            policy.Insert(L"defaultExpectedUser", JsonValue::CreateStringValue(to_hstring(baseline.DefaultExpectedUser)));
        }
        policy.Insert(L"allowRules", JsonArray{});
    }

    policy.Insert(L"protectionEnabled", JsonValue::CreateBooleanValue(enabled));
    return SaveJsonFile(PolicyPath(), policy, error);
}

static OperationResult ApplyLocalProtectionChange(bool enabled, DashboardSnapshot baseline)
{
    if (enabled && Trim(baseline.ProtectedVolume).empty())
    {
        auto snapshot = LoadLocalSnapshot();
        snapshot.BackendLabel = "cached";
        snapshot.LiveBackend = false;
        snapshot.PipeUp = false;
        return { false, "Set a mounted drive before enabling protection.", std::move(snapshot), true };
    }

    std::string error;
    if (!ApplyLocalProtectionSetting(enabled, baseline, error))
    {
        auto snapshot = LoadLocalSnapshot();
        snapshot.BackendLabel = "cached";
        snapshot.LiveBackend = false;
        snapshot.PipeUp = false;
        return { false, "Failed to write policy.json: " + error, std::move(snapshot), true };
    }

    std::vector<std::string> actions{ "policy saved locally" };

    if (QueryServiceStatusText(L"SecureVolSvc") != "Running")
    {
        std::string startError;
        if (TryRunProcess(L"sc.exe", L"start SecureVolSvc", 2500, startError, { 0, 1056 }))
        {
            actions.push_back("service start requested");
        }
        else if (!startError.empty())
        {
            actions.push_back("service start pending (" + startError + ")");
        }
    }

    if (enabled && QueryServiceStatusText(L"SecureVolFlt") != "Running")
    {
        std::string loadError;
        if (TryRunProcess(L"fltmc.exe", L"load SecureVolFlt", 2500, loadError, { 0 }))
        {
            actions.push_back("filter loaded");
        }
        else if (!loadError.empty())
        {
            actions.push_back("filter load pending (" + loadError + ")");
        }
    }

    auto confirmed = WaitForServiceStatusConfirmation(enabled, 2500);

    auto snapshot = LoadLocalSnapshot();
    snapshot.BackendLabel = "cached";
    snapshot.LiveBackend = false;
    snapshot.PipeUp = false;

    auto confirmationText = confirmed ? "confirmed by local service state." : "waiting for service file watcher; click Sync in a few seconds.";

    OperationResult result;
    result.Success = true;
    result.Message = (enabled ? "Protection enabled locally: " : "Protection paused locally: ") + JoinCsv(actions) + ", " + confirmationText;
    result.Snapshot = std::move(snapshot);
    result.HasSnapshot = true;
    return result;
}

static std::string BuildAdminRequestJson(JsonObject const& request)
{
    return to_string(request.Stringify());
}

static bool SendAdminRequest(std::string const& requestJson, std::string& responseJson, std::string& error, DWORD timeoutMs = 1200)
{
    static constexpr wchar_t PipeName[] = LR"(\\.\pipe\SecureVolAdmin)";

    if (!WaitNamedPipeW(PipeName, timeoutMs))
    {
        error = GetLastError() == ERROR_FILE_NOT_FOUND
            ? "SecureVolSvc admin pipe is not available."
            : FormatWin32Error(GetLastError());
        return false;
    }

    ScopedHandle pipe(CreateFileW(PipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!pipe.IsValid())
    {
        error = FormatWin32Error(GetLastError());
        return false;
    }

    auto payload = requestJson + "\n";
    DWORD written = 0;
    if (!WriteFile(pipe.Value, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr))
    {
        error = FormatWin32Error(GetLastError());
        return false;
    }

    auto deadline = GetTickCount64() + timeoutMs;
    std::string response;
    std::array<char, 4096> buffer{};

    while (true)
    {
        DWORD available = 0;
        if (!PeekNamedPipe(pipe.Value, nullptr, 0, nullptr, &available, nullptr))
        {
            auto last = GetLastError();
            if (last == ERROR_BROKEN_PIPE)
            {
                break;
            }

            error = FormatWin32Error(last);
            return false;
        }

        if (available == 0)
        {
            if (GetTickCount64() >= deadline)
            {
                error = "The operation has timed out.";
                return false;
            }

            Sleep(15);
            continue;
        }

        DWORD read = 0;
        auto chunk = std::min<DWORD>(available, static_cast<DWORD>(buffer.size()));
        if (!ReadFile(pipe.Value, buffer.data(), chunk, &read, nullptr))
        {
            auto last = GetLastError();
            if (last == ERROR_BROKEN_PIPE)
            {
                break;
            }

            error = FormatWin32Error(last);
            return false;
        }

        response.append(buffer.data(), read);
        auto newline = response.find('\n');
        if (newline != std::string::npos)
        {
            response.resize(newline);
            responseJson = response;
            return true;
        }
    }

    if (!response.empty())
    {
        responseJson = response;
        return true;
    }

    error = "SecureVolSvc returned no response.";
    return false;
}

static std::optional<JsonObject> TryAdminCommand(JsonObject const& request, std::string& error, DWORD timeoutMs = 1200)
{
    std::string responseJson;
    if (!SendAdminRequest(BuildAdminRequestJson(request), responseJson, error, timeoutMs))
    {
        return std::nullopt;
    }

    return ParseJsonObject(responseJson, error);
}

static OperationResult RefreshDashboard()
{
    JsonObject request;
    request.Insert(L"command", JsonValue::CreateStringValue(L"dashboard"));

    std::string error;
    auto response = TryAdminCommand(request, error, 5000);
    if (!response)
    {
        auto fallback = LoadLocalSnapshot();
        fallback.BackendError = "Backend request timed out. Showing cached local state. " + error;
        return { false, fallback.BackendError, std::move(fallback), true };
    }

    if (!JsonBool(*response, L"success", false))
    {
        auto fallback = LoadLocalSnapshot();
        fallback.BackendError = JsonString(*response, L"message", "Dashboard request failed.");
        return { false, fallback.BackendError, std::move(fallback), true };
    }

    auto snapshot = SnapshotFromDashboardResponse(*response);
    return { true, JsonString(*response, L"message", "Dashboard retrieved."), std::move(snapshot), true };
}

static OperationResult ExecuteCommandAndRefresh(JsonObject const& request, std::string_view fallbackSuccess)
{
    std::string error;
    auto response = TryAdminCommand(request, error, 5000);
    if (!response)
    {
        return { false, error, {}, false };
    }

    if (!JsonBool(*response, L"success", false))
    {
        return { false, JsonString(*response, L"message", "SecureVol rejected the request."), {}, false };
    }

    auto refresh = RefreshDashboard();
    if (refresh.HasSnapshot)
    {
        if (refresh.Success)
        {
            refresh.Message = JsonString(*response, L"message", std::string(fallbackSuccess));
            return refresh;
        }

        refresh.Message = JsonString(*response, L"message", std::string(fallbackSuccess)) + " Live refresh degraded after the command.";
        refresh.Success = true;
        return refresh;
    }

    auto snapshot = LoadLocalSnapshot();
    snapshot.BackendLabel = "cached";
    snapshot.LiveBackend = true;
    snapshot.PipeUp = true;
    return { true, JsonString(*response, L"message", std::string(fallbackSuccess)), std::move(snapshot), true };
}

static OperationResult ExecuteProtectionChange(bool enabled, DashboardSnapshot baseline)
{
    return ApplyLocalProtectionChange(enabled, std::move(baseline));
}

static std::optional<std::wstring> BrowseExecutable()
{
    std::array<wchar_t, 520> fileBuffer{};
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.lpstrFilter = L"Executables\0*.exe\0All Files\0*.*\0";
    dialog.lpstrFile = fileBuffer.data();
    dialog.nMaxFile = static_cast<DWORD>(fileBuffer.size());
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    dialog.lpstrDefExt = L"exe";

    return GetOpenFileNameW(&dialog) ? std::optional<std::wstring>(fileBuffer.data()) : std::nullopt;
}

static void OpenShellPath(fs::path const& path)
{
    ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

static bool HasBlockingOperation(AppState const& state)
{
    return state.PendingAction.has_value();
}

static bool HasSyncOperation(AppState const& state)
{
    return state.PendingSync.has_value();
}

static void StartOperation(AppState& state, std::string busyText, std::function<OperationResult()> action, bool blocksControls = true)
{
    auto& slot = blocksControls ? state.PendingAction : state.PendingSync;
    if (slot)
    {
        return;
    }

    auto epoch = state.OperationEpoch;
    if (blocksControls)
    {
        epoch = ++state.OperationEpoch;
    }

    slot = PendingOperation
    {
        std::async(std::launch::async, std::move(action)),
        std::move(busyText),
        blocksControls,
        epoch
    };
}

static void ApplyOperationResult(AppState& state, PendingOperation const& operation, OperationResult&& result)
{
    // A background Sync must not overwrite a newer state-changing action.
    if (!operation.BlocksControls && operation.Epoch != state.OperationEpoch)
    {
        return;
    }

    if (result.HasSnapshot)
    {
        state.Snapshot = std::move(result.Snapshot);
    }

    state.StatusLine = result.Message.empty()
        ? (result.Success ? "Operation completed." : "Operation failed.")
        : result.Message;

    if (!state.Snapshot.DefaultExpectedUser.empty())
    {
        std::snprintf(state.Draft.User.data(), state.Draft.User.size(), "%s", state.Snapshot.DefaultExpectedUser.c_str());
    }
}

static void PumpPendingSlot(AppState& state, std::optional<PendingOperation>& slot)
{
    if (!slot || slot->Future.wait_for(0ms) != std::future_status::ready)
    {
        return;
    }

    auto operation = std::move(*slot);
    auto result = operation.Future.get();
    slot.reset();
    ApplyOperationResult(state, operation, std::move(result));
}

static void PumpPendingOperation(AppState& state)
{
    PumpPendingSlot(state, state.PendingAction);
    PumpPendingSlot(state, state.PendingSync);
}

static const char* ProtectionLabel(DashboardSnapshot const& snapshot)
{
    if (snapshot.ProtectionEnabled && snapshot.LiveBackend && snapshot.DriverConnected)
    {
        return "PROTECTED";
    }

    if (snapshot.ProtectionEnabled)
    {
        return "POLICY ENABLED";
    }

    return "PAUSED";
}

static ImVec4 ProtectionColor(DashboardSnapshot const& snapshot)
{
    if (snapshot.ProtectionEnabled && snapshot.LiveBackend && snapshot.DriverConnected)
    {
        return ImVec4(0.18f, 0.84f, 0.36f, 1.0f);
    }

    if (snapshot.ProtectionEnabled)
    {
        return ImVec4(0.94f, 0.72f, 0.18f, 1.0f);
    }

    return ImVec4(0.72f, 0.72f, 0.72f, 1.0f);
}

static std::string TruncateMiddle(std::string const& value, size_t maxChars)
{
    if (value.size() <= maxChars)
    {
        return value;
    }

    if (maxChars <= 7)
    {
        return value.substr(0, maxChars);
    }

    auto left = (maxChars - 3) / 2;
    auto right = maxChars - 3 - left;
    return value.substr(0, left) + "..." + value.substr(value.size() - right);
}

static void DrawEllipsizedText(std::string const& value, size_t maxChars = 72, bool disabled = false)
{
    auto display = TruncateMiddle(value.empty() ? "<none>" : value, maxChars);
    if (disabled)
    {
        ImGui::TextDisabled("%s", display.c_str());
    }
    else
    {
        ImGui::TextUnformatted(display.c_str());
    }

    if (display != value && ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
    {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(520.0f);
        ImGui::TextUnformatted(value.c_str());
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

static void DrawKeyValueLine(char const* label, std::string const& value, float labelWidth = 104.0f, size_t maxChars = 56)
{
    ImGui::TextDisabled("%s", label);
    ImGui::SameLine(labelWidth);
    DrawEllipsizedText(value, maxChars);
}

static AllowRule const* GetSelectedRule(AppState const& state)
{
    if (state.SelectedRuleIndex < 0 || state.SelectedRuleIndex >= static_cast<int>(state.Snapshot.Rules.size()))
    {
        return nullptr;
    }

    return &state.Snapshot.Rules[static_cast<size_t>(state.SelectedRuleIndex)];
}

static void SetOptionalString(JsonObject& object, wchar_t const* key, std::string_view value)
{
    if (Trim(std::string(value)).empty())
    {
        object.Insert(key, JsonValue::CreateNullValue());
        return;
    }

    object.Insert(key, JsonValue::CreateStringValue(to_hstring(value)));
}

static void DrawSystemPane(AppState& state, float height);
static void DrawDeniesPane(DashboardSnapshot const& snapshot, float height);
static void DrawToolsPane(AppState& state, float height);

static void DrawSectionTitle(char const* title)
{
    ImGui::TextUnformatted(title);
    ImGui::Separator();
}

static float ButtonWidth(char const* label, float extra = 12.0f)
{
    auto const& style = ImGui::GetStyle();
    return ImGui::CalcTextSize(label).x + (style.FramePadding.x * 2.0f) + extra;
}

static void DrawHeader(AppState& state)
{
    auto statusColor = ProtectionColor(state.Snapshot);
    auto busy = HasBlockingOperation(state);
    auto syncBusy = HasSyncOperation(state);
    auto syncDisabled = syncBusy || busy;
    auto syncWidth = ButtonWidth("Sync");
    auto onWidth = ButtonWidth("On");
    auto offWidth = ButtonWidth("Off");
    auto moreWidth = ButtonWidth("More");
    auto controlsWidth = syncWidth + onWidth + offWidth + moreWidth + 18.0f;
    if (ImGui::BeginTable("CompactHeader", 2, ImGuiTableFlags_SizingFixedFit))
    {
        ImGui::TableSetupColumn("HeaderLeft", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("HeaderRight", ImGuiTableColumnFlags_WidthFixed, std::max(246.0f, controlsWidth + 12.0f));
        ImGui::TableNextColumn();
        ImGui::TextUnformatted("SecureVol");
        ImGui::SameLine();
        ImGui::TextDisabled("compact-main v8");
        ImGui::TextDisabled("backend: %s", state.Snapshot.BackendLabel.c_str());
        DrawEllipsizedText(state.StatusLine, 44, true);

        ImGui::TableNextColumn();
        auto avail = ImGui::GetContentRegionAvail().x;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + std::max(0.0f, avail - controlsWidth));
        ImGui::TextColored(statusColor, "%s", ProtectionLabel(state.Snapshot));
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + std::max(0.0f, avail - controlsWidth));

        if (syncDisabled)
        {
            ImGui::BeginDisabled();
        }

        if (ImGui::Button("Sync", ImVec2(syncWidth, 0.0f)))
        {
            StartOperation(state, "Refreshing backend state...", [] { return RefreshDashboard(); }, false);
        }

        if (syncDisabled)
        {
            ImGui::EndDisabled();
        }

        ImGui::SameLine();
        if (busy)
        {
            ImGui::BeginDisabled();
        }

        if (ImGui::Button("On", ImVec2(onWidth, 0.0f)))
        {
            auto baseline = state.Snapshot;
            StartOperation(state, "Enabling protection...", [baseline] { return ExecuteProtectionChange(true, baseline); });
        }

        ImGui::SameLine();
        if (ImGui::Button("Off", ImVec2(offWidth, 0.0f)))
        {
            auto baseline = state.Snapshot;
            StartOperation(state, "Disabling protection...", [baseline] { return ExecuteProtectionChange(false, baseline); });
        }

        ImGui::SameLine();
        if (ImGui::Button("More", ImVec2(moreWidth, 0.0f)))
        {
            state.OpenMorePopup = true;
        }

        if (busy)
        {
            ImGui::EndDisabled();
        }

        ImGui::EndTable();
    }
}

static void DrawRuleDetailsPane(AppState const& state, float height)
{
    ImGui::BeginChild("RuleDetailsPane", ImVec2(0, height), true);
    if (auto rule = GetSelectedRule(state))
    {
        DrawSectionTitle("rule");
        DrawKeyValueLine("name", rule->Name, 72.0f, 28);
        DrawKeyValueLine("user", rule->User, 72.0f, 28);
        DrawKeyValueLine("sig", rule->RequireSignature ? "required" : "optional", 72.0f, 20);
        if (!Trim(rule->Publisher).empty())
        {
            DrawKeyValueLine("pub", rule->Publisher, 72.0f, 32);
        }
        DrawKeyValueLine("path", rule->ImagePath, 72.0f, 46);
        if (!Trim(rule->Sha256).empty() && rule->Sha256 != "<not pinned>")
        {
            DrawKeyValueLine("sha256", rule->Sha256, 72.0f, 24);
        }
    }
    else
    {
        DrawSectionTitle("rule");
        ImGui::TextDisabled("Select a rule to inspect it.");
    }
    ImGui::EndChild();
}

static void DrawRulesPane(AppState& state, float height)
{
    ImGui::BeginChild("RulesPane", ImVec2(0, height), true);
    ImGui::Text("rules %d", static_cast<int>(state.Snapshot.Rules.size()));
    ImGui::SameLine();
    auto reloadWidth = ButtonWidth("Reload");
    auto removeWidth = ButtonWidth("Remove");
    auto addWidth = ButtonWidth("Add");

    auto busy = HasBlockingOperation(state);
    if (busy)
    {
        ImGui::BeginDisabled();
    }

    if (ImGui::Button("Reload", ImVec2(reloadWidth, 0.0f)))
    {
        JsonObject request;
        request.Insert(L"command", JsonValue::CreateStringValue(L"reload"));
        StartOperation(state, "Reloading policy...", [request] { return ExecuteCommandAndRefresh(request, "Policy reloaded."); });
    }

    ImGui::SameLine();
    auto canRemove = state.SelectedRuleIndex >= 0 && state.SelectedRuleIndex < static_cast<int>(state.Snapshot.Rules.size());
    if (!canRemove)
    {
        ImGui::BeginDisabled();
    }
    if (ImGui::Button("Remove", ImVec2(removeWidth, 0.0f)))
    {
        auto selected = state.Snapshot.Rules[static_cast<size_t>(state.SelectedRuleIndex)].Name;
        JsonObject request;
        request.Insert(L"command", JsonValue::CreateStringValue(L"remove-rule"));
        request.Insert(L"ruleName", JsonValue::CreateStringValue(to_hstring(selected)));
        StartOperation(state, "Removing allow rule...", [request] { return ExecuteCommandAndRefresh(request, "Rule removed."); });
        state.SelectedRuleIndex = -1;
    }
    if (!canRemove)
    {
        ImGui::EndDisabled();
    }

    ImGui::SameLine();
    if (ImGui::Button("Add", ImVec2(addWidth, 0.0f)))
    {
        state.OpenAddRulePopup = true;
        state.Draft.Reset(state.Snapshot.DefaultExpectedUser);
    }

    if (busy)
    {
        ImGui::EndDisabled();
    }

    ImGui::Separator();

    auto tableFlags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp;
    if (ImGui::BeginTable("RuleListTable", 2, tableFlags, ImVec2(0, -FLT_MIN)))
    {
        ImGui::TableSetupColumn("App", ImGuiTableColumnFlags_WidthStretch, 0.65f);
        ImGui::TableSetupColumn("User", ImGuiTableColumnFlags_WidthStretch, 0.35f);
        ImGui::TableHeadersRow();

        for (int index = 0; index < static_cast<int>(state.Snapshot.Rules.size()); ++index)
        {
            auto const& rule = state.Snapshot.Rules[static_cast<size_t>(index)];
            auto selected = index == state.SelectedRuleIndex;

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(rule.Name.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns))
            {
                state.SelectedRuleIndex = selected ? -1 : index;
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
            {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(420.0f);
                ImGui::Text("user: %s", rule.User.c_str());
                if (!Trim(rule.Publisher).empty())
                {
                    ImGui::Text("pub: %s", rule.Publisher.c_str());
                }
                ImGui::Separator();
                ImGui::TextUnformatted(rule.ImagePath.c_str());
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }

            ImGui::TableSetColumnIndex(1);
            DrawEllipsizedText(rule.User, 18);
        }

        ImGui::EndTable();
    }
    ImGui::EndChild();
}

static void DrawMorePopup(AppState& state)
{
    if (state.OpenMorePopup)
    {
        ImGui::OpenPopup("More");
        state.OpenMorePopup = false;
    }

    ImGui::SetNextWindowSize(ImVec2(540.0f, 360.0f), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("More", nullptr, ImGuiWindowFlags_NoResize))
    {
        return;
    }

    ImGui::BeginChild("MoreScroll", ImVec2(0, -34.0f), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);
    DrawSystemPane(state, 0.0f);
    ImGui::Spacing();
    DrawDeniesPane(state.Snapshot, 0.0f);
    ImGui::Spacing();
    DrawToolsPane(state, 0.0f);
    ImGui::EndChild();

    if (ImGui::Button("Close", ImVec2(ButtonWidth("Close"), 0.0f)))
    {
        ImGui::CloseCurrentPopup();
    }

    ImGui::EndPopup();
}

static void DrawSystemPane(AppState& state, float height)
{
    (void)height;
    DrawSectionTitle("system");
    DrawKeyValueLine("volume", state.Snapshot.ProtectedVolume, 72.0f, 40);
    DrawKeyValueLine("backend", "svc=" + state.Snapshot.ServiceStatus + " drv=" + state.Snapshot.DriverStatus + " port-" + (state.Snapshot.DriverConnected ? std::string("up") : std::string("down")), 72.0f, 40);
    DrawKeyValueLine("user", state.Snapshot.DefaultExpectedUser, 72.0f, 34);

    ImGui::Spacing();
    ImGui::TextDisabled("drive");
    ImGui::SameLine(72.0f);
    ImGui::SetNextItemWidth(90.0f);
    ImGui::InputText("##mounted-drive", state.MountedDrive.data(), state.MountedDrive.size());
    ImGui::SameLine();

    auto busy = HasBlockingOperation(state);
    if (busy)
    {
        ImGui::BeginDisabled();
    }

    if (ImGui::Button("Apply", ImVec2(ButtonWidth("Apply"), 0.0f)))
    {
        JsonObject request;
        request.Insert(L"command", JsonValue::CreateStringValue(L"set-volume"));
        request.Insert(L"volume", JsonValue::CreateStringValue(to_hstring(state.MountedDrive.data())));
        StartOperation(state, "Setting protected volume...", [request] { return ExecuteCommandAndRefresh(request, "Protected volume updated."); });
    }

    if (busy)
    {
        ImGui::EndDisabled();
    }
}

static void DrawDeniesPane(DashboardSnapshot const& snapshot, float height)
{
    (void)height;
    DrawSectionTitle("denies");

    if (snapshot.RecentDenies.empty())
    {
        ImGui::TextDisabled("No recent denies.");
    }
    else
    {
        auto flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp;
        if (ImGui::BeginTable("RecentDeniesTable", 2, flags, ImVec2(0, -FLT_MIN)))
        {
            ImGui::TableSetupColumn("Image", ImGuiTableColumnFlags_WidthStretch, 0.58f);
            ImGui::TableSetupColumn("Reason", ImGuiTableColumnFlags_WidthStretch, 0.42f);
            ImGui::TableHeadersRow();

            for (auto const& deny : snapshot.RecentDenies)
            {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                DrawEllipsizedText(deny.ImageName, 36);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(deny.Reason.c_str());
            }

            ImGui::EndTable();
        }
    }
}

static void DrawToolsPane(AppState& state, float height)
{
    (void)height;
    DrawSectionTitle("tools");
    if (ImGui::Button("Logs", ImVec2(ButtonWidth("Logs"), 0.0f)))
    {
        OpenShellPath(ProgramDataRoot() / L"logs");
    }
    ImGui::SameLine();
    if (ImGui::Button("Config", ImVec2(ButtonWidth("Config"), 0.0f)))
    {
        OpenShellPath(ConfigDirectory());
    }
    ImGui::SameLine();
    if (ImGui::Button("Quit", ImVec2(ButtonWidth("Quit"), 0.0f)))
    {
        PostQuitMessage(0);
    }

    if (state.PendingAction)
    {
        ImGui::Spacing();
        DrawEllipsizedText(state.PendingAction->BusyText, 44, true);
    }
    else if (state.PendingSync)
    {
        ImGui::Spacing();
        DrawEllipsizedText(state.PendingSync->BusyText, 44, true);
    }
}

static void DrawAddRulePopup(AppState& state)
{
    if (state.OpenAddRulePopup)
    {
        ImGui::OpenPopup("AddAllowRule");
        state.OpenAddRulePopup = false;
    }

    if (!ImGui::BeginPopupModal("AddAllowRule", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
    {
        return;
    }

    ImGui::InputText("name", state.Draft.Name.data(), state.Draft.Name.size());
    ImGui::InputText("executable", state.Draft.ImagePath.data(), state.Draft.ImagePath.size());
    ImGui::SameLine();
    if (ImGui::Button("Browse"))
    {
        if (auto file = BrowseExecutable())
        {
            auto utf8 = WideToUtf8(*file);
            std::snprintf(state.Draft.ImagePath.data(), state.Draft.ImagePath.size(), "%s", utf8.c_str());
        }
    }

    ImGui::InputText("publisher", state.Draft.Publisher.data(), state.Draft.Publisher.size());
    ImGui::InputText("user", state.Draft.User.data(), state.Draft.User.size());
    ImGui::InputText("sha256", state.Draft.Sha256.data(), state.Draft.Sha256.size());
    ImGui::Checkbox("require signature", &state.Draft.RequireSignature);

    auto busy = HasBlockingOperation(state);
    if (busy)
    {
        ImGui::BeginDisabled();
    }

    if (ImGui::Button("Save"))
    {
        JsonObject request;
        request.Insert(L"command", JsonValue::CreateStringValue(L"add-rule"));

        JsonObject rule;
        rule.Insert(L"name", JsonValue::CreateStringValue(to_hstring(state.Draft.Name.data())));
        rule.Insert(L"imagePath", JsonValue::CreateStringValue(to_hstring(state.Draft.ImagePath.data())));
        rule.Insert(L"requireSignature", JsonValue::CreateBooleanValue(state.Draft.RequireSignature));
        SetOptionalString(rule, L"publisher", state.Draft.Publisher.data());
        SetOptionalString(rule, L"expectedUser", state.Draft.User.data());
        SetOptionalString(rule, L"sha256", state.Draft.Sha256.data());
        SetOptionalString(rule, L"notes", "");

        request.Insert(L"rule", rule);

        StartOperation(state, "Saving allow rule...", [request] { return ExecuteCommandAndRefresh(request, "Rule saved."); });
        ImGui::CloseCurrentPopup();
    }

    ImGui::SameLine();
    if (ImGui::Button("Cancel"))
    {
        ImGui::CloseCurrentPopup();
    }

    if (busy)
    {
        ImGui::EndDisabled();
    }

    ImGui::EndPopup();
}

static void DrawMainUi(AppState& state)
{
    PumpPendingOperation(state);
    DrawAddRulePopup(state);

    auto* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);

    auto flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings;
    ImGui::Begin("SecureVolRoot", nullptr, flags);
    DrawHeader(state);
    ImGui::Separator();
    DrawMorePopup(state);

    auto avail = ImGui::GetContentRegionAvail();
    auto detailsHeight = GetSelectedRule(state) ? 154.0f : 88.0f;
    auto rulesHeight = std::max(180.0f, avail.y - detailsHeight - 8.0f);
    DrawRulesPane(state, rulesHeight);
    ImGui::Spacing();
    DrawRuleDetailsPane(state, detailsHeight);

    ImGui::End();
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    init_apartment(apartment_type::single_threaded);

    ImGui_ImplWin32_EnableDpiAwareness();
    auto mainScale = ImGui_ImplWin32_GetDpiScaleForMonitor(::MonitorFromPoint(POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY));

    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandleW(nullptr), nullptr, nullptr, nullptr, nullptr, L"SecureVolImGuiNative", nullptr };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"SecureVol CompactMain v8", WS_OVERLAPPEDWINDOW, 80, 80, static_cast<int>(760 * mainScale), static_cast<int>(560 * mainScale), nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        uninit_apartment();
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    auto& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();
    auto& style = ImGui::GetStyle();
    style.WindowPadding = ImVec2(8.0f, 8.0f);
    style.FramePadding = ImVec2(8.0f, 4.0f);
    style.ItemSpacing = ImVec2(6.0f, 5.0f);
    style.ItemInnerSpacing = ImVec2(4.0f, 4.0f);
    style.CellPadding = ImVec2(5.0f, 3.0f);
    style.ScrollbarSize = 12.0f;
    style.ScaleAllSizes(mainScale);
    style.FontScaleDpi = mainScale;
    style.WindowRounding = 5.0f;
    style.FrameRounding = 3.0f;
    style.GrabRounding = 3.0f;

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    AppState state;
    state.Snapshot = LoadLocalSnapshot();
    state.Draft.Reset(state.Snapshot.DefaultExpectedUser);

    bool done = false;
    while (!done)
    {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
            {
                done = true;
            }
        }

        if (done)
        {
            break;
        }

        if (g_SwapChainOccluded && g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
        {
            ::Sleep(10);
            continue;
        }
        g_SwapChainOccluded = false;

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        DrawMainUi(state);

        ImGui::Render();
        constexpr float clearColor[4] = { 0.09f, 0.10f, 0.12f, 1.00f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clearColor);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        auto hr = g_pSwapChain->Present(1, 0);
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    uninit_apartment();

    return 0;
}

bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel{};
    constexpr D3D_FEATURE_LEVEL featureLevels[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    auto hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevels, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (hr == DXGI_ERROR_UNSUPPORTED)
    {
        hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevels, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    }

    if (FAILED(hr))
    {
        return false;
    }

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* backBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
    g_pd3dDevice->CreateRenderTargetView(backBuffer, nullptr, &g_mainRenderTargetView);
    backBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
    {
        return true;
    }

    switch (msg)
    {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
        {
            return 0;
        }

        g_ResizeWidth = static_cast<UINT>(LOWORD(lParam));
        g_ResizeHeight = static_cast<UINT>(HIWORD(lParam));
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
        {
            return 0;
        }
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    default:
        break;
    }

    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
