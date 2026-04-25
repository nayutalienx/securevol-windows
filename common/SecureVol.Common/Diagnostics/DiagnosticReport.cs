using System.ComponentModel;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SecureVol.Common.Policy;

namespace SecureVol.Common.Diagnostics;

public sealed record DiagnosticReportResult(
    string ReportPath,
    string ReportText);

public sealed record DiagnosticUploadResult(
    string Url,
    string Provider,
    string ReportPath);

public sealed class DiagnosticUploadException : InvalidOperationException
{
    public DiagnosticUploadException(
        string message,
        string reportPath,
        string reportText,
        IReadOnlyList<string> failures)
        : base(message)
    {
        ReportPath = reportPath;
        ReportText = reportText;
        Failures = failures;
    }

    public string ReportPath { get; }

    public string ReportText { get; }

    public IReadOnlyList<string> Failures { get; }
}

public static class DiagnosticReport
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan UploadTimeout = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan OverallUploadTimeout = TimeSpan.FromSeconds(18);

    public static async Task<DiagnosticReportResult> CreateAsync(CancellationToken cancellationToken = default)
    {
        AppPaths.EnsureDirectories();

        var diagnosticsRoot = Path.Combine(AppPaths.ProgramDataRoot, "diagnostics");
        Directory.CreateDirectory(diagnosticsRoot);

        var reportPath = Path.Combine(diagnosticsRoot, $"securevol-diagnostics-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
        var builder = new StringBuilder(capacity: 96 * 1024);

        AppendHeader(builder, "SecureVol Diagnostics");
        AppendLine(builder, "warning", "This report can include local Windows user names, local paths, policy rules, volume IDs, and recent SecureVol logs.");
        AppendLine(builder, "timestamp_utc", DateTimeOffset.UtcNow.ToString("O"));
        AppendLine(builder, "release_tag", BuildIdentity.ReleaseTag);
        AppendLine(builder, "machine", Environment.MachineName);
        AppendLine(builder, "user", WindowsIdentity.GetCurrent().Name);
        AppendLine(builder, "elevated", IsElevated().ToString());
        AppendLine(builder, "os", Environment.OSVersion.VersionString);
        AppendLine(builder, "dotnet", Environment.Version.ToString());
        AppendLine(builder, "process", Environment.ProcessPath ?? "<unknown>");

        await AppendPolicyAndStatusAsync(builder, cancellationToken).ConfigureAwait(false);
        await AppendAdminPipeSnapshotAsync(builder, cancellationToken).ConfigureAwait(false);
        await AppendMountedVolumesAsync(builder, cancellationToken).ConfigureAwait(false);
        await AppendCommandOutputsAsync(builder, cancellationToken).ConfigureAwait(false);
        await AppendProgramFilesLayoutAsync(builder, cancellationToken).ConfigureAwait(false);
        await AppendRecentLogsAsync(builder, cancellationToken).ConfigureAwait(false);

        var text = builder.ToString();
        await File.WriteAllTextAsync(reportPath, text, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
        return new DiagnosticReportResult(reportPath, text);
    }

    public static async Task<DiagnosticUploadResult> UploadAsync(CancellationToken cancellationToken = default)
    {
        using var boundedCollection = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        boundedCollection.CancelAfter(TimeSpan.FromSeconds(12));
        var report = await CreateAsync(boundedCollection.Token).ConfigureAwait(false);
        var failures = new List<string>();
        var uploaders = new (string Name, Func<DiagnosticReportResult, CancellationToken, Task<DiagnosticUploadResult>> Upload)[]
        {
            ("paste.rs", UploadToPasteRsAsync),
            ("dpaste.org", UploadToDpasteAsync),
            ("mclo.gs", UploadToMclogsAsync),
            ("0x0.st", UploadTo0x0Async)
        };

        using var uploadSweep = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        uploadSweep.CancelAfter(OverallUploadTimeout);

        var tasks = uploaders
            .Select(uploader => RunUploaderWithTimeoutAsync(uploader.Name, uploader.Upload, report, uploadSweep.Token))
            .ToList();
        var overallTimeout = Task.Delay(OverallUploadTimeout, CancellationToken.None);

        while (tasks.Count > 0)
        {
            var completed = await Task.WhenAny(tasks.Cast<Task>().Append(overallTimeout)).ConfigureAwait(false);
            if (completed == overallTimeout)
            {
                uploadSweep.Cancel();
                failures.Add($"overall upload timed out after {OverallUploadTimeout.TotalSeconds:N0}s");
                break;
            }

            var completedUpload = (Task<DiagnosticUploadResult>)completed;
            tasks.Remove(completedUpload);

            try
            {
                return await completedUpload.ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                failures.Add(ex.Message);
            }
        }

        TryWriteUploadFailureLog(report.ReportPath, failures);
        var message = "All diagnostic upload providers failed. Local report: " + report.ReportPath + Environment.NewLine +
                      string.Join(Environment.NewLine, failures);
        throw new DiagnosticUploadException(message, report.ReportPath, report.ReportText, failures);
    }

    private static async Task<DiagnosticUploadResult> RunUploaderWithTimeoutAsync(
        string providerName,
        Func<DiagnosticReportResult, CancellationToken, Task<DiagnosticUploadResult>> uploader,
        DiagnosticReportResult report,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(UploadTimeout + TimeSpan.FromSeconds(2));
        var uploadTask = uploader(report, timeout.Token);
        var timeoutTask = Task.Delay(UploadTimeout + TimeSpan.FromSeconds(2), CancellationToken.None);
        var completed = await Task.WhenAny(uploadTask, timeoutTask).ConfigureAwait(false);
        if (completed != uploadTask)
        {
            timeout.Cancel();
            throw new TimeoutException($"{providerName} upload timed out after {UploadTimeout.TotalSeconds + 2:N0}s");
        }

        return await uploadTask.ConfigureAwait(false);
    }

    public static void OpenInBrowser(string url)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = url,
            UseShellExecute = true
        });
    }

    private static async Task<DiagnosticUploadResult> UploadToPasteRsAsync(
        DiagnosticReportResult report,
        CancellationToken cancellationToken)
    {
        using var client = CreateUploadClient();
        using var content = new StringContent(report.ReportText, Encoding.UTF8, "text/plain");
        using var response = await client.PostAsync("https://paste.rs/", content, cancellationToken).ConfigureAwait(false);
        var body = (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)).Trim();
        if (!response.IsSuccessStatusCode || !Uri.TryCreate(body, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException($"paste.rs returned {(int)response.StatusCode}: {TrimForMessage(body)}");
        }

        return new DiagnosticUploadResult(body, "paste.rs", report.ReportPath);
    }

    private static async Task<DiagnosticUploadResult> UploadToDpasteAsync(
        DiagnosticReportResult report,
        CancellationToken cancellationToken)
    {
        using var client = CreateUploadClient();
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["format"] = "url",
            ["lexer"] = "text",
            ["expires"] = "604800",
            ["content"] = report.ReportText
        });

        using var response = await client.PostAsync("https://dpaste.org/api/", form, cancellationToken).ConfigureAwait(false);
        var body = (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)).Trim().Trim('"');
        if (!response.IsSuccessStatusCode || !Uri.TryCreate(body, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException($"dpaste.org returned {(int)response.StatusCode}: {TrimForMessage(body)}");
        }

        return new DiagnosticUploadResult(body, "dpaste.org", report.ReportPath);
    }

    private static async Task<DiagnosticUploadResult> UploadTo0x0Async(
        DiagnosticReportResult report,
        CancellationToken cancellationToken)
    {
        using var client = CreateUploadClient();
        await using var stream = File.OpenRead(report.ReportPath);
        using var form = new MultipartFormDataContent();
        using var fileContent = new StreamContent(stream);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("text/plain");
        form.Add(fileContent, "file", Path.GetFileName(report.ReportPath));
        form.Add(new StringContent(string.Empty), "secret");
        form.Add(new StringContent("168"), "expires");

        using var response = await client.PostAsync("https://0x0.st", form, cancellationToken).ConfigureAwait(false);
        var body = (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)).Trim();
        if (!response.IsSuccessStatusCode || !Uri.TryCreate(body, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException($"0x0.st returned {(int)response.StatusCode}: {TrimForMessage(body)}");
        }

        return new DiagnosticUploadResult(body, "0x0.st", report.ReportPath);
    }

    private static async Task<DiagnosticUploadResult> UploadToMclogsAsync(
        DiagnosticReportResult report,
        CancellationToken cancellationToken)
    {
        using var client = CreateUploadClient();
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["content"] = report.ReportText
        });

        using var response = await client.PostAsync("https://api.mclo.gs/1/log", form, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"mclo.gs returned {(int)response.StatusCode}: {TrimForMessage(body)}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        if (!root.TryGetProperty("success", out var success) ||
            !success.GetBoolean() ||
            !root.TryGetProperty("url", out var urlElement) ||
            string.IsNullOrWhiteSpace(urlElement.GetString()) ||
            !Uri.TryCreate(urlElement.GetString(), UriKind.Absolute, out _))
        {
            throw new InvalidOperationException($"mclo.gs returned an invalid response: {TrimForMessage(body)}");
        }

        return new DiagnosticUploadResult(urlElement.GetString()!, "mclo.gs", report.ReportPath);
    }

    private static HttpClient CreateUploadClient()
    {
        var client = new HttpClient
        {
            Timeout = UploadTimeout
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("SecureVol-Diagnostics");
        client.DefaultRequestHeaders.ExpectContinue = false;
        return client;
    }

    private static void TryWriteUploadFailureLog(string reportPath, IReadOnlyList<string> failures)
    {
        try
        {
            var failurePath = Path.Combine(
                Path.GetDirectoryName(reportPath)!,
                Path.GetFileNameWithoutExtension(reportPath) + ".upload-errors.txt");
            File.WriteAllLines(failurePath, failures, Encoding.UTF8);
        }
        catch
        {
            // Upload diagnostics must not fail again while recording why upload failed.
        }
    }

    private static async Task AppendPolicyAndStatusAsync(StringBuilder builder, CancellationToken cancellationToken)
    {
        AppendHeader(builder, "Policy And Status Files");
        await AppendFileAsync(builder, "policy.json", AppPaths.PolicyFilePath, cancellationToken).ConfigureAwait(false);
        await AppendFileAsync(builder, "status.json", AppPaths.StatusFilePath, cancellationToken).ConfigureAwait(false);
    }

    private static async Task AppendAdminPipeSnapshotAsync(StringBuilder builder, CancellationToken cancellationToken)
    {
        AppendHeader(builder, "Admin Pipe Snapshot");
        try
        {
            var client = new AdminPipeClient();
            var response = await client.SendAsync(new AdminRequest { Command = "dashboard" }, cancellationToken).ConfigureAwait(false);
            var json = JsonSerializer.Serialize(response, PolicyConfig.JsonOptions());
            builder.AppendLine(json);
        }
        catch (Exception ex)
        {
            AppendLine(builder, "admin_pipe_error", ex.Message);
        }
    }

    private static async Task AppendMountedVolumesAsync(StringBuilder builder, CancellationToken cancellationToken)
    {
        AppendHeader(builder, "Mounted Drive Map");
        foreach (var root in SafeEnumerateMountedDriveRoots())
        {
            try
            {
                AppendLine(builder, root, VolumeHelpers.ResolveVolumeGuid(root));
            }
            catch (Exception ex)
            {
                AppendLine(builder, root, "resolve failed: " + ex.Message);
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
    }

    private static async Task AppendCommandOutputsAsync(StringBuilder builder, CancellationToken cancellationToken)
    {
        AppendHeader(builder, "Command Output");
        var commands = new List<(string Title, string FileName, string Arguments)>
        {
            ("sc queryex SecureVolSvc", "sc.exe", "queryex SecureVolSvc"),
            ("sc qc SecureVolSvc", "sc.exe", "qc SecureVolSvc"),
            ("sc queryex SecureVolFlt", "sc.exe", "queryex SecureVolFlt"),
            ("sc qc SecureVolFlt", "sc.exe", "qc SecureVolFlt"),
            ("fltmc filters", "fltmc.exe", "filters"),
            ("fltmc instances -f SecureVolFlt", "fltmc.exe", "instances -f SecureVolFlt"),
            ("fltmc volumes", "fltmc.exe", "volumes"),
        };

        if (TryReadProtectedMountPoint() is { } protectedMount)
        {
            var mount = protectedMount.TrimEnd('\\');
            commands.Add(($"fltmc instances -v {mount}", "fltmc.exe", $"instances -v {mount}"));
        }
        else if (SafeEnumerateMountedDriveRoots().FirstOrDefault(static drive => drive.StartsWith("A:", StringComparison.OrdinalIgnoreCase)) is { } driveA)
        {
            commands.Add(("fltmc instances -v A:", "fltmc.exe", $"instances -v {driveA.TrimEnd('\\')}"));
        }

        var tasks = commands
            .Select(async command =>
            {
                var result = await RunCommandAsync(command.FileName, command.Arguments, CommandTimeout, cancellationToken).ConfigureAwait(false);
                return (command.Title, Result: result);
            })
            .ToArray();

        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        foreach (var result in results)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AppendSubHeader(builder, result.Title);
            builder.AppendLine(result.Result);
        }
    }

    private static async Task AppendProgramFilesLayoutAsync(StringBuilder builder, CancellationToken cancellationToken)
    {
        AppendHeader(builder, "Installed File Layout");
        var installRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "SecureVol");

        if (!Directory.Exists(installRoot))
        {
            AppendLine(builder, "install_root", installRoot + " <missing>");
            return;
        }

        AppendLine(builder, "install_root", installRoot);
        IEnumerable<FileInfo> files;
        try
        {
            files = Directory.EnumerateFiles(installRoot, "*", SearchOption.AllDirectories)
                .Select(path => new FileInfo(path))
                .OrderBy(file => file.FullName, StringComparer.OrdinalIgnoreCase)
                .Take(180)
                .ToArray();
        }
        catch (Exception ex)
        {
            AppendLine(builder, "installed_layout_error", ex.Message);
            return;
        }

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relative = Path.GetRelativePath(installRoot, file.FullName);
            builder.AppendLine($"{relative}\t{file.Length}\t{file.LastWriteTimeUtc:O}");
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    private static async Task AppendRecentLogsAsync(StringBuilder builder, CancellationToken cancellationToken)
    {
        AppendHeader(builder, "Recent Logs");
        if (!Directory.Exists(AppPaths.LogDirectory))
        {
            AppendLine(builder, "logs", AppPaths.LogDirectory + " <missing>");
            return;
        }

        IEnumerable<FileInfo> files;
        try
        {
            files = Directory.EnumerateFiles(AppPaths.LogDirectory, "*", SearchOption.AllDirectories)
                .Select(path => new FileInfo(path))
                .OrderByDescending(file => file.LastWriteTimeUtc)
                .Take(8)
                .OrderBy(file => file.FullName, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (Exception ex)
        {
            AppendLine(builder, "logs_error", ex.Message);
            return;
        }

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AppendSubHeader(builder, Path.GetRelativePath(AppPaths.LogDirectory, file.FullName));
            await AppendTailAsync(builder, file.FullName, maxChars: 24_000, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task AppendFileAsync(StringBuilder builder, string label, string path, CancellationToken cancellationToken)
    {
        AppendSubHeader(builder, label);
        if (!File.Exists(path))
        {
            builder.AppendLine(path + " <missing>");
            return;
        }

        await AppendTailAsync(builder, path, maxChars: 48_000, cancellationToken).ConfigureAwait(false);
    }

    private static async Task AppendTailAsync(
        StringBuilder builder,
        string path,
        int maxChars,
        CancellationToken cancellationToken)
    {
        try
        {
            var text = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
            if (text.Length > maxChars)
            {
                builder.AppendLine($"<truncated to last {maxChars} chars from {path}>");
                text = text[^maxChars..];
            }

            builder.AppendLine(text);
        }
        catch (Exception ex)
        {
            AppendLine(builder, path, "read failed: " + ex.Message);
        }
    }

    private static async Task<string> RunCommandAsync(
        string fileName,
        string arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            var output = new StringBuilder();
            process.Start();
            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
            var waitTask = process.WaitForExitAsync(cancellationToken);
            var timeoutTask = Task.Delay(timeout, cancellationToken);
            var completed = await Task.WhenAny(waitTask, timeoutTask).ConfigureAwait(false);
            if (completed != waitTask)
            {
                TryKill(process);
                output.AppendLine($"<timed out after {timeout.TotalSeconds:N0}s>");
            }

            if (completed == waitTask)
            {
                await waitTask.ConfigureAwait(false);
            }

            output.AppendLine("exit_code=" + (process.HasExited ? process.ExitCode.ToString() : "<killed>"));
            output.AppendLine(await ReadCommandStreamBestEffortAsync(stdoutTask).ConfigureAwait(false));
            var stderr = await ReadCommandStreamBestEffortAsync(stderrTask).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(stderr))
            {
                output.AppendLine("--- stderr ---");
                output.AppendLine(stderr);
            }

            return output.ToString();
        }
        catch (Win32Exception ex)
        {
            return "start failed: " + ex.Message;
        }
        catch (Exception ex)
        {
            return "command failed: " + ex.Message;
        }
    }

    private static IReadOnlyList<string> SafeEnumerateMountedDriveRoots()
    {
        try
        {
            return VolumeHelpers.EnumerateMountedDriveRoots();
        }
        catch
        {
            return [];
        }
    }

    private static string? TryReadProtectedMountPoint()
    {
        try
        {
            if (!File.Exists(AppPaths.PolicyFilePath))
            {
                return null;
            }

            var policy = PolicyConfig.Load(AppPaths.PolicyFilePath);
            return string.IsNullOrWhiteSpace(policy.ProtectedMountPoint)
                ? null
                : PolicyConfig.NormalizeVolumeIdentifier(policy.ProtectedMountPoint);
        }
        catch
        {
            return null;
        }
    }

    private static async Task<string> ReadCommandStreamBestEffortAsync(Task<string> readTask)
    {
        var completed = await Task.WhenAny(readTask, Task.Delay(TimeSpan.FromMilliseconds(600))).ConfigureAwait(false);
        if (completed != readTask)
        {
            return "<stream read timed out>";
        }

        return await readTask.ConfigureAwait(false);
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Diagnostics must continue even if a helper process is already gone.
        }
    }

    private static void AppendHeader(StringBuilder builder, string title)
    {
        builder.AppendLine();
        builder.AppendLine("================================================================================");
        builder.AppendLine(title);
        builder.AppendLine("================================================================================");
    }

    private static void AppendSubHeader(StringBuilder builder, string title)
    {
        builder.AppendLine();
        builder.AppendLine("---- " + title + " ----");
    }

    private static void AppendLine(StringBuilder builder, string key, string value)
    {
        builder.AppendLine($"{key}: {value}");
    }

    private static string TrimForMessage(string value)
    {
        value = value.Trim();
        return value.Length <= 300 ? value : value[..300] + "...";
    }
}
