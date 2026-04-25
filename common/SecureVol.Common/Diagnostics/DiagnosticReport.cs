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

public static class DiagnosticReport
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(6);

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
        var report = await CreateAsync(cancellationToken).ConfigureAwait(false);
        var failures = new List<string>();

        foreach (var uploader in new Func<DiagnosticReportResult, CancellationToken, Task<DiagnosticUploadResult>>[]
                 {
                     UploadToPasteRsAsync,
                     UploadTo0x0Async
                 })
        {
            try
            {
                return await uploader(report, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                failures.Add(ex.Message);
            }
        }

        throw new InvalidOperationException(
            "All diagnostic upload providers failed. Local report: " + report.ReportPath + Environment.NewLine +
            string.Join(Environment.NewLine, failures));
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

    private static HttpClient CreateUploadClient()
    {
        var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(20)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("SecureVol-Diagnostics");
        return client;
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
            ("mountvol", "mountvol.exe", string.Empty),
            ("bcdedit enum", "bcdedit.exe", "/enum"),
            ("wevtutil SecureVol Application events", "wevtutil.exe", "qe Application /q:\"*[System[(Provider[@Name='SecureVol'] or Provider[@Name='SecureVolSvc'])]]\" /f:text /c:80"),
        };

        foreach (var drive in SafeEnumerateMountedDriveRoots())
        {
            var mount = drive.TrimEnd('\\');
            commands.Add(($"fltmc instances -v {mount}", "fltmc.exe", $"instances -v {mount}"));
        }

        foreach (var command in commands)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AppendSubHeader(builder, command.Title);
            var result = await RunCommandAsync(command.FileName, command.Arguments, CommandTimeout, cancellationToken).ConfigureAwait(false);
            builder.AppendLine(result);
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
                .Take(700)
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
                .Take(16)
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
            await AppendTailAsync(builder, file.FullName, maxChars: 60_000, cancellationToken).ConfigureAwait(false);
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

        await AppendTailAsync(builder, path, maxChars: 120_000, cancellationToken).ConfigureAwait(false);
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
            output.AppendLine(await stdoutTask.ConfigureAwait(false));
            var stderr = await stderrTask.ConfigureAwait(false);
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
