using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecureVol.Common.Diagnostics;

namespace SecureVol.Installer;

internal sealed class InstallerForm : Form
{
    private const string ReleasesApiUrl = "https://api.github.com/repos/nayutalienx/securevol-windows/releases?per_page=20";
    private const string InstallerAssetPrefix = "SecureVol.Installer-win-x64-";
    private const string InstallerAssetSuffix = ".zip";

    private readonly Label _titleLabel;
    private readonly Label _subtitleLabel;
    private readonly Label _statusLabel;
    private readonly CheckBox _enableTestSigningCheckBox;
    private readonly CheckBox _autoStartCheckBox;
    private readonly Button _installButton;
    private readonly Button _repairButton;
    private readonly Button _updateFromGitHubButton;
    private readonly Button _uninstallButton;
    private readonly Button _launchAdminButton;
    private readonly Button _openLogsButton;
    private readonly Button _uploadDiagnosticsButton;
    private readonly Button _quitButton;
    private readonly TextBox _logTextBox;
    private readonly ProgressBar _progressBar;
    private readonly string _logsRoot;
    private readonly object _logSync = new();

    private string? _currentLogPath;
    private bool _busy;

    public InstallerForm(InstallerStartupAction? startupAction = null)
    {
        Text = "SecureVol Installer";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(840, 620);
        ClientSize = new Size(920, 700);
        Font = new Font("Segoe UI", 10F, FontStyle.Regular, GraphicsUnit.Point);
        BackColor = Color.FromArgb(245, 247, 250);

        _logsRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "SecureVol",
            "logs",
            "installer-ui");

        Directory.CreateDirectory(_logsRoot);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 5,
            Padding = new Padding(18),
            BackColor = Color.Transparent
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        Controls.Add(root);

        var headerPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 112,
            BackColor = Color.White,
            Padding = new Padding(18, 16, 18, 16),
            Margin = new Padding(0, 0, 0, 12)
        };
        root.Controls.Add(headerPanel, 0, 0);

        _titleLabel = new Label
        {
            AutoSize = true,
            Font = new Font("Segoe UI Semibold", 20F, FontStyle.Bold, GraphicsUnit.Point),
            Text = "SecureVol Installer",
            Location = new Point(0, 0)
        };
        headerPanel.Controls.Add(_titleLabel);

        _subtitleLabel = new Label
        {
            AutoSize = false,
            Width = 820,
            Height = 48,
            Font = new Font("Segoe UI", 10F, FontStyle.Regular, GraphicsUnit.Point),
            ForeColor = Color.FromArgb(75, 85, 99),
            Text = "Installs the SecureVol backend, minifilter package, native Dear ImGui admin app, and can update from the latest GitHub release.",
            Location = new Point(0, 42)
        };
        headerPanel.Controls.Add(_subtitleLabel);

        var controlsPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            ColumnCount = 1,
            RowCount = 4,
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 12)
        };
        controlsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
        controlsPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        controlsPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        controlsPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        controlsPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.Controls.Add(controlsPanel, 0, 1);

        _enableTestSigningCheckBox = new CheckBox
        {
            AutoSize = true,
            Text = "Enable Windows test-signing automatically if needed",
            Checked = true,
            Margin = new Padding(0, 0, 0, 6)
        };
        controlsPanel.Controls.Add(_enableTestSigningCheckBox, 0, 0);

        _autoStartCheckBox = new CheckBox
        {
            AutoSize = true,
            Text = "Start SecureVol backend automatically with Windows",
            Checked = true,
            Margin = new Padding(0, 0, 0, 10)
        };
        controlsPanel.Controls.Add(_autoStartCheckBox, 0, 1);

        var adminNoteLabel = new Label
        {
            AutoSize = true,
            Text = "Important: SecureVol Installer, Admin UI, install, repair, update, and protection controls must run as Administrator.",
            ForeColor = Color.DarkRed,
            Font = new Font("Segoe UI Semibold", 9.5F, FontStyle.Bold, GraphicsUnit.Point),
            Margin = new Padding(0, 0, 0, 10)
        };
        controlsPanel.Controls.Add(adminNoteLabel, 0, 2);

        var actionsPanel = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Dock = DockStyle.Top,
            WrapContents = true,
            FlowDirection = FlowDirection.LeftToRight,
            Margin = new Padding(0)
        };
        controlsPanel.Controls.Add(actionsPanel, 0, 3);

        _installButton = CreateActionButton("Install", async (_, _) => await RunSetupActionAsync("install"));
        _repairButton = CreateActionButton("Repair", async (_, _) => await RunSetupActionAsync("repair"));
        _updateFromGitHubButton = CreateActionButton("Update from GitHub", async (_, _) => await RunGitHubUpdateAsync());
        _uninstallButton = CreateActionButton("Uninstall", async (_, _) => await RunSetupActionAsync("uninstall"));
        _launchAdminButton = CreateActionButton("Launch Admin", (_, _) => LaunchAdminApp());
        _openLogsButton = CreateActionButton("Open Logs", (_, _) => OpenLogsFolder());
        _uploadDiagnosticsButton = CreateActionButton("Upload Diagnostics", async (_, _) => await UploadDiagnosticsAsync());
        _quitButton = CreateActionButton("Quit", (_, _) => Close());

        actionsPanel.Controls.Add(_installButton);
        actionsPanel.Controls.Add(_repairButton);
        actionsPanel.Controls.Add(_updateFromGitHubButton);
        actionsPanel.Controls.Add(_uninstallButton);
        actionsPanel.Controls.Add(_launchAdminButton);
        actionsPanel.Controls.Add(_openLogsButton);
        actionsPanel.Controls.Add(_uploadDiagnosticsButton);

        var statusPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            ColumnCount = 2,
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 12)
        };
        statusPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
        statusPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        root.Controls.Add(statusPanel, 0, 2);

        _statusLabel = new Label
        {
            AutoSize = true,
            Text = "Ready.",
            ForeColor = Color.FromArgb(31, 41, 55),
            Margin = new Padding(0, 8, 0, 8)
        };
        statusPanel.Controls.Add(_statusLabel, 0, 0);

        _progressBar = new ProgressBar
        {
            Style = ProgressBarStyle.Marquee,
            Width = 180,
            Visible = false,
            Margin = new Padding(12, 4, 0, 4)
        };
        statusPanel.Controls.Add(_progressBar, 1, 0);

        var logPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = Color.White,
            Padding = new Padding(12)
        };
        logPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        logPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
        root.Controls.Add(logPanel, 0, 3);

        var logHeader = new Label
        {
            AutoSize = true,
            Text = "Installer Log",
            Font = new Font("Segoe UI Semibold", 11F, FontStyle.Bold, GraphicsUnit.Point),
            Margin = new Padding(0, 0, 0, 8)
        };
        logPanel.Controls.Add(logHeader, 0, 0);

        _logTextBox = new TextBox
        {
            Multiline = true,
            ScrollBars = ScrollBars.Both,
            ReadOnly = true,
            WordWrap = false,
            Font = new Font("Consolas", 10F, FontStyle.Regular, GraphicsUnit.Point),
            BackColor = Color.FromArgb(15, 23, 42),
            ForeColor = Color.Gainsboro,
            BorderStyle = BorderStyle.FixedSingle,
            Dock = DockStyle.Fill,
            Margin = new Padding(0)
        };
        logPanel.Controls.Add(_logTextBox, 0, 1);

        var footerPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            AutoSize = true,
            Padding = new Padding(0, 8, 0, 0)
        };
        footerPanel.Controls.Add(_quitButton);
        root.Controls.Add(footerPanel, 0, 4);

        AppendInstallerMessage("Embedded payload ready. Click Install to deploy SecureVol.");
        AppendInstallerMessage($"Installer logs are written to '{_logsRoot}'.");

        if (startupAction is not null)
        {
            _enableTestSigningCheckBox.Checked = startupAction.EnableTestSigning;
            _autoStartCheckBox.Checked = startupAction.AutoStart;
            Shown += async (_, _) =>
            {
                AppendInstallerMessage($"Auto-run requested: {startupAction.Action}.");
                if (string.Equals(startupAction.Action, "update", StringComparison.OrdinalIgnoreCase))
                {
                    await RunGitHubUpdateAsync();
                }
                else
                {
                    await RunSetupActionAsync(startupAction.Action);
                }
            };
        }
    }

    private Button CreateActionButton(string text, EventHandler onClick)
    {
        var button = new Button
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(14, 8, 14, 8),
            Text = text,
            BackColor = Color.FromArgb(37, 99, 235),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Margin = new Padding(0, 0, 8, 8)
        };

        button.FlatAppearance.BorderSize = 0;
        button.Click += onClick;
        return button;
    }

    private async Task RunSetupActionAsync(string action)
    {
        if (_busy)
        {
            return;
        }

        SetBusy(true, $"{Capitalize(action)} in progress...");
        _currentLogPath = Path.Combine(_logsRoot, $"securevol-{action}-{DateTime.Now:yyyyMMdd-HHmmss}.log");
        AppendInstallerMessage($"Starting '{action}'.");
        AppendInstallerMessage($"Writing log to '{_currentLogPath}'.");

        string? extractRoot = null;
        try
        {
            extractRoot = await ExtractEmbeddedPayloadAsync();
            AppendInstallerMessage($"Extracted payload to '{extractRoot}'.");

            var setupHost = ResolveSetupHostPath(extractRoot);
            AppendInstallerMessage($"Resolved SetupHost at '{setupHost}'.");

            var arguments = new List<string> { action };
            if ((action == "install" || action == "repair") && _enableTestSigningCheckBox.Checked)
            {
                arguments.Add("--enable-testsigning");
            }

            if ((action == "install" || action == "repair") && _autoStartCheckBox.Checked)
            {
                arguments.Add("--autostart");
            }

            if (action == "install" || action == "repair")
            {
                var installerSource = Environment.ProcessPath;
                if (!string.IsNullOrWhiteSpace(installerSource))
                {
                    arguments.Add("--installer-source");
                    arguments.Add(installerSource);
                }
            }

            var exitCode = await RunProcessAsync(setupHost, arguments, Path.GetDirectoryName(setupHost)!);
            if (exitCode != 0)
            {
                throw new InvalidOperationException($"SetupHost exited with code {exitCode}. See '{_currentLogPath}' for details.");
            }

            var logContent = File.Exists(_currentLogPath) ? await File.ReadAllTextAsync(_currentLogPath) : string.Empty;
            if (logContent.Contains("RebootRequired   : True", StringComparison.OrdinalIgnoreCase))
            {
                SetStatus("Reboot required to finish the operation safely.", Color.DarkGoldenrod);
                MessageBox.Show(
                    this,
                    "SecureVol completed the requested operation, but Windows must be rebooted to finish driver load/unload changes safely.",
                    "SecureVol Installer",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            else
            {
                SetStatus($"{Capitalize(action)} completed successfully.", Color.DarkGreen);
            }
        }
        catch (Exception ex)
        {
            AppendInstallerMessage($"ERROR: {ex.Message}");
            SetStatus($"{Capitalize(action)} failed.", Color.DarkRed);
            MessageBox.Show(
                this,
                ex.Message,
                "SecureVol Installer",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(extractRoot))
            {
                TryDeleteDirectory(extractRoot);
            }

            SetBusy(false, _statusLabel.Text);
        }
    }

    private async Task RunGitHubUpdateAsync()
    {
        if (_busy)
        {
            return;
        }

        SetBusy(true, "Downloading latest GitHub release...");
        _currentLogPath = Path.Combine(_logsRoot, $"securevol-github-update-{DateTime.Now:yyyyMMdd-HHmmss}.log");
        AppendInstallerMessage("Starting GitHub auto-update.");
        AppendInstallerMessage($"Writing log to '{_currentLogPath}'.");

        string? sessionRoot = null;
        try
        {
            sessionRoot = Path.Combine(
                Path.GetTempPath(),
                "SecureVolInstallerUpdate",
                DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(sessionRoot);

            var release = await ResolveLatestInstallerReleaseAsync();
            AppendInstallerMessage($"Latest release: {release.TagName}");
            AppendInstallerMessage($"Selected asset: {release.AssetName}");

            var zipPath = Path.Combine(sessionRoot, release.AssetName);
            await DownloadFileAsync(release.DownloadUrl, zipPath);
            AppendInstallerMessage($"Downloaded artifact to '{zipPath}'.");
            VerifyDownloadedChecksum(zipPath, release);

            var extractRoot = Path.Combine(sessionRoot, "extracted");
            ZipFile.ExtractToDirectory(zipPath, extractRoot, overwriteFiles: true);
            AppendInstallerMessage($"Extracted latest installer to '{extractRoot}'.");

            var installerPath = ResolveDownloadedInstallerPath(extractRoot);
            AppendInstallerMessage($"Launching latest installer at '{installerPath}'.");

            var arguments = new List<string> { "--autorun", "repair" };
            if (_enableTestSigningCheckBox.Checked)
            {
                arguments.Add("--enable-testsigning");
            }

            if (_autoStartCheckBox.Checked)
            {
                arguments.Add("--autostart");
            }
            else
            {
                arguments.Add("--no-autostart");
            }

            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = installerPath,
                WorkingDirectory = Path.GetDirectoryName(installerPath)!,
                UseShellExecute = true,
                Arguments = string.Join(" ", arguments.Select(QuoteArgument))
            });

            if (process is null)
            {
                throw new InvalidOperationException("Failed to launch the downloaded SecureVol installer.");
            }

            AppendInstallerMessage("The latest installer was launched and will run Repair automatically.");
            AppendInstallerMessage($"Keeping extracted update payload for the child installer: '{sessionRoot}'.");
            AppendInstallerMessage("Closing this installer instance so the downloaded repair can replace the persistent installer files.");
            SetStatus("Latest installer launched. Follow the new installer window.", Color.DarkGreen);
            BeginInvoke(() => Close());
        }
        catch (Exception ex)
        {
            AppendInstallerMessage($"ERROR: {ex.Message}");
            SetStatus("GitHub update failed.", Color.DarkRed);
            MessageBox.Show(
                this,
                ex.Message,
                "SecureVol Installer",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);

            if (!string.IsNullOrWhiteSpace(sessionRoot))
            {
                TryDeleteDirectory(sessionRoot);
            }
        }
        finally
        {
            SetBusy(false, _statusLabel.Text);
        }
    }

    private async Task<string> ExtractEmbeddedPayloadAsync()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = assembly.GetManifestResourceNames()
            .FirstOrDefault(name => string.Equals(name, "SecureVol.Payload.zip", StringComparison.Ordinal));

        if (resourceName is null)
        {
            throw new InvalidOperationException("The embedded installer payload is missing. Rebuild the installer artifact.");
        }

        var sessionRoot = Path.Combine(
            Path.GetTempPath(),
            "SecureVolInstaller",
            DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(sessionRoot);

        var zipPath = Path.Combine(sessionRoot, "SecureVol.Payload.zip");
        var extractRoot = Path.Combine(sessionRoot, "payload");

        await using (var resourceStream = assembly.GetManifestResourceStream(resourceName)
                                   ?? throw new InvalidOperationException("The embedded installer payload stream could not be opened."))
        await using (var fileStream = File.Create(zipPath))
        {
            await resourceStream.CopyToAsync(fileStream);
        }

        ZipFile.ExtractToDirectory(zipPath, extractRoot, overwriteFiles: true);
        return extractRoot;
    }

    private static async Task<GithubInstallerRelease> ResolveLatestInstallerReleaseAsync()
    {
        using var client = CreateGitHubHttpClient();
        await using var stream = await client.GetStreamAsync(ReleasesApiUrl);
        using var document = await JsonDocument.ParseAsync(stream);

        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException("GitHub releases response was not an array.");
        }

        foreach (var release in document.RootElement.EnumerateArray())
        {
            if (release.TryGetProperty("draft", out var draftElement) && draftElement.GetBoolean())
            {
                continue;
            }

            var tagName = release.TryGetProperty("tag_name", out var tagElement)
                ? tagElement.GetString() ?? "<unknown>"
                : "<unknown>";
            var body = release.TryGetProperty("body", out var bodyElement)
                ? bodyElement.GetString() ?? string.Empty
                : string.Empty;
            var expectedSha256 = ExtractSha256FromReleaseBody(body);

            if (!release.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var asset in assets.EnumerateArray())
            {
                var name = asset.TryGetProperty("name", out var nameElement)
                    ? nameElement.GetString()
                    : null;

                if (string.IsNullOrWhiteSpace(name) ||
                    !name.StartsWith(InstallerAssetPrefix, StringComparison.OrdinalIgnoreCase) ||
                    !name.EndsWith(InstallerAssetSuffix, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var downloadUrl = asset.TryGetProperty("browser_download_url", out var urlElement)
                    ? urlElement.GetString()
                    : null;

                if (string.IsNullOrWhiteSpace(downloadUrl))
                {
                    continue;
                }

                if (string.IsNullOrWhiteSpace(expectedSha256))
                {
                    throw new InvalidOperationException(
                        $"Latest release '{tagName}' does not publish a SHA-256 checksum in its release notes. Refusing to auto-update.");
                }

                return new GithubInstallerRelease(tagName, name, downloadUrl, expectedSha256);
            }
        }

        throw new InvalidOperationException(
            $"No '{InstallerAssetPrefix}*{InstallerAssetSuffix}' asset was found in the latest GitHub releases.");
    }

    private static string? ExtractSha256FromReleaseBody(string body)
    {
        var match = Regex.Match(body, @"SHA-256:\s*([A-Fa-f0-9]{64})", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value.ToUpperInvariant() : null;
    }

    private void VerifyDownloadedChecksum(string zipPath, GithubInstallerRelease release)
    {
        using var stream = File.OpenRead(zipPath);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(actual, release.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Downloaded artifact checksum mismatch. Expected {release.Sha256}, got {actual}.");
        }

        AppendInstallerMessage($"SHA-256 verified: {actual}");
    }

    private async Task DownloadFileAsync(string url, string destinationPath)
    {
        using var client = CreateGitHubHttpClient();
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
        response.EnsureSuccessStatusCode();

        var expectedBytes = response.Content.Headers.ContentLength;
        if (expectedBytes.HasValue)
        {
            AppendInstallerMessage($"Download size: {expectedBytes.Value / 1024 / 1024} MB.");
        }

        await using var remoteStream = await response.Content.ReadAsStreamAsync();
        await using var fileStream = File.Create(destinationPath);

        var buffer = new byte[1024 * 1024];
        long totalBytes = 0;
        long nextLogAt = 32L * 1024L * 1024L;
        while (true)
        {
            var read = await remoteStream.ReadAsync(buffer);
            if (read == 0)
            {
                break;
            }

            await fileStream.WriteAsync(buffer.AsMemory(0, read));
            totalBytes += read;

            if (totalBytes >= nextLogAt)
            {
                AppendInstallerMessage($"Downloaded {totalBytes / 1024 / 1024} MB...");
                nextLogAt += 32L * 1024L * 1024L;
            }
        }
    }

    private static HttpClient CreateGitHubHttpClient()
    {
        var client = new HttpClient();
        client.DefaultRequestHeaders.UserAgent.ParseAdd("SecureVol-Installer");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return client;
    }

    private static string ResolveDownloadedInstallerPath(string extractRoot)
    {
        var installer = Directory.EnumerateFiles(extractRoot, "SecureVol.Installer.exe", SearchOption.AllDirectories)
            .OrderBy(path => path.Length)
            .FirstOrDefault();

        if (!string.IsNullOrWhiteSpace(installer))
        {
            return installer;
        }

        var topLevelEntries = Directory.EnumerateFileSystemEntries(extractRoot)
            .Select(Path.GetFileName)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var entrySummary = topLevelEntries.Length == 0 ? "<empty>" : string.Join(", ", topLevelEntries);
        throw new InvalidOperationException(
            $"SecureVol.Installer.exe was not found inside the downloaded artifact. Top-level entries: {entrySummary}.");
    }

    private static string ResolveSetupHostPath(string extractRoot)
    {
        var directPath = Path.Combine(extractRoot, "managed", "setup", "SecureVol.SetupHost.exe");
        if (File.Exists(directPath))
        {
            return directPath;
        }

        var nestedMatch = Directory.EnumerateFiles(extractRoot, "SecureVol.SetupHost.exe", SearchOption.AllDirectories)
            .Where(path => path.EndsWith(
                Path.Combine("managed", "setup", "SecureVol.SetupHost.exe"),
                StringComparison.OrdinalIgnoreCase))
            .OrderBy(path => path.Length)
            .FirstOrDefault();

        if (!string.IsNullOrWhiteSpace(nestedMatch))
        {
            return nestedMatch;
        }

        var topLevelEntries = Directory.EnumerateFileSystemEntries(extractRoot)
            .Select(Path.GetFileName)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var entrySummary = topLevelEntries.Length == 0
            ? "<empty>"
            : string.Join(", ", topLevelEntries);

        throw new InvalidOperationException(
            $"SetupHost was not found inside '{extractRoot}'. Top-level payload entries: {entrySummary}.");
    }

    private async Task<int> RunProcessAsync(string fileName, IReadOnlyCollection<string> arguments, string workingDirectory)
    {
        AppendInstallerMessage($"Running: {fileName} {string.Join(' ', arguments)}");
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process
        {
            StartInfo = startInfo,
            EnableRaisingEvents = true
        };

        process.Start();

        var stdoutTask = PumpStreamAsync(process.StandardOutput);
        var stderrTask = PumpStreamAsync(process.StandardError);

        await process.WaitForExitAsync();
        await Task.WhenAll(stdoutTask, stderrTask);

        AppendInstallerMessage($"Process exit code: {process.ExitCode}");
        return process.ExitCode;
    }

    private async Task PumpStreamAsync(StreamReader reader)
    {
        while (!reader.EndOfStream)
        {
            var line = await reader.ReadLineAsync();
            if (!string.IsNullOrWhiteSpace(line))
            {
                AppendProcessLine(line);
            }
        }
    }

    private void LaunchAdminApp()
    {
        var installRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "SecureVol");
        var appPath = ResolveInstalledAdminApp(installRoot);

        if (string.IsNullOrWhiteSpace(appPath) || !File.Exists(appPath))
        {
            MessageBox.Show(
                this,
                $"SecureVol admin app was not found under '{installRoot}'. Install SecureVol first.",
                "SecureVol Installer",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = appPath,
            UseShellExecute = true
        });
    }

    private static string? ResolveInstalledAdminApp(string installRoot)
    {
        var payloadsRoot = Path.Combine(installRoot, "payloads");
        if (Directory.Exists(payloadsRoot))
        {
            var versionedPath = Directory.EnumerateFiles(payloadsRoot, "SecureVol.ImGui.exe", SearchOption.AllDirectories)
                .Select(path => new FileInfo(path))
                .OrderByDescending(file => file.LastWriteTimeUtc)
                .Select(file => file.FullName)
                .FirstOrDefault();

            if (!string.IsNullOrWhiteSpace(versionedPath))
            {
                return versionedPath;
            }
        }

        var legacyPath = Path.Combine(installRoot, "app", "SecureVol.ImGui.exe");
        return File.Exists(legacyPath) ? legacyPath : null;
    }

    private void OpenLogsFolder()
    {
        Directory.CreateDirectory(_logsRoot);
        Process.Start(new ProcessStartInfo
        {
            FileName = _logsRoot,
            UseShellExecute = true
        });
    }

    private async Task UploadDiagnosticsAsync()
    {
        if (_busy)
        {
            return;
        }

        SetBusy(true, "Uploading diagnostics report...");
        _currentLogPath = Path.Combine(_logsRoot, $"securevol-diagnostics-upload-{DateTime.Now:yyyyMMdd-HHmmss}.log");
        AppendInstallerMessage("Collecting and uploading SecureVol diagnostics.");
        AppendInstallerMessage("The report may include local paths, Windows user names, volume IDs, policy rules, and recent SecureVol logs.");

        try
        {
            var result = await DiagnosticReport.UploadAsync();
            AppendInstallerMessage($"Diagnostics uploaded via {result.Provider}: {result.Url}");
            AppendInstallerMessage($"Local report copy: {result.ReportPath}");
            TrySetClipboard(result.Url);
            DiagnosticReport.OpenInBrowser(result.Url);
            SetStatus("Diagnostics uploaded. URL copied and opened.", Color.DarkGreen);
            MessageBox.Show(
                this,
                $"Diagnostics uploaded via {result.Provider}.{Environment.NewLine}{Environment.NewLine}{result.Url}{Environment.NewLine}{Environment.NewLine}The URL was copied to the clipboard and opened in the browser.",
                "SecureVol Installer",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            AppendInstallerMessage($"ERROR: {ex.Message}");
            SetStatus("Diagnostics upload failed.", Color.DarkRed);
            MessageBox.Show(
                this,
                ex.Message,
                "SecureVol Installer",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
        finally
        {
            SetBusy(false, _statusLabel.Text);
        }
    }

    private void SetBusy(bool value, string statusText)
    {
        _busy = value;
        _installButton.Enabled = !value;
        _repairButton.Enabled = !value;
        _updateFromGitHubButton.Enabled = !value;
        _uninstallButton.Enabled = !value;
        _launchAdminButton.Enabled = !value;
        _openLogsButton.Enabled = !value;
        _uploadDiagnosticsButton.Enabled = !value;
        _quitButton.Enabled = !value;
        _enableTestSigningCheckBox.Enabled = !value;
        _progressBar.Visible = value;
        SetStatus(statusText, value ? Color.FromArgb(30, 64, 175) : Color.FromArgb(31, 41, 55));
    }

    private void SetStatus(string text, Color color)
    {
        _statusLabel.Text = text;
        _statusLabel.ForeColor = color;
    }

    private void AppendInstallerMessage(string message)
    {
        var line = $"[{DateTime.Now:HH:mm:ss}] {message}";
        AppendLine(line);
    }

    private void AppendProcessLine(string line)
    {
        AppendLine(line);
    }

    private void AppendLine(string line)
    {
        if (InvokeRequired)
        {
            try
            {
                BeginInvoke(() => AppendLine(line));
            }
            catch (InvalidOperationException)
            {
                // The window is closing; dropping late process output is safer than surfacing
                // a generic WinForms error dialog after the setup action already finished.
            }

            return;
        }

        _logTextBox.AppendText(line + Environment.NewLine);
        _logTextBox.SelectionStart = _logTextBox.TextLength;
        _logTextBox.ScrollToCaret();

        if (!string.IsNullOrWhiteSpace(_currentLogPath))
        {
            lock (_logSync)
            {
                try
                {
                    File.AppendAllText(_currentLogPath, line + Environment.NewLine, Encoding.UTF8);
                }
                catch
                {
                    // The visible log is the primary feedback channel. File logging is best-effort
                    // and must never fail the install/uninstall operation.
                }
            }
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch
        {
            // Keep the extracted payload for troubleshooting if cleanup fails.
        }
    }

    private static string QuoteArgument(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "\"\"";
        }

        return value.Any(char.IsWhiteSpace) || value.Contains('"')
            ? $"\"{value.Replace("\"", "\\\"", StringComparison.Ordinal)}\""
            : value;
    }

    private static string Capitalize(string value) =>
        string.IsNullOrWhiteSpace(value) ? value : char.ToUpperInvariant(value[0]) + value[1..];

    private static void TrySetClipboard(string text)
    {
        try
        {
            Clipboard.SetText(text);
        }
        catch
        {
            // Clipboard is a convenience only; the URL is still shown and opened.
        }
    }
}

internal sealed record InstallerStartupAction(string Action, bool EnableTestSigning, bool AutoStart);

internal sealed record GithubInstallerRelease(string TagName, string AssetName, string DownloadUrl, string Sha256);
