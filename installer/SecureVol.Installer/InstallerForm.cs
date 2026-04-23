using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Text;

namespace SecureVol.Installer;

internal sealed class InstallerForm : Form
{
    private readonly Label _titleLabel;
    private readonly Label _subtitleLabel;
    private readonly Label _statusLabel;
    private readonly CheckBox _enableTestSigningCheckBox;
    private readonly Button _installButton;
    private readonly Button _repairButton;
    private readonly Button _uninstallButton;
    private readonly Button _launchAdminButton;
    private readonly Button _openLogsButton;
    private readonly Button _quitButton;
    private readonly TextBox _logTextBox;
    private readonly ProgressBar _progressBar;
    private readonly string _logsRoot;
    private readonly object _logSync = new();

    private string? _currentLogPath;
    private bool _busy;

    public InstallerForm()
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
            Text = "Installs the SecureVol backend, minifilter package, and native Dear ImGui admin app from the embedded release payload.",
            Location = new Point(0, 42)
        };
        headerPanel.Controls.Add(_subtitleLabel);

        var controlsPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            ColumnCount = 6,
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 12)
        };
        controlsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
        controlsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        controlsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        controlsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        controlsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        controlsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        root.Controls.Add(controlsPanel, 0, 1);

        _enableTestSigningCheckBox = new CheckBox
        {
            AutoSize = true,
            Text = "Enable Windows test-signing automatically if needed",
            Checked = true,
            Margin = new Padding(0, 8, 16, 8)
        };
        controlsPanel.Controls.Add(_enableTestSigningCheckBox, 0, 0);

        _installButton = CreateActionButton("Install", async (_, _) => await RunSetupActionAsync("install"));
        _repairButton = CreateActionButton("Repair", async (_, _) => await RunSetupActionAsync("repair"));
        _uninstallButton = CreateActionButton("Uninstall", async (_, _) => await RunSetupActionAsync("uninstall"));
        _launchAdminButton = CreateActionButton("Launch Admin", (_, _) => LaunchAdminApp());
        _openLogsButton = CreateActionButton("Open Logs", (_, _) => OpenLogsFolder());
        _quitButton = CreateActionButton("Quit", (_, _) => Close());

        controlsPanel.Controls.Add(_installButton, 1, 0);
        controlsPanel.Controls.Add(_repairButton, 2, 0);
        controlsPanel.Controls.Add(_uninstallButton, 3, 0);
        controlsPanel.Controls.Add(_launchAdminButton, 4, 0);
        controlsPanel.Controls.Add(_openLogsButton, 5, 0);

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
            Margin = new Padding(8, 0, 0, 0)
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

            var exitCode = await RunProcessAsync(setupHost, arguments, Path.GetDirectoryName(setupHost)!);
            if (exitCode != 0)
            {
                throw new InvalidOperationException($"SetupHost exited with code {exitCode}. See '{_currentLogPath}' for details.");
            }

            var logContent = File.Exists(_currentLogPath) ? await File.ReadAllTextAsync(_currentLogPath) : string.Empty;
            if (logContent.Contains("RebootRequired   : True", StringComparison.OrdinalIgnoreCase))
            {
                SetStatus("Reboot required. Run the installer again after Windows restarts.", Color.DarkGoldenrod);
                MessageBox.Show(
                    this,
                    "Windows test-signing was enabled for the packaged test-signed driver. Reboot Windows and run the installer again.",
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
        var appPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "SecureVol",
            "app",
            "SecureVol.ImGui.exe");

        if (!File.Exists(appPath))
        {
            MessageBox.Show(
                this,
                $"SecureVol admin app was not found at '{appPath}'. Install SecureVol first.",
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

    private void OpenLogsFolder()
    {
        Directory.CreateDirectory(_logsRoot);
        Process.Start(new ProcessStartInfo
        {
            FileName = _logsRoot,
            UseShellExecute = true
        });
    }

    private void SetBusy(bool value, string statusText)
    {
        _busy = value;
        _installButton.Enabled = !value;
        _repairButton.Enabled = !value;
        _uninstallButton.Enabled = !value;
        _launchAdminButton.Enabled = !value;
        _openLogsButton.Enabled = !value;
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
            BeginInvoke(() => AppendLine(line));
            return;
        }

        _logTextBox.AppendText(line + Environment.NewLine);
        _logTextBox.SelectionStart = _logTextBox.TextLength;
        _logTextBox.ScrollToCaret();

        if (!string.IsNullOrWhiteSpace(_currentLogPath))
        {
            lock (_logSync)
            {
                File.AppendAllText(_currentLogPath, line + Environment.NewLine, Encoding.UTF8);
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

    private static string Capitalize(string value) =>
        string.IsNullOrWhiteSpace(value) ? value : char.ToUpperInvariant(value[0]) + value[1..];
}
