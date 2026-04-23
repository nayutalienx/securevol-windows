using SecureVol.AppCore;
using SecureVol.Common;
using SecureVol.Common.Policy;
using System.Collections.ObjectModel;
using System.Linq;
using System.ServiceProcess;
using System.Windows;
using System.Windows.Input;

namespace SecureVol.App;

public partial class MainWindow : Window
{
    private readonly SecureVolDesktopController _controller = new();
    private readonly ObservableCollection<AllowRule> _rules = [];
    private readonly ObservableCollection<string> _recentDenies = [];

    public MainWindow()
    {
        InitializeComponent();

        AllowedAppsGrid.ItemsSource = _rules;
        RecentDeniesListBox.ItemsSource = _recentDenies;

        Loaded += OnLoadedAsync;
    }

    private async void OnLoadedAsync(object sender, RoutedEventArgs e)
    {
        ApplySnapshot(_controller.GetCachedDashboard());
        StatusMessageTextBlock.Text = "Loaded local snapshot. Syncing backend...";
        await RefreshAsync(showBusy: false).ConfigureAwait(true);
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        await RefreshAsync().ConfigureAwait(true);
    }

    private async void EnableProtectionButton_Click(object sender, RoutedEventArgs e)
    {
        await ExecuteCommandAsync(
            async () => await _controller.SetProtectionAsync(enabled: true, CancellationToken.None).ConfigureAwait(true),
            "Protection enabled.").ConfigureAwait(true);
    }

    private async void DisableProtectionButton_Click(object sender, RoutedEventArgs e)
    {
        var confirmation = MessageBox.Show(
            this,
            "Pause protection for the configured protected volume?",
            "SecureVol",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmation != MessageBoxResult.Yes)
        {
            return;
        }

        await ExecuteCommandAsync(
            async () => await _controller.SetProtectionAsync(enabled: false, CancellationToken.None).ConfigureAwait(true),
            "Protection paused.").ConfigureAwait(true);
    }

    private async void ReloadPolicyButton_Click(object sender, RoutedEventArgs e)
    {
        await ExecuteCommandAsync(
            async () => await _controller.ReloadAsync(CancellationToken.None).ConfigureAwait(true),
            "Policy reloaded.").ConfigureAwait(true);
    }

    private async void ApplyVolumeButton_Click(object sender, RoutedEventArgs e)
    {
        if (MountedVolumeComboBox.SelectedItem is not string selectedVolume)
        {
            MessageBox.Show(this, "Choose a mounted drive first.", "SecureVol", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        await ExecuteCommandAsync(
            async () => await _controller.SetProtectedVolumeAsync(selectedVolume, CancellationToken.None).ConfigureAwait(true),
            $"Protected volume set to {selectedVolume}.").ConfigureAwait(true);
    }

    private async void SaveDefaultUserButton_Click(object sender, RoutedEventArgs e)
    {
        await ExecuteCommandAsync(
            async () => await _controller.SetDefaultExpectedUserAsync(DefaultUserTextBox.Text, CancellationToken.None).ConfigureAwait(true),
            "Default expected user updated.").ConfigureAwait(true);
    }

    private async void AddRuleButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new AddRuleWindow(_controller, DefaultUserTextBox.Text)
        {
            Owner = this
        };

        if (dialog.ShowDialog() != true || dialog.CreatedRule is null)
        {
            return;
        }

        await ExecuteCommandAsync(
            async () => await _controller.AddRuleAsync(dialog.CreatedRule, CancellationToken.None).ConfigureAwait(true),
            $"Rule '{dialog.CreatedRule.Name}' saved.").ConfigureAwait(true);
    }

    private async void RemoveRuleButton_Click(object sender, RoutedEventArgs e)
    {
        if (AllowedAppsGrid.SelectedItem is not AllowRule selectedRule)
        {
            MessageBox.Show(this, "Choose a rule to remove.", "SecureVol", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirmation = MessageBox.Show(
            this,
            $"Remove allow rule '{selectedRule.Name}'?",
            "SecureVol",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmation != MessageBoxResult.Yes)
        {
            return;
        }

        await ExecuteCommandAsync(
            async () => await _controller.RemoveRuleAsync(selectedRule.Name, CancellationToken.None).ConfigureAwait(true),
            $"Rule '{selectedRule.Name}' removed.").ConfigureAwait(true);
    }

    private void OpenLogsButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _controller.OpenLogDirectory();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "SecureVol", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OpenConfigButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _controller.OpenConfigDirectory();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "SecureVol", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task RefreshAsync(bool showBusy = true)
    {
        try
        {
            if (showBusy)
            {
                Mouse.OverrideCursor = Cursors.Wait;
            }

            var snapshot = await _controller.GetDashboardAsync(CancellationToken.None).ConfigureAwait(true);
            ApplySnapshot(snapshot);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "SecureVol", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            if (showBusy)
            {
                Mouse.OverrideCursor = null;
            }
        }
    }

    private async Task ExecuteCommandAsync(Func<Task<PolicyConfig>> action, string successMessage)
    {
        try
        {
            Mouse.OverrideCursor = Cursors.Wait;
            var policy = await action().ConfigureAwait(true);

            if (_controller.LastOperationUsedFallback)
            {
                ApplySnapshot(_controller.GetCachedDashboard(policy, _controller.LastOperationMessage));
            }
            else
            {
                await RefreshAsync().ConfigureAwait(true);
                StatusMessageTextBlock.Text = _controller.LastOperationMessage ?? successMessage;
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "SecureVol", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            Mouse.OverrideCursor = null;
        }
    }

    private void ApplySnapshot(DashboardSnapshot snapshot)
    {
        var mountedVolumes = _controller.GetMountedDriveRoots();
        MountedVolumeComboBox.ItemsSource = mountedVolumes;

        if (!string.IsNullOrWhiteSpace(snapshot.Policy.NormalizedProtectedVolume))
        {
            var selectedDrive = mountedVolumes.FirstOrDefault(
                drive => string.Equals(
                    VolumeHelpers.ResolveVolumeGuid(drive),
                    snapshot.Policy.NormalizedProtectedVolume,
                    StringComparison.OrdinalIgnoreCase));

            MountedVolumeComboBox.SelectedItem = selectedDrive;
        }
        else
        {
            MountedVolumeComboBox.SelectedItem = null;
        }

        DefaultUserTextBox.Text = snapshot.Policy.DefaultExpectedUser ?? string.Empty;
        DefaultUserEchoTextBlock.Text = string.IsNullOrWhiteSpace(snapshot.Policy.DefaultExpectedUser)
            ? "<none>"
            : snapshot.Policy.DefaultExpectedUser;

        ReplaceCollection(_rules, snapshot.Policy.AllowRules.OrderBy(rule => rule.Name, StringComparer.OrdinalIgnoreCase));
        ReplaceCollection(_recentDenies, snapshot.RecentDenies.Select(FormatDenyEvent));

        var serviceRunning = snapshot.ServiceStatus == ServiceControllerStatus.Running;
        var driverRunning = snapshot.DriverServiceStatus == ServiceControllerStatus.Running;
        var enforcementKnown = snapshot.DriverState?.ClientConnected == true && serviceRunning && driverRunning;
        var backendLive = snapshot.IsLive && enforcementKnown;

        if (!snapshot.Policy.ProtectionEnabled)
        {
            ProtectionStateTextBlock.Text = "PAUSED";
            ProtectionStateTextBlock.Foreground = FindResource("DangerBrush") as System.Windows.Media.Brush;
        }
        else if (enforcementKnown)
        {
            ProtectionStateTextBlock.Text = "PROTECTED";
            ProtectionStateTextBlock.Foreground = FindResource("SuccessBrush") as System.Windows.Media.Brush;
        }
        else if (snapshot.IsLive)
        {
            ProtectionStateTextBlock.Text = "DEGRADED";
            ProtectionStateTextBlock.Foreground = FindResource("WarningBrush") as System.Windows.Media.Brush;
        }
        else
        {
            ProtectionStateTextBlock.Text = "POLICY ENABLED";
            ProtectionStateTextBlock.Foreground = FindResource("WarningBrush") as System.Windows.Media.Brush;
        }

        ProtectedVolumeTextBlock.Text = string.IsNullOrWhiteSpace(snapshot.Policy.NormalizedProtectedVolume)
            ? "<not configured>"
            : snapshot.Policy.NormalizedProtectedVolume;

        BackendStateTextBlock.Text =
            $"svc={FormatServiceStatus(snapshot.ServiceStatus)}  " +
            $"drv={FormatServiceStatus(snapshot.DriverServiceStatus)}  " +
            $"port={(snapshot.DriverState?.ClientConnected == true ? "live" : "down")}";

        RuleCountTextBlock.Text = snapshot.Policy.AllowRules.Count.ToString();

        BackendLatencyTextBlock.Text = snapshot.IsLive
            ? $"backend: {snapshot.BackendLatencyMs} ms"
            : $"backend: cached ({snapshot.BackendLatencyMs} ms)";

        if (!string.IsNullOrWhiteSpace(snapshot.BackendError))
        {
            StatusMessageTextBlock.Text = snapshot.BackendError;
        }
        else if (enforcementKnown && snapshot.Policy.ProtectionEnabled)
        {
            StatusMessageTextBlock.Text = snapshot.IsLive
                ? "Enforcement is live. New file opens on the protected volume are filtered; existing open handles remain valid until the app or window is reopened."
                : "Enforcement is confirmed from the service status cache. New file opens on the protected volume should be filtered.";
        }
        else if (!snapshot.Policy.ProtectionEnabled)
        {
            StatusMessageTextBlock.Text = snapshot.IsLive ? "Protection is paused." : "Local paused snapshot loaded.";
        }
        else if (snapshot.IsLive)
        {
            StatusMessageTextBlock.Text = "Policy is enabled, but backend health is degraded. Do not trust enforcement until the driver and service report a live connection.";
        }
        else
        {
            StatusMessageTextBlock.Text = "Local cached policy is enabled, but backend state is unknown. Enforcement may already be live, but this UI has not verified it.";
        }
    }

    private static void ReplaceCollection<T>(ObservableCollection<T> target, IEnumerable<T> source)
    {
        target.Clear();
        foreach (var item in source)
        {
            target.Add(item);
        }
    }

    private static string FormatDenyEvent(RecentDenyEventDto deny)
    {
        var image = string.IsNullOrWhiteSpace(deny.ImageName) ? "<unknown>" : deny.ImageName;
        return $"{deny.TimestampUtc:yyyy-MM-dd HH:mm:ss}  pid={deny.ProcessId}  reason={deny.Reason}  image={image}";
    }

    private static string FormatServiceStatus(ServiceControllerStatus? status)
    {
        return status?.ToString() ?? "Not installed";
    }
}
