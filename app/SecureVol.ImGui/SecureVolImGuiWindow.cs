using System.Numerics;
using ImGuiNET;
using OpenTK.Graphics.OpenGL4;
using OpenTK.Windowing.Common;
using OpenTK.Windowing.Desktop;
using SecureVol.AppCore;
using SecureVol.Common.Policy;
using ImGuiApi = ImGuiNET.ImGui;

namespace SecureVol.ImGui;

internal sealed class SecureVolImGuiWindow : GameWindow
{
    private readonly SecureVolDesktopController _controller = new();
    private DashboardSnapshot _snapshot;
    private ImGuiController? _imgui;
    private Task<DashboardSnapshot>? _pendingRefresh;
    private Task<PolicyConfig>? _pendingPolicyAction;
    private DateTimeOffset? _pendingRefreshStartedUtc;
    private string _statusText = "Starting SecureVol...";
    private bool _closeRequested;
    private string[] _mountedVolumes = [];
    private int _mountedVolumeIndex = -1;

    public SecureVolImGuiWindow(GameWindowSettings gameWindowSettings, NativeWindowSettings nativeWindowSettings)
        : base(gameWindowSettings, nativeWindowSettings)
    {
        _snapshot = _controller.GetCachedDashboard();
    }

    protected override void OnLoad()
    {
        base.OnLoad();

        GL.ClearColor(0.07f, 0.08f, 0.10f, 1.0f);
        _imgui = new ImGuiController(ClientSize.X, ClientSize.Y);
        ApplySnapshot(_snapshot, "Loaded local snapshot. Syncing backend...");
        BeginRefresh();
    }

    protected override void OnRenderFrame(FrameEventArgs args)
    {
        base.OnRenderFrame(args);

        if (_imgui is null)
        {
            return;
        }

        GL.Clear(ClearBufferMask.ColorBufferBit);
        _imgui.Update(this, (float)args.Time);
        DrawUi();
        _imgui.Render();
        SwapBuffers();
    }

    protected override void OnUpdateFrame(FrameEventArgs args)
    {
        base.OnUpdateFrame(args);

        if (_closeRequested)
        {
            Close();
            return;
        }

        PumpOperations();
    }

    protected override void OnTextInput(TextInputEventArgs e)
    {
        base.OnTextInput(e);
        _imgui?.PressChar((uint)e.Unicode);
    }

    protected override void OnFramebufferResize(FramebufferResizeEventArgs e)
    {
        base.OnFramebufferResize(e);
        GL.Viewport(0, 0, e.Width, e.Height);
        _imgui?.WindowResized(ClientSize.X, ClientSize.Y);
    }

    protected override void OnUnload()
    {
        _imgui?.Dispose();
        base.OnUnload();
    }

    private void DrawUi()
    {
        var io = ImGuiApi.GetIO();
        ImGuiApi.SetNextWindowPos(Vector2.Zero);
        ImGuiApi.SetNextWindowSize(io.DisplaySize);

        var flags = ImGuiWindowFlags.NoDecoration |
                    ImGuiWindowFlags.NoMove |
                    ImGuiWindowFlags.NoSavedSettings |
                    ImGuiWindowFlags.NoBringToFrontOnFocus;

        ImGuiApi.PushStyleVar(ImGuiStyleVar.WindowRounding, 0);
        ImGuiApi.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(16, 16));
        ImGuiApi.Begin("SecureVolRoot", flags);
        ImGuiApi.PopStyleVar(2);

        DrawHeader();
        ImGuiApi.Spacing();

        var leftWidth = MathF.Max(560.0f, io.DisplaySize.X * 0.63f);
        var rightWidth = MathF.Max(300.0f, io.DisplaySize.X - leftWidth - 48.0f);
        var availableHeight = ImGuiApi.GetContentRegionAvail().Y;

        ImGuiApi.BeginChild("LeftPane", new Vector2(leftWidth, availableHeight), ImGuiChildFlags.Borders);
        DrawRulesPane();
        ImGuiApi.EndChild();

        ImGuiApi.SameLine();

        ImGuiApi.BeginChild("RightPane", new Vector2(rightWidth, availableHeight));
        DrawStatusPane();
        ImGuiApi.Spacing();
        DrawDeniesPane();
        ImGuiApi.Spacing();
        DrawToolsPane();
        ImGuiApi.EndChild();

        ImGuiApi.End();
    }

    private void DrawHeader()
    {
        ImGuiApi.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.10f, 0.11f, 0.14f, 1.0f));
        ImGuiApi.BeginChild("Header", new Vector2(0, 88), ImGuiChildFlags.Borders, ImGuiWindowFlags.NoScrollbar);
        ImGuiApi.PopStyleColor();

        ImGuiApi.Text("SecureVol");
        ImGuiApi.TextDisabled("Native Dear ImGui shell. Backend-first status, flat console mode.");
        if (!string.IsNullOrWhiteSpace(_snapshot.BackendError))
        {
            ImGuiApi.SameLine();
            ImGuiApi.TextColored(new Vector4(1.0f, 0.68f, 0.30f, 1.0f), _snapshot.BackendError);
        }

        var buttonSize = new Vector2(110, 40);
        var rightStart = ImGuiApi.GetWindowWidth() - 360;
        if (rightStart > 0)
        {
            ImGuiApi.SameLine(rightStart);
        }

        if (ImGuiApi.Button("Refresh", buttonSize))
        {
            BeginRefresh();
        }

        ImGuiApi.SameLine();
        if (ImGuiApi.Button("Enable", buttonSize))
        {
            BeginPolicyAction(enabled: true);
        }

        ImGuiApi.SameLine();
        if (ImGuiApi.Button("Disable", buttonSize))
        {
            BeginPolicyAction(enabled: false);
        }

        ImGuiApi.EndChild();
    }

    private void DrawRulesPane()
    {
        ImGuiApi.Text($"allowlist {_snapshot.Policy.AllowRules.Count}");
        ImGuiApi.SameLine();
        if (ImGuiApi.Button("Reload", new Vector2(96, 34)))
        {
            BeginReload();
        }

        ImGuiApi.SameLine();
        ImGuiApi.BeginDisabled();
        ImGuiApi.Button("Add App", new Vector2(96, 34));
        ImGuiApi.SameLine();
        ImGuiApi.Button("Remove", new Vector2(96, 34));
        ImGuiApi.EndDisabled();

        ImGuiApi.TextDisabled("The Dear ImGui shell starts as a truthful dashboard first. Rule onboarding UI will move here next.");
        ImGuiApi.Separator();

        if (ImGuiApi.BeginTable("AllowRules", 6, ImGuiTableFlags.RowBg | ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY | ImGuiTableFlags.SizingStretchProp, new Vector2(-1, -1)))
        {
            ImGuiApi.TableSetupColumn("Name");
            ImGuiApi.TableSetupColumn("Executable");
            ImGuiApi.TableSetupColumn("Publisher");
            ImGuiApi.TableSetupColumn("User");
            ImGuiApi.TableSetupColumn("Signed");
            ImGuiApi.TableSetupColumn("SHA256");
            ImGuiApi.TableHeadersRow();

            foreach (var rule in _snapshot.Policy.AllowRules)
            {
                ImGuiApi.TableNextRow();

                ImGuiApi.TableSetColumnIndex(0);
                ImGuiApi.TextUnformatted(rule.Name);

                ImGuiApi.TableSetColumnIndex(1);
                ImGuiApi.TextWrapped(rule.ImagePath);

                ImGuiApi.TableSetColumnIndex(2);
                ImGuiApi.TextWrapped(rule.Publisher ?? "<none>");

                ImGuiApi.TableSetColumnIndex(3);
                ImGuiApi.TextWrapped(rule.ExpectedUser ?? "<any>");

                ImGuiApi.TableSetColumnIndex(4);
                ImGuiApi.TextUnformatted(rule.RequireSignature ? "yes" : "no");

                ImGuiApi.TableSetColumnIndex(5);
                ImGuiApi.TextWrapped(rule.Sha256 ?? "<not pinned>");
            }

            ImGuiApi.EndTable();
        }
    }

    private void DrawStatusPane()
    {
        ImGuiApi.BeginChild("StatusPane", new Vector2(0, 188), ImGuiChildFlags.Borders);

        ImGuiApi.TextDisabled("PROTECTION");
        ImGuiApi.SameLine(ImGuiApi.GetWindowWidth() - 130);
        var (label, color) = ClassifyProtectionState();
        ImGuiApi.TextColored(color, label);

        ImGuiApi.Spacing();
        ImGuiApi.TextDisabled("VOLUME");
        ImGuiApi.TextWrapped(_snapshot.Policy.NormalizedProtectedVolume);

        ImGuiApi.Spacing();
        ImGuiApi.TextDisabled("BACKEND");
        var svc = _snapshot.ServiceStatus?.ToString() ?? "Unknown";
        var drv = _snapshot.DriverServiceStatus?.ToString() ?? "Unknown";
        var port = _snapshot.DriverState?.ClientConnected == true ? "port-up" : "port-down";
        ImGuiApi.Text($"svc={svc}  drv={drv}  {port}");

        ImGuiApi.Spacing();
        ImGuiApi.TextDisabled("DEFAULT USER");
        ImGuiApi.TextWrapped(_snapshot.Policy.DefaultExpectedUser ?? "<none>");

        ImGuiApi.Spacing();
        ImGuiApi.TextDisabled("MOUNTED DRIVE");
        if (_mountedVolumes.Length == 0)
        {
            ImGuiApi.TextDisabled("<no mounted drives detected>");
        }
        else
        {
            var preview = _mountedVolumeIndex >= 0 && _mountedVolumeIndex < _mountedVolumes.Length
                ? _mountedVolumes[_mountedVolumeIndex]
                : _mountedVolumes[0];

            if (ImGuiApi.BeginCombo("##volumes", preview))
            {
                for (var i = 0; i < _mountedVolumes.Length; i++)
                {
                    var selected = i == _mountedVolumeIndex;
                    if (ImGuiApi.Selectable(_mountedVolumes[i], selected))
                    {
                        _mountedVolumeIndex = i;
                    }

                    if (selected)
                    {
                        ImGuiApi.SetItemDefaultFocus();
                    }
                }

                ImGuiApi.EndCombo();
            }

            ImGuiApi.SameLine();
            if (ImGuiApi.Button("Apply", new Vector2(80, 30)))
            {
                BeginSetVolume();
            }
        }

        ImGuiApi.EndChild();
    }

    private void DrawDeniesPane()
    {
        ImGuiApi.BeginChild("DeniesPane", new Vector2(0, 260), ImGuiChildFlags.Borders);
        ImGuiApi.Text("recent denies");
        ImGuiApi.Separator();

        if (_snapshot.RecentDenies.Count == 0)
        {
            ImGuiApi.TextDisabled("No deny events in the current snapshot.");
        }
        else
        {
            foreach (var deny in _snapshot.RecentDenies.Take(18))
            {
                ImGuiApi.TextWrapped($"{deny.TimestampUtc:HH:mm:ss}  pid={deny.ProcessId}  {deny.ImageName}  {deny.Reason}");
            }
        }

        ImGuiApi.EndChild();
    }

    private void DrawToolsPane()
    {
        ImGuiApi.BeginChild("ToolsPane", new Vector2(0, 0), ImGuiChildFlags.Borders);
        ImGuiApi.Text("tools");
        ImGuiApi.Separator();

        if (ImGuiApi.Button("Open Logs", new Vector2(110, 34)))
        {
            TryRun(() => _controller.OpenLogDirectory(), "Opened log directory.");
        }

        ImGuiApi.SameLine();
        if (ImGuiApi.Button("Open Config", new Vector2(110, 34)))
        {
            TryRun(() => _controller.OpenConfigDirectory(), "Opened config directory.");
        }

        ImGuiApi.SameLine();
        if (ImGuiApi.Button("Quit", new Vector2(90, 34)))
        {
            _closeRequested = true;
        }

        ImGuiApi.Spacing();
        ImGuiApi.TextWrapped(_statusText);
        ImGuiApi.EndChild();
    }

    private void BeginRefresh()
    {
        if (_pendingPolicyAction is not null)
        {
            return;
        }

        if (_pendingRefresh is not null)
        {
            return;
        }

        _statusText = "Refreshing backend state...";
        _pendingRefreshStartedUtc = DateTimeOffset.UtcNow;
        _pendingRefresh = _controller.GetDashboardAsync(CancellationToken.None);
    }

    private void BeginReload()
    {
        if (_pendingPolicyAction is not null)
        {
            return;
        }

        CancelPendingRefresh();
        _statusText = "Reloading policy...";
        _pendingPolicyAction = _controller.ReloadAsync(CancellationToken.None);
    }

    private void BeginPolicyAction(bool enabled)
    {
        if (_pendingPolicyAction is not null)
        {
            return;
        }

        CancelPendingRefresh();
        _statusText = enabled ? "Enabling protection..." : "Disabling protection...";
        _pendingPolicyAction = _controller.SetProtectionAsync(enabled, CancellationToken.None);
    }

    private void BeginSetVolume()
    {
        if (_pendingPolicyAction is not null)
        {
            return;
        }

        if (_mountedVolumeIndex < 0 || _mountedVolumeIndex >= _mountedVolumes.Length)
        {
            _statusText = "Choose a mounted drive first.";
            return;
        }

        CancelPendingRefresh();
        _statusText = "Updating protected volume...";
        _pendingPolicyAction = _controller.SetProtectedVolumeAsync(_mountedVolumes[_mountedVolumeIndex], CancellationToken.None);
    }

    private void PumpOperations()
    {
        if (_pendingRefresh is not null &&
            _pendingRefreshStartedUtc is not null &&
            DateTimeOffset.UtcNow - _pendingRefreshStartedUtc.Value > TimeSpan.FromSeconds(3))
        {
            ApplySnapshot(
                _controller.GetCachedDashboard(_snapshot.Policy, "Backend refresh timed out. Showing cached local state."),
                "Backend refresh timed out. Using cached state.");
            _pendingRefresh = null;
            _pendingRefreshStartedUtc = null;
        }

        if (_pendingRefresh is not null && _pendingRefresh.IsCompleted)
        {
            try
            {
                ApplySnapshot(_pendingRefresh.GetAwaiter().GetResult(), "Backend state refreshed.");
            }
            catch (Exception ex)
            {
                _statusText = ex.Message;
            }
            finally
            {
                _pendingRefresh = null;
                _pendingRefreshStartedUtc = null;
            }
        }

        if (_pendingPolicyAction is not null && _pendingPolicyAction.IsCompleted)
        {
            try
            {
                var policy = _pendingPolicyAction.GetAwaiter().GetResult();
                ApplySnapshot(
                    _controller.GetCachedDashboard(policy, _controller.LastOperationUsedFallback ? _controller.LastOperationMessage : null),
                    _controller.LastOperationMessage ?? "Policy updated.");

                if (!_controller.LastOperationUsedFallback)
                {
                    BeginRefresh();
                }
            }
            catch (Exception ex)
            {
                _statusText = ex.Message;
            }
            finally
            {
                _pendingPolicyAction = null;
            }
        }
    }

    private void CancelPendingRefresh()
    {
        if (_pendingRefresh is null)
        {
            return;
        }

        _pendingRefresh = null;
        _pendingRefreshStartedUtc = null;
    }

    private void ApplySnapshot(DashboardSnapshot snapshot, string statusText)
    {
        _snapshot = snapshot;
        _statusText = statusText;
        _mountedVolumes = _controller.GetMountedDriveRoots().ToArray();
        _mountedVolumeIndex = Array.FindIndex(
            _mountedVolumes,
            drive => string.Equals(VolumeHelpers.ResolveVolumeGuid(drive), snapshot.Policy.NormalizedProtectedVolume, StringComparison.OrdinalIgnoreCase));

        if (_mountedVolumeIndex < 0 && _mountedVolumes.Length > 0)
        {
            _mountedVolumeIndex = 0;
        }
    }

    private void TryRun(Action action, string successText)
    {
        try
        {
            action();
            _statusText = successText;
        }
        catch (Exception ex)
        {
            _statusText = ex.Message;
        }
    }

    private (string Label, Vector4 Color) ClassifyProtectionState()
    {
        var isProtected = _snapshot.Policy.ProtectionEnabled && _snapshot.IsLive && _snapshot.DriverState?.ClientConnected == true;
        if (isProtected)
        {
            return ("PROTECTED", new Vector4(0.18f, 0.84f, 0.36f, 1.0f));
        }

        if (_snapshot.Policy.ProtectionEnabled)
        {
            return ("POLICY ENABLED", new Vector4(0.95f, 0.69f, 0.17f, 1.0f));
        }

        return ("PAUSED", new Vector4(0.85f, 0.33f, 0.33f, 1.0f));
    }
}
