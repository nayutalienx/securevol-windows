# SecureVol

SecureVol is a defensive local-only Windows project that restricts read/write access to a mounted VeraCrypt volume by combining:

- a Windows Filter Manager minifilter driver scoped to one configured volume,
- a .NET 8 Windows service that performs process identity verification,
- a small admin CLI for policy management, state inspection, and dedicated-user launches,
- a shared app-core library for desktop control paths,
- a WPF desktop manager, a transitional managed ImGui shell, and a new native upstream Dear ImGui shell for user-facing operations,
- an installer/bootstrapper engine that installs the packaged backend, driver payload, and admin UI from a release bundle.

The repository is intentionally conservative:

- protection is deny-by-default only for the configured protected volume,
- the driver stays small and asks user mode for first-seen process decisions,
- complex identity checks stay in user mode,
- the minifilter stays demand-start, while the backend can optionally auto-start after Windows boots and load the filter outside the boot-critical path.

See `docs/` for threat model, build/install steps, recovery, and testing guidance.
See `docs/product-backlog.md` for the productization roadmap.

## Current UI

The current admin surface is a native Win32/DX11 shell built on upstream [`ocornut/imgui`](https://github.com/ocornut/imgui).

![SecureVol native Dear ImGui admin UI](docs/assets/securevol-ui.png)

## Installer artifact

The repository now produces a packaged Windows install bundle that contains:

- the minifilter driver package,
- the SecureVol Windows service,
- the CLI,
- the native Dear ImGui admin app,
- the setup host used for install, repair, and uninstall,
- a GUI installer bootstrapper for new machines.

Important for the current preview:

- the bundled driver is still test-signed,
- a new machine currently needs Windows test-signing mode enabled,
- installation must be run as Administrator; the GUI installer requests elevation,
- if test-signing was just enabled, Windows must be rebooted and the installer run again.
- repair/update installs backend payloads into versioned directories under `C:\Program Files\SecureVol\payloads`, so a running old service cannot block copying the new release.
- the installer can configure the SecureVol backend to start with Windows; the backend then loads the minifilter and reapplies the saved policy automatically.

## Quick install on a new machine

1. Download and extract the latest `SecureVol.Installer-*.zip` package.
2. Run `SecureVol.Installer.exe`.
3. Click `Install` in the installer window.
4. Reboot if the installer enables test-signing.
5. Run `SecureVol.Installer.exe` again after reboot if prompted.
6. Launch the admin app from the installer or the Start Menu shortcut.

## Updating

Run the newer `SecureVol.Installer.exe` as Administrator and click `Repair`. The installer writes a fresh payload directory, points the Windows service at the new backend path, updates shortcuts, and only then tries to clean old payloads. If Windows still has the old backend loaded, cleanup is skipped and the installer reports `RebootRequired: True` instead of failing.

## Startup And Remount Behavior

When the installer option `Start SecureVol backend automatically with Windows` is enabled, `SecureVolSvc` is configured as an automatic Windows service. The service loads `SecureVolFlt` on startup, pushes the saved policy to the driver, and keeps watching the configured mount point such as `A:\`. If the VeraCrypt container is mounted after Windows starts, the service resolves the current volume GUID for that mount point and updates the driver policy without requiring repair.

## Project status

SecureVol is already usable as a local defensive tool, but it is still in productization:

- the minifilter, service, CLI, and current desktop manager work locally,
- the packaged installer path now has a real GUI bootstrapper plus the underlying install engine,
- the native `ocornut/imgui` desktop shell is the primary admin UI,
- a polished public installer wrapper and a production-signed driver are still pending,
- open-source hygiene and release automation are now part of the repo instead of ad hoc local setup.

## Open-source expectations

- No stealth, persistence tricks, privilege escalation, or security-product tampering will be accepted.
- Recovery must remain obvious and documented.
- Degraded backend states must never be shown as a healthy protected state.

## Repository guide

- `driver/`: minifilter driver
- `service/`: Windows service and policy coordinator
- `cli/`: admin CLI and launch helper
- `app/`: desktop control surfaces
- `app/SecureVol.AppCore`: shared desktop control-path logic
- `app/SecureVol.App`: current WPF manager
- `app/SecureVol.ImGui`: transitional managed shell based on `ImGui.NET`
- `app/SecureVol.ImGuiNative`: native shell built on official upstream `ocornut/imgui`
- `installer/`: setup host and install/bootstrap work
- `common/`: shared protocol, interop, policy, logging
- `scripts/`: local build, install, release, and artifact packaging utilities
- `docs/`: threat model, testing, hardening, product backlog, and release notes

## Building

- Managed projects: `dotnet build`
- Tests: `dotnet test`
- Driver: Visual Studio 2022 + latest WDK
- Full packaged installer artifact: `powershell -ExecutionPolicy Bypass -File .\scripts\Build-Installer-Artifact.ps1`

The GitHub Actions workflow currently validates only the managed projects. The driver still needs a dedicated WDK-capable Windows build environment.
