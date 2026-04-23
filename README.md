# SecureVol

SecureVol is a defensive local-only Windows project that restricts read/write access to a mounted VeraCrypt volume by combining:

- a Windows Filter Manager minifilter driver scoped to one configured volume,
- a .NET 8 Windows service that performs process identity verification,
- a small admin CLI for policy management, state inspection, and dedicated-user launches,
- a shared app-core library for desktop control paths,
- a WPF desktop manager, a transitional managed ImGui shell, and a new native upstream Dear ImGui shell for user-facing operations,
- an installer/bootstrapper scaffold that is intended to replace the current PowerShell-first bootstrap path for end users.

The repository is intentionally conservative:

- protection is deny-by-default only for the configured protected volume,
- the driver stays small and asks user mode for first-seen process decisions,
- complex identity checks stay in user mode,
- the default operational model is manual/demand start to avoid boot-path risk.

See `docs/` for threat model, build/install steps, recovery, and testing guidance.
See `docs/product-backlog.md` for the productization roadmap.

## Project status

SecureVol is already usable as a local defensive tool, but it is still in productization:

- the minifilter, service, CLI, and current desktop manager work locally,
- the end-user installer path is still being upgraded from a bootstrap scaffold to a full release installer,
- the desktop UI is being migrated from WPF to an upstream `ocornut/imgui` Win32/DX11 shell,
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
- `installer/`: setup/bootstrap work
- `common/`: shared protocol, interop, policy, logging
- `scripts/`: local build, install, and migration utilities
- `docs/`: threat model, testing, hardening, product backlog, and release notes

## Building

- Managed projects: `dotnet build`
- Tests: `dotnet test`
- Driver: Visual Studio 2022 + latest WDK

The GitHub Actions workflow currently validates only the managed projects. The driver still needs a dedicated WDK-capable Windows build environment.
