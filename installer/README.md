# Installer Layer

This folder is the beginning of the end-user installer/bootstrapper path for SecureVol.

Current state:

- `SecureVol.SetupHost` is now the install engine for packaged release payloads.
- It supports `check`, `plan`, `install`, `repair`, and `uninstall`.
- `SecureVol.Installer` is now the GUI bootstrapper for end users.
- Install and repair use versioned payload directories under `C:\Program Files\SecureVol\payloads` so a running old backend does not block the new release from being copied.
- The GUI installer exposes `Start SecureVol backend automatically with Windows`, which maps to the setup host `--autostart` option.
- `scripts/Build-Release.ps1` produces a portable release layout with:
  - `Install-SecureVol.cmd`
  - `Repair-SecureVol.cmd`
  - `Uninstall-SecureVol.cmd`
  - `Launch-SecureVol-Admin.cmd`
- `scripts/Build-Installer-Artifact.ps1` builds the driver payload, exports the local test certificate, assembles the full Dear ImGui-based release bundle, and then packages the GUI installer artifact.

Target direction:

- replace the current PowerShell-first bootstrap path for normal users,
- install the service, driver package, desktop app, and shortcuts,
- launch the first-run setup wizard after installation,
- provide repair and uninstall entry points,
- become the payload that a future WiX/MSIX/bootstrapper layer wraps into a single download.

Current caveats:

- the installer is now GUI-driven, but still intentionally small and pragmatic rather than a polished marketing-style wizard,
- stale payload cleanup is best-effort; if Windows still holds old service files, they are left in place and can be removed after reboot,
- the minifilter remains demand-start; the automatic backend service loads it after Windows starts instead of placing the driver directly in the boot path,
- the bundled driver path currently assumes a test-signed driver package unless you replace it with a production-signed package,
- a fully signed WiX/MSIX-style public installer is still the next step after this bootstrapper.
