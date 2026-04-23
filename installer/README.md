# Installer Layer

This folder is the beginning of the end-user installer/bootstrapper path for SecureVol.

Current state:

- `SecureVol.SetupHost` is a buildable scaffold.
- It validates that the release artifacts needed for installation exist.
- `scripts/Build-Release.ps1` now produces a repeatable managed release layout that SetupHost can target.
- It is intended to become the engine behind a future packaged setup experience.

Target direction:

- replace the current PowerShell-first bootstrap path for normal users,
- install the service, driver package, desktop app, and shortcuts,
- launch the first-run setup wizard after installation,
- provide repair and uninstall entry points,
- become the payload that a future WiX/MSIX/bootstrapper layer wraps into a single download.

Near-term direction:

- keep SetupHost as the install engine and environment validator,
- add a real GUI shell in front of it,
- wrap the final payload in a signed installer experience instead of PowerShell scripts.
