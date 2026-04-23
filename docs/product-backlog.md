# SecureVol Product Backlog

Updated: 2026-04-23

## Product Goal

Ship SecureVol as an open-source Windows product that feels normal to install and operate:

- download one installer,
- approve UAC once,
- choose a mounted VeraCrypt volume,
- add Chrome / Telegram / other allowed apps,
- use desktop shortcuts or a tray app instead of PowerShell,
- recover safely if the protected volume is unavailable or a rule breaks.

## Current Baseline

Implemented:

- volume-scoped minifilter driver
- user-mode policy service
- admin CLI
- JSON policy model
- dedicated-user launch flow
- deny-by-default enforcement for the configured protected volume
- emergency recovery path

Missing product layers:

- end-user desktop UI completion
- normal installer/bootstrapper
- first-run setup wizard
- desktop/start menu shortcuts
- upgrade flow
- release signing pipeline

## MVP Roadmap

### P0: End-User Productization

1. desktop control surfaces
   - keep `SecureVol.AppCore` as the shared backend-facing control layer
   - keep `SecureVol.App` working during migration
   - move the primary end-user shell to `SecureVol.ImGui`
   - preserve truthful degraded-state messaging in every UI path

2. `SecureVol.Setup` bootstrapper
   - elevated install path
   - install service
   - install driver package
   - copy app/CLI payloads
   - create start menu entries
   - launch first-run wizard

3. external launchers
   - generate shortcuts outside the protected volume
   - support "Secure Chrome" and "Secure Telegram"
   - explain why shortcuts inside the protected volume are not reliable

4. app update handling
   - detect hash drift
   - show "publisher still matches" vs "hash pin broken"
   - one-click rule refresh

5. dashboard responsiveness
   - show cached local snapshot immediately on app launch
   - fetch live backend state asynchronously with a tight timeout
   - keep compatibility with older running services through a legacy admin fallback
   - keep the ImGui shell non-blocking while refresh and policy tasks run in the background

### P1: Reliability and UX

1. tray mode
   - show current status
   - quick enable/disable
   - recent deny notifications

2. VeraCrypt remount workflow
   - detect that the protected volume disappeared
   - detect that the drive letter now maps to a new volume instance
   - guide the user to rebind protection safely

3. safer app onboarding
   - file picker
   - prefill signer, publisher, SHA-256
   - optional recommended presets for Chrome and Telegram

4. readable logs
   - friendly event viewer section in the app
   - export deny log bundle for troubleshooting

5. minimal desktop shell
   - continue replacing the WPF-first UX with the new Dear ImGui shell
   - add onboarding, add/remove rule flow, and deny inspection directly in `SecureVol.ImGui`
   - keep the backend/service protocol stable so multiple UI shells can coexist during migration

### P2: Release Engineering

1. code signing pipeline
   - user-mode binary signing
   - production kernel signing path
   - remove test-signing from the normal release story

2. CI/CD
   - build matrices for `AppCore`, `WPF`, `ImGui`, service, CLI, driver
   - artifact publishing
   - smoke tests for installer and upgrade

3. documentation
   - user guide
   - admin guide
   - recovery guide
   - app update maintenance guide

## Acceptance Criteria For "Downloaded And Works"

- no PowerShell required for the normal install path
- no manual policy JSON editing required
- no test-signing required for normal release builds
- normal uninstall path from Windows Apps & Features
- one-click disable or recovery path
- Chrome and Telegram can be onboarded by non-technical users
- desktop UI clearly explains current protection state

## Engineering Notes

- Keep the driver small. Product complexity belongs in user mode.
- The desktop manager may require elevation for administrative actions.
- `SecureVol.AppCore` should stay UI-agnostic so WPF, Dear ImGui, or future setup shells all reuse the same control-path rules.
- Launch shortcuts must live outside the protected volume.
- Explorer must not be treated as an always-allowed process just to make `.lnk` files inside the protected volume work.
- The installer should call documented Windows setup mechanisms, not shell out to fragile scripts for the primary user path.
