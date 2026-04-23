# Release Process

## Goal

Produce a repeatable Windows release layout that can later feed:

- GitHub Releases,
- an end-user installer bundle,
- signing and notarization steps,
- smoke-test VMs.

## Managed release build

Use:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\Build-Release.ps1
```

Important switches:

- `-UiFlavor wpf`
- `-UiFlavor imgui`
- `-SkipTests`
- `-SkipDriver`

The script:

1. runs managed tests unless skipped,
2. publishes the managed projects self-contained for `win-x64`,
3. copies the current signed driver package from `out\driver\package` if present,
4. copies core docs and repo metadata into the release bundle,
5. emits `release-manifest.json` with SHA-256 hashes,
6. produces a `.zip` archive next to the layout.

## Current limitation

The release script does not build or sign the minifilter driver by itself. Driver signing still depends on a WDK-capable Windows environment and the current local signing workflow.

## Open-source release checklist

- build managed projects
- run managed tests
- build and sign the minifilter package
- verify install and uninstall on a clean Windows 11 VM
- verify emergency disable and recovery path
- verify Chrome and Telegram onboarding
- attach the generated `.zip`
- attach installer artifacts once the full installer path lands
