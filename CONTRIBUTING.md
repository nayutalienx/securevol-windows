# Contributing

SecureVol is a defensive Windows project. Keep changes explicit, documented, and easy to audit.

## Ground rules

- Use documented Windows APIs only.
- Do not add stealth, persistence tricks, privilege escalation, code injection, AV/EDR tampering, anti-forensics, or anything malware-like.
- Keep the minifilter small. Push complex identity logic into user mode unless a kernel path is clearly required.
- Prefer narrow policy changes over broad bypasses or catch-all exemptions.

## Development workflow

1. Open `SecureVol.sln` in Visual Studio 2022 for the driver and Windows projects.
2. Use `dotnet build` / `dotnet test` for the managed projects.
3. Test changes on a disposable or non-critical Windows machine first.
4. Document recovery steps for anything that touches install, boot, filter load, or policy application.

## Pull requests

- Describe the user-facing behavior change.
- Call out any security tradeoffs explicitly.
- Include test evidence:
  - `dotnet build`
  - `dotnet test`
  - manual Windows validation if driver/service/install behavior changed
- Keep PRs focused. Split UI, driver, service, and installer work when practical.

## Coding notes

- C# code should stay readable and conservative. Avoid reflection-heavy or magic-heavy patterns.
- Driver code should favor documented WDK patterns and fail-safe behavior.
- UI work should explain degraded/fallback states honestly. Never display a false protected state.

## Reporting risky ideas

If a proposal would weaken the trust model, broaden volume access, or hide behavior from the user, open an issue first instead of landing it directly.
