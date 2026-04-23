# Stage G: Hardening Checklist

- Use the resolved volume GUID instead of depending on a drive letter.
- Keep `C:\ProgramData\SecureVol\config` ACLed to Administrators and LocalSystem only.
- Protect the service executable, driver binary, and CLI with standard admin-only ACLs.
- Prefer publisher validation plus optional hash pinning for frequently updating software.
- Use hash pinning for infrequently changing portable tools if you want stronger integrity checks.
- Keep allow rules as narrow as possible: exact path, expected user, require signature when available.
- Keep service logs and config on an unprotected system volume, not inside the protected VeraCrypt volume.
- Review recent denies with `securevol denies` after policy changes.
- Leave the driver on manual start until you are comfortable with the policy.
- Replace the placeholder test altitude with a production-assigned altitude before any non-lab deployment.
- Keep kernel-mode exemptions narrow. The current design only bypasses kernel requests and the connected service process.
- Reload policy after each app update if you hash-pin binaries.
- Re-resolve the protected volume after VeraCrypt dismount/remount cycles.
- Keep an emergency admin shell available on an unprotected volume.
- Document and rehearse `protection disable` plus `fltmc unload SecureVolFlt` before daily use.
