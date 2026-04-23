# Stage F: Testing Plan

## Unit tests

Current automated tests cover:

- allow on exact path/hash/publisher/user match,
- deny on wrong user,
- deny on hash mismatch,
- SHA-256 helper correctness.

Run:

```powershell
$env:DOTNET_ROLL_FORWARD='Major'
dotnet test .\tests\SecureVol.Service.Tests\SecureVol.Service.Tests.csproj
```

## Manual test checklist

### Basic access control

1. Mount the VeraCrypt volume as `V:`.
2. Set `V:` as the protected volume.
3. Add an allow rule for Chrome under `.\vc_app`.
4. Enable protection and load the driver.
5. Launch Chrome with `--user-data-dir=V:\ChromeProfile` under `.\vc_app`.
6. Confirm Chrome can create and modify files in `V:\ChromeProfile`.
7. Open `V:\` from `notepad.exe`, `powershell.exe`, and Explorer under the normal user account.
8. Confirm access is denied.

### Telegram

1. Add an allow rule for portable `Telegram.exe`.
2. Launch it under `.\vc_app`.
3. Confirm it can read and write its portable data on the protected volume.
4. Confirm the same binary launched under the wrong user is denied if the rule is user-bound.

### Service/driver resilience

1. Start an allowed Chrome instance and confirm it is working.
2. Stop the service but leave the driver loaded.
3. Confirm already-cached Chrome activity continues.
4. Launch a new unlisted process and confirm it is denied for the protected volume.
5. Restart the service and confirm new allowed launches work again.

### VeraCrypt remount behavior

1. Dismount the VeraCrypt volume.
2. Remount it, possibly getting a new volume GUID.
3. Re-run `securevol volume set --volume V:`.
4. Confirm state shows the refreshed protected volume GUID.

### App update behavior

1. Use a publisher-only Chrome rule and confirm access still works after an update.
2. Use a hash-pinned rule, update the app, and confirm access fails until the hash is refreshed.
3. Use `securevol hash --image <path>` to capture the new SHA-256 if you intentionally pin hashes.

## Known failure modes and mitigations

- Service down before policy push: the driver stays disabled by design on first start; start the service first.
- Service crash after policy push: unknown processes are denied, cached allowed processes continue until cache flush or process restart.
- Volume GUID changed after VeraCrypt remount: reset the protected volume using the CLI.
- Authenticode verification fails because the binary is unsigned: use hash pinning instead of publisher matching, or deny by policy.
- Overly broad allow rule: tighten by adding expected user and signature/publisher constraints.
