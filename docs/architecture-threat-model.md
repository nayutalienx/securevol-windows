# Stage A: Architecture and Threat Model

## What SecureVol protects against

SecureVol is a local defensive control for a mounted VeraCrypt volume. It is designed to reduce accidental or opportunistic access from ordinary user-mode processes on the same Windows machine by enforcing:

- deny-by-default access for one configured mounted volume only,
- explicit allowlisting by normalized image path,
- optional SHA-256 pinning,
- optional Authenticode signature and publisher checks,
- optional binding to a specific Windows user account such as `.\vc_app`.

This is useful when you want a VeraCrypt-mounted drive to behave like a normal Windows volume for selected applications, while preventing everything else on the box from browsing, indexing, or modifying it.

## What SecureVol does not protect against

SecureVol is not a sandbox and is not a host-compromise defense.

Out of scope:

- administrators, `SYSTEM`, or anyone who can change local policy, unload the driver, or replace binaries,
- kernel compromise, signed malicious drivers, DMA attacks, or firmware compromise,
- memory scraping or in-app data exfiltration from an already allowed process,
- a malicious browser extension or compromised Telegram session running inside an allowed app,
- screen capture, clipboard theft, keylogging, or other compromise above the file I/O layer,
- direct access to the VeraCrypt container file while it is dismounted.

SecureVol therefore improves privacy and operational separation for ordinary local software, but it is not a substitute for securing the whole endpoint.

## Why this architecture

### Minifilter driver

A Filter Manager minifilter is used because it is the documented Windows mechanism for volume/file I/O policy enforcement. The driver:

- scopes itself to one configured volume only,
- intercepts `IRP_MJ_CREATE` before the file is opened,
- denies unauthorized opens with `STATUS_ACCESS_DENIED`,
- caches process-instance decisions to avoid repeated round trips,
- keeps kernel logic intentionally small.

### User-mode service

Executable identity checks are complex and easier to maintain safely in user mode. The service:

- owns the JSON policy store,
- verifies path, SHA-256, signer, publisher, and user account,
- talks to the minifilter through the standard Filter Manager communication port,
- logs denies and state changes,
- can reload policy without rebooting.

### Dedicated local user

Launching allowed applications under a dedicated local user such as `.\vc_app` gives an additional separation boundary:

- policy can require both executable identity and expected user,
- the same executable launched under the wrong user can be denied,
- user profile and app data can be isolated from the main interactive account.

For Chrome specifically, the multiprocess model is handled by allowlisting the actual `chrome.exe` binary with the same path/signer/user constraints; child processes reuse the same image and are evaluated the same way.

## Safety decisions

- The driver starts in a disabled state until the service pushes policy.
- Only the configured protected volume is affected. All other volumes are ignored.
- Kernel-mode opens are bypassed intentionally. Kernel compromise is out of scope, and blocking kernel/internal metadata opens is fragile.
- The recommended operating mode is demand-start for both service and driver.
- Emergency recovery is explicit and documented: disable protection in policy, unload the minifilter, or do not start it in Safe Mode.
