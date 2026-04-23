# Security Policy

## Supported scope

SecureVol is a defensive local-only privacy tool for a machine that the user already controls.

The intended scope includes:

- access control for one configured mounted VeraCrypt volume,
- allowlisting by executable identity and expected Windows user,
- recovery paths that let the machine owner disable protection safely.

The following are explicitly out of scope:

- admin or SYSTEM attackers,
- kernel compromise,
- firmware compromise,
- physical access attacks,
- malware-style bypasses, stealth, or security-product tampering.

## Reporting vulnerabilities

Please do not open public issues for bypasses or vulnerabilities that could weaken deployed systems.

Instead:

1. Share a minimal reproduction.
2. Include the SecureVol version or commit.
3. Include whether the issue affects the driver, service, UI, or installer path.
4. Include recovery impact: can the user still disable protection safely?

Until a private reporting address is published, treat security issues as private coordination items with the maintainer.

## Hardening expectations

- Recovery must stay documented and reversible.
- Unknown or degraded backend states must not be shown as protected.
- Broad allow rules need justification in docs or code comments.
