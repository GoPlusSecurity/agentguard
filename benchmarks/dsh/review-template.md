# DSH plugin manual review template

## Artifact identity

- Repository:
- Commit:
- Scanned subpath:
- Artifact hash:
- Reviewer/date:

## Static result

- Full repository risk:
- Runtime-surface risk:
- Review priority:
- Key runtime tags:

## Runtime entry points

- Package/DSH manifest:
- Cordis rows:
- Host entry:
- Client entry:
- Install/update lifecycle:

## Evidence review

For every HIGH or CRITICAL runtime tag, record:

- Rule and representative file/line.
- Whether the evidence is first-party, generated, vendored, documentation, test, or data.
- The actual behavior and triggering condition.
- Inputs controlled by a user, model, network, or local administrator.
- Security controls and missing controls.
- Verdict: confirmed capability, expected-but-sensitive, false positive, or unresolved.

Never paste a complete credential, private key, webhook identifier, or access token into this document.

## Final posture

- Recommended environment:
- Required version pin/configuration:
- Residual risks:
- Follow-up issue:
