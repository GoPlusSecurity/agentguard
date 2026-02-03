# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in GoPlus AgentGuard, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

Email: **security@gopluslabs.io**

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix and disclosure**: Coordinated with the reporter

### Scope

The following are in scope:
- Detection rule bypasses (false negatives)
- Trust registry tampering
- Hook bypass techniques
- Data exfiltration through AgentGuard itself
- Privilege escalation via skill trust levels

### Out of Scope

- Vulnerabilities in dependencies (report to the upstream project)
- Social engineering attacks
- Denial of service against the local scanning engine

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |
