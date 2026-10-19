# Security Policy

## Supported versions
Latest `master` is supported. Security fixes are released as soon as possible.

## Reporting a vulnerability
**Do not open a public issue** for scanner bypasses or vulnerabilities in this tool.

Instead, please report privately:
- Open a [private security advisory](https://github.com/Flynntaggart26/ai-code-auditor/security/advisories/new), or
- Contact the maintainer via GitHub profile email.

Include: affected file/rule, minimal reproducer, expected vs actual behavior.

We aim to acknowledge within 72 hours and fix critical bypasses within 14 days.

## Scope
In scope: rule bypasses, false negatives on documented rules, auto-fix producing broken/insecure code, SARIF/HTML injection via finding content.
Out of scope: AI explanation quality (BYOK, best-effort), missing rules not yet documented.
