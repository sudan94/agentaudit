# Security Policy

skillcheck is a security tool, so its own correctness matters. Two classes of
issue are especially important to us:

1. **Bypasses** — a way to hide malicious instructions from skillcheck (e.g. an
   encoding, unicode trick, or phrasing that evades every rule and analyzer).
2. **Vulnerabilities in skillcheck itself** — since it parses untrusted files,
   e.g. a crash, resource exhaustion, or code execution triggered by a crafted
   input.

## Reporting

Please **do not** open a public issue for a bypass or vulnerability. Instead:

- Use GitHub's [private vulnerability reporting](https://github.com/sudanupadhaya/skillcheck/security/advisories/new), or
- Email the maintainer at sudanupadhaya@gmail.com with `[skillcheck security]` in the subject.

Include a minimal reproducer (the smallest file that demonstrates the bypass or
crash) and, if you can, a suggested rule or fix.

## What to expect

- Acknowledgement within 72 hours.
- A fix or mitigation plan, typically shipped as a new rule or analyzer.
- Credit in the changelog and release notes, unless you prefer to stay anonymous.

## Supported versions

skillcheck is pre-1.0; security fixes are released against the latest `0.x`
version. Please upgrade to the newest release before reporting.
