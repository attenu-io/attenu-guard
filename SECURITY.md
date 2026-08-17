# Security Policy

delegation-guard is a security library; we hold ourselves to the standard we
ask of the ecosystem.

## Reporting a vulnerability

Email **security@attenu.io** (PGP key at https://attenu.io/.well-known/security.txt).
Please do not open public issues for vulnerabilities.

We commit to: acknowledge within 2 business days; a triage assessment within 5;
a fix or mitigation timeline agreed with you; and public credit unless you prefer
otherwise. We follow coordinated disclosure — 90 days, or sooner by mutual
agreement.

## Scope

In scope: any way to make a child `Authority` exceed its parent; any way to make
a revoked chain authorize an action; any way to tamper with an audit log without
`AuditLog.verify` detecting it; any way to bypass a ceiling.

The `Break-Our-Plane` standing pledge (commercial): any verified bypass of an
enforced invariant earns a public advisory, a fixed-SLA patch, and — for design
partners — the pilot free.

## Supported versions

Pre-1.0: the latest minor release only. A security-supported LTS line begins at
1.0.
