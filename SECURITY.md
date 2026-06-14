# Security Policy

## Reporting a Vulnerability

If you find a security issue in this repository, please **do not** open a public GitHub issue.

Instead, email **security@lucairn.eu** with:
- A description of the issue
- Steps to reproduce
- Affected version / commit SHA
- Optional: a suggested fix

You can encrypt the report via Signal or PGP-by-arrangement (request a key in your initial email and we will share one out-of-band).

## What you can expect

- **Acknowledgement within 72 hours** of your initial email
- **Initial triage within 7 days** with a severity assessment and an estimated fix window
- **Fix or update within 30 days** for high-severity issues; longer for low-severity, with a tracked plan
- **Coordinated disclosure window of 90 days** before any public disclosure (we may agree on a shorter window for trivial issues, or longer for issues requiring customer migration)

## Scope

In scope: code, configuration, build artefacts, and deployment templates published in **this repository**.

Out of scope:
- Third-party services we depend on (Hetzner, Cloudflare, Supabase, Anthropic, etc.). Report those to the relevant vendor's security disclosure channel.
- Issues in clients' own deployments of our software (configuration, network, identity provider integrations) — those are the customer's responsibility.
- Social engineering attacks against employees or contractors.
