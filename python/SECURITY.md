# Security Policy

## Supported versions

| Version      | Supported          |
| ------------ | ------------------ |
| 1.0.x        | :white_check_mark: |
| < 1.0.0      | :x:                |

`lucairn` is the current 1.0.x line. Security fixes ship against the
current 1.0.x line. Earlier releases (published under the previous
package name `theveil`, pre-1.0) are not supported and should not be
relied on.

## Reporting a vulnerability

Please report suspected security issues through **GitHub Private
Vulnerability Reporting** on this repository:

`lucairn-sdks` → **Security** tab → **Report a vulnerability**

PVR is the preferred channel — it's private, auditable, and ties directly
into GitHub Security Advisories, which simplifies coordinated disclosure.

### Fallback: email

If you cannot use GitHub PVR (e.g. you don't have a GitHub account), email:

**contact@lucairn.eu** with `[security]` in the subject line.

Do **not** open a public GitHub issue for security reports.

### What to include

- affected version (output of `python -c "import lucairn; print(lucairn.__version__)"`)
- reproduction steps or a minimal PoC
- observed vs. expected behaviour
- impact assessment, if you have one

## Response commitment

- **Acknowledgement**: within 72 hours of receipt.
- **Coordinated disclosure**: we work with you on a disclosure timeline.
- **Default embargo**: 90 days from acknowledgement, unless mutually
  shortened (e.g. low-risk) or extended (e.g. dependency coordination).
- **Credit**: researchers are credited in the release notes unless they
  request anonymity.

## Scope

**In scope**

- The `lucairn` PyPI package and its source in this repository.
- The publish pipeline (`.github/workflows/publish-python.yml`) and its
  trusted-publisher configuration.
- Cryptographic verification paths inside the SDK (certificate signature
  verification, witness validation).

**Out of scope**

- User code that *uses* the SDK — please report to the user code's
  maintainer, not here.
- Upstream dependencies (`httpx`, `pydantic`, `cryptography`) — please
  report directly to those projects. If a vulnerability in an upstream
  dependency affects `lucairn` specifically, you may CC us.
- The hosted gateway service (`gateway.lucairn.eu`) — report infrastructure
  issues via GitHub PVR on this repository or to `contact@lucairn.eu` with
  `[security][gateway]` in the subject line.

## Release integrity

From `lucairn` 1.0.0 onward (and previously, from `theveil` 0.1.1
through 0.1.x while the package was published under the old name),
releases are published to PyPI via
[PyPI trusted publishers](https://docs.pypi.org/trusted-publishers/) using
OIDC tokens minted by GitHub Actions. The uploader identity is bound to
this repository, the `publish-python.yml` workflow, and the `pypi`
deployment environment — no long-lived PyPI API token exists.

Each release is traceable to a specific workflow run. The workflow run
link is recorded on the corresponding GitHub release page; the run's
OIDC claims are cryptographically tied to the uploaded artifact by PyPI's
mint-token flow.

If you believe a release was published from an identity *other* than this
repository, please report it via GitHub PVR immediately.
