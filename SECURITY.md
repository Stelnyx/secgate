```text
░▒▓█ SECGATE · SECURITY POLICY █▓▒░
```

# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SecGate, please report it privately.

**Do not open a public GitHub issue for security reports.**

### Preferred channels

1. **GitHub Security Advisory** — open a [private security advisory](https://github.com/Stelnyx/SecGate/security/advisories/new). This is the fastest route and is tracked via the GitHub Security Advisories (GHSA) workflow. **This is the only fully private channel available right now.**
2. **Email** — `security@stelnyx.dev`. Plain email is accepted; encrypted email is not yet available (see below).

### PGP Key

**Status: not yet generated (tracked in issue #34).** Encrypted email is unavailable until the key is published. Use the GitHub Security Advisory channel for fully private reporting.

Once generated, the key fingerprint and `pgp-public.asc` will be committed to the repo root and this section updated.

### Include in your report

- A description of the vulnerability and its impact
- Steps to reproduce (minimal PoC preferred)
- Affected version(s)
- Any suggested remediation
- Your disclosure timeline preference

---

## Response SLA

We commit to the following response times from first triage acknowledgment:

| Severity | Acknowledge | Initial assessment | Fix / mitigation target |
|----------|:-----------:|:------------------:|:-----------------------:|
| **Critical** | 24h | 48h | **48h** |
| **High**     | 48h | 72h | **7 days** |
| **Medium**   | 72h | 7d  | **30 days** |
| **Low**      | 7d  | 14d | **90 days** |

Severity follows CVSS v3.1. If we disagree with your severity assessment, we will state why in the initial response and propose a revised rating.

---

## Coordinated Disclosure Timeline

We follow a **90-day coordinated disclosure** policy by default:

1. **Day 0** — reporter files private advisory.
2. **Within SLA** — we acknowledge and begin triage.
3. **During fix window** — we work with reporter on patch, credit, and advisory text.
4. **Public disclosure** — after patch is released, or at day 90, whichever comes first.
5. **Extension** — we may request extension for complex fixes; reporter may decline.

If a vulnerability is being actively exploited, we may compress this timeline and coordinate expedited disclosure.

CVE assignment is handled via the GHSA workflow when GitHub is our CNA.

---

## GHSA Process

We use GitHub Security Advisories as the primary tracking mechanism:

1. Reporter files advisory → triage by maintainers.
2. Maintainers request CVE from GitHub CNA when confirmed.
3. Private fork used for patch development.
4. Reporter credited in advisory unless anonymity is requested.
5. Advisory published simultaneously with patch release.
6. `npm audit` reports the advisory once it is in the GitHub Advisory Database.

---

## Supported Versions

Only the latest `main` branch receives security fixes at this stage. Once v1.0.0 ships, we will support the current minor and the previous minor (N and N-1).

---

## Scope

SecGate is a security scanning engine itself. Please report:

- Bypasses of the scanning / remediation logic
- Unsafe handling of scan artifacts, secrets, or intermediate files
- Supply-chain concerns in declared dependencies
- Any path traversal, command injection, or privilege escalation paths
- Information disclosure via reports or logs

**Out of scope:**

- Findings in third-party scanners invoked by SecGate (report upstream to Semgrep / Gitleaks / osv-scanner / Trivy / npm)
- Misconfiguration in end-user CI environments
- Denial of service caused by maliciously crafted scanned repos against upstream scanners (upstream concern)

See [`docs/threat-model.md`](docs/threat-model.md) for the full STRIDE model, trust boundaries, and known mitigations.

---

## Supply-chain trust

The GitHub Releases `v0.2.9` to `v0.2.13` ship with these verifiable assets.
Older tags do not. `0.2.14` was published to npm without a tag or a GitHub
Release, so it has none of them. From the next release, every `vX.Y.Z` tag
produces them through `.github/workflows/release.yml`.

| Artifact | Filename pattern | Purpose |
|---|---|---|
| Release tarball | `secgate-X.Y.Z.tgz` | Signed build of the npm package |
| CycloneDX SBOM | `secgate-X.Y.Z.sbom.cdx.json` | Full dependency manifest (CycloneDX 1.5+) |
| cosign signature | `*.sig`, `*.pem`, `*.cosign.bundle` | Keyless Sigstore signature over tarball and SBOM |
| SLSA L3 attestation | `secgate-vX.Y.Z.intoto.jsonl` | Non-falsifiable build provenance (SLSA v1.0, Level 3) |
| Checksums | `SHA256SUMS` | SHA-256 manifest for tarball + SBOM |

npm versions `0.2.9` and `0.2.11` to `0.2.13` carry
[npm provenance](https://docs.npmjs.com/generating-provenance-statements);
`0.2.14` does not. From the next release, the `Release` workflow publishes the
signed tarball to npm with provenance through npm Trusted Publishing. Check a
version with
`npm view @stelnyx/secgate@<version> dist.attestations.provenance.predicateType`
(expected: `https://slsa.dev/provenance/v1`).

### Trust root (keyless cosign)

SecGate uses **keyless cosign** via Sigstore and GitHub OIDC — there is no
long-lived signing key to steal or rotate. Verification binds the artifact to
the exact workflow that produced it:

- Expected OIDC issuer: `https://token.actions.githubusercontent.com`
- Expected signer identity (regex):
  `^https://github\.com/Stelnyx/SecGate/\.github/workflows/release\.yml@refs/tags/.*`

The npm publish and the release-artifact signatures come from the same
workflow, `.github/workflows/release.yml`.

The Sigstore transparency log (Rekor) entry is the public record. There is no
"public key" to rotate; if the signer identity or issuer ever changes, that is
the signal, and release notes will call it out.

### One-line verification

```bash
curl -fsSL https://raw.githubusercontent.com/Stelnyx/SecGate/main/scripts/verify-release.sh \
  | bash -s -- v0.1.0
```

Or from a clone:

```bash
scripts/verify-release.sh v0.1.0
```

The script verifies: SBOM presence + CycloneDX shape, SHA256SUMS, cosign
keyless signature on tarball + SBOM, and SLSA L3 provenance on both.

### Manual verification

Install [`cosign`](https://docs.sigstore.dev/system_config/installation) (>=
2.0) and [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier) (>=
2.4), then:

```bash
VERSION=v0.1.0
BASE="https://github.com/Stelnyx/SecGate/releases/download/${VERSION}"
TARBALL="secgate-${VERSION#v}.tgz"
SBOM="secgate-${VERSION#v}.sbom.cdx.json"
ATT="secgate-${VERSION}.intoto.jsonl"

for f in "$TARBALL" "${TARBALL}.sig" "${TARBALL}.pem" "${TARBALL}.cosign.bundle" \
         "$SBOM" "$ATT" SHA256SUMS; do
  curl -fsSLO "${BASE}/${f}"
done

# 1. Checksums
sha256sum -c SHA256SUMS

# 2. cosign keyless signature on the tarball
cosign verify-blob \
  --bundle "${TARBALL}.cosign.bundle" \
  --certificate "${TARBALL}.pem" \
  --signature "${TARBALL}.sig" \
  --certificate-identity-regexp \
    '^https://github\.com/Stelnyx/SecGate/\.github/workflows/release\.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$TARBALL"

# 3. SLSA L3 provenance
slsa-verifier verify-artifact \
  --provenance-path "$ATT" \
  --source-uri github.com/Stelnyx/SecGate \
  --source-tag "$VERSION" \
  "$TARBALL"
```

### Release gate

The release workflow fails closed: the GitHub Release is not published, and
npm publish does not run, if either the SBOM or SLSA attestation is missing
or empty. cosign signatures are likewise gated before release assets are
uploaded.

If verification fails for an artifact you downloaded, **do not install it** —
open a private security advisory immediately.

---

## Safe Harbor

Good-faith security research following this policy will not be subject to legal action by Stelnyx. Please:

- Do not access, modify, or exfiltrate data beyond what is needed to demonstrate the vulnerability.
- Do not publicly disclose before coordinated disclosure timeline ends.
- Do not test against production systems of SecGate users (test against your own installs).

---

## Hall of Fame

Security researchers who report valid vulnerabilities will be credited here (with consent) after public disclosure.

_No reports received yet._
