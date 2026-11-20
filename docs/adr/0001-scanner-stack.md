# ADR-0001: Scanner Stack

- **Status:** Accepted
- **Date:** 2026-04-23
- **Deciders:** Stelnyx

## Context

SecGate's value is orchestration. The stack of upstream scanners defines what SecGate actually covers. The choice needs to balance:

- **Coverage** — SAST + SCA + secrets + IaC + license, the five CI-relevant categories.
- **Cost** — must be free for commercial use.
- **Stability** — boring, widely adopted tools with long track records.
- **No vendor lock-in** — each scanner must be independently installable and replaceable.
- **JSON output** — parseable without screen-scraping.

## Decision

**We will use Semgrep + Gitleaks + npm audit + osv-scanner + Trivy as the default scanner stack.**

- **Semgrep** — SAST. OSS ruleset, multi-language, stable JSON output.
- **Gitleaks** — secrets. Purpose-built, fast, handles git history.
- **npm audit** — Node SCA. Ships with npm; zero install cost when Node is present.
- **osv-scanner** — polyglot SCA. Google-maintained, uses OSV.dev (open advisory DB).
- **Trivy** — IaC + license + discovered base-image CVEs. Aqua Security, huge policy bundle, active development.

## Consequences

### Positive

- Every category covered by a mature, widely adopted tool.
- All five are free for commercial use (Gitleaks MIT; osv-scanner and Trivy Apache 2.0; Semgrep engine LGPL-2.1). Semgrep-maintained registry rules, which `--config=auto` downloads, are under the [Semgrep Rules License v1.0](https://semgrep.dev/legal/rules-license) and limited to internal use.
- Each is individually installable via Homebrew / pip / curl-install scripts.
- JSON output is stable and documented for all five.
- Defense in depth: npm audit + osv-scanner both cover Node dependencies from different advisory sources.

### Negative

- Five binaries to install. Mitigated by install hints printed per missing scanner and documented install commands. Since `v0.3.0` a missing scanner that applies is a coverage gap (`INCOMPLETE`, exit 2), not a silent skip.
- Base-image scanning is covered by discovering Dockerfile `FROM` references and running Trivy `image` mode. SecGate still does not build and scan final application image layers.
- Semgrep's OSS ruleset is narrower than Semgrep Pro — organizations wanting proprietary rules need to BYO.

### Neutral

- Future scanners can be added if they meet criteria in `coverage.md`. The bundle is deliberately small.

## Alternatives Considered

### Snyk CLI
Rejected. Requires free-tier signup, has seat caps, and phones home. Violates our "no account, no telemetry" principle (ADR-0005). Also requires a proprietary database — not self-hostable.

### CodeQL
Rejected. Excellent SAST but (1) free tier is GitHub-only, (2) heavy — minutes per scan, (3) license restricts commercial use outside GitHub repos.

### Grype + Syft (replacement for osv-scanner)
Considered. Anchore's tools are strong but overlap heavily with Trivy for containers. osv-scanner has better polyglot lockfile coverage for CI-stage SCA. We can revisit if osv-scanner becomes unmaintained.

### Bandit / ESLint plugins (replace Semgrep)
Rejected. Single-language, thin coverage. Semgrep subsumes them with broader language support.

### Building a single unified scanner
Rejected. Months of work, no unique value vs orchestration, and we'd still want to replace Semgrep/Gitleaks rules rather than rewrite them.

## References

- [`docs/coverage.md`](../coverage.md)
- [`docs/comparison.md`](../comparison.md)
