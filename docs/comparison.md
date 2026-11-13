```text
░▒▓█ SECGATE · COMPARISON █▓▒░
```

# SecGate vs Alternatives

Honest side-by-side comparison against the tools SecGate is most often weighed against.

All comparisons reflect the **free / open-source tier** of each product as of 2026-04. Paid tiers add capabilities not listed here.

---

## Feature Matrix

| Capability | SecGate | Snyk (free) | Trivy (standalone) | Semgrep OSS | Aikido (free) |
|-----------|:-------:|:-----------:|:------------------:|:-----------:|:-------------:|
| **SAST** | via Semgrep | limited | no | yes | yes |
| **SCA — Node** | via npm + osv | yes | via osv plugin | no | yes |
| **SCA — polyglot** | via osv | yes | yes | no | yes |
| **Secrets detection** | via Gitleaks | basic | yes | no | yes |
| **IaC misconfiguration** | via Trivy | yes | yes | partial | yes |
| **License scanning** | via Trivy | yes | yes | no | yes |
| **Container image scanning** | base images only | yes | **yes** | no | yes |
| **SARIF output** | yes (v0.2.0) | yes | yes | yes | yes |
| **Baseline / ratcheting** | yes (v0.2.0) | yes | no | yes | yes |
| **Auto-fix** | npm only (ADR-0002) | yes (paid mostly) | no | no | limited |
| **Free for commercial use** | **yes** (MIT) | limited (seat cap) | yes (Apache 2.0) | yes (LGPL rules) | free tier |
| **Self-hosted / air-gapped** | **yes** | no (SaaS only on free) | yes | yes | no |
| **Bundled orchestration** | **yes** | — | no (single tool) | no | yes (SaaS) |
| **No account / signup required** | **yes** | no | yes | yes | no |
| **No telemetry by default** | **yes** (ADR-0005) | no | yes | yes | no |
| **Single HTML report across all scanners** | **yes** | dashboard only | per-scan | per-scan | dashboard only |
| **CI-first CLI** | **yes** | yes | yes | yes | partial |

---

## Where each tool wins

### SecGate wins when
- You want **one command** that runs five scanners and gives one verdict.
- You need **local, offline, self-hosted** scanning with no SaaS account.
- You want **zero lock-in** — every scanner is independently installable.
- You want **zero telemetry** by default.
- You're a solo founder / small team and can't afford Snyk seats.

### Snyk wins when
- You need a **managed vulnerability database** with triage workflow, Jira sync, and dashboards.
- You have budget for seats and want **vendor-backed** exploit prioritization.
- You need **runtime monitoring** (Snyk Runtime) beyond CI-time scanning.

### Trivy (standalone) wins when
- You need **deep container image scanning** — SecGate scans Dockerfile base images, but does not build and scan your final application image layers.
- You're only scanning containers and don't need SAST/secrets in the same pass.

### Semgrep OSS wins when
- You need **custom static analysis rules** (Semgrep's DSL is best-in-class).
- SAST is your only requirement.

### Aikido wins when
- You want a **SaaS dashboard** with triage workflow across scanners, and are OK with cloud-hosted.
- You want vendor-managed rule updates and exploit prioritization.

---

## Unique Value Proposition

**SecGate's niche: zero-config bundled orchestration.**

Every other tool on this list either:
- Does one thing (Semgrep = SAST only; Trivy standalone = container/IaC only), forcing you to wire together multiple tools yourself, **or**
- Bundles many scanners behind a SaaS account with telemetry, seat caps, and lock-in (Snyk, Aikido).

SecGate is the only option that:

1. **Bundles five best-in-class OSS scanners** behind one CLI.
2. **Requires zero config** — `npx @stelnyx/secgate .` runs npm audit with no extra installs, plus Semgrep, Gitleaks, osv-scanner and Trivy when they are on `PATH`. Missing scanners are reported as not run (`n/a`), and the run exits `2` when none ran.
3. **Ships no telemetry, no account, no dashboard** — output is local files.
4. **Stays MIT-licensed and free forever** — no seat caps, no commercial restrictions.
5. **Produces one normalized report** — one JSON schema, one HTML file, across all scanners.

If you need SaaS-grade triage workflow, buy Snyk or Aikido. If you need a CI gate that blocks critical issues without a sales call, use SecGate.

---

## Honest limitations vs paid tools

Paid SAST/SCA vendors invest heavily in:

- **Exploit prioritization** — weighing CVEs by known-exploited status (KEV), reachability analysis, EPSS scores. SecGate uses severity only.
- **Curated rule packs** — Semgrep Pro rules, Snyk's proprietary rule DB. SecGate uses OSS rules only.
- **Auto-fix across ecosystems** — Snyk can PR-fix Python, Java, Go. SecGate auto-fixes Node only (see [ADR-0002](adr/0002-npm-only-auto-fix.md)).
- **Triage UX** — dashboards, ignore policies, developer assignment. SecGate is CLI + files only.

These are real gaps. If they matter to your org, a paid tool is the right buy. SecGate is for teams that prefer **boring, owned, local tooling** over SaaS.

---

See also: [`coverage.md`](coverage.md), [`tuning.md`](tuning.md), [`adr/0005-no-external-api-v1.md`](adr/0005-no-external-api-v1.md).
