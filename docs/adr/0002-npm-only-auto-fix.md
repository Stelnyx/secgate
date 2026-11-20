# ADR-0002: npm-only Auto-Fix

- **Status:** Accepted
- **Date:** 2026-04-23
- **Deciders:** Stelnyx

## Context

Auto-remediation is attractive: "SecGate found a CVE and fixed it" is a strong UX. But auto-fix is also dangerous — a wrong fix breaks the build, or worse, silently changes runtime behavior.

Each ecosystem has different auto-fix maturity:

| Ecosystem | Auto-fix command | Maturity |
|-----------|------------------|----------|
| npm | `npm audit fix` | Mature, well-tested, preserves semver |
| pip | `pip-audit --fix` | Newer, limited scope |
| Go | `go get -u <pkg>` | Manual; no `go audit fix` |
| Cargo | `cargo update` | Coarse — updates everything, not just vulnerable |
| Maven | Manual | No standard auto-fix |
| Docker base image | Manual | No standard auto-fix |
| IaC (Terraform/K8s) | **Dangerous** — auto-fix changes infra |
| Semgrep / Gitleaks findings | **Impossible** — requires human judgment |

## Decision

**We will only auto-fix findings that `npm audit fix` can handle. All other findings are report-only, with manual remediation guidance in the fix plan.**

Scope of auto-fix today:
- `findings[].fixable == true` **and** `findings[].tool == "npm"` → candidate for `npm audit fix --ignore-scripts` when `--apply` is set. CRITICAL findings are never auto-fixed; they go to `remediation.blocked[]`.
- Everything else → surfaced in `remediation.plan[]` as a manual step with a display command, but never executed.

## Consequences

### Positive

- Low blast radius. npm audit fix has years of field testing and respects semver.
- Clear mental model: "auto-fix = npm only; everything else is your call."
- Reduces risk of a wrong auto-fix silently breaking production (e.g., a Terraform auto-update changing a security group).

### Negative

- No auto-fix for pip, Cargo, Go, Maven. Users must fix manually. Documented in `tuning.md`.
- Risks users expecting feature parity with paid tools (Snyk auto-fixes more ecosystems). Mitigation: honest docs, see [`comparison.md`](../comparison.md).

### Neutral

- Auto-fix scope can expand scanner-by-scanner as we gain confidence. Next candidates: `pip-audit --fix`, `cargo audit fix` if/when stable.

## Alternatives Considered

### Auto-fix everything we can detect
Rejected. Auto-fixing IaC or Semgrep findings requires understanding intent, not just pattern-matching. One wrong fix and we burn trust for every future fix.

### No auto-fix at all
Considered. Simpler, safer. But `npm audit fix` is a genuinely useful UX win — installs are the most common CVE source in Node ecosystems, and the fix is usually just a lockfile bump.

### Open PRs with suggested fixes instead of direct apply
Strong candidate for v0.2.x. See [ADR-0003](0003-dry-run-default.md) for the dry-run default that points in this direction. Out of scope for v0.1.

## References

- [ADR-0003 — dry-run default](0003-dry-run-default.md)
- [`docs/tuning.md`](../tuning.md)
- `lib/intelligence.mjs` — `patch()` and `remediate()`
