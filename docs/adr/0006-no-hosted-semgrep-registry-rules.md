# ADR-0006: No Semgrep Registry Rules in Any Hosted Service

- **Status:** Accepted
- **Date:** 2026-11-21
- **Deciders:** Stelnyx

## Context

SecGate is MIT-licensed, but that license covers SecGate's own code only. The Semgrep step runs `semgrep --config=auto` (`runSemgrep` in `lib/scanners.mjs`), and Semgrep then downloads its maintained rules from the Semgrep Registry. Those rules are under the [Semgrep Rules License v1.0](https://semgrep.dev/legal/rules-license), which grants use "for your own internal business purposes" and forbids distributing the rules or making them available to others as a service. Semgrep's [licensing page](https://docs.semgrep.dev/licensing) states that vendors cannot use Semgrep-maintained rules in competing products or SaaS offerings. A breach ends the license automatically.

Today SecGate ships no rules and hosts nothing. Each user runs their own `semgrep` binary on their own machine or CI, so the user is the licensee and the use is internal. The risk only appears if Stelnyx runs scans on its own infrastructure for paying customers, which is a candidate in [OPEN-CORE.md](../../OPEN-CORE.md) (hosted dashboard, multi-repo aggregation).

The Semgrep engine (Community Edition, LGPL 2.1) is not the constraint. The rules are.

## Decision

**We will** keep running Semgrep only on the user's own machine, and never run Semgrep-maintained registry rules on customer code from Stelnyx infrastructure. SecGate will not bundle, mirror or redistribute registry rules in the npm package, a container image or any other artifact. A paid tier will be built first as ingest-only (it reads reports the customer's own runs produce) plus customer-run scanning. If Stelnyx ever runs scans itself, it will use only rules whose license allows that use (rules we write, or permissively licensed packs after a per-rule provenance check), never `--config=auto`, and only after legal review.

## Consequences

### Positive

- The free CLI stays clear of the Semgrep Rules License: the user fetches and uses the rules.
- A buyer's diligence question ("does the business depend on rules it cannot use commercially?") has a short, documented answer.
- The paid features already listed in OPEN-CORE.md (dashboard, policy, evidence packs, SSO, audit log, Jira) do not need server-side scanning.

### Negative

- A hosted "we scan for you" product cannot reuse the registry's rule coverage. It would need its own or permissively licensed rules, which cover less.
- Stored findings include Semgrep rule IDs and messages. Whether showing them in a hosted dashboard counts as making the rules available is not settled and needs legal review before launch.

### Neutral

- Semgrep sends its own usage metrics when it uses registry rules. SecGate does not change that setting, and the README discloses it.
- The other wrapped scanners (Trivy and its databases, osv-scanner and OSV.dev, the npm audit API, Gitleaks) have their own terms. They need the same review before any hosted tier.

## Alternatives Considered

### Run `--config=auto` on Stelnyx servers
Rejected. It is the case the Semgrep Rules License forbids.

### Customer-supplied Semgrep tokens in a hosted runner
Not adopted. The Semgrep platform terms were not reviewed, and Semgrep sells its own managed scans, so a hosted wrapper competes with it. Revisit only with legal review.

### Commercial agreement with Semgrep
Kept open. No public pricing; contact is partnerships@semgrep.com. Worth pursuing only once a hosted tier has demand.

### The pre-December 2024 rules snapshot (opengrep-rules)
Rejected. It is under Commons Clause, which also forbids selling hosted use, and the fork is archived.

## References

- [Semgrep Rules License v1.0](https://semgrep.dev/legal/rules-license)
- [Semgrep licensing](https://docs.semgrep.dev/licensing)
- [Semgrep metrics](https://docs.semgrep.dev/metrics)
- [ADR-0005](0005-no-external-api-v1.md): no external API or dashboard in v1
- README "Semgrep rules licensing" and [OPEN-CORE.md](../../OPEN-CORE.md) paid-extensions note
