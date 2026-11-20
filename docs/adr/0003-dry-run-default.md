# ADR-0003: Dry-Run Default, `--apply` Opt-In

- **Status:** Accepted
- **Date:** 2026-04-23
- **Deciders:** Stelnyx

## Context

SecGate's remediation engine can mutate the user's repository — specifically, it runs `npm audit fix` which modifies `package-lock.json` and `node_modules/`.

For a tool that runs in CI **and** on developer laptops, mutation on every run is a footgun:

- A developer runs `secgate .` to check their branch and their lockfile gets rewritten without consent.
- A CI run in a shared container modifies state that a subsequent step relies on.
- A scheduled "just report" run in CI surprises someone by committing a fix.

The user's mental model of `secgate .` should be: "a scanner reads my code and tells me what's wrong." Side effects break that model.

## Decision

**We will default to dry-run. Side effects (executing fixes) require an explicit `--apply` flag.**

- Default mode (`secgate .`) → read-only. Produces report. Exit code reflects findings. No filesystem mutation outside scan artifacts.
- Opt-in mode (`secgate . --apply`) → executes fixable remediations. Side effects are logged in `remediation.executed[]` and `auditLog[]`. `--apply` also requires `SECGATE_CONFIRM_APPLY=1` or a `y` answer at a TTY prompt; otherwise SecGate exits 2 before scanning.

Scan artifacts (`secgate-v7-report.json`, `<repo>.html`) are always written — they are the product of the tool, not a side effect.

## Consequences

### Positive

- Safe by default. Running SecGate never surprises the user with mutations.
- Reversibility — dry-run runs are safe to repeat, chain, and embed in any CI step.
- Matches Unix principle of least surprise (`rm -i`, `terraform plan`, `kubectl --dry-run=client`).
- CI can run `secgate .` in PR gates without a commit step. `--apply` belongs in scheduled maintenance jobs, not PR gates.

### Negative

- "Why didn't it fix my issue?" support questions. Mitigated by fix plan output telling the user exactly what `--apply` would do and suggesting the flag.
- One extra flag for the power user. Acceptable cost.

### Neutral

- Future `--apply` scope can expand (see [ADR-0002](0002-npm-only-auto-fix.md)) without changing this default.

## Alternatives Considered

### Auto-apply by default with `--dry-run` opt-out
Rejected. Inverts the blast radius — the wrong default is to mutate. First-time users discovering the tool would be blindsided.

### Prompt interactively ("apply this fix? y/n")
Rejected as a replacement for the flag. Breaks non-interactive CI. Would require dual code paths. (Later, a TTY confirmation was added on top of `--apply`, with `SECGATE_CONFIRM_APPLY=1` for CI; the flag is still required.)

### Split commands: `secgate scan` and `secgate fix`
Considered. Arguably cleaner but doubles the surface. For v0.1.x the flag-based split is enough. Can refactor if we add more mutating operations.

## References

- [ADR-0002 — npm-only auto-fix](0002-npm-only-auto-fix.md)
- `secgate.js` — `confirmApplyOrExit()`; `lib/intelligence.mjs` — `remediate()` executes only when `apply` is true
- [`docs/threat-model.md`](../threat-model.md) — dry-run as a mitigation against E-of-P via malicious lifecycle scripts
