# Aggregation rules

SecGate runs five external scanners in parallel and merges their output into one normalized report. This document is the contract for what happens between raw scanner output and `secgate-v7-report.json`.

The behavior is exercised by `test/determinism.mjs` (locks ordering / dedup invariants) and `test/golden-secgate.mjs` (locks count, score, and gate status against a hand-crafted fixture). If you change anything documented below, update both tests in the same PR.

---

## Pipeline (per finding)

Every raw finding from every scanner passes through `makeFindingProcessor` in [`lib/scanners.mjs`](../lib/scanners.mjs). Stages, in order:

1. **Severity normalization** — `normalizeSeverity` ([`lib/utils.mjs`](../lib/utils.mjs)) uppercases `severity` and maps it to one of `CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN`: `MODERATE` and `WARNING` → MEDIUM, `ERROR` → HIGH, `INFO`, `NOTE`, `INFORMATIONAL` and `NEGLIGIBLE` → LOW. Anything unrecognized becomes `UNKNOWN` (never dropped, never miscounted).
2. **Severity override** — first matching entry in `config.severityOverrides` wins. The `rule` field supports glob `*`. Matched against the finding's `signature`.
3. **Ignore glob** — if `signature` matches any entry in `config.ignore` (glob `*` supported), the finding is dropped entirely. Counts as 0 in summary, score, and gate.
4. **Exclude paths** — if the finding has a `file` and that path matches any glob in `config.excludePaths`, the finding is dropped. Tried against both the raw `file` value and a target-relative form.
5. **Dedup** — keyed by `${tool}|${signature}|${file}|${image}|${line}`. First occurrence wins; later identical hits are silently dropped. Dedup is per-run, not cross-run.
6. **Inline suppression** — if a line of source matches `# secgate:ignore <rule>` (or `//`, `/*`) on the flagged line *or* the line above, the finding is dropped and recorded in `suppressions.byRule` for audit. Only findings with a `line` and a `file` inside the target can be suppressed.
7. **Fixability inference** — `fixableBy` is the scanner's hint when it is `"auto"` or `"manual"`, else `"manual"` if the raw finding has `fixable: true`, else `null`. Only npm audit findings are `"auto"`. `fixable` mirrors `fixableBy === "auto"`.
8. **Push** — the normalized finding (canonical field order) is appended to `findings[]`.

A finding that survives stages 1–7 always lands in `findings[]`. A finding never appears twice unless its `(tool, signature, file, image, line)` tuple differs.

When every scanner has finished, `findings[]` is sorted with `compareFindings` ([`lib/scanners.mjs`](../lib/scanners.mjs)): scanner, file, line, column, signature, image, then the whole finding. The scanners run in parallel and Trivy does not list its results in a fixed order, so the same findings would otherwise come out in a different order from run to run. The reports, the SARIF file and a written baseline all use the sorted list.

---

## Severity tiers (locked)

| Tier        | Penalty | Maps from upstream                                              |
|-------------|--------:|------------------------------------------------------------------|
| `CRITICAL`  |  -25    | numeric CVSS ≥ 9, Gitleaks secrets, secret-like Semgrep rules, scanner-reported `CRITICAL` |
| `HIGH`      |  -10    | numeric CVSS 7.0–8.9, Semgrep `ERROR`, scanner-reported `HIGH`   |
| `MEDIUM`    |   -3    | numeric CVSS 4.0–6.9, Semgrep `WARNING`, npm `moderate`          |
| `LOW`       |   -1    | numeric CVSS < 4.0, `INFO`, `NOTE`, `INFORMATIONAL`, `NEGLIGIBLE`, scanner-reported `LOW` |
| `UNKNOWN`   |    0    | scanner provided no severity or an unrecognized value           |

`SEVERITY_PENALTY` in [`lib/score.mjs`](../lib/score.mjs) also has an `INFO: 0` entry, but `normalizeSeverity` turns `INFO` into `LOW` before scoring, so no stored finding has severity `INFO`. `UNKNOWN` findings surface in the report so they can be audited; they don't move the score or trigger the gate by default (`unknown` can be added to `failOn`).

---

## Score (`SCORE_VERSION = "v1"`)

```
score = max(0, 100 − Σ penalty(severity))
```

Deterministic. No timestamps, no random sampling, no Map-iteration order. Penalty table is the column above. Floor is 0 (a single CRITICAL is worth `-25`; four CRITICAL findings reach 0). The score is `null` when no scanner ran. It is computed over every reported finding, including findings matched by the baseline in `--baseline` mode.

Per-tool scores apply the same formula to the subset of findings emitted by that tool. A tool that ran with no findings scores `100`; a tool that did not run scores `null`.

If the penalty table changes, bump `SCORE_VERSION` so dashboards can branch on the lock. The golden test asserts `SCORE_VERSION === "v1"` to flag silent edits.

---

## Gate status

```
status = "FAIL" if any finding has severity ∈ failOn else "PASS"
```

`failOn` defaults to `["critical", "high"]`. In baseline mode, findings tagged `baseline: true` are excluded from the gate (they still appear in the report).

Coverage then overrides this status (`secgate.js`): if no scanner ran, or a scanner named in `--require` / `requireScanners` did not run, the status is `INCOMPLETE` (exit 2) even with blocking findings. If the status is `PASS` and a scanner that applies did not run (not installed, error, timeout), the status is `INCOMPLETE` (exit 2). `FAIL` exits 1 and `PASS` exits 0. The full flow is in [`ARCHITECTURE.md`](../ARCHITECTURE.md#gate-and-exit-code).

The gate is unchanged by curated demotion. Demotion is presentation-only — it moves a finding to the Informational block in the HTML report, but the JSON, the SARIF, and the exit code are unaffected.

---

## Curated vs strict profile

The aggregation pipeline above runs identically under both profiles. The profile only changes the HTML report:

- **`curated` (default)** — known-noisy patterns are demoted to a collapsed `Informational` block. See [the README demotion table](../README.md#what-we-demote-and-why) for the rule list.
- **`strict`** — every surviving finding renders inline.

Counts in `summary`, the score, the gate, and the SARIF output are identical across profiles. The invariant is tested in `test/confidence.mjs`.

---

## Cross-check against raw scanner output

SecGate's aggregated count for any given scanner is guaranteed to equal the raw scanner's count *minus*:

1. findings dropped by `config.ignore` (signature match),
2. findings dropped by `config.excludePaths` (file match),
3. findings dropped by inline `secgate:ignore` comments,
4. duplicates collapsed by the dedup key.

A cross-check test against the raw scanner output (e.g. running `semgrep --json` and diffing the result count) is tracked in the follow-up issue to [#66](https://github.com/Stelnyx/SecGate/issues/66). It requires the scanner binary in CI and a hermetic fixture repo, both of which are deferred until the local determinism and golden contracts are settled.

---

## Stability guarantees

| Property                                              | Guaranteed | Tested in |
|-------------------------------------------------------|:---------:|-----------|
| Identical inputs → identical `findings[]` (JSON-equal) | yes       | `test/determinism.mjs` |
| Dedup keeps "first seen", drops later duplicates        | yes       | `test/determinism.mjs` |
| Severity override applied before ignore + dedup         | yes       | `test/determinism.mjs`, `test/golden-secgate.mjs` |
| Ignore glob drops the finding entirely                  | yes       | `test/determinism.mjs`, `test/golden-secgate.mjs` |
| Score / summary / status are pure functions of findings | yes       | `test/score.mjs`, `test/determinism.mjs` |
| `SCORE_VERSION` change is detected by tests             | yes       | `test/golden-secgate.mjs` |
