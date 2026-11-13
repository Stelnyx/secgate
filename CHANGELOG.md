# Changelog

All notable changes to SecGate are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) + [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Bundled GitHub Action**: the step now fails when the CLI exits 2
  (INCOMPLETE, no scanners ran, or a `--require`d scanner did not run). The
  `fail-on` filter used to run whenever a report file existed and turned that
  exit 2 into exit 0. Other exit codes above 1 (for example 127 when `npx`
  fails) are kept as well. New optional `require` input passes `--require` to
  the CLI. The step also no longer needs bash 4 (`${var,,}`), so it runs on
  macOS' bash 3.2. Covered by `test/action-exit.mjs`.
- **Release pipeline**: npm publish now runs inside `release.yml`, after the
  signed GitHub Release is created, with `npm publish --provenance` through
  npm trusted publishing. It publishes the same tarball that is signed and
  attached to the release. The separate `publish.yml` was removed: it waited
  for a `release` event created with `GITHUB_TOKEN`, which never triggers
  other workflows, so it never ran. The release build now also runs the
  dependency guard and lint.
- **Release hardening**: only the `publish-npm` job can publish to npm, once
  the npm Trusted Publisher record names the `npm` GitHub environment it runs
  in (`provenance` and `sign-and-release` also hold `id-token: write`, for SLSA
  and keyless cosign). `sign-and-release` runs in the protected `release`
  environment. The workflow runs only from a `vX.Y.Z` tag that points at the
  commit that triggered the run (`GITHUB_SHA`, which is what is checked out)
  and is on `main`, checks the
  tarball sha256 before `npm publish`, refuses to overwrite an existing GitHub
  Release or republish a version, and verifies the published package in a
  separate job with no token and no lifecycle scripts.

### Changed
- **Breaking: exit code 2 on partial coverage.** A scan where a scanner that
  applies did not run (not installed, timed out, or failed in a way SecGate
  detects) now reports `INCOMPLETE` and exits `2` instead of `PASS` with exit
  `0`. Blocking findings from the scanners that ran still give `FAIL` (exit
  `1`). CI steps that run SecGate on a runner without all external scanners
  installed will go from exit `0` to exit `2`.
- Projects with only a `yarn.lock` or `pnpm-lock.yaml` (no `package-lock.json`)
  now exit `2`: npm audit cannot run without an npm lockfile, so the scan is
  `INCOMPLETE`.
- Trivy counts as ran only when its filesystem scan ran and its image scan did
  not fail. A failed base-image pull or a timed-out filesystem scan is a gap.
- No scanner ran, or a scanner named in `--require` / `requireScanners` did
  not run: exit `2`. Scanners that did not run are shown as `n/a`, not
  `100 / 100`.
- To skip a scanner on purpose, set `"scanners": { "<name>": false }` in
  `.secgate.config.json`; a disabled scanner is not a gap.
- **Docs**: removed the npm provenance badge and the provenance claims that
  were false for `0.2.14` (published without provenance, tag or GitHub
  Release) from `README.md`, `SECURITY.md` and `docs/index.html`. The docs
  page no longer hard-codes a version. `CONTRIBUTING.md` now describes one
  tag-driven release flow.

### Added
- `--require <tools>` (also `--require=<tools>`) and the `requireScanners`
  config key.

## [0.2.14] - 2026-07-10

### Fixed
- Added a bounded scan preflight before launching external scanners so large
  workspace-like targets no longer appear to hang after the banner. The walk
  skips dependency, VCS, vendor, and build-output directories by default,
  skips symlinks, caps depth/files/file size/time, and emits visible progress.
- Detects targets that look like multi-project workspaces and exits with a
  clear message unless `--allow-workspace` is supplied.
- Reused the bounded walker for Trivy image Dockerfile discovery, replacing
  the previous unbounded recursive walk.
- Report-output failures now return a clear exit-2 message instead of a raw
  stack trace.

### Added
- CLI safety knobs: `--max-files`, `--max-depth`, `--max-file-size`,
  `--walk-timeout-ms`, and `--allow-workspace`.
- Regression tests for bounded walking, vendor/build excludes, symlink skips,
  workspace detection, empty targets, and unwritable output directories.

## [0.2.13] - 2026-05-19

### Added
- **Determinism contract test** (`test/determinism.mjs`): pins the aggregation
  pipeline against silent flakes — same inputs produce JSON-byte-identical
  `findings[]`, score, summary, status, and toolScores across two runs.
  Also asserts dedup is order-stable and reversing input order does not
  change the unique key set. Closes a class of "silent miscount" bugs that
  could appear with Map/Set iteration order changes or new time-based fields.
  Issue: #66 (item 1).
- **Golden snapshot test** (`test/golden-secgate.mjs`): locks the aggregation
  contract against a hand-crafted 11-finding fixture exercising dedup,
  severity override, ignore globs, UNKNOWN severity, and 5 tools. Expected
  counts, summary, score (22), per-tool scores, and gate status are inline
  in the test so any change surfaces in code review as a literal diff,
  not an opaque snapshot blob. Issue: #66 (item 3).
- **Aggregation rules doc** (`docs/aggregation.md`): documents the per-finding
  pipeline (severity normalize → override → ignore → exclude → dedup →
  inline suppression → fixability), score formula, gate status rule, and
  the curated/strict invariant. Cross-linked from the two new tests and the
  follow-up scanner-cross-check work.

### Deferred
- **Scanner cross-check** (`test/crosscheck-semgrep.mjs`) is deferred to a
  follow-up issue (#68). Item 2 of #66 needs `semgrep` installed in CI and a
  hermetic fixture repo with known findings; the cost-benefit argued for
  shipping the local determinism + golden contracts first.

### Changed
- **README**: added the "Accuracy contract" block under Status, linking the
  new `test/determinism.mjs`, `test/golden-secgate.mjs`, and
  `docs/aggregation.md`. Documentation table now lists `docs/aggregation.md`.
- **LICENSE** + **scripts/verify-release.sh**: brand-rename leftovers cleaned
  (`StelNyx` → `Stelnyx`, `tinydarkforge/SecGate` → `Stelnyx/SecGate`).

## [0.2.12] - 2026-05-19

### Changed
- **README**: premium polish for the npm registry page. Replaced the ASCII
  robot/wordmark block with a clean centered hero (H1 + tagline + badges),
  stripped the `░▒▓█` glyphs from every section header, dropped the
  closing ASCII face under License, and normalized the opening blockquotes
  to body paragraphs. No code changes; this release exists solely to
  refresh the README rendered on `npmjs.com/package/@stelnyx/secgate`,
  which is built from the tarball, not from `main`.

## [0.2.11] - 2026-05-19

### Changed
- **CI**: reverted to token-based npm publish. Trusted Publishing (OIDC)
  attempt returned `404 PUT @stelnyx/secgate` twice despite valid provenance
  signing; root cause is a config mismatch on the npm trusted-publisher
  record (org/repo/workflow case or environment field). Restored
  `NODE_AUTH_TOKEN` env on the publish step using a granular token scoped
  to `@stelnyx` with 2FA bypass. TP migration deferred until the npm UI
  config can be audited against the actual OIDC claim.

## [0.2.10] - 2026-05-18

### Changed
- **CI**: validates the new Trusted Publishing (OIDC) auth flow end-to-end.
  No code or behavior changes from `0.2.9`; the bump exists to exercise
  the publish pipeline now that `NPM_TOKEN` has been revoked.

## [0.2.9] - 2026-05-18

### Fixed
- **CI publish job missing `npm ci`**: the `npm publish (provenance)` job ran
  `node secgate.js .` (self-scan) without first installing dependencies, so
  `@stelnyx/report-theme` failed to resolve and the publish was blocked.
  `0.2.8` shipped the same fix only for the build job; `0.2.9` extends it
  to the publish job. Code identical to `0.2.8`.

## [0.2.8] - 2026-05-18

(First release under the `@stelnyx/secgate` npm scope. `v0.2.7` was tagged
but its CI pipeline failed before publish — the `npm test` step lacked an
`npm ci` install step, so `@stelnyx/report-theme` could not be resolved.
Code in `0.2.8` is identical to `0.2.7` plus the CI install fix and two
stale HTML-tab assertions updated to match the new theme markup.)

### Changed
- **npm scope rename**: `@tinydarkforge/secgate` → `@stelnyx/secgate`.
  Repository, homepage, and bug-tracker URLs now point to
  `github.com/Stelnyx/SecGate`. The old `@tinydarkforge/secgate@0.2.4`
  remains published but is deprecated; install
  `npm i @stelnyx/secgate` going forward.
- **Theme dependency**: `@stelnyx/report-theme@^0.1.0` (registry), replacing
  the previous local `file:../report-theme` path so end-user installs
  resolve cleanly via npm.
- **README**: lead with the 1,858 → 46 actionable demote stat; "Tiers
  (planned)" and "Product vision" moved below the CI / Report sections
  so first-time readers reach `npx @stelnyx/secgate .` faster. Stale
  schema example `version: "0.2.4"` corrected to `"0.2.7"`.
- **`riskScore` vs `securityScore`**: new note clarifying the deterministic
  0–100 Security Score (top of README) is the canonical posture metric;
  the legacy unbounded `riskScore` is kept for back-compat only.

### Added
- **Example config shipped**: `.secgate.config.example.json` is now included
  in the npm tarball (`files[]`), so `npx`'d users see the canonical
  template without cloning the repo.

### Fixed
- **CI release pipeline**: `npm ci` step added before `npm test` in
  `.github/workflows/release.yml` (smoke tests previously failed to
  resolve registry-installed dependencies).
- **Stale `id="tab-${tool}"` assertions** in `test/engine.mjs` and
  `test/smoke.mjs` rewritten to check for lower-case tool tokens in the
  rendered HTML — the new `themeShell`-based report no longer renders
  the legacy `<input id="tab-…">` radio-tab markup.

## [0.2.7] - 2026-05-12

(The `v0.2.6` tag was cut but never published to npm; everything below — the
confidence-profile work and the timeout/network-disclosure changes — ships in
`v0.2.7`. npm latest before this release: `0.2.4`.)

### Added
- **Universal scanner timeout.** Every scanner invocation now has a default
  180s ceiling (`DEFAULT_TOOL_TIMEOUT_MS` in `lib/utils.mjs`) — a hung or
  wedged scanner binary can no longer stall SecGate or the CI job. Individual
  callers may still override `timeout` (Trivy image scans keep their tighter
  120s budget). Covered by `test/timeout.mjs`.
- **Display-filtering invariant tests** in `test/confidence.mjs`: `curated`
  and `strict` profiles partition the same finding set (nothing dropped, only
  the actionable/informational split changes); `strict` never demotes.
- **Post-publish healthcheck** in the release workflow — installs the freshly
  published `@stelnyx/secgate@<version>` and runs `--version` / `--help`
  so a broken `bin` entry or tarball is caught at release time.
- **Confidence profiles for the HTML report.** New `profile` config field
  (`"curated"` default, `"strict"` opt-in) and matching `--profile` CLI flag.
  Curated profile demotes known-noisy patterns to a collapsed Informational
  details block instead of mixing them with actionable findings:
  - Trivy `type: license` findings (governance, not security)
  - Trivy base-image OS CVEs at LOW/MEDIUM (`scanMode: image` or
    `signature: trivy-image:*`) — rarely reachable from app runtime
  - CVEs >5 years old, severity != CRITICAL — upstream-bounded exploitability
  - `UNKNOWN` severity findings — scanner couldn't classify
  - `html.security.audit.missing-integrity` Semgrep rule — fires on every
    `<script src>` including inline favicon SVGs
  - `path-join-resolve-traversal` Semgrep rule — common false positive in
    CLI tools that legitimately resolve user-supplied paths
  Real-world impact: 2,628-file production codebase scan went from 1,858
  raw findings → 46 actionable (98% demoted). Demotion is display-only;
  the `failOn` policy alone gates CI exit code.
- **Suppressed findings details block.** Findings dropped via inline
  `# secgate:ignore` comments now get their own collapsed block with
  per-rule counts in the HTML report (still excluded from counters).
- **`.secgate.config.example.json`** — fully-commented example config
  shipped at repo root; copy into your repo and edit.
- **19 new unit tests** in `test/confidence.mjs` covering all demotion
  paths (license, image-scan via tool/scanMode/signature, stale-CVE year
  arithmetic, profile bypass).
- **Sidebar shell parity with luxfaber + lucen.** SecGate report now
  renders in the unified Midnight Blossom / Dawn Blossom shell shared
  across the three Stelnyx products. 240px sticky sidebar with
  brand block + score + band pill + PASS/FAIL chip + scroll-spy nav.
  Theme toggle persisted in `localStorage`. 🛡 inline SVG favicon.

### Changed
- HTML report `Findings` section meta line now reads
  `N actionable · M informational · K suppressed` instead of raw total,
  matching the curated/strict bucket split.
- Tab labels show `<actionable> +<informational>` (e.g. `npm audit  3 +5`)
  so demoted findings remain discoverable per-tool.
- Sidebar `Reasoning` and `Remediation` nav counts now reflect filtered
  (actionable-only) item counts. Previously they showed the per-finding
  upstream count, which made the sidebar inconsistent with the Findings
  count under curated profile.

### Changed
- Scanner JSON-parse failures are no longer swallowed silently. Each scanner's
  output is parsed via `parseToolJson()` (in `lib/utils.mjs`); on failure it
  logs the error + the first ~200 bytes of raw output through `--debug` before
  rethrowing, so a `{ status: "error" }` result is now diagnosable instead of
  opaque.
- Landing-page CTAs no longer point at a personal Gmail — replaced with
  `hello@stelnyx.com` (a Cal.com booking flow is the planned follow-up).
- GitHub repo description rewritten to match reality ("deterministic security
  gate", not "autonomous AI SOC engine").
- Stale `docs/github-issues/*` planning templates moved to `docs/archive/`.

### Documentation
- README: new **"Network access"** section + per-scanner network markers in
  the scanner table. SecGate itself sends nothing, but `npm audit`,
  `osv-scanner`, and `Trivy` query vulnerability data over the network — the
  intro no longer claims "Local files only" without that caveat. ("No
  telemetry" was accurate; "fully air-gapped" was not.)
- README: new "What we demote (and why)" section + `profile` row in
  config reference table + JSON example + `--profile` CLI usage.
- Landing page: new "What we don't pretend" section listing curated
  profile, suppression UX, and the no-exploitability-oracle limit;
  real-world reduction stat (1,858 → 46) cited inline.
- `docs/tuning.md`: new "Confidence Profiles" section before Severity
  Thresholds; reflects v0.2.6 behavior.
- `docs/config.schema.json`: new `profile` enum field with description.
- `DESIGN_PARITY.md`: SecGate added as third sister product alongside
  luxfaber + lucen.

---

## [0.2.6] — 2026-05-07

### Fixed
- Release workflow now installs external scanners (Semgrep, Gitleaks, osv-scanner,
  Trivy) before running smoke tests. Previously the build job ran `npm test`
  without scanners, causing the `vulnerable-dockerfile fixture → trivy detects
  misconfig` smoke test to fail in CI while passing locally.

### Note
- `v0.2.5` was tagged but never published to npm or GitHub Releases due to the
  CI bug above. All `v0.2.5` content is included in `v0.2.6`.

---

## [0.2.5] — 2026-05-07

### Fixed
- `excludePaths` now matches against repo-relative paths, so absolute lockfile paths
  reported by osv-scanner (e.g. fixtures, vendored trees) are correctly excluded
  instead of leaking into scan results.
- `runTrivyImage` Dockerfile discovery honors `excludePaths`, preventing fixture
  Dockerfiles from being scanned as base images outside test mode.

### Security
- Suppressed two false-positive Semgrep findings on internal `path.resolve` and
  `RegExp` helpers (target dir / glob compiler — not user-controlled).

---

## [0.2.4] — 2026-04-24

### Changed
- Refreshed README with updated ASCII CLI banner and corrected `--tuning` flag documentation.

---

## [0.2.3] — 2026-04-23

No functional changes. Patch release to validate CI/CD pipeline configuration after v0.2.2.

---

## [0.2.2] — 2026-04-23

### Fixed
- `runTool()` was mixing stdout and stderr on non-zero exit codes. Now returns stdout only, preventing scanner noise from polluting parsed output.

---

## [0.2.1] — 2026-04-23

### Added
- Core engine extracted into `lib/` modules for testability.
- Scanner fixture tests and end-to-end smoke test suite.
- Trivy image scanning mode documented in README.

---

## [0.2.0] — 2026-04-23

### Added
- `.secgate.json` config file: severity thresholds, scope patterns, tool toggles, tuning presets.
- Baseline workflow: suppress known findings by committing a signed baseline snapshot.
- Inline `secgate-ignore` suppression comments for per-finding exceptions.
- SARIF 2.1.0 output format (`--format sarif`) for GitHub Code Scanning integration.
- Composite GitHub Action (`.github/actions/secgate`) for zero-config consumer integration.
- Trivy image scanning mode (`--mode image`) and no-lockfile detection finding.
- Documentation bundle: threat model, scanner coverage matrix, tuning guide, tool comparison, ADRs.

### Changed
- **Breaking:** findings schema overhauled — each finding now carries `location` (file, line, col) and structured `severity` fields. Consumers parsing the JSON report must update selectors.

### Security
- GitHub Releases now include CycloneDX SBOM, SLSA L3 provenance attestation, and cosign keyless signatures on tarball and SBOM.
- Hardened `--apply` flag against path traversal attacks.
- Sanitized file paths in HTML and JSON reports to prevent path leak to downstream consumers.

### Fixed
- Skipped-tool reason now shown clearly in report output (was previously blank for missing tools).

---

## [0.1.0] — 2026-04-23

Initial public release to npm as `@stelnyx/secgate`.

### Added
- Five scanner integrations: Semgrep (SAST), Gitleaks (secrets), npm audit (dependency CVEs), osv-scanner (OSV database), Trivy (CVEs + misconfigs).
- Per-tool scanner status tracking in report (`ok`, `skipped`, `error`).
- Normalized JSON findings report (`secgate-v7-report.json`) with unified severity tiers (CRITICAL / HIGH / MEDIUM / LOW / INFO).
- Tabbed HTML report with per-scanner breakdown.
- npm publish with provenance (`--provenance`).
- Risk scoring and exit code semantics: exit `0` = clean or low/medium only; exit `1` = CRITICAL or HIGH findings present.

[Unreleased]: https://github.com/Stelnyx/SecGate/compare/v0.2.13...HEAD
[0.2.13]: https://github.com/Stelnyx/SecGate/compare/v0.2.12...v0.2.13
[0.2.12]: https://github.com/Stelnyx/SecGate/compare/v0.2.11...v0.2.12
[0.2.11]: https://github.com/Stelnyx/SecGate/compare/v0.2.10...v0.2.11
[0.2.10]: https://github.com/Stelnyx/SecGate/compare/v0.2.9...v0.2.10
[0.2.9]: https://github.com/Stelnyx/SecGate/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/Stelnyx/SecGate/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/Stelnyx/SecGate/compare/v0.2.4...v0.2.7
[0.2.4]: https://github.com/Stelnyx/SecGate/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/Stelnyx/SecGate/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/Stelnyx/SecGate/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Stelnyx/SecGate/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Stelnyx/SecGate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Stelnyx/SecGate/releases/tag/v0.1.0
