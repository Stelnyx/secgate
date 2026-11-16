```text
░▒▓█ SECGATE · TUNING █▓▒░
```

# Tuning SecGate

How to adjust severity thresholds, baseline noisy findings, suppress rules, toggle scanners, and tune CI vs local defaults. This document reflects the `v0.3.2` CLI.

---

## Confidence Profiles (display-only, never gating)

SecGate's HTML report ships two confidence profiles. The profile **never** changes the exit code: the `failOn` policy decides `0` or `1`, and a scanner that applies but did not run turns a pass into `2`. Profiles only change which findings render inline vs in collapsed details blocks.

### `curated` (default)

Demotes known-noisy patterns to a collapsed **Informational** block so the actionable pane is triageable on first scroll.

| Pattern | Why demoted |
|---------|-------------|
| `type: "license"` (Trivy SPDX flagging) | Governance/legal posture, not a security threat. |
| Trivy base-image OS CVEs at LOW/MEDIUM (`scanMode: "image"` or `signature: "trivy-image:*"`) | Rarely reachable from app runtime (`apt-secure`, `libtinfo`, `perl-base`). CRITICAL/HIGH still surface inline. |
| CVEs >5 years old, severity != CRITICAL | Upstream has decided exploitability is bounded. |
| `UNKNOWN` severity | Scanner couldn't classify — surfaced for audit. |
| `html.security.audit.missing-integrity` | Fires on every `<script src>` (incl. inline favicon SVGs). HSTS/COEP cover the real risk. |
| `path-join-resolve-traversal` Semgrep rule | Common false positive in CLI tools that resolve user-supplied paths against a known root. |

Real-world impact: 2,628-file production codebase scan went from **1,858 raw findings → 46 actionable** (98% demoted). The 46: 2 CRITICAL · 36 HIGH · 8 LOW.

### `strict`

No demotion. Every finding renders inline. Use for compliance audits or when re-validating the curated mute list.

### Selecting a profile

```json
// .secgate.config.json
{ "profile": "curated" }   // default
{ "profile": "strict" }
```

Or via CLI override:

```bash
secgate . --profile strict
```

### Suppressed findings

Findings dropped via inline `# secgate:ignore` comments (see [Suppression Syntax](#suppression-syntax) below) get their own collapsed details block with per-rule counts. Profiles do not change suppression behavior.

---

## Severity Thresholds

### Default behavior

SecGate exits `1` on any **CRITICAL** or **HIGH** finding. MEDIUM and LOW findings are reported but do not fail the build.

### Custom threshold

Set `failOn` in `.secgate.config.json`:

```json
{ "failOn": ["critical"] }                      // only fail on CRITICAL
{ "failOn": ["critical", "high", "medium"] }    // stricter
{ "failOn": [] }                                // report only — never fail
```

### Alternative — exit-code masking

```bash
# Report only, don't fail CI
secgate . || true
```

---

## Baseline: Accepting Known Findings

Large existing codebases onboarding SecGate often have pre-existing findings that cannot be remediated immediately. A **baseline** records the current findings as acknowledged and fails the build only on *new* findings.

### Workflow

```bash
# 1. Record current state as baseline
secgate . --update-baseline

# 2. Subsequent scans diff against baseline, failing only on net-new findings
secgate . --baseline

# 3. A new CRITICAL finding not in baseline → exit 1
# 4. Review + regenerate baseline quarterly
```

Baseline file defaults to `.secgate-baseline.json` in the target directory (override via `baselineFile` in config). It is a JSON list of finding **signatures** (rule ID + file path + line). Commit it to the repo.

### Complementary — inline suppression

See next section.

---

## Suppression Syntax

Inline suppression disables a rule for a specific line or block.

### Line comment

```javascript
const token = "AKIA..."; // secgate:ignore gitleaks-aws-access-key
```

```python
password = "test"  # secgate:ignore gitleaks-generic-api-key
```

### Block comment

```javascript
/* secgate:ignore semgrep-javascript-lang-eval-detected */
const result = eval(input);
```

### Multiple rules

```javascript
// secgate:ignore gitleaks-github-pat, semgrep-javascript-crypto-weak-ssl
```

### Placement

- **Same line** as the finding — most reliable.
- **Line above** — accepted.
- **Block comment preceding** — applies to the next statement.

### What it does

SecGate filters suppressed findings out of the report before severity rollup. They do not count toward fail thresholds. They still appear in the HTML report under a "Suppressed" section so reviewers can audit them.

### Rule IDs

Use the rule ID from the JSON report (`findings[].signature` field). Copy-paste from a dry run.

---

## Per-Scanner Toggles

### Disable scanners via config

```json
{
  "scanners": {
    "semgrep":  true,
    "gitleaks": true,
    "npm":      true,
    "osv":      true,
    "trivy":    false
  }
}
```

Any scanner set to `false` is skipped and reported as `status: "skipped"`. To run only one scanner, disable the rest.

### Missing scanner binaries

A scanner whose binary is not on `$PATH` is reported as `skipped` with reason `not installed`. Since `v0.3.0` that is a coverage gap: if the scanner applies to the project, a scan with no blocking findings ends `INCOMPLETE` with exit `2` instead of `PASS`. To skip a scanner on purpose, set it to `false` in `.secgate.config.json` as shown above; a disabled scanner is not a gap.

CLI flags `--disable <list>` and `--only <scanner>` are planned — see [#32](https://github.com/Stelnyx/SecGate/issues/32).

---

## Target Size and Walk Limits

SecGate is designed to scan one project at a time. Before launching scanners,
it performs a bounded preflight walk so large workspaces, symlink cycles, deep
trees, and vendored dependency folders do not look like a silent hang.

Default exclusions include dependency, VCS, vendor, and build-output
directories such as `node_modules`, `.git`, `vendor`, `dist`, `build`,
`coverage`, `.next`, `.nuxt`, `out`, and package-manager caches. Symlinks are
skipped. Large files are counted but not parsed for lightweight preflight
classification.

Useful CLI knobs:

```bash
# Raise limits for an unusually large single project
secgate . --max-files 50000 --max-depth 32

# Raise the per-file cap for Dockerfile/source preflight parsing
secgate . --max-file-size 4194304

# Raise the preflight walk timeout
secgate . --walk-timeout-ms 60000

# Override workspace detection when intentionally scanning many sub-projects
secgate /path/to/workspace --allow-workspace
```

If a target looks like a workspace with multiple sub-projects and no root
`package.json`, SecGate exits with a clear message. Prefer scanning each
project directory separately unless the broader workspace scan is intentional.

---

## Scanner Timeouts and First-Run Downloads

Every external scanner invocation has a hard process timeout. The default is
180 seconds; Trivy image scans use 120 seconds per image reference. A timeout
is reported as `status: "error"` with an inconclusive timeout reason, never as
`clean`.

`osv-scanner` and Trivy may download vulnerability databases on first run.
SecGate prints a note before starting those scanners. In CI, keep a job-level
timeout as a belt-and-braces guard around the whole workflow.

---

## CI vs Local Defaults

| Setting | Local dev | CI |
|---------|-----------|----|
| Mode | `--apply` after review | dry-run (default) |
| Threshold | `.secgate.config.json` with `"failOn": ["critical","high","medium"]` while developing | default `["critical","high"]` |
| Baseline | Not used — see every issue | Used — only fail on new |
| Output | Human-readable summary + HTML | JSON artifact + HTML uploaded |
| Scanner set | All | All |
| Timeout | Scanner hard timeout + preflight walk limits | Add job-level timeout (15–30 min) |
| Clone depth | Full | `fetch-depth: 0` for secrets history |

### Recommended CI config (GitHub Actions)

```yaml
jobs:
  secgate:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history for gitleaks

      - name: Install scanners
        run: |
          brew install semgrep gitleaks osv-scanner trivy || \
          (pip install semgrep && \
           curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | sh && \
           curl -sSfL https://raw.githubusercontent.com/google/osv-scanner/main/scripts/install.sh | sh && \
           curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh)

      - name: Run SecGate
        run: npx @stelnyx/secgate .

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: secgate-report
          path: |
            secgate-v7-report.json
            *.html
```

---

## Worked Examples

### Example 1 — New repo, strict mode

You are starting a green-field repo and want every issue caught.

```json
// .secgate.config.json
{ "failOn": ["critical", "high", "medium", "low"] }
```

No baseline needed (green field). Same config in CI and local.

### Example 2 — Legacy repo, onboarding

You have a five-year-old repo with 200 pre-existing findings. You cannot fix them all in one PR but you want to prevent new ones.

```bash
# 1. First run — record baseline
secgate . --update-baseline

# 2. Commit baseline
git add .secgate-baseline.json
git commit -m "chore(security): establish secgate baseline"

# 3. All future PRs
secgate . --baseline
# → passes unless a NEW CRITICAL/HIGH appears

# 4. Quarterly cleanup: fix a batch of findings, regenerate baseline
secgate . --update-baseline
```

### Example 3 — Monorepo with IaC in one subdir only

Your repo has `app/` (Node) and `infra/` (Terraform). You want Trivy only against `infra/`.

```bash
# Recommended — two configs, two runs
# app/.secgate.config.json          → { "scanners": { "trivy": false } }
# infra/.secgate.config.json        → { "scanners": { "semgrep": false, "gitleaks": false, "npm": false, "osv": false } }

secgate app/
secgate infra/

# Or run against the whole workspace intentionally.
secgate . --allow-workspace

# Scoping today is path-based, not scanner-per-path.
# CLI equivalents (--disable, --only) planned: #32.
```

---

## Debugging

```bash
# Verbose scanner output + parse failures
secgate . --debug

# Inspect raw JSON
cat secgate-v7-report.json | jq '.findings[] | select(.severity=="CRITICAL")'

# Check tool status
cat secgate-v7-report.json | jq '.tools'
```

If a scanner reports `"error"` state, re-run with `--debug` to see the raw stdout/stderr that failed to parse.

---

See also: [`coverage.md`](coverage.md), [`threat-model.md`](threat-model.md), [`adr/0003-dry-run-default.md`](adr/0003-dry-run-default.md).
