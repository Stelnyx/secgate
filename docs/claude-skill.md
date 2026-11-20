Perform a security scan on the target directory. Target = $ARGUMENTS if provided, else current working directory (`.`).

## Step 1 — Detect tools

```bash
which semgrep 2>/dev/null && echo "semgrep:ok" || echo "semgrep:missing"
which gitleaks 2>/dev/null && echo "gitleaks:ok" || echo "gitleaks:missing"
which npm 2>/dev/null && echo "npm:ok" || echo "npm:missing"
which osv-scanner 2>/dev/null && echo "osv-scanner:ok" || echo "osv-scanner:missing"
which trivy 2>/dev/null && echo "trivy:ok" || echo "trivy:missing"
```

If ALL missing: report it, list install commands, stop.

## Step 2 — Run scanners (only tools that exist)

**semgrep:**
```bash
semgrep --config=auto --json <target> 2>/dev/null
```
Parse `.results[]` → `check_id`=signature, `extra.severity`=severity, `extra.message`=message, `path`+`start.line`=location.

**gitleaks:**
```bash
gitleaks detect --source <target> --report-format json --report-path /tmp/gl.json --redact 2>/dev/null
cat /tmp/gl.json 2>/dev/null || echo "[]"
```
Parse array → `RuleID`=signature, `Description`=message, `File`+`StartLine`=location. All severity = CRITICAL. `detect` scans git history only; outside a git repository, report Gitleaks as not run.

**npm audit** (only if `<target>/package.json` exists):
```bash
cd <target> && npm audit --json 2>/dev/null
```
Parse `.vulnerabilities` → key=package, `severity`, `title`. Map: `critical`→CRITICAL, `high`→HIGH, `moderate`→MEDIUM, `low` and `info`→LOW.

**osv-scanner:**
```bash
osv-scanner --format json -r <target> 2>/dev/null
```
Parse `.results[].packages[].vulnerabilities[]` → advisory ID, package ecosystem/name, severity/CVSS, source lockfile path.

**trivy fs:**
```bash
trivy fs --quiet --format json --exit-code 0 --scanners misconfig,license --skip-dirs '**/node_modules' <target> 2>/dev/null
```
Parse `.Results[].Misconfigurations[]` and `.Results[].Licenses[]`.

**trivy image** (for Dockerfile `FROM` images):
```bash
trivy image --format json --quiet --exit-code 0 <image-ref> 2>/dev/null
```
Parse `.Results[].Vulnerabilities[]`, marking findings as base-image scan results.

SecGate's CLI wraps scanner execution with hard timeouts and reports timeout as
`error` / inconclusive. It also performs a bounded preflight walk that skips
common dependency, VCS, vendor, and build-output directories. If you implement
this skill manually, preserve those safety properties.

## Step 3 — Verify findings

Read flagged files with the Read tool. Mark each finding confirmed or likely-false-positive based on actual code context.

## Step 4 — Score

CRITICAL=10pts, HIGH=6pts, MEDIUM=3pts, LOW=1pt. Sum = risk score.

## Step 5 — Print report

```
═══════════════════════════════════
 SECGATE SECURITY SCAN
 Target: <target>
 Date:   <ISO timestamp>
═══════════════════════════════════

TOOLS: semgrep ✓  gitleaks ✓  npm-audit ✓  osv-scanner ✓  trivy ✓
STATUS: PASS | FAIL
RISK SCORE: <n>

FINDINGS (<n> total)
─────────────────────
[CRITICAL] <signature>
  Tool:     <tool>
  Location: <file>:<line>
  Issue:    <message>
  Fix:      <specific step>

[HIGH] ...
[MEDIUM] ...

SUMMARY
───────
Critical: <n>  High: <n>  Medium: <n>  Low: <n>

RECOMMENDATIONS
───────────────
1. <most urgent>
2. ...

MISSING TOOLS (if any)
──────────────────────
<tool>: brew install <tool> | pip install <tool>
```

Zero findings → print `NO FINDINGS — clean scan`.

## Step 6 — Final status

- Any CRITICAL or HIGH → `SCAN FAILED — review before merging`
- Otherwise → `SCAN PASSED`

## Rules

- Never fabricate findings
- Read flagged files before confirming a finding
- Recommendations must be specific commands, not generic advice
