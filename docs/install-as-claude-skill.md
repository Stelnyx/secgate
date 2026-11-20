## Goal

Install SecGate as a Claude Code slash command (`/security-scan`) in any project.

## Why

No npm install. Works in any project opened in Claude Code. Claude reads flagged files to separate real findings from likely false positives. The skill runs the scanners directly; it does not run the SecGate CLI, so it has no baseline, config file, SARIF or HTML output.

## This Is an Implementation Task

Follow these steps exactly. No source code changes. File operations only.

---

## Option A — Project-level install (this project only)

### Step 1 — Create commands directory

```bash
mkdir -p .claude/commands
```

### Step 2 — Copy skill content

Copy the full content of `docs/claude-skill.md` (from this repo) into:

```
.claude/commands/security-scan.md
```

Exact copy. No modifications.

### Step 3 — Verify

File must exist at `.claude/commands/security-scan.md`.

Check: `ls .claude/commands/security-scan.md && echo "OK"`

### Step 4 — Test

Open Claude Code in this project. Type:

```
/security-scan .
```

Expect: Claude runs tool detection, scans, prints report in the format defined in the skill file.

---

## Option B — Global install (all projects)

### Step 1 — Create global commands directory

```bash
mkdir -p ~/.claude/commands
```

### Step 2 — Copy skill content

Copy full content of `docs/claude-skill.md` into:

```
~/.claude/commands/security-scan.md
```

### Step 3 — Verify

```bash
ls ~/.claude/commands/security-scan.md && echo "OK"
```

### Step 4 — Test

Open Claude Code in any project. Type `/security-scan .`

---

## What the skill does

| Step | What Claude does |
|------|-----------------|
| Detect tools | Checks `which` for semgrep, gitleaks, npm, osv-scanner and trivy |
| Run scanners | Runs only tools that exist, captures JSON output |
| Verify findings | Reads flagged files to confirm vs false-positive |
| Score | CRITICAL=10pts, HIGH=6pts, MEDIUM=3pts, LOW=1pt |
| Report | Structured output with findings, locations, fix steps |
| Exit | PASS (no CRITICAL/HIGH) or FAIL |

---

## Prerequisites (optional — skill degrades gracefully)

| Tool | Install |
|------|---------|
| semgrep | `brew install semgrep` or `pip install semgrep` |
| gitleaks | `brew install gitleaks` |
| npm | bundled with Node.js |
| osv-scanner | `brew install osv-scanner` |
| trivy | `brew install trivy` |

Skill runs without any of these — missing tools are skipped and listed in output.

---

## Acceptance Criteria

- `.claude/commands/security-scan.md` exists (project) OR `~/.claude/commands/security-scan.md` exists (global)
- `/security-scan .` runs in Claude Code without error
- Output includes STATUS, RISK SCORE, and FINDINGS sections
- Missing tools listed if not installed

## Scope

Copy one file. No npm install. No code changes. No config beyond the file copy.
