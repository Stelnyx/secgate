# Design parity

SecGate gets its report look from the public npm package
[`@stelnyx/report-theme`](https://www.npmjs.com/package/@stelnyx/report-theme)
(`^0.1.4` in `package.json`). The theme package owns the CSS, the sidebar
shell, the score hero, the KPI grid, the scanner list, the findings table and
the favicons. SecGate does not keep its own copy of the shell or the CSS, so
there is nothing to mirror by hand: change the theme package, then bump the
dependency.

This file documents how SecGate uses the theme and where it deviates.

## Theme tokens (from `@stelnyx/report-theme` 0.1.4)

The theme ships one dark palette. There is no light theme and no theme toggle.

| Token | Value |
|-------|-------|
| `--bg` | `#0a0a0a` |
| `--surface` | `#141414` |
| `--border` | `#1f1f1f` |
| `--text` | `#e5e5e7` |
| `--muted` | `#a3a3a8` |
| `--success` | `#34c759` |
| `--warn` | `#ff9500` |
| `--error` | `#ff3b30` |
| `--pink` | `#ff2d78` |

Fonts: system fonts only. The theme shell loads Inter from Google Fonts unless
it is called with `skipInterFont: true`; SecGate passes it, so the report makes
no external requests (see ADR-0004).

## SecGate-specific facts

| What | Value |
|------|-------|
| Renderer | `lib/report.mjs` → `renderHtml(rep, repoName, profile)` |
| Shell | `shell()` from `@stelnyx/report-theme`, called with `brand: "SECGATE"`, `product: "SecGate Report"` |
| CSS | the theme's `css`, inlined in one `<style>` block; SecGate passes no `extraCss` |
| JavaScript | none (SecGate passes no `bodyJs`) |
| Favicon | `FAVICON_WHITE` (inline PNG data URI from the theme) |
| Sidebar score | risk score (`intelligence.riskScore`) with a PASS / FAIL / INCOMPLETE badge |
| Band | `Security · STRONG/GOOD/MIXED/WEAK` from `securityScore`: STRONG `>= 85`, GOOD `>= 70`, MIXED `>= 50`, WEAK below; `NO COVERAGE` when no scanner ran |
| SecGate-only markup | `sg-` classes for the Informational and Suppressed `<details>` blocks; the theme has no CSS for them, so they render with browser defaults |

## Sections

Sections appear in this order; the ones marked "if any" are omitted when empty.

1. Overview: coverage warning, status hero, KPI grid (Critical, High, Medium,
   Low, Unknown, Risk Score)
2. Attack surface (if any)
3. Baseline diff (with `--baseline`)
4. Findings by tool: one row per scanner (Semgrep, Gitleaks, npm audit,
   osv-scanner, Trivy) with count and status
5. Top findings: the 10 most severe actionable findings, then the collapsed
   Informational and Suppressed blocks
6. Reasoning (if any)
7. Recommendations (if any)
8. Remediation plan (if any)

## Rules

- Change shared look (tokens, shell, brand block, score pill) in
  `@stelnyx/report-theme`, not in `lib/report.mjs`.
- Keep SecGate-only markup in `renderHtml` and prefix new classes with `sg-`.
