# Design parity

SecGate shares its visual identity with the other Stelnyx products. **Any change to the shared shell, theme, brand block, or theme toggle must keep the report consistent with the shared theme package.** Drift makes the product family feel inconsistent.

The shared tokens ship in the public npm package [`@stelnyx/report-theme`](https://www.npmjs.com/package/@stelnyx/report-theme). That package is the reference for tokens, sidebar nav, brand block, theme button, export row, and score band thresholds. This file documents only SecGate-specific deviations and where to look.

## Shared design tokens (summary)

| Token | Dark (Midnight Blossom) | Light (Dawn Blossom) |
|-------|-------------------------|----------------------|
| `--color-pink` | `#ff2d78` | `#e8155f` |
| `--color-green` | `#00d68f` | `#00976a` |
| `--color-amber` | `#ffaa00` | `#b45309` |
| `--color-red` | `#ff4d6a` | `#c5173a` |
| `--color-muted` | `#8b7aa8` | `#7c5e9e` |
| `--color-bg` | `#0a0a0f` | `#fef8ff` |
| `--color-surface` | `#13131f` | `#f4ecff` |
| `--color-border` | `#2a1f3d` | `#e2cefd` |
| `--color-text` | `#f0e6ff` | `#1a0a2e` |

Score bands: `STRONG ≥85`, `GOOD ≥70`, `MIXED ≥50`, `WEAK <50`.

## SecGate-specific facts

| What | Value |
|------|-------|
| Shell builder | `lib/report.mjs` → `renderHtml(rep, repoName)` |
| Shell CSS | inline in `renderHtml` (single `<style>` block) |
| Class prefix | `sg-` (avoids collision with other products' prefixes) |
| Theme toggle | `#sg-theme-toggle` (script inline at bottom of body) |
| Theme storage key | `sg-theme` |
| Favicon | 🛡 inline SVG |
| Branding type | none — derived from `rep.securityScore`, `rep.target`, `rep.timestamp`, `rep.mode` |
| Brand block extras | extra `PASS`/`FAIL` chip next to band pill (SecGate is a CI gate; the other products don't have a binary pass concept) |

## Sections

1. Summary — lede + 8-cell KPI row (Score, Risk, Confidence, Critical, High, Medium, Low, Unknown)
2. Attack surface — chip list
3. Baseline diff (only if `rep.baselineDiff` present)
4. Findings — CSS-only tabs per tool (Semgrep, Gitleaks, npm, osv, Trivy)
5. Reasoning — card grid
6. Recommendations — list
7. Remediation — list
8. Tools — status table

## Rules

Touching shell, theme button, brand block, score pill, or tokens means **keeping SecGate aligned with the shared theme in the same change**. SecGate is a single `.mjs` file with no build step, so the cost of mirroring is one Edit; no excuse to defer.

If you're tempted to ship one without the others "and circle back", don't. The drift compounds.
