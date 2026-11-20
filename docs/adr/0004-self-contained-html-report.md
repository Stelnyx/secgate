# ADR-0004: Self-Contained HTML Report

- **Status:** Accepted
- **Date:** 2026-04-23
- **Deciders:** Stelnyx

## Context

SecGate's premium HTML report (`<repo>.html`) is a visible differentiator. It needs to be:

- **Shareable** — someone drags the file into Slack or email; it must render.
- **Auditable offline** — compliance reviewers read it on a disconnected laptop.
- **CI-artifact friendly** — a single file in `actions/upload-artifact` is trivial; a directory with CSS/JS requires tarballing.
- **Zero supply-chain surface** — no CDN fetch at render time (that's a tracking pixel surface and an availability risk).

Options considered included per-file HTML with external CSS/JS, multi-file SPA, and a self-contained file with inline styles and scripts.

## Decision

**We will produce a single self-contained HTML file per run with inline CSS, inline JS, and no external assets.**

- All styles → inline `<style>` block.
- All JavaScript (tab switching, filtering) → inline `<script>` block.
- No CDN links, no `<img src=http...>`, no fonts from remote.
- Per-scanner tabs as a UX pattern — tabs are cheap in vanilla JS, no framework needed.
- Dark-mode default; no user preference persistence (ephemeral artifact).

## Consequences

### Positive

- File works offline, across email, on air-gapped networks, in compliance audits.
- Zero external-dependency surface — no CDN outage or tracking pixel can affect the report.
- Single file → one-line CI artifact upload.
- Future-proof: even if external services vanish, a 2026 report opens identically in 2036.
- Privacy — reports do not phone home by loading external resources.

### Negative

- Larger file size (inline everything). Typical report is 50–500 KB; acceptable for an artifact.
- No code reuse of styles across reports. Acceptable — styles are small and change rarely.
- No framework → tab/filter logic is hand-rolled vanilla JS. Trade-off we accept; no React/Vue dependency to maintain.

### Neutral

- Rendering logic lives in `secgate.js` alongside report generation. If the renderer grows, we can extract to a `lib/report/` module — not needed at current size.

### Implementation status (v0.3.3)

The renderer now lives in `lib/report.mjs` (`renderHtml`) and builds on the shared `@stelnyx/report-theme` shell. It still writes one HTML file with inline CSS and inline images, but it differs from the decision above in three ways: there is no JavaScript and no per-scanner tabs (sections are plain anchors in a sidebar), and the theme shell adds `<link>` tags to Google Fonts (`fonts.googleapis.com`, `fonts.gstatic.com`), so the file is not free of external requests. The theme supports `skipInterFont: true`, which SecGate does not pass today.

## Alternatives Considered

### External CSS/JS (minimal inline)
Rejected. Requires either CDN (supply-chain risk) or multi-file distribution (breaks single-artifact UX). Saves maybe 20 KB per file; not worth it.

### Markdown report instead of HTML
Considered. Great for git diffs but weak for compliance reviewers expecting a branded artifact. We generate JSON for machine use; HTML is the human artifact.

### PDF output
Rejected. PDF requires a rendering engine (headless Chrome / wkhtmltopdf). Adds ~100 MB of deps for marginal gain. Users can print the HTML to PDF themselves.

### SPA with React / Svelte
Rejected. Framework overhead for a static report is absurd. Ship JSON; render client-side tooling later if someone wants a live dashboard.

## References

- `lib/report.mjs` — `renderHtml()`; shell and CSS from `@stelnyx/report-theme`
- [`docs/comparison.md`](../comparison.md) — report quality as a differentiator
- [ADR-0005 — no external API v1](0005-no-external-api-v1.md) — aligned on "artifacts are the product"
