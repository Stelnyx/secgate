import { execFileSync } from "child_process";
import path from "path";
import { bucketByConfidence, informationalReason } from "./confidence.mjs";
import {
  shell as themeShell,
  scoreHero as themeScoreHero,
  kpiGrid as themeKpiGrid,
  scannerList as themeScannerList,
  findingsTable as themeFindingsTable,
  bars as themeBars,
  FAVICON_WHITE,
} from "@stelnyx/report-theme";

export const TOOLS = ["semgrep", "gitleaks", "npm", "osv", "trivy", "trivyImage"];

/**
 * The five scanners that count toward coverage. Trivy image scanning is part
 * of the Trivy scanner (its findings carry tool "trivy"), so it is not counted
 * separately.
 */
export const SCANNERS = ["semgrep", "gitleaks", "npm", "osv", "trivy"];

export const SCANNER_LABEL = {
  semgrep:  "Semgrep",
  gitleaks: "Gitleaks",
  npm:      "npm audit",
  osv:      "osv-scanner",
  trivy:    "Trivy"
};

/** One-line install hint per scanner, printed when it is not on PATH. */
export const INSTALL_HINTS = {
  semgrep:  "pipx install semgrep (or: brew install semgrep)",
  gitleaks: "brew install gitleaks (or a release binary from github.com/gitleaks/gitleaks)",
  npm:      "install Node.js (npm ships with it)",
  osv:      "brew install osv-scanner (or: go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest)",
  trivy:    "brew install trivy (other platforms: trivy.dev)"
};

const SCANNER_ALIASES = { "osv-scanner": "osv", "npm-audit": "npm" };

/**
 * Map user-supplied scanner names (CLI --require, config requireScanners) to
 * scanner keys. Returns { valid, unknown }.
 */
export function normalizeScannerNames(names) {
  const valid = [];
  const unknown = [];
  for (const raw of names) {
    const name = String(raw).trim().toLowerCase();
    if (!name) continue;
    const key = SCANNER_ALIASES[name] || name;
    if (SCANNERS.includes(key)) {
      if (!valid.includes(key)) valid.push(key);
    } else {
      unknown.push(String(raw).trim());
    }
  }
  return { valid, unknown };
}

const RAN_STATUSES = new Set(["ran", "clean"]);

/**
 * Which scanners actually produced a result. "skipped" lists every scanner
 * that did not (not installed, disabled, not applicable, or errored); the
 * reason is in report.toolSkipReason.
 */
//
// Trivy runs two sub-scans and each must succeed on its own: Trivy counts as
// ran only when the fs scan ran AND the image scan did not fail. An image scan
// that is "skipped" (no Dockerfile, no FROM image, Trivy disabled or not
// installed) is not applicable and is not a gap; an image scan with status
// "error" (pull failure, timeout, unparsable output) is a gap.
export function computeCoverage(toolStatus) {
  const ran = [];
  const skipped = [];
  for (const key of SCANNERS) {
    let didRun = RAN_STATUSES.has(toolStatus[key]);
    if (key === "trivy" && toolStatus.trivyImage === "error") didRun = false;
    (didRun ? ran : skipped).push(key);
  }
  return { ran, skipped, total: SCANNERS.length };
}

/**
 * Scanners the scanned repo's own config turned off, in SCANNERS order.
 * Only the CLI --require flag is out of the scanned repo's reach.
 */
export function disabledByConfig(toolSkipReason = {}) {
  return SCANNERS.filter(key => toolSkipReason[key] === "disabled in config");
}

/**
 * Why a scanner counts as not run, for warnings and reports. For Trivy whose
 * fs scan ran but whose image scan failed, the reason comes from the image scan.
 */
export function coverageSkipReason(key, toolStatus, toolSkipReason = {}) {
  if (key === "trivy" && RAN_STATUSES.has(toolStatus.trivy) && toolStatus.trivyImage === "error") {
    return `image scan error: ${toolSkipReason.trivyImage || "no usable output"}`;
  }
  return toolSkipReason[key] || toolStatus[key] || "not run";
}

/**
 * Compute severity counts for a findings array.
 */
export function summarize(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const f of findings) {
    const key = String(f.severity || "UNKNOWN").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(summary, key)) {
      summary[key]++;
    } else {
      summary.unknown++;
    }
  }
  return summary;
}

/**
 * Determine PASS/FAIL status from findings and config.failOn set.
 */
export function resolveStatus(findings, failOn, baselineMode) {
  const failOnSet = new Set(failOn.map(s => s.toUpperCase()));
  const failFindings = baselineMode
    ? findings.filter(f => !f.baseline && failOnSet.has(f.severity))
    : findings.filter(f => failOnSet.has(f.severity));
  return failFindings.length > 0 ? "FAIL" : "PASS";
}

/**
 * Strip absolute paths from a string value, replacing with repoName.
 */
export function stripAbsolutePaths(s, target, repoName) {
  if (typeof s !== "string") return s;
  let out = s.split(target).join(repoName);
  const parent = path.dirname(target);
  if (parent && parent !== "/" && parent !== ".") {
    out = out.split(parent + path.sep).join("");
  }
  return out;
}

/**
 * Walk report fields and relativize all embedded absolute target paths.
 */
export function applyPathStripping(report, target, repoName) {
  const strip = s => stripAbsolutePaths(s, target, repoName);

  for (const f of report.findings) {
    if (f.signature) f.signature = strip(f.signature);
    if (f.message)   f.message   = strip(f.message);
    if (f.file)      f.file      = strip(f.file);
  }
  for (const r of report.intelligence.reasoning || []) {
    if (r.issue) r.issue = strip(r.issue);
    if (r.why)   r.why   = strip(r.why);
  }
  for (const p of report.remediation.plan || []) {
    if (p.issue) p.issue = strip(p.issue);
    if (p.patch) {
      if (p.patch.cmd) p.patch.cmd = strip(p.patch.cmd);
      if (p.patch.exec && p.patch.exec.cwd) p.patch.exec.cwd = strip(p.patch.exec.cwd);
    }
  }
  for (const p of report.remediation.stagedChanges || []) {
    if (p.cmd) p.cmd = strip(p.cmd);
    if (p.exec && p.exec.cwd) p.exec.cwd = strip(p.exec.cwd);
  }
  for (const p of report.remediation.blocked || []) {
    if (p.cmd) p.cmd = strip(p.cmd);
    if (p.exec && p.exec.cwd) p.exec.cwd = strip(p.exec.cwd);
  }
  for (const a of report.auditLog || []) {
    if (a.cwd) a.cwd = strip(a.cwd);
  }
}

/* ────────────────────────────────────────────────────────────────────────────
   HTML renderer
   ──────────────────────────────────────────────────────────────────────────── */

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[c]));
}

function formatLocation(f) {
  if (!f.file) return "";
  const rel = f.file;
  const lineFrag = f.line != null ? `:${f.line}` : "";
  const colFrag  = f.col  != null ? `:${f.col}`  : "";
  const label    = `${rel}${lineFrag}${colFrag}`;
  const isAbs = rel.startsWith("/") || /^[a-zA-Z]:[\\/]/.test(rel);
  if (isAbs) {
    const href = `file://${rel}${f.line != null ? `#L${f.line}` : ""}`;
    return `<a href="${escapeHtml(href)}" class="loc">${escapeHtml(label)}</a>`;
  }
  return `<span class="loc">${escapeHtml(label)}</span>`;
}

function bandFromScore(score) {
  if (score >= 85) return "strong";
  if (score >= 70) return "good";
  if (score >= 50) return "mixed";
  return "weak";
}

export function renderHtml(rep, repoName, profile = "curated") {
  const e = escapeHtml;
  const surfaces = rep.intelligence.attackSurface || [];
  const sum      = rep.summary;
  const tools    = rep.tools || {};

  const TOOL_ORDER = ["semgrep", "gitleaks", "npm", "osv", "trivy"];
  const TOOL_LABEL = {
    semgrep:  "Semgrep",
    gitleaks: "Gitleaks",
    npm:      "npm audit",
    osv:      "osv-scanner",
    trivy:    "Trivy"
  };

  // Split all findings by confidence under the active profile.
  // Suppressed findings never reach `rep.findings` — they're counted
  // in rep.suppressions only — so we only split actionable vs informational here.
  const { actionable: actionableAll, informational: informationalAll } =
    bucketByConfidence(rep.findings, profile);

  const byToolActionable = Object.fromEntries(TOOL_ORDER.map(t => [t, []]));
  for (const f of actionableAll) if (byToolActionable[f.tool]) byToolActionable[f.tool].push(f);

  const byToolInformational = Object.fromEntries(TOOL_ORDER.map(t => [t, []]));
  for (const f of informationalAll) if (byToolInformational[f.tool]) byToolInformational[f.tool].push(f);

  const sevPill = sev => {
    const cls = { CRITICAL: "risk", HIGH: "risk", MEDIUM: "warn", LOW: "ok", UNKNOWN: "" }[sev] || "";
    return `<span class="sg-pill${cls ? ` sg-pill-${cls}` : ""}">${e(sev)}</span>`;
  };

  // ── Informational findings block (collapsed by default) ──────────────
  const infoRowsFor = list =>
    list
      .map(f => `
        <tr class="sg-info-row">
          <td>${sevPill(f.severity)}</td>
          <td><span class="sg-mono">${e(f.tool)}</span></td>
          <td class="sg-mono">${e(f.signature)}</td>
          <td class="sg-mono">${formatLocation(f) || '<span class="sg-empty">—</span>'}</td>
          <td>${e(f.message)}</td>
          <td><span class="sg-info-reason">${e(informationalReason(f))}</span></td>
        </tr>`)
      .join("");

  const informationalBlock = informationalAll.length
    ? `
      <details class="sg-details">
        <summary>
          <span class="sg-details-label">Informational</span>
          <span class="sg-details-count">${informationalAll.length}</span>
          <span class="sg-details-hint">demoted by ${e(profile)} profile — click to expand</span>
        </summary>
        <div class="sg-details-body">
          <p class="sg-lede-sub" style="margin-bottom:.75rem">These findings matched scanner rules but were demoted because they are commonly false-positive (noisy SAST rules, base-image OS packages, stale CVEs, unknown severity). Run with <code>profile: "strict"</code> to see them inline above.</p>
          <table class="sg-table">
            <thead><tr><th>Severity</th><th>Tool</th><th>Signature</th><th>Location</th><th>Message</th><th>Reason</th></tr></thead>
            <tbody>${infoRowsFor(informationalAll)}</tbody>
          </table>
        </div>
      </details>`
    : "";

  // ── Suppressed findings summary (counts only — items are dropped at scan time)
  const suppressionsCount = rep.suppressions?.count ?? 0;
  const suppressionsByRule = rep.suppressions?.byRule || {};
  const suppressedRows = Object.entries(suppressionsByRule)
    .sort((a, b) => b[1] - a[1])
    .map(([rule, n]) => `<tr><td class="sg-mono">${e(rule)}</td><td class="sg-num">${e(n)}</td></tr>`)
    .join("");
  const suppressedBlock = suppressionsCount > 0
    ? `
      <details class="sg-details">
        <summary>
          <span class="sg-details-label">Suppressed</span>
          <span class="sg-details-count">${suppressionsCount}</span>
          <span class="sg-details-hint">via inline <code># secgate:ignore</code> comments — click to expand</span>
        </summary>
        <div class="sg-details-body">
          <p class="sg-lede-sub" style="margin-bottom:.75rem">Findings explicitly suppressed in source. Counted for audit, not surfaced inline.</p>
          <table class="sg-table">
            <thead><tr><th>Rule</th><th class="sg-num">Count</th></tr></thead>
            <tbody>${suppressedRows}</tbody>
          </table>
        </div>
      </details>`
    : "";

  // Filter reasoning + remediation to only items whose signature appears in
  // actionable findings under the active profile. Reasoning/plan are built
  // 1-per-finding upstream — without filtering, sidebar nav would show
  // "Findings 46 · Reasoning 1858 · Remediation 1858" which is confusing.
  const actionableSignatures = new Set(actionableAll.map(f => f.signature));
  const filteredReasoning = (rep.intelligence.reasoning || [])
    .filter(r => actionableSignatures.has(r.issue));
  const filteredPlan = (rep.remediation.plan || [])
    .filter(p => actionableSignatures.has(p.issue));

  const reasoningCards = filteredReasoning
    .map(r => `
      <div class="sg-card">
        <h3 class="sg-card-title sg-mono">${e(r.issue)}</h3>
        <p class="sg-card-body">${e(r.why)}</p>
      </div>`)
    .join("");

  const remedItems = filteredPlan
    .map(p => `
      <li>
        <span class="sg-mono">${e(p.issue)}</span> — ${e(p.patch?.action || "manual")}
        ${p.patch?.cmd ? `<code class="sg-cmd">${e(p.patch.cmd)}</code>` : ""}
      </li>`)
    .join("");

  const score    = rep.securityScore;
  const band     = score == null ? "no coverage" : bandFromScore(score);
  const bandLbl  = band.toUpperCase();
  const passText = rep.status === "PASS" ? "PASS" : rep.status === "INCOMPLETE" ? "INCOMPLETE" : "FAIL";

  const coverage   = rep.coverage || computeCoverage(tools);
  const notRun     = new Set(coverage.skipped);
  const coverageTxt = `${coverage.ran.length} of ${coverage.total} scanners ran`;
  const coverageWarning = coverage.skipped.length
    ? `<p class="sg-coverage-warning" style="color:var(--warn, #f59e0b);font-size:13px;margin:0 0 12px">WARNING: ${e(coverageTxt)}. Not run: ${coverage.skipped
        .map(t => `${e(TOOL_LABEL[t] || t)} (${e(coverageSkipReason(t, tools, rep.toolSkipReason || {}))})`)
        .join(", ")}. Results below cover only the scanners that ran.</p>`
    : "";

  // ── Themed report shell ────────────────────────────────────────────
  const TOOL_TONE = (st, count) => {
    if (st === "skipped" || st === "pending") return { label: "skipped", tone: "found" };
    if (st === "error") return { label: "error", tone: "found" };
    if (count === 0) return { label: "clean", tone: "clean" };
    return { label: "found issues", tone: "found" };
  };

  const SEV_TONE = sev => ({
    CRITICAL: "high",
    HIGH: "high",
    MEDIUM: "med",
    LOW: "low",
    UNKNOWN: "low",
  }[sev] || "low");

  const scannerListItems = TOOL_ORDER.map(t => {
    const st = tools[t] || "pending";
    const total = byToolActionable[t].length + byToolInformational[t].length;
    const ran = !notRun.has(t);
    return {
      name: TOOL_LABEL[t],
      count: !ran ? "n/a" : total === 1 ? "1 finding" : `${total} findings`,
      badge: TOOL_TONE(ran ? st : (st === "error" ? "error" : "skipped"), total),
    };
  });

  const TOP_N = 10;
  const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
  const topFindings = [...actionableAll]
    .sort((a, b) => (sevRank[a.severity] ?? 5) - (sevRank[b.severity] ?? 5))
    .slice(0, TOP_N)
    .map(f => ({
      severity: { label: f.severity, tone: SEV_TONE(f.severity) },
      cells: [
        e(f.type),
        `<code>${e(f.signature)}</code>`,
        f.file ? `<code>${e(f.file)}${f.line != null ? `:${f.line}` : ""}</code>` : '<span style="color:var(--faint)">—</span>',
        e(f.message),
        f.fixableBy === "auto" ? "auto" : f.fixableBy === "manual" ? "manual" : "no",
      ],
    }));

  const surfaceBars = surfaces.length
    ? themeBars(surfaces.map(s => ({ name: s, score: "·", pct: 50, weight: "" })))
    : `<p style="color:var(--muted);font-size:13px">Nothing detected.</p>`;

  const recBlock = (rep.intelligence.recommendations || []).length
    ? `<ul style="color:var(--muted);font-size:13px;line-height:1.7;padding-left:20px">${(rep.intelligence.recommendations || []).map(r => `<li>${e(r)}</li>`).join("")}</ul>`
    : `<p style="color:var(--faint);font-size:13px">No recommendations.</p>`;

  const remedBlock = filteredPlan.length
    ? `<ul style="color:var(--muted);font-size:13px;line-height:1.7;padding-left:20px">${remedItems}</ul>`
    : `<p style="color:var(--faint);font-size:13px">No plan items.</p>`;

  const reasoningBlock = filteredReasoning.length
    ? `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px">${reasoningCards}</div>`
    : `<p style="color:var(--faint);font-size:13px">No reasoning produced.</p>`;

  const baselineBlock = rep.baselineDiff
    ? `${themeKpiGrid([
        { label: "Net-new", value: rep.baselineDiff.netNew },
        { label: "Baseline matched", value: rep.baselineDiff.baselineMatchedCount },
        { label: "Suppressed", value: rep.suppressions?.count ?? 0 },
      ])}`
    : "";

  const bodyHtml = `
    <section id="overview">
      <h1>Overview <span class="lead">${e(coverageTxt)} · ${e(actionableAll.length)} actionable findings</span></h1>
      ${coverageWarning}
      ${themeScoreHero({
        label: "Status",
        num: passText,
        denom: `Risk ${rep.intelligence.riskScore ?? 0}`,
        sub: `${sum.critical} CRITICAL · ${sum.high} HIGH · ${sum.medium} MED · ${sum.low} LOW · confidence ${rep.remediation.confidence}%`,
        fillPct: passText === "PASS" ? 100 : passText === "INCOMPLETE" ? 0 : Math.max(0, 100 - (rep.intelligence.riskScore ?? 0)),
        fillColor: passText === "PASS" ? "success" : "warn",
        desc: "SecGate runs Semgrep, Gitleaks, npm audit, osv-scanner, and Trivy in one command. Normalizes findings and fails the pipeline on CRITICAL or HIGH.",
      })}
      ${themeKpiGrid([
        { label: "Critical", value: sum.critical, tone: "crit" },
        { label: "High", value: sum.high, tone: "high" },
        { label: "Medium", value: sum.medium, tone: "med" },
        { label: "Low", value: sum.low, tone: "low" },
        { label: "Unknown", value: sum.unknown ?? 0 },
        { label: "Risk Score", value: rep.intelligence.riskScore ?? 0 },
      ])}
    </section>

    ${surfaces.length ? `<section id="surface">
      <h2>Attack surface <span class="lead">categories detected</span></h2>
      ${surfaceBars}
    </section>` : ""}

    ${baselineBlock ? `<section id="baseline">
      <h2>Baseline diff</h2>
      ${baselineBlock}
    </section>` : ""}

    <section id="tools">
      <h2>Findings by tool <span class="lead">${e(actionableAll.length)} total · ${e(coverageTxt)}</span></h2>
      ${themeScannerList(scannerListItems)}
    </section>

    <section id="findings">
      <h2>Top findings <span class="lead">ranked by severity · top ${e(Math.min(TOP_N, actionableAll.length))} of ${e(actionableAll.length)}</span></h2>
      ${topFindings.length ? themeFindingsTable({
        columns: ["Severity", "Type", "Signature", "Location", "Message", "Fixable"],
        rows: topFindings,
      }) : `<p style="color:var(--faint);font-size:13px">No actionable findings.</p>`}
      ${informationalBlock}
      ${suppressedBlock}
    </section>

    ${filteredReasoning.length ? `<section id="reasoning">
      <h2>Reasoning</h2>
      ${reasoningBlock}
    </section>` : ""}

    ${(rep.intelligence.recommendations || []).length ? `<section id="recommendations">
      <h2>Recommendations</h2>
      ${recBlock}
    </section>` : ""}

    ${filteredPlan.length ? `<section id="remediation">
      <h2>Remediation plan</h2>
      ${remedBlock}
    </section>` : ""}
  `;

  const navItems = [
    { id: "overview", label: "Overview", active: true },
    ...(surfaces.length ? [{ id: "surface", label: "Attack Surface", count: surfaces.length }] : []),
    ...(rep.baselineDiff ? [{ id: "baseline", label: "Baseline Diff" }] : []),
    { id: "tools", label: "Tools", count: TOOL_ORDER.length },
    { id: "findings", label: "Findings", count: actionableAll.length },
    ...(filteredReasoning.length ? [{ id: "reasoning", label: "Reasoning", count: filteredReasoning.length }] : []),
    ...((rep.intelligence.recommendations || []).length ? [{ id: "recommendations", label: "Recommendations", count: (rep.intelligence.recommendations || []).length }] : []),
    ...(filteredPlan.length ? [{ id: "remediation", label: "Remediation", count: filteredPlan.length }] : []),
  ];

  return themeShell({
    brand: "SECGATE",
    target: repoName || rep.target || "",
    meta: `v${rep.version} · rule v7`,
    favicon: FAVICON_WHITE,
    product: "SecGate Report",
    score: {
      num: rep.intelligence.riskScore ?? 0,
      denom: "risk",
      badge: { label: passText, tone: passText === "PASS" ? "pass" : "warn" },
    },
    reportType: `Security · ${bandLbl}`,
    reportTypeFooter: "Security Report",
    reportPill: "SECURITY REPORT",
    navLabel: "Report",
    nav: navItems,
    bodyHtml,
    title: `SecGate Report — ${repoName || rep.target || "scan"}`,
    reportVersion: `v${rep.version}`,
    generatedAt: rep.timestamp,
  });
}

/* ────────────────────────────────────────────────────────────────────────────
   SARIF 2.1.0 serializer
   ──────────────────────────────────────────────────────────────────────────── */

const SARIF_LEVEL = {
  CRITICAL: "error",
  HIGH:     "error",
  MEDIUM:   "warning",
  LOW:      "note",
  UNKNOWN:  "none"
};

const SARIF_SCORE = {
  CRITICAL: 9.5,
  HIGH:     7.5,
  MEDIUM:   5.0,
  LOW:      2.0,
  UNKNOWN:  0.0
};

const TOOL_INFO = {
  semgrep:    { name: "Semgrep",     uri: "https://semgrep.dev" },
  gitleaks:   { name: "Gitleaks",    uri: "https://github.com/gitleaks/gitleaks" },
  npm:        { name: "npm audit",   uri: "https://docs.npmjs.com/cli/commands/npm-audit" },
  osv:        { name: "osv-scanner", uri: "https://github.com/google/osv-scanner" },
  trivy:      { name: "Trivy",       uri: "https://github.com/aquasecurity/trivy" },
  trivyImage: { name: "Trivy Image", uri: "https://github.com/aquasecurity/trivy" }
};

function toolVersion(binary) {
  try {
    const out = execFileSync(binary, ["--version"], {
      encoding: "utf-8",
      stdio: "pipe",
      timeout: 5000
    });
    const m = out.match(/(\d+\.\d+\.\d+[\w.-]*)/);
    return m ? m[1] : "unknown";
  } catch {
    return "unknown";
  }
}

function relativizeUri(filePath, baseDir) {
  if (!filePath) return null;
  if (path.isAbsolute(filePath)) {
    const rel = path.relative(baseDir, filePath);
    return rel.startsWith("..") ? filePath : rel;
  }
  return filePath;
}

export function buildSarif(rep, repoName, baseDir) {
  const toolGroups = {};
  for (const f of rep.findings) {
    if (!toolGroups[f.tool]) toolGroups[f.tool] = [];
    toolGroups[f.tool].push(f);
  }

  const disabled = rep.disabledByConfig || [];
  const runs = TOOLS.map(toolKey => {
    const info        = TOOL_INFO[toolKey] || { name: toolKey, uri: "" };
    const toolFindings = toolGroups[toolKey] || [];

    const rules   = [];
    const ruleIds = new Set();
    for (const f of toolFindings) {
      if (!ruleIds.has(f.signature)) {
        ruleIds.add(f.signature);
        rules.push({
          id:               f.signature,
          name:             f.signature,
          shortDescription: { text: f.message || f.signature },
          properties:       { "security-severity": String(SARIF_SCORE[f.severity] ?? 0) }
        });
      }
    }

    const results = toolFindings.map(f => {
      const uri    = relativizeUri(f.file, baseDir);
      const region = {};
      if (f.line    != null) region.startLine   = f.line;
      if (f.col     != null) region.startColumn = f.col;
      if (f.endLine != null) region.endLine     = f.endLine;

      const location = uri
        ? {
            physicalLocation: {
              artifactLocation: { uri, uriBaseId: "%SRCROOT%" },
              ...(Object.keys(region).length ? { region } : {})
            }
          }
        : null;

      return {
        ruleId:  f.signature,
        level:   SARIF_LEVEL[f.severity] || "none",
        message: { text: f.message || f.signature },
        ...(location ? { locations: [location] } : {}),
        properties: {
          "security-severity": String(SARIF_SCORE[f.severity] ?? 0),
          tool:       f.tool,
          type:       f.type,
          fixableBy:  f.fixableBy || null
        }
      };
    });

    const binary  = toolKey === "osv" ? "osv-scanner" : toolKey === "npm" ? null : toolKey === "trivyImage" ? "trivy" : toolKey;
    const status  = rep.tools[toolKey] || "pending";
    const version = (binary && status !== "skipped" && status !== "pending")
      ? toolVersion(binary)
      : "unknown";

    return {
      tool: {
        driver: {
          name:           info.name,
          version,
          informationUri: info.uri,
          rules
        }
      },
      results,
      artifacts:  [],
      properties: {
        toolStatus: rep.tools[toolKey] || "pending",
        ...(disabled.includes(toolKey === "trivyImage" ? "trivy" : toolKey) ? { disabledByConfig: true } : {})
      }
    };
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
    version: "2.1.0",
    runs
  };
}
