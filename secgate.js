#!/usr/bin/env node

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import { loadConfig } from "./lib/config.mjs";
import { makeFindingProcessor } from "./lib/scanners.mjs";
import {
  runGitleaks,
  runSemgrep,
  runOsvScanner,
  runTrivy,
  runTrivyImage,
  runNpmAudit
} from "./lib/scanners.mjs";
import { loadBaseline, writeBaseline, applyBaseline } from "./lib/baseline.mjs";
import { analyze, remediate } from "./lib/intelligence.mjs";
import {
  TOOLS,
  SCANNERS,
  SCANNER_LABEL,
  INSTALL_HINTS,
  summarize,
  resolveStatus,
  computeCoverage,
  coverageSkipReason,
  normalizeScannerNames,
  applyPathStripping,
  renderHtml,
  buildSarif
} from "./lib/report.mjs";
import {
  SCORE_VERSION,
  computeScore,
  computeToolScores
} from "./lib/score.mjs";
import {
  DEFAULT_WALK_LIMITS,
  WalkLimitError,
  parsePositiveInt,
  scanTargetTree
} from "./lib/walk.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  fs.readFileSync(path.join(__dirname, "package.json"), "utf-8")
);

/* ────────────────────────────────────────────────────────────────────────────
   CLI FLAGS
   ──────────────────────────────────────────────────────────────────────────── */

const argv = process.argv.slice(2);

if (argv.includes("--version") || argv.includes("-v")) {
  console.log(pkg.version);
  process.exit(0);
}

if (argv.includes("--help") || argv.includes("-h")) {
  console.log(`
    ╔═══════╗   █████ █████ █████ █████ █████ █████ █████
    ║ ╔═══╗ ║   █     █     █     █     █   █   █   █
    ║ ║ ⊙ ║ ║   █████ ████  █     █ ███ █████   █   ████
    ║ ╚═══╝ ║       █ █     █     █   █ █   █   █   █
    ╠═══════╣   █████ █████ █████ █████ █   █   █   █████
╔═══╬═══════╬═══╗
║   ║ [===] ║   ║  v${pkg.version} — tiny security gate for CI/CD
╚═══╬═══════╬═══╝  Semgrep · Gitleaks · osv-scanner · Trivy · npm
    ╚═╝   ╚═╝

Usage:
  secgate [target] [options]

Arguments:
  target              Directory to scan (default: current directory)

Options:
  --apply             Execute fixable remediations (default: dry-run).
                      Requires SECGATE_CONFIRM_APPLY=1 or an interactive
                      y/n confirmation. Runs npm with --ignore-scripts.
  --output-dir <dir>  Directory to write report files (default: target)
  --strip-paths       Relativize target to repo basename in the report.
                      Auto-enabled when CI=true.
  --format <fmt>      Output formats: json,html (default) or sarif
  --max-files <n>     Maximum files to walk before aborting preflight
                      (default: ${DEFAULT_WALK_LIMITS.maxFiles})
  --max-depth <n>     Maximum directory depth to walk before aborting
                      (default: ${DEFAULT_WALK_LIMITS.maxDepth})
  --max-file-size <n> Maximum file size in bytes for lightweight parsing
                      (default: ${DEFAULT_WALK_LIMITS.maxFileSizeBytes})
  --walk-timeout-ms <n>
                      Maximum preflight walk time before aborting
                      (default: ${DEFAULT_WALK_LIMITS.timeoutMs})
  --allow-workspace   Allow scanning a directory that looks like a workspace
                      containing multiple sub-projects.
  --baseline          Compare against baseline; fail only on net-new findings
  --update-baseline   Write current findings to baseline file then exit 0.
                      Exits 2 without writing if no scanner ran or a
                      required scanner did not run.
  --require <tools>   Comma-separated scanners that must run (semgrep,
                      gitleaks,npm,osv,trivy); also --require=<tools>.
                      Exit 2 if any did not run, or if the list is empty
                      or names an unknown scanner. Overrides
                      requireScanners in the config file.
  --debug             Print raw scanner output
  --profile <name>    Confidence profile: 'curated' (default; demotes
                      noisy rules + base-image OS CVEs + stale CVEs to
                      Informational) or 'strict' (no demotion). Findings
                      are never dropped — only re-classified for display.
  --version, -v       Print version and exit
  --help, -h          Show this help

Environment:
  SECGATE_CONFIRM_APPLY=1   Non-interactive confirmation for --apply
  CI=true                   Auto-enables --strip-paths

Config file (.secgate.config.json in target):
  failOn             Severities that trigger exit 1 (default: ["critical","high"])
  scanners           Map of scanner name → true/false to enable/disable
  severityOverrides  Array of {rule, severity} to override matched findings
  ignore             Array of signatures to drop entirely
  baselineFile       Path to baseline JSON (default: .secgate-baseline.json)
  customSemgrepRules Path to additional semgrep rules (passed as --config=<path>)
  requireScanners    Array of scanners that must run (exit 2 if one did not,
                     if the value is not an array, or if a name is unknown)

Precedence: CLI flag > config file > defaults

Scanners: npm audit needs only Node.js. Semgrep, Gitleaks, osv-scanner and
Trivy must be installed separately and on PATH; a scanner that is missing is
reported as "n/a", never as a clean 100 / 100.

Exit codes:
  0  PASS — no findings matching failOn severities (or all matched baseline)
  1  FAIL — net-new findings matching failOn severities
  2  Invalid target or CLI error; no scanners available (none of the five
     scanners ran); or a scanner listed in --require / requireScanners
     did not run

Output:
  secgate-v7-report.json    machine-readable report
  <repo-name>.html          premium HTML report
  <repo-name>.sarif.json    SARIF 2.1.0 report (when --format sarif)
`);
  process.exit(0);
}

function argValue(flag) {
  const i = argv.indexOf(flag);
  if (i === -1) return null;
  const v = argv[i + 1];
  if (!v || v.startsWith("--")) return null;
  return v;
}

const rawTarget    = argv[0] && !argv[0].startsWith("--") ? argv[0] : ".";
const APPLY        = argv.includes("--apply");
const DEBUG        = argv.includes("--debug");
const STRIP_PATHS  = argv.includes("--strip-paths") || process.env.CI === "true";
const OUTPUT_DIR_FLAG = argValue("--output-dir");
const FORMAT_IDX   = argv.indexOf("--format");
const FORMAT       = FORMAT_IDX >= 0 ? (argv[FORMAT_IDX + 1] || "json,html") : "json,html";
const EMIT_SARIF   = FORMAT.split(",").map(s => s.trim()).includes("sarif");
const BASELINE_MODE    = argv.includes("--baseline");
const UPDATE_BASELINE  = argv.includes("--update-baseline");
const PROFILE_FLAG     = argValue("--profile");
const ALLOW_WORKSPACE  = argv.includes("--allow-workspace");
// Accept both "--require semgrep,gitleaks" and "--require=semgrep,gitleaks".
const REQUIRE_EQ       = argv.find(a => a.startsWith("--require="));
const REQUIRE_PRESENT  = argv.includes("--require") || REQUIRE_EQ !== undefined;
const REQUIRE_FLAG     = REQUIRE_EQ !== undefined
  ? REQUIRE_EQ.slice("--require=".length)
  : argValue("--require");

let cliRequired = null;
if (REQUIRE_PRESENT) {
  const { valid, unknown } = normalizeScannerNames((REQUIRE_FLAG ?? "").split(","));
  if (unknown.length) {
    console.error(`Unknown scanner in --require: ${unknown.join(", ")}. Valid: ${SCANNERS.join(", ")}`);
    process.exit(2);
  }
  // An empty list must not silently replace requireScanners from the config.
  if (!valid.length) {
    console.error(`--require needs a comma-separated list of scanners: ${SCANNERS.join(",")}`);
    process.exit(2);
  }
  cliRequired = valid;
}

let scanLimits;
try {
  scanLimits = {
    maxFiles: parsePositiveInt(argValue("--max-files"), DEFAULT_WALK_LIMITS.maxFiles, "--max-files"),
    maxDepth: parsePositiveInt(argValue("--max-depth"), DEFAULT_WALK_LIMITS.maxDepth, "--max-depth"),
    maxFileSizeBytes: parsePositiveInt(argValue("--max-file-size"), DEFAULT_WALK_LIMITS.maxFileSizeBytes, "--max-file-size"),
    timeoutMs: parsePositiveInt(argValue("--walk-timeout-ms"), DEFAULT_WALK_LIMITS.timeoutMs, "--walk-timeout-ms")
  };
} catch (e) {
  console.error(e.message);
  process.exit(2);
}

const target = path.resolve(rawTarget);

if (!fs.existsSync(target)) {
  console.error(`Target not found: ${rawTarget}`);
  process.exit(2);
}
if (!fs.statSync(target).isDirectory()) {
  console.error(`Target is not a directory: ${rawTarget}`);
  process.exit(2);
}

const outputDir = OUTPUT_DIR_FLAG ? path.resolve(OUTPUT_DIR_FLAG) : target;

if (!OUTPUT_DIR_FLAG) {
  if (process.cwd() !== target) {
    console.error(
      `Warning: cwd (${process.cwd()}) differs from target (${target}); ` +
        `writing reports to target. Use --output-dir to override.`
    );
  }
} else {
  if (!fs.existsSync(outputDir)) {
    try {
      fs.mkdirSync(outputDir, { recursive: true });
    } catch (e) {
      console.error(`Cannot create --output-dir ${outputDir}: ${e.message}`);
      process.exit(2);
    }
  }
  if (!fs.statSync(outputDir).isDirectory()) {
    console.error(`--output-dir is not a directory: ${outputDir}`);
    process.exit(2);
  }
}

try {
  fs.accessSync(outputDir, fs.constants.W_OK);
} catch (e) {
  console.error(`Cannot write to output directory ${outputDir}: ${e.message}`);
  process.exit(2);
}

const repoName     = path.basename(path.resolve(target));
const reportTarget = STRIP_PATHS ? repoName : target;
const outputFile   = path.join(outputDir, "secgate-v7-report.json");

/* ────────────────────────────────────────────────────────────────────────────
   CONFIG + STATE
   ──────────────────────────────────────────────────────────────────────────── */

const config = loadConfig(target);
if (PROFILE_FLAG) {
  if (PROFILE_FLAG === "curated" || PROFILE_FLAG === "strict") {
    config.profile = PROFILE_FLAG;
  } else {
    console.error(`Invalid --profile '${PROFILE_FLAG}'. Use 'curated' or 'strict'.`);
    process.exit(2);
  }
}

// requireScanners is validated even when --require overrides it: a broken
// config is an error (exit 2), the same as a bad CLI value.
if (!Array.isArray(config.requireScanners)) {
  console.error(`Invalid requireScanners in .secgate.config.json: expected an array of scanner names (${SCANNERS.join(", ")}).`);
  process.exit(2);
}
const configRequired = normalizeScannerNames(config.requireScanners);
if (configRequired.unknown.length) {
  console.error(`Unknown scanner in requireScanners: ${configRequired.unknown.join(", ")}. Valid: ${SCANNERS.join(", ")}`);
  process.exit(2);
}
const requiredScanners = cliRequired ?? configRequired.valid;

const findings    = [];
const suppressions = { count: 0, byRule: {} };

const toolStatus     = Object.fromEntries(TOOLS.map(t => [t, "pending"]));
const toolSkipReason = {};

const report = {
  version:       pkg.version,
  timestamp:     new Date().toISOString(),
  target:        reportTarget,
  mode:          APPLY ? "apply" : "dry-run",
  status:        "PASS",
  securityScore: 100,
  summary:       { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
  findings:      [],
  tools:         toolStatus,
  toolSkipReason,
  suppressions,
  intelligence:  { riskScore: 0, attackSurface: [], reasoning: [], recommendations: [] },
  remediation:   { plan: [], stagedChanges: [], executed: [], blocked: [], confidence: 100 },
  auditLog:      []
};

function auditLog(event, detail) {
  const entry = { timestamp: new Date().toISOString(), event, target: reportTarget, ...detail };
  report.auditLog.push(entry);
  console.error(`[audit] ${JSON.stringify(entry)}`);
}

function debugFn(label, data) {
  if (DEBUG) {
    console.log(`\n[DEBUG] ${label}`);
    console.log(String(data).slice(0, 1000));
  }
}

/* ────────────────────────────────────────────────────────────────────────────
   APPLY CONFIRMATION
   ──────────────────────────────────────────────────────────────────────────── */

function confirmApplyOrExit() {
  if (!APPLY) return;
  if (process.env.SECGATE_CONFIRM_APPLY === "1") {
    auditLog("apply_confirmed", { via: "env" });
    return;
  }
  if (process.stdin.isTTY) {
    process.stderr.write(
      `\nSecGate --apply will execute remediations against:\n  ${target}\n` +
        `npm invocations run with --ignore-scripts. Proceed? [y/N] `
    );
    let answer = "";
    try {
      const buf = Buffer.alloc(64);
      const n = fs.readSync(0, buf, 0, buf.length, null);
      answer = buf.slice(0, n).toString("utf-8").trim().toLowerCase();
    } catch {
      answer = "";
    }
    if (answer !== "y" && answer !== "yes") {
      console.error("Aborted: --apply not confirmed.");
      process.exit(2);
    }
    auditLog("apply_confirmed", { via: "tty" });
    return;
  }
  console.error(
    "Refusing to run --apply without confirmation. " +
      "Set SECGATE_CONFIRM_APPLY=1 or run in a TTY."
  );
  process.exit(2);
}

/* ────────────────────────────────────────────────────────────────────────────
   SCAN
   ──────────────────────────────────────────────────────────────────────────── */

console.log(`
░▒▓█ SECGATE v${pkg.version} █▓▒░`);
console.log("Target:", reportTarget);
console.log("Mode:  ", APPLY ? "APPLY" : "DRY RUN");
console.log("────────────────────────────────");

confirmApplyOrExit();
if (APPLY) {
  auditLog("apply_start", { outputDir });
}

const addFinding = makeFindingProcessor(config, target, findings, suppressions);

let treeStats;
try {
  console.log("\nPreparing scan: walking target with safety limits...");
  treeStats = scanTargetTree(target, {
    limits: scanLimits,
    onProgress: stats => {
      console.log(
        `Preparing scan: ${stats.files} files, ${stats.dirs} dirs ` +
          `(skipped ${stats.skippedDirs} dirs, ${stats.skippedSymlinks} symlinks)`
      );
    }
  });
} catch (e) {
  if (e instanceof WalkLimitError) {
    console.error(e.message);
    if (e.stats) {
      console.error(
        `Walk stopped after ${e.stats.files} files, ${e.stats.dirs} dirs, ` +
          `${e.stats.skippedDirs} skipped dirs, ${e.stats.skippedSymlinks} skipped symlinks.`
      );
    }
    process.exit(2);
  }
  console.error(`Cannot scan target ${target}: ${e.message}`);
  process.exit(2);
}

if (!ALLOW_WORKSPACE && !treeStats.rootHasPackageJson && treeStats.packageJsonFiles > 1) {
  console.error(
    `This looks like a workspace with ${treeStats.packageJsonFiles} sub-projects. ` +
      "Point SecGate at a single project or pass --allow-workspace."
  );
  process.exit(2);
}

if (treeStats.sourceFiles === 0) {
  console.log("Preparing scan: no scannable source, manifest, lockfile, or Dockerfile entries found.");
} else {
  console.log(
    `Preparing scan: ${treeStats.sourceFiles} scannable files found ` +
      `(${treeStats.skippedDirs} dirs, ${treeStats.skippedSymlinks} symlinks, ` +
      `${treeStats.skippedLargeFiles} large files skipped).`
  );
}

if (config.scanners.osv !== false || config.scanners.trivy !== false) {
  console.log("Note: osv-scanner and Trivy may download vulnerability databases on first run; this can take a moment.");
}

function applyResult(toolKey, result) {
  toolStatus[toolKey] = result.status;
  if (result.skipReason) toolSkipReason[toolKey] = result.skipReason;
}

async function runScanner(label, fn) {
  console.log(`Starting ${label}...`);
  let result;
  try {
    result = await fn();
  } catch (e) {
    const message = e && e.message ? e.message : String(e);
    console.error(`${label} failed: ${message}`);
    result = { status: "error", skipReason: message };
  }
  const reason = result.skipReason ? ` (${result.skipReason})` : "";
  console.log(`Finished ${label}: ${result.status}${reason}`);
  return result;
}

const [sgRes, glRes, npmRes, osvRes, trivyRes, trivyImgRes] = await Promise.all([
  runScanner("Semgrep", () => runSemgrep(target, config, addFinding, debugFn)),
  runScanner("Gitleaks", () => runGitleaks(target, config, addFinding, debugFn)),
  runScanner("npm audit", () => runNpmAudit(target, config, addFinding, debugFn)),
  runScanner("osv-scanner", () => runOsvScanner(target, config, addFinding, debugFn)),
  runScanner("Trivy fs", () => runTrivy(target, config, addFinding, debugFn)),
  runScanner("Trivy image", () => runTrivyImage(target, config, addFinding, debugFn, scanLimits))
]);

applyResult("semgrep",    sgRes);
applyResult("gitleaks",   glRes);
applyResult("npm",        npmRes);
applyResult("osv",        osvRes);
applyResult("trivy",      trivyRes);
applyResult("trivyImage", trivyImgRes);

/* ────────────────────────────────────────────────────────────────────────────
   BASELINE
   ──────────────────────────────────────────────────────────────────────────── */

/* ── Coverage (decided before any output that could look like success) ── */

const coverage        = computeCoverage(toolStatus);
const noScannersRan   = coverage.ran.length === 0;
const missingRequired = requiredScanners.filter(t => !coverage.ran.includes(t));
const coverageExit2   = noScannersRan || missingRequired.length > 0;
// Skips that are not a coverage gap: the user turned the scanner off, or there
// is nothing for it to scan. Any other skip (not installed, error, timeout,
// no lockfile) means a scanner that should have run did not.
const NOT_A_GAP       = new Set(["disabled in config", "no package.json in target"]);
const skipReasonOf    = t => coverageSkipReason(t, toolStatus, toolSkipReason);
const coverageGaps    = coverage.skipped.filter(t => !NOT_A_GAP.has(skipReasonOf(t)));
const coverageLine    = `${coverage.ran.length} of ${coverage.total} scanners ran`;

function printCoverageWarning() {
  if (!coverage.skipped.length) return;
  console.error(`\nWARNING: ${coverageLine}. Results cover only the scanners that ran.`);
  for (const key of coverage.skipped) {
    const reason = skipReasonOf(key);
    const hint = reason === "not installed" ? ` — install: ${INSTALL_HINTS[key]}` : "";
    console.error(`  - ${SCANNER_LABEL[key]}: ${reason}${hint}`);
  }
}

function exitIfCoverageFails() {
  if (noScannersRan) {
    console.error("\nSecGate: no scanners available — nothing was scanned (exit 2).");
    process.exit(2);
  }
  if (missingRequired.length) {
    const list = missingRequired
      .map(t => `${t} (${skipReasonOf(t)})`)
      .join(", ");
    console.error(`\nSecGate: required scanner(s) did not run: ${list} (exit 2).`);
    process.exit(2);
  }
}

if (UPDATE_BASELINE) {
  // Same coverage rules as a normal scan: never record a baseline from a
  // scan that could not look.
  printCoverageWarning();
  exitIfCoverageFails();
  const baselinePath = writeBaseline(config, target, findings);
  console.log(`\nBaseline written: ${baselinePath} (${findings.length} findings)`);
  process.exit(0);
}

let baselineDiff   = null;
let activeFindings = findings;

if (BASELINE_MODE) {
  const baseline = loadBaseline(config, target);
  if (baseline) {
    const { annotated, baselineMatchedCount } = applyBaseline(findings, baseline);
    activeFindings = annotated;
    const netNew = annotated.filter(f => !f.baseline).length;
    baselineDiff = { netNew, baselineMatchedCount };
    console.log(`\nBaseline: ${baselineMatchedCount} matched, ${netNew} net-new`);
  } else {
    console.log("\nBaseline: no baseline file found, treating all findings as net-new");
  }
}

/* ────────────────────────────────────────────────────────────────────────────
   FINALIZE REPORT
   ──────────────────────────────────────────────────────────────────────────── */

report.findings      = activeFindings;
if (baselineDiff) report.baselineDiff = baselineDiff;
report.toolSkipReason = toolSkipReason;
report.summary       = summarize(activeFindings);
report.intelligence  = analyze(activeFindings);
report.remediation   = remediate(activeFindings, {
  apply:        APPLY,
  target,
  reportTarget,
  auditLog
});
report.status        = resolveStatus(activeFindings, config.failOn, BASELINE_MODE);
report.coverage      = coverage;

// A scan that could not look is not a pass: exit 2 and say so in the report.
if (coverageExit2) report.status = "INCOMPLETE";
// Partial coverage is never a PASS: blocking findings still FAIL (exit 1),
// otherwise the verdict is INCOMPLETE (exit 2).
if (report.status === "PASS" && coverageGaps.length) report.status = "INCOMPLETE";

// Nothing ran → no score to give. Partial coverage keeps a score over the
// scanners that did run; skipped scanners are never scored (null, not 100).
report.securityScore = noScannersRan ? null : computeScore(activeFindings);
report.toolScores    = computeToolScores(activeFindings, SCANNERS, coverage.skipped);

// Confidence cannot exceed the share of scanners that actually ran.
const coveragePct = Math.round((100 * coverage.ran.length) / coverage.total);
report.remediation.confidence = Math.min(report.remediation.confidence, coveragePct);

/* ────────────────────────────────────────────────────────────────────────────
   OUTPUT
   ──────────────────────────────────────────────────────────────────────────── */

/* ── Security Score header (LuxFaber-parity: emerald>=90, amber>=70, red<70) ── */
function scoreBar(n) {
  const filled = Math.round(n / 5);
  const empty  = 20 - filled;
  return "█".repeat(filled) + "░".repeat(empty);
}
function scoreColor(n, s) {
  if (!process.stdout.isTTY) return s;
  if (n >= 90) return `\x1b[32m${s}\x1b[0m`;
  if (n >= 70) return `\x1b[33m${s}\x1b[0m`;
  return `\x1b[31m${s}\x1b[0m`;
}

const sc = report.securityScore;
console.log("\n────────────────────────────────");
if (sc == null) {
  console.log(`Security Score: n/a (no scanners ran)  rule ${SCORE_VERSION}`);
} else {
  console.log(`Security Score: ${scoreColor(sc, `${sc} / 100`)}   ${scoreColor(sc, scoreBar(sc))}  rule ${SCORE_VERSION}`);
}
console.log("");

for (const key of SCANNERS) {
  const label = SCANNER_LABEL[key];
  const ts = report.toolScores[key];
  if (ts == null) {
    const reason = skipReasonOf(key);
    console.log(`  ${label.padEnd(12)} n/a       not run (${reason})`);
  } else {
    console.log(`  ${label.padEnd(12)} ${scoreColor(ts, `${ts} / 100`)}   ${scoreColor(ts, scoreBar(ts))}`);
  }
}

console.log("\n────────────────────────────────");
console.log(coverage.skipped.length ? `STATUS: ${report.status} (${coverageLine})` : `STATUS: ${report.status}`);
console.log("RISK SCORE:", report.intelligence.riskScore);
console.log("CONFIDENCE:", report.remediation.confidence + "%");

console.log("\nSCANNER STATUS:");
for (const t of TOOLS) {
  const reason = toolSkipReason[t] ? ` (${toolSkipReason[t]})` : "";
  console.log(`- ${t.padEnd(10)} ${toolStatus[t]}${reason}`);
}

console.log("\nTOP ISSUES:");
activeFindings.slice(0, 5).forEach(f =>
  console.log("-", f.signature, "|", f.severity, f.baseline ? "[baseline]" : "")
);

console.log("\nRECOMMENDATIONS:");
report.intelligence.recommendations.forEach(r => console.log("-", r));

if (suppressions.count > 0) {
  console.log(`\nSUPPRESSED: ${suppressions.count} finding(s) via inline comment`);
}

if (APPLY) {
  console.log("\nEXECUTED FIXES:");
  report.remediation.executed.forEach(e => console.log("-", e));
}

if (STRIP_PATHS) {
  applyPathStripping(report, target, repoName);
}

function writeReportFile(file, contents) {
  try {
    fs.writeFileSync(file, contents);
  } catch (e) {
    console.error(`Cannot write report ${file}: ${e.message}`);
    process.exit(2);
  }
}

writeReportFile(outputFile, JSON.stringify(report, null, 2));

const htmlFile = path.join(outputDir, `${repoName}.html`);
writeReportFile(htmlFile, renderHtml(report, repoName, config.profile));

console.log("\nReport saved:", outputFile);
console.log("HTML report:", htmlFile);

if (EMIT_SARIF) {
  const sarifFile = path.join(outputDir, `${repoName}.sarif.json`);
  const sarif = buildSarif(report, repoName, target);
  writeReportFile(sarifFile, JSON.stringify(sarif, null, 2));
  console.log("SARIF report:", sarifFile);
}

/* ── Coverage warning + exit code ── */

printCoverageWarning();
exitIfCoverageFails();

if (report.status === "INCOMPLETE") {
  console.error(`\nSecGate: INCOMPLETE — ${coverageGaps.join(", ")} did not run, so this is not a PASS (exit 2).`);
  process.exit(2);
}

process.exit(report.status === "PASS" ? 0 : 1);
