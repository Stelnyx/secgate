import fs from "fs";
import os from "os";
import path from "path";
import { runToolAsync, toolExists, normalizeSeverity, matchPattern, matchesAny, parseToolJson } from "./utils.mjs";
import { scanTargetTree } from "./walk.mjs";

const SEMGREP_TIER = {
  ERROR: "HIGH",
  WARNING: "MEDIUM",
  INFO: "LOW",
  NOTE: "LOW"
};

const SECRET_RE = /(secret|credential|password|token|api[_-]?key|hardcoded)/i;
const SECRET_CWES = ["CWE-798", "CWE-259", "CWE-321", "CWE-522"];

function semgrepSeverity(r) {
  const base = SEMGREP_TIER[(r.extra?.severity || "").toUpperCase()] || "MEDIUM";

  const meta = r.extra?.metadata || {};
  const category = String(meta.category || "").toLowerCase();
  const checkId = String(r.check_id || "");
  const cweArr = []
    .concat(meta.cwe || [])
    .concat(meta.owasp || [])
    .map(x => String(x));

  const isSecret =
    (category === "security" && SECRET_RE.test(checkId + " " + JSON.stringify(meta))) ||
    cweArr.some(c => SECRET_CWES.some(sc => c.toUpperCase().includes(sc)));

  return isSecret ? "CRITICAL" : base;
}

function severityFromCvss(score) {
  if (!Number.isFinite(score) || score <= 0) return null;
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  return "LOW";
}

function cvssBaseScore(vec) {
  const stripped = String(vec || "").replace(/CVSS:\d+\.\d+\/?/, "");
  const m = stripped.match(/(?:^|[^\d])(\d+(?:\.\d+)?)/);
  return m ? parseFloat(m[1]) : NaN;
}

function ratingFromText(txt) {
  const s = String(txt || "").toUpperCase();
  if (/\bCRITICAL\b/.test(s)) return "CRITICAL";
  if (/\bHIGH\b/.test(s)) return "HIGH";
  if (/\b(MODERATE|MEDIUM)\b/.test(s)) return "MEDIUM";
  if (/\bLOW\b/.test(s)) return "LOW";
  return null;
}

function osvSeverity(v) {
  const sev = v.severity || [];
  let best = 0;
  for (const s of sev) {
    const t = (s.type || "").toUpperCase();
    if (t === "CVSS_V3" || t === "CVSS_V2") {
      const score = cvssBaseScore(s.score);
      if (Number.isFinite(score)) best = Math.max(best, score);
    }
  }
  const bySeverity = severityFromCvss(best);
  if (bySeverity) return bySeverity;

  const dbSev = v.database_specific?.severity;
  const byDb = ratingFromText(dbSev);
  if (byDb) return byDb;

  for (const s of sev) {
    const byText = ratingFromText(s.type) || ratingFromText(s.score);
    if (byText) return byText;
  }

  const byDetails = ratingFromText(v.details);
  if (byDetails) return byDetails;

  return "UNKNOWN";
}

function findDockerfiles(dir, limits) {
  return scanTargetTree(dir, { limits }).dockerfiles;
}

function extractBaseImages(dockerfilePath, maxFileSizeBytes) {
  let stat;
  try { stat = fs.statSync(dockerfilePath); } catch { return []; }
  if (maxFileSizeBytes && stat.size > maxFileSizeBytes) return [];

  let content;
  try { content = fs.readFileSync(dockerfilePath, "utf-8"); } catch { return []; }
  const images = new Set();
  // Names given with `FROM <image> AS <name>`. A later `FROM <name>` builds
  // on that stage, so it is not an image to pull.
  const stages = new Set();
  for (const line of content.split("\n")) {
    const m = line.match(/^FROM\s+(?:--platform=\S+\s+)?([^\s]+)(?:\s+AS\s+(\S+))?$/i);
    if (m) {
      const ref = m[1];
      if (ref.toLowerCase() !== "scratch" && !stages.has(ref.toLowerCase())) images.add(ref);
      if (m[2]) stages.add(m[2].toLowerCase());
    }
  }
  return [...images];
}

function timeoutResult(label, result) {
  const seconds = Math.round((result.timeoutMs || 0) / 1000);
  const duration = seconds > 0 ? `${seconds}s` : `${result.timeoutMs}ms`;
  return {
    status: "error",
    skipReason: `${label} timed out after ${duration} - result inconclusive`
  };
}

/**
 * Why a scanner process failed, or null when it exited 0 or with one of
 * `okCodes` (the codes the scanner uses to say "findings found"). A process
 * that could not start (ENOENT, EACCES, ENOEXEC, ...) has a string code; one
 * killed by a signal has a signal and no exit code.
 */
function processFailure(label, toolResult, okCodes = []) {
  const err = toolResult.error;
  if (!err) return null;
  if (typeof err.code === "string") return `${label} could not run (${err.code})`;
  if (err.signal) return `${label} was killed by ${err.signal}`;
  if (okCodes.includes(err.code)) return null;
  return `${label} exited with code ${err.code ?? "unknown"}`;
}

function exitCodeOf(toolResult) {
  return toolResult.error ? toolResult.error.code : 0;
}

/**
 * Check a source file for an inline suppression comment on line N or N-1.
 */
export function hasInlineSuppression(filePath, lineNumber, ruleId) {
  if (!filePath || lineNumber == null) return false;

  let src;
  try {
    src = fs.readFileSync(filePath, "utf-8");
  } catch {
    return false;
  }

  const lines = src.split("\n");
  const checkLines = [lineNumber - 1, lineNumber - 2].filter(i => i >= 0);

  for (const idx of checkLines) {
    const line = lines[idx] || "";
    const suppressRe = /(?:#|\/\/|\/\*)\s*secgate:ignore\s+(\S+)/;
    const m = line.match(suppressRe);
    if (m) {
      const suppressedRule = m[1];
      if (matchPattern(suppressedRule, ruleId)) {
        return suppressedRule;
      }
    }
  }
  return false;
}

/**
 * Build a finding-processor bound to the given config, target, suppressions state.
 * Returns an addFinding function for scanners to call.
 */
export function makeFindingProcessor(config, target, findings, suppressions) {
  const seen = new Set();

  return function addFinding(f) {
    const rawSeverity = normalizeSeverity(f.severity);
    const signature = f.signature || "";

    const severity = applyOverrides(config, rawSeverity, signature);

    if (matchesAny(config.ignore, signature)) return;

    if (f.file && config.excludePaths && config.excludePaths.length > 0) {
      let relForMatch = f.file;
      if (path.isAbsolute(f.file)) {
        // secgate:ignore javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
        const rel = path.relative(path.resolve(target), f.file);
        if (rel && !rel.startsWith("..")) relForMatch = rel;
      }
      if (matchesAny(config.excludePaths, relForMatch) || matchesAny(config.excludePaths, f.file)) return;
    }

    const dedupKey = `${f.tool}|${signature}|${f.file ?? ""}|${f.image ?? ""}|${f.line ?? ""}`;
    if (seen.has(dedupKey)) return;
    seen.add(dedupKey);

    let resolvedFile = null;
    if (f.file) {
      if (path.isAbsolute(f.file)) {
        resolvedFile = f.file;
      } else {
        // secgate:ignore javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
        const candidate = path.resolve(target, f.file);
        // secgate:ignore javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
        const t = path.resolve(target);
        if (candidate.startsWith(t + path.sep) || candidate === t) resolvedFile = candidate;
      }
    }
    const suppressedRule = hasInlineSuppression(resolvedFile, f.line, signature);
    if (suppressedRule) {
      suppressions.count++;
      suppressions.byRule[suppressedRule] = (suppressions.byRule[suppressedRule] || 0) + 1;
      return;
    }

    const fixableBy =
      f.fixableBy === "auto" || f.fixableBy === "manual"
        ? f.fixableBy
        : f.fixable
        ? "manual"
        : null;

    const finding = {
      tool: f.tool,
      type: f.type,
      severity,
      signature,
      message: f.message,
      file: f.file ?? null,
      line: f.line ?? null,
      col: f.col ?? null,
      endLine: f.endLine ?? null,
      fixable: fixableBy === "auto",
      fixableBy
    };

    if (f.scanMode != null) finding.scanMode = f.scanMode;
    if (f.image != null) finding.image = f.image;

    findings.push(finding);
  };
}

function applyOverrides(config, severity, signature) {
  for (const ov of config.severityOverrides) {
    if (ov && typeof ov.rule === "string" && typeof ov.severity === "string") {
      if (matchPattern(ov.rule, signature)) {
        return normalizeSeverity(ov.severity);
      }
    }
  }
  return severity;
}

/**
 * Each scanner returns { status, skipReason? } and calls addFinding for each hit.
 * All are deterministic when the tool binary is missing: status="skipped", skipReason set.
 */

export async function runGitleaks(target, config, addFinding, debugFn) {
  if (config.scanners.gitleaks === false) {
    return { status: "skipped", skipReason: "disabled in config" };
  }
  if (!toolExists("gitleaks")) {
    return { status: "skipped", skipReason: "not installed" };
  }

  // Gitleaks writes its JSON report only to --report-path, never to stdout,
  // so it goes to a private temp directory; --redact keeps secret values out
  // of that file. LC_ALL=C keeps git's error messages in English.
  const reportDir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-gitleaks-"));
  const reportFile = path.join(reportDir, "report.json");
  try {
    const toolResult = await runToolAsync(
      "gitleaks",
      ["detect", "--source", target, "--report-format", "json", "--report-path", reportFile, "--redact"],
      { env: { ...process.env, LC_ALL: "C" } }
    );
    if (toolResult.timedOut) return timeoutResult("Gitleaks", toolResult);
    // Exit 1 means leaks found, or a scan that failed part way.
    const failure = processFailure("Gitleaks", toolResult, [1]);
    if (failure) return { status: "error", skipReason: failure };
    // `detect` scans git history only, so outside a repository it scans
    // nothing; Gitleaks relays git's error on stderr.
    if (/not a git repository/i.test(toolResult.stderr)) {
      return { status: "skipped", skipReason: "not a git repository (Gitleaks scans git history only)" };
    }

    const out = fs.existsSync(reportFile) ? fs.readFileSync(reportFile, "utf-8") : "";
    if (debugFn) debugFn("gitleaks", out);
    const leaksFound = exitCodeOf(toolResult) === 1;

    if (!out.trim()) {
      return leaksFound
        ? { status: "error", skipReason: "Gitleaks exited with code 1 and wrote no report" }
        : { status: "clean" };
    }

    const data = parseToolJson("gitleaks", out, debugFn);
    if (!Array.isArray(data)) return { status: "error", skipReason: "Gitleaks report is not a list" };
    if (leaksFound && data.length === 0) {
      return { status: "error", skipReason: "Gitleaks exited with code 1 without reporting a leak" };
    }

    data.forEach(item => {
      addFinding({
        tool: "gitleaks",
        type: "secret",
        severity: "CRITICAL",
        signature: item.RuleID,
        message: item.Description,
        file: item.File ?? null,
        line: item.StartLine ?? null,
        endLine: item.EndLine ?? null,
        fixableBy: "manual"
      });
    });

    return { status: data.length > 0 ? "ran" : "clean" };
  } catch {
    return { status: "error" };
  } finally {
    fs.rmSync(reportDir, { recursive: true, force: true });
  }
}

export async function runSemgrep(target, config, addFinding, debugFn) {
  if (config.scanners.semgrep === false) {
    return { status: "skipped", skipReason: "disabled in config" };
  }
  if (!toolExists("semgrep")) {
    return { status: "skipped", skipReason: "not installed" };
  }

  const semgrepArgs = ["--config=auto", "--json", target];
  if (config.customSemgrepRules) {
    semgrepArgs.unshift(`--config=${config.customSemgrepRules}`);
  }

  const toolResult = await runToolAsync("semgrep", semgrepArgs);
  if (toolResult.timedOut) return timeoutResult("Semgrep", toolResult);
  // Without --error Semgrep exits 0 whether or not it finds anything (1 only
  // reports findings); 2 and above mean the scan failed.
  const failure = processFailure("Semgrep", toolResult, [1]);
  if (failure) return { status: "error", skipReason: failure };
  const out = toolResult.stdout;
  if (debugFn) debugFn("semgrep", out);

  try {
    const data = parseToolJson("semgrep", out, debugFn);
    // A fatal error comes at level "error". A file Semgrep could not parse
    // comes at level "warn" and does not fail the scan.
    const fatal = (data.errors || []).find(e => e && e.level === "error");

    data.results.forEach(r => {
      addFinding({
        tool: "semgrep",
        type: "code",
        severity: semgrepSeverity(r),
        signature: r.check_id,
        message: r.extra?.message,
        file: r.path ?? null,
        line: r.start?.line ?? null,
        col: r.start?.col ?? null,
        endLine: r.end?.line ?? null,
        fixableBy: "manual"
      });
    });

    if (fatal) {
      const message = String(fatal.message || "unknown error").split("\n")[0].slice(0, 200);
      return { status: "error", skipReason: `Semgrep reported an error: ${message}` };
    }
    return { status: data.results.length > 0 ? "ran" : "clean" };
  } catch {
    return { status: "error" };
  }
}

export async function runOsvScanner(target, config, addFinding, debugFn) {
  if (config.scanners.osv === false) {
    return { status: "skipped", skipReason: "disabled in config" };
  }
  if (!toolExists("osv-scanner")) {
    return { status: "skipped", skipReason: "not installed" };
  }

  const toolResult = await runToolAsync("osv-scanner", ["--format", "json", "-r", target]);
  if (toolResult.timedOut) return timeoutResult("osv-scanner", toolResult);
  // Exit 1: vulnerabilities found. Exit 128: no package sources found.
  const failure = processFailure("osv-scanner", toolResult, [1, 128]);
  if (failure) return { status: "error", skipReason: failure };
  const out = toolResult.stdout;
  if (debugFn) debugFn("osv-scanner", out);
  const exitCode = exitCodeOf(toolResult);

  // Exit 128: osv-scanner found no lockfile or manifest it can read, so it
  // scanned nothing. That is not a clean result.
  if (exitCode === 128 || /No package sources found/i.test(out)) {
    return { status: "skipped", skipReason: "no package sources found" };
  }
  if (!out.trim()) {
    return exitCode === 0
      ? { status: "clean" }
      : { status: "error", skipReason: "osv-scanner exited with code 1 and printed no results" };
  }

  try {
    const data = parseToolJson("osv-scanner", out, debugFn);
    const results = data.results || [];
    let count = 0;

    for (const r of results) {
      const lockFile = r.source?.path || null;

      for (const p of r.packages || []) {
        const pkgName = p.package?.name || "unknown";
        const pkgEco = p.package?.ecosystem || "unknown";

        for (const v of p.vulnerabilities || []) {
          addFinding({
            tool: "osv",
            type: "dependency",
            severity: osvSeverity(v),
            signature: `${pkgEco}:${pkgName}@${v.id}`,
            message: v.summary || v.id,
            file: lockFile || pkgName,
            line: null,
            fixableBy: "manual"
          });
          count++;
        }
      }
    }

    return { status: count > 0 ? "ran" : "clean" };
  } catch {
    return { status: "error" };
  }
}

export async function runTrivy(target, config, addFinding, debugFn) {
  if (config.scanners.trivy === false) {
    return { status: "skipped", skipReason: "disabled in config" };
  }
  if (!toolExists("trivy")) {
    return { status: "skipped", skipReason: "not installed" };
  }

  // --exit-code 0 overrides TRIVY_EXIT_CODE or a trivy.yaml exit-code, so
  // findings never change the exit code and any non-zero exit is a failure.
  const toolResult = await runToolAsync("trivy", [
    "fs",
    "--quiet",
    "--format", "json",
    "--exit-code", "0",
    "--scanners", "misconfig,license",
    ...(process.env.SECGATE_INTERNAL_TEST === "1" ? ["--skip-dirs", "**/test/fixtures"] : []),
    "--skip-dirs", "**/node_modules",
    target
  ]);
  if (toolResult.timedOut) return timeoutResult("Trivy fs", toolResult);
  const failure = processFailure("Trivy fs", toolResult);
  if (failure) return { status: "error", skipReason: failure };
  const out = toolResult.stdout;
  if (debugFn) debugFn("trivy", out);

  try {
    const data = parseToolJson("trivy", out, debugFn);
    const results = data.Results || [];
    let count = 0;

    for (const r of results) {
      for (const m of r.Misconfigurations || []) {
        addFinding({
          tool: "trivy",
          type: "iac",
          severity: m.Severity,
          signature: `${m.ID}:${r.Target}`,
          message: m.Title || m.Description || m.ID,
          file: r.Target ?? null,
          line: m.CauseMetadata?.StartLine ?? null,
          endLine: m.CauseMetadata?.EndLine ?? null,
          fixableBy: "manual"
        });
        count++;
      }

      for (const l of r.Licenses || []) {
        addFinding({
          tool: "trivy",
          type: "license",
          severity: l.Severity,
          signature: `${l.Name}:${l.PkgName || r.Target}`,
          message: `License ${l.Name} flagged for ${l.PkgName || r.Target}`,
          file: l.FilePath || r.Target || null,
          line: null,
          fixableBy: "manual"
        });
        count++;
      }
    }

    return { status: count > 0 ? "ran" : "clean" };
  } catch {
    return { status: "error" };
  }
}

export async function runTrivyImage(target, config, addFinding, debugFn, scanLimits = undefined) {
  if (config.scanners.trivy === false) {
    return { status: "skipped", skipReason: "disabled in config" };
  }
  if (!toolExists("trivy")) {
    return { status: "skipped", skipReason: "not installed" };
  }

  const isInternalTest = process.env.SECGATE_INTERNAL_TEST === "1";
  // secgate:ignore javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  const targetResolved = path.resolve(target);
  const excludePaths = Array.isArray(config.excludePaths) ? config.excludePaths : [];
  const dockerfiles = findDockerfiles(target, scanLimits).filter(f => {
    if (isInternalTest && f.includes("/test/fixtures")) return false;
    if (excludePaths.length > 0) {
      // secgate:ignore javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
      const rel = path.relative(targetResolved, f);
      if (rel && !rel.startsWith("..") && matchesAny(excludePaths, rel)) return false;
    }
    return true;
  });
  if (dockerfiles.length === 0) return { status: "skipped" };

  const imageRefs = new Set();
  for (const df of dockerfiles) {
    for (const ref of extractBaseImages(df, scanLimits?.maxFileSizeBytes)) {
      imageRefs.add(ref);
    }
  }

  if (imageRefs.size === 0) return { status: "skipped" };

  let anyRan = false;
  let anyError = false;
  let errorReason = null;
  let count = 0;

  for (const imageRef of imageRefs) {
    const toolResult = await runToolAsync("trivy", [
      "image",
      "--format", "json",
      "--quiet",
      "--exit-code", "0",
      imageRef
    ], { timeout: 120000 });
    if (toolResult.timedOut) {
      anyError = true;
      errorReason = timeoutResult(`Trivy image ${imageRef}`, toolResult).skipReason;
      continue;
    }
    const failure = processFailure(`Trivy image ${imageRef}`, toolResult);
    if (failure) {
      anyError = true;
      errorReason = failure;
      continue;
    }
    const out = toolResult.stdout;
    if (debugFn) debugFn(`trivy image ${imageRef}`, out);

    if (!out.trim()) { anyError = true; continue; }

    try {
      const data = parseToolJson(`trivy image ${imageRef}`, out, debugFn);
      const results = data.Results || [];
      anyRan = true;

      for (const r of results) {
        for (const v of r.Vulnerabilities || []) {
          addFinding({
            tool: "trivy",
            type: "dependency",
            severity: v.Severity,
            signature: `trivy-image:${imageRef}:${v.VulnerabilityID}`,
            message: v.Title || v.Description || v.VulnerabilityID,
            file: imageRef,
            line: null,
            fixableBy: "manual",
            scanMode: "image",
            image: imageRef
          });
          count++;
        }
      }
    } catch {
      anyError = true;
    }
  }

  if (anyError) return { status: "error", ...(errorReason ? { skipReason: errorReason } : {}) };
  if (count > 0) return { status: "ran" };
  if (anyRan) return { status: "clean" };
  return { status: "error" };
}

export async function runNpmAudit(target, config, addFinding, debugFn) {
  if (config.scanners.npm === false) {
    return { status: "skipped", skipReason: "disabled in config" };
  }
  if (!fs.existsSync(path.join(target, "package.json"))) {
    return { status: "skipped", skipReason: "no package.json in target" };
  }
  if (!toolExists("npm")) {
    return { status: "skipped", skipReason: "not installed" };
  }

  const toolResult = await runToolAsync("npm", ["audit", "--json"], { cwd: target });
  if (toolResult.timedOut) return timeoutResult("npm audit", toolResult);
  const out = toolResult.stdout;
  if (debugFn) debugFn("npm audit", out);

  const jsonStart = out.indexOf("{");
  const jsonEnd = out.lastIndexOf("}");
  const cleanOut =
    jsonStart >= 0 && jsonEnd > jsonStart
      ? out.slice(jsonStart, jsonEnd + 1)
      : out;

  try {
    const json = parseToolJson("npm audit", cleanOut, debugFn);

    if (json.error) {
      if (json.error.code === "ENOLOCK") {
        addFinding({
          tool: "secgate",
          type: "policy",
          severity: "MEDIUM",
          signature: "no-lockfile",
          message: "package.json present but no lockfile — supply-chain determinism not guaranteed",
          file: "package.json",
          line: null,
          fixableBy: "manual"
        });
        return { status: "skipped", skipReason: "no package-lock.json (run `npm install` to generate)" };
      }
      return { status: "error" };
    }

    const vulns = json.vulnerabilities || {};
    const lockFile = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock"]
      .find(f => fs.existsSync(path.join(target, f))) || "package.json";
    let count = 0;

    for (const k in vulns) {
      const v = vulns[k];
      addFinding({
        tool: "npm",
        type: "dependency",
        severity: v.severity,
        signature: k,
        message: v.title || v.name || k,
        file: lockFile,
        line: null,
        fixableBy: "auto"
      });
      count++;
    }

    return { status: count > 0 ? "ran" : "clean" };
  } catch {
    return { status: "error" };
  }
}
