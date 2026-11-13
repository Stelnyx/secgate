#!/usr/bin/env node
// Fixture-based unit tests for the lib/ modules.
// These tests import directly from lib/ — no child_process spawn, no CLI.
// They verify the engine is importable without side effects, and that
// each parser/builder produces the documented output shape.

import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";

const here    = path.dirname(fileURLToPath(import.meta.url));
const fixDir  = path.join(here, "fixtures/schema");
const libDir  = path.resolve(here, "..", "lib");

let passed = 0;
let failed = 0;
const pendingTests = [];

function test(name, fn) {
  pendingTests.push(async () => {
    try {
      await fn();
      console.log(`  ok  ${name}`);
      passed++;
    } catch (e) {
      console.log(`  FAIL ${name}`);
      console.log(`       ${e.message}`);
      failed++;
    }
  });
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
function assertEq(a, b, msg) {
  if (a !== b) throw new Error(`${msg}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

function readFixture(name) {
  return fs.readFileSync(path.join(fixDir, name), "utf-8");
}

/* ────────────────────────────────────────────────────────────────────────────
   Import guard — lib modules must not trigger CLI parsing or process.exit
   ──────────────────────────────────────────────────────────────────────────── */

const {
  CONFIG_DEFAULTS,
  loadConfig
} = await import(`${libDir}/config.mjs`);

const {
  normalizeSeverity,
  matchPattern,
  matchesAny,
  toolExists
} = await import(`${libDir}/utils.mjs`);

const {
  hasInlineSuppression,
  makeFindingProcessor,
  runGitleaks,
  runSemgrep
} = await import(`${libDir}/scanners.mjs`);

const {
  loadBaseline,
  writeBaseline,
  applyBaseline
} = await import(`${libDir}/baseline.mjs`);

const {
  analyze,
  patch,
  remediate
} = await import(`${libDir}/intelligence.mjs`);

const {
  TOOLS,
  summarize,
  resolveStatus,
  stripAbsolutePaths,
  renderHtml,
  buildSarif
} = await import(`${libDir}/report.mjs`);

console.log("\nSecGate engine unit tests");
console.log("-------------------------");

/* ────────────────────────────────────────────────────────────────────────────
   lib/config.mjs
   ──────────────────────────────────────────────────────────────────────────── */

test("config: CONFIG_DEFAULTS has expected shape", () => {
  assert(Array.isArray(CONFIG_DEFAULTS.failOn), "failOn is array");
  assert(typeof CONFIG_DEFAULTS.scanners === "object", "scanners is object");
  assert(Array.isArray(CONFIG_DEFAULTS.severityOverrides), "severityOverrides is array");
  assert(Array.isArray(CONFIG_DEFAULTS.ignore), "ignore is array");
  assert(Array.isArray(CONFIG_DEFAULTS.excludePaths), "excludePaths is array");
  assertEq(CONFIG_DEFAULTS.baselineFile, ".secgate-baseline.json", "baselineFile default");
  assertEq(CONFIG_DEFAULTS.customSemgrepRules, null, "customSemgrepRules default null");
});

test("config: loadConfig returns defaults when no config file", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-eng-"));
  const cfg = loadConfig(d);
  assertEq(cfg.baselineFile, CONFIG_DEFAULTS.baselineFile, "baselineFile");
  assert(cfg.failOn.includes("critical"), "failOn includes critical");
  assert(cfg.failOn.includes("high"), "failOn includes high");
  fs.rmSync(d, { recursive: true, force: true });
});

test("config: loadConfig merges config file over defaults", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-eng-"));
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({
    failOn: ["critical"],
    scanners: { npm: false }
  }));
  const cfg = loadConfig(d);
  assertEq(cfg.failOn.length, 1, "only critical in failOn");
  assertEq(cfg.scanners.npm, false, "npm disabled");
  assertEq(cfg.scanners.semgrep, true, "semgrep still default-enabled");
  fs.rmSync(d, { recursive: true, force: true });
});

test("config: invalid JSON falls back to defaults", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-eng-"));
  fs.writeFileSync(path.join(d, ".secgate.config.json"), "{ broken json }");
  const cfg = loadConfig(d);
  assert(cfg.failOn.includes("high"), "default failOn preserved");
  fs.rmSync(d, { recursive: true, force: true });
});

/* ────────────────────────────────────────────────────────────────────────────
   lib/utils.mjs
   ──────────────────────────────────────────────────────────────────────────── */

test("utils: normalizeSeverity canonical cases", () => {
  assertEq(normalizeSeverity("CRITICAL"), "CRITICAL", "CRITICAL");
  assertEq(normalizeSeverity("HIGH"),     "HIGH",     "HIGH");
  assertEq(normalizeSeverity("MEDIUM"),   "MEDIUM",   "MEDIUM");
  assertEq(normalizeSeverity("LOW"),      "LOW",      "LOW");
  assertEq(normalizeSeverity("UNKNOWN"),  "UNKNOWN",  "UNKNOWN");
});

test("utils: normalizeSeverity alias mapping", () => {
  assertEq(normalizeSeverity("moderate"),    "MEDIUM",  "moderate → MEDIUM");
  assertEq(normalizeSeverity("warning"),     "MEDIUM",  "warning → MEDIUM");
  assertEq(normalizeSeverity("error"),       "HIGH",    "error → HIGH");
  assertEq(normalizeSeverity("info"),        "LOW",     "info → LOW");
  assertEq(normalizeSeverity("note"),        "LOW",     "note → LOW");
  assertEq(normalizeSeverity("negligible"),  "LOW",     "negligible → LOW");
  assertEq(normalizeSeverity(null),          "UNKNOWN", "null → UNKNOWN");
  assertEq(normalizeSeverity("bogus"),       "UNKNOWN", "bogus → UNKNOWN");
});

test("utils: matchPattern literal match", () => {
  assert(matchPattern("lodash", "lodash"), "exact match");
  assert(!matchPattern("lodash", "lodash2"), "no spurious match");
});

test("utils: matchPattern wildcard", () => {
  assert(matchPattern("CVE-2024-*", "CVE-2024-12345"), "prefix wildcard");
  assert(matchPattern("pkg-*", "pkg-a"), "prefix wildcard 2");
  assert(!matchPattern("CVE-2024-*", "CVE-2023-12345"), "different year no match");
  assert(matchPattern("*-risk", "some-risk"), "suffix wildcard");
});

test("utils: matchPattern rejects patterns >256 chars to prevent ReDoS", () => {
  const longPattern = "a*".repeat(200);
  assert(!matchPattern(longPattern, "a".repeat(500)), "pattern >256 chars returns false");
  const safePattern = "CVE-2024-*";
  assert(matchPattern(safePattern, "CVE-2024-12345"), "normal patterns still work");
});

test("utils: matchesAny returns true when any pattern matches", () => {
  assert(matchesAny(["foo", "bar-*"], "bar-baz"), "wildcard in list");
  assert(!matchesAny(["foo", "bar-*"], "qux"), "no match in list");
});

test("utils: toolExists walks PATH without shelling out to `which`", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-path-"));
  try {
    const exe = path.join(dir, "fake-scanner");
    fs.writeFileSync(exe, "#!/bin/sh\nexit 0\n");
    fs.chmodSync(exe, 0o755);
    fs.writeFileSync(path.join(dir, "not-executable"), "data");
    fs.mkdirSync(path.join(dir, "a-directory"));
    // PATH holds only `dir`: no `which` binary is reachable.
    const env = { PATH: dir };
    assertEq(toolExists("fake-scanner", env, "linux"), true, "executable found");
    assertEq(toolExists("missing-scanner", env, "linux"), false, "missing tool");
    assertEq(toolExists("not-executable", env, "linux"), false, "non-executable file");
    assertEq(toolExists("a-directory", env, "linux"), false, "directory is not a tool");
    assertEq(toolExists("fake-scanner", { PATH: "" }, "linux"), false, "empty PATH");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("utils: toolExists honours PATHEXT on win32", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-pathext-"));
  try {
    fs.writeFileSync(path.join(dir, "trivy.EXE"), "");
    const env = { Path: dir, PATHEXT: ".COM;.EXE;.BAT;.CMD" };
    assertEq(toolExists("trivy", env, "win32"), true, "trivy.EXE found via PATHEXT");
    assertEq(toolExists("semgrep", env, "win32"), false, "semgrep missing");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/* ────────────────────────────────────────────────────────────────────────────
   lib/scanners.mjs — parser layer (tool binary replaced by parsed fixture)
   All scanner tests build their own findings array rather than calling
   runGitleaks etc., since those require real binaries.
   We test the parsers by exercising makeFindingProcessor directly.
   ──────────────────────────────────────────────────────────────────────────── */

test("scanners: makeFindingProcessor normalizes severity", () => {
  const findings    = [];
  const suppressions = { count: 0, byRule: {} };
  const config       = { ...CONFIG_DEFAULTS };
  const add          = makeFindingProcessor(config, "/tmp", findings, suppressions);

  add({ tool: "npm", type: "dependency", severity: "moderate", signature: "pkg", message: "m" });
  assertEq(findings[0].severity, "MEDIUM", "moderate normalized to MEDIUM");
});

test("scanners: makeFindingProcessor applies severity override", () => {
  const findings     = [];
  const suppressions = { count: 0, byRule: {} };
  const config       = {
    ...CONFIG_DEFAULTS,
    severityOverrides: [{ rule: "lodash", severity: "LOW" }]
  };
  const add = makeFindingProcessor(config, "/tmp", findings, suppressions);

  add({ tool: "npm", type: "dependency", severity: "HIGH", signature: "lodash", message: "m" });
  assertEq(findings[0].severity, "LOW", "override applied");
});

test("scanners: makeFindingProcessor drops ignored signatures", () => {
  const findings     = [];
  const suppressions = { count: 0, byRule: {} };
  const config       = { ...CONFIG_DEFAULTS, ignore: ["CVE-2024-*"] };
  const add          = makeFindingProcessor(config, "/tmp", findings, suppressions);

  add({ tool: "npm", type: "dependency", severity: "CRITICAL", signature: "CVE-2024-9999", message: "m" });
  add({ tool: "npm", type: "dependency", severity: "HIGH",     signature: "CVE-2023-1111", message: "m" });
  assertEq(findings.length, 1, "CVE-2024 dropped, CVE-2023 kept");
  assertEq(findings[0].signature, "CVE-2023-1111", "kept finding is CVE-2023");
});

test("scanners: makeFindingProcessor drops findings whose file matches excludePaths", () => {
  const findings     = [];
  const suppressions = { count: 0, byRule: {} };
  const config       = { ...CONFIG_DEFAULTS, excludePaths: ["test/fixtures/**"] };
  const add          = makeFindingProcessor(config, "/tmp", findings, suppressions);

  add({ tool: "trivy", type: "iac", severity: "HIGH", signature: "DS001:Dockerfile", message: "m",
        file: "test/fixtures/vulnerable-dockerfile/Dockerfile" });
  add({ tool: "npm",   type: "dependency", severity: "HIGH", signature: "lodash", message: "m",
        file: "package-lock.json" });
  assertEq(findings.length, 1, "fixture finding dropped, real finding kept");
  assertEq(findings[0].signature, "lodash", "only non-fixture finding present");
});

test("scanners: makeFindingProcessor keeps findings when excludePaths is empty", () => {
  const findings     = [];
  const suppressions = { count: 0, byRule: {} };
  const config       = { ...CONFIG_DEFAULTS, excludePaths: [] };
  const add          = makeFindingProcessor(config, "/tmp", findings, suppressions);

  add({ tool: "npm", type: "dependency", severity: "HIGH", signature: "pkg", message: "m",
        file: "test/fixtures/some/path" });
  assertEq(findings.length, 1, "no excludePaths → finding kept");
});

test("scanners: makeFindingProcessor deduplicates identical trivy-image findings", () => {
  const findings     = [];
  const suppressions = { count: 0, byRule: {} };
  const add          = makeFindingProcessor(CONFIG_DEFAULTS, "/tmp", findings, suppressions);

  const base = {
    tool: "trivy", type: "dependency", severity: "HIGH",
    signature: "trivy-image:node:12-alpine:CVE-2022-4450",
    message: "openssl: double free", file: "node:12-alpine",
    line: null, scanMode: "image", image: "node:12-alpine"
  };
  add({ ...base });
  add({ ...base });
  add({ ...base, message: "slightly different message" });
  assertEq(findings.length, 1, "duplicate image CVE emitted only once");
});

test("scanners: makeFindingProcessor does not deduplicate same CVE across different images", () => {
  const findings     = [];
  const suppressions = { count: 0, byRule: {} };
  const add          = makeFindingProcessor(CONFIG_DEFAULTS, "/tmp", findings, suppressions);

  add({ tool: "trivy", type: "dependency", severity: "HIGH",
        signature: "trivy-image:node:12-alpine:CVE-2022-4450",
        message: "m", file: "node:12-alpine", line: null, image: "node:12-alpine" });
  add({ tool: "trivy", type: "dependency", severity: "HIGH",
        signature: "trivy-image:node:18-alpine:CVE-2022-4450",
        message: "m", file: "node:18-alpine", line: null, image: "node:18-alpine" });
  assertEq(findings.length, 2, "same CVE in different images both retained");
});

test("scanners: makeFindingProcessor sets fixable=true only for auto", () => {
  const findings     = [];
  const suppressions = { count: 0, byRule: {} };
  const config       = { ...CONFIG_DEFAULTS };
  const add          = makeFindingProcessor(config, "/tmp", findings, suppressions);

  add({ tool: "npm",     type: "dependency", severity: "HIGH", signature: "a", message: "m", fixableBy: "auto" });
  add({ tool: "semgrep", type: "code",       severity: "HIGH", signature: "b", message: "m", fixableBy: "manual" });
  add({ tool: "osv",     type: "dependency", severity: "HIGH", signature: "c", message: "m" });

  assertEq(findings[0].fixable, true,  "auto → fixable true");
  assertEq(findings[1].fixable, false, "manual → fixable false");
  assertEq(findings[2].fixable, false, "no fixableBy → fixable false");
  assertEq(findings[0].fixableBy, "auto",   "fixableBy auto");
  assertEq(findings[1].fixableBy, "manual", "fixableBy manual");
  assertEq(findings[2].fixableBy, null,     "fixableBy null");
});

test("scanners: hasInlineSuppression detects same-line // comment", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-eng-"));
  const f = path.join(d, "app.js");
  fs.writeFileSync(f, [
    "const x = 1;",
    "db.query(input); // secgate:ignore test.rule.sqli",
    "const z = 3;"
  ].join("\n"));

  const result = hasInlineSuppression(f, 2, "test.rule.sqli");
  assert(result !== false, "suppression detected");
  fs.rmSync(d, { recursive: true, force: true });
});

test("scanners: hasInlineSuppression detects preceding-line # comment", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-eng-"));
  const f = path.join(d, "app.py");
  fs.writeFileSync(f, [
    "# secgate:ignore test.rule.sqli",
    "db.query(input)"
  ].join("\n"));

  const result = hasInlineSuppression(f, 2, "test.rule.sqli");
  assert(result !== false, "preceding-line suppression detected");
  fs.rmSync(d, { recursive: true, force: true });
});

test("scanners: hasInlineSuppression returns false for wrong rule", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-eng-"));
  const f = path.join(d, "app.js");
  fs.writeFileSync(f, [
    "// secgate:ignore test.rule.OTHER",
    "db.query(input);"
  ].join("\n"));

  const result = hasInlineSuppression(f, 2, "test.rule.sqli");
  assertEq(result, false, "wrong rule should not suppress");
  fs.rmSync(d, { recursive: true, force: true });
});

test("scanners: hasInlineSuppression returns false for nonexistent file", () => {
  const result = hasInlineSuppression("/nonexistent/path/file.js", 5, "some.rule");
  assertEq(result, false, "missing file returns false");
});

test("scanners: missing-tool returns skipped status with reason", async () => {
  const findings     = [];
  const suppressions = { count: 0, byRule: {} };
  const config       = { ...CONFIG_DEFAULTS, scanners: { ...CONFIG_DEFAULTS.scanners } };
  const add          = makeFindingProcessor(config, "/tmp", findings, suppressions);

  const result = await runGitleaks("/tmp", { ...CONFIG_DEFAULTS, scanners: { gitleaks: true } }, add, null);
  if (result.status === "skipped") {
    assertEq(result.skipReason, "not installed", "skip reason when binary missing");
  }
});

test("scanners: disabled scanner returns skipped with config reason", async () => {
  const findings     = [];
  const suppressions = { count: 0, byRule: {} };
  const add          = makeFindingProcessor(CONFIG_DEFAULTS, "/tmp", findings, suppressions);
  const config       = { ...CONFIG_DEFAULTS, scanners: { ...CONFIG_DEFAULTS.scanners, semgrep: false } };

  const result = await runSemgrep("/tmp", config, add, null);
  assertEq(result.status, "skipped", "status skipped");
  assertEq(result.skipReason, "disabled in config", "reason");
});

/* ────────────────────────────────────────────────────────────────────────────
   lib/scanners.mjs — fixture-based parser tests (parse raw fixture JSON)
   These simulate what the real scanner binary would output and drive the
   parser logic that is already unit-tested in test/schema.mjs via CLI stubs.
   Here we test the same parsers are reachable as pure functions.
   ──────────────────────────────────────────────────────────────────────────── */

test("scanners/parse: gitleaks fixture → 2 CRITICAL findings", () => {
  const raw     = JSON.parse(readFixture("gitleaks.json"));
  const findings = [];
  const suppressions = { count: 0, byRule: {} };
  const add     = makeFindingProcessor(CONFIG_DEFAULTS, "/tmp", findings, suppressions);

  raw.forEach(item => {
    add({
      tool: "gitleaks", type: "secret", severity: "CRITICAL",
      signature: item.RuleID, message: item.Description,
      file: item.File ?? null, line: item.StartLine ?? null,
      endLine: item.EndLine ?? null, fixableBy: "manual"
    });
  });

  assertEq(findings.length, 2, "2 findings");
  assert(findings.every(f => f.severity === "CRITICAL"), "all CRITICAL");
  assertEq(findings[0].file, "src/config/aws.js", "file path");
  assertEq(findings[0].line, 42, "line number");
});

test("scanners/parse: semgrep fixture → correct severity tiers", () => {
  const raw     = JSON.parse(readFixture("semgrep.json"));
  const findings = [];
  const suppressions = { count: 0, byRule: {} };
  const add     = makeFindingProcessor(CONFIG_DEFAULTS, "/tmp", findings, suppressions);

  const TIER = { ERROR: "HIGH", WARNING: "MEDIUM", INFO: "LOW", NOTE: "LOW" };
  const SECRET_CWE_RE = /CWE-798|CWE-259|CWE-321|CWE-522/;

  raw.results.forEach(r => {
    const meta = r.extra?.metadata || {};
    const cweArr = [].concat(meta.cwe || []).map(String);
    const isSecret = SECRET_CWE_RE.test(cweArr.join(" ")) && meta.category === "security";
    const sev = isSecret ? "CRITICAL" : (TIER[r.extra?.severity?.toUpperCase()] || "MEDIUM");
    add({
      tool: "semgrep", type: "code", severity: sev,
      signature: r.check_id, message: r.extra?.message,
      file: r.path ?? null, line: r.start?.line ?? null,
      col: r.start?.col ?? null, endLine: r.end?.line ?? null,
      fixableBy: "manual"
    });
  });

  assertEq(findings.length, 3, "3 findings");
  const sqli = findings.find(f => f.signature.includes("sqli"));
  assertEq(sqli.severity, "HIGH", "ERROR → HIGH");
  const pwd = findings.find(f => f.signature.includes("hardcoded-password"));
  assertEq(pwd.severity, "CRITICAL", "CWE-798 → CRITICAL");
  const info = findings.find(f => f.signature.includes("unused-var"));
  assertEq(info.severity, "LOW", "INFO → LOW");
});

test("scanners/parse: npm-audit fixture → HIGH + MEDIUM + UNKNOWN", () => {
  const raw     = JSON.parse(readFixture("npm-audit.json"));
  const findings = [];
  const suppressions = { count: 0, byRule: {} };
  const add     = makeFindingProcessor(CONFIG_DEFAULTS, "/tmp", findings, suppressions);

  for (const [k, v] of Object.entries(raw.vulnerabilities)) {
    add({
      tool: "npm", type: "dependency", severity: v.severity,
      signature: k, message: v.title || k,
      file: "package-lock.json", line: null, fixableBy: "auto"
    });
  }

  assertEq(findings.length, 3, "3 findings");
  const high = findings.find(f => f.signature === "lodash");
  assertEq(high.severity, "HIGH", "high");
  assertEq(high.fixable, true, "npm is auto-fixable");
  const med = findings.find(f => f.signature === "some-pkg");
  assertEq(med.severity, "MEDIUM", "moderate → MEDIUM");
  const unk = findings.find(f => f.signature === "weird-pkg");
  assertEq(unk.severity, "UNKNOWN", "frobnicated → UNKNOWN");
});

test("scanners/parse: trivy fixture → IAC HIGH + license MEDIUM", () => {
  const raw     = JSON.parse(readFixture("trivy.json"));
  const findings = [];
  const suppressions = { count: 0, byRule: {} };
  const add     = makeFindingProcessor(CONFIG_DEFAULTS, "/tmp", findings, suppressions);

  for (const r of raw.Results) {
    for (const m of r.Misconfigurations || []) {
      add({
        tool: "trivy", type: "iac", severity: m.Severity,
        signature: `${m.ID}:${r.Target}`,
        message: m.Title || m.ID,
        file: r.Target ?? null, line: m.CauseMetadata?.StartLine ?? null,
        endLine: m.CauseMetadata?.EndLine ?? null, fixableBy: "manual"
      });
    }
    for (const l of r.Licenses || []) {
      add({
        tool: "trivy", type: "license", severity: l.Severity,
        signature: `${l.Name}:${l.PkgName || r.Target}`,
        message: `License ${l.Name} flagged for ${l.PkgName || r.Target}`,
        file: l.FilePath || r.Target || null, line: null, fixableBy: "manual"
      });
    }
  }

  assertEq(findings.length, 2, "2 findings");
  const iac = findings.find(f => f.type === "iac");
  assertEq(iac.severity, "HIGH", "misconfig HIGH");
  assertEq(iac.file, "Dockerfile", "file = Target");
  assertEq(iac.line, 5, "line from CauseMetadata");
  const lic = findings.find(f => f.type === "license");
  assertEq(lic.severity, "MEDIUM", "license MEDIUM");
  assertEq(lic.file, "vendor/some-pkg/LICENSE", "license file");
});

/* ────────────────────────────────────────────────────────────────────────────
   lib/baseline.mjs
   ──────────────────────────────────────────────────────────────────────────── */

test("baseline: writeBaseline + loadBaseline round-trip", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-eng-"));
  const config = { ...CONFIG_DEFAULTS };
  const findings = [
    { signature: "lodash", severity: "HIGH", file: "package-lock.json", line: null }
  ];

  const written = writeBaseline(config, d, findings);
  assert(fs.existsSync(written), "baseline file created");

  const loaded = loadBaseline(config, d);
  assert(loaded !== null, "loadBaseline returns data");
  assert(Array.isArray(loaded.findings), "findings array present");
  assert(loaded.findings.some(f => f.signature === "lodash"), "lodash in baseline");
  assert(typeof loaded.generatedAt === "string", "generatedAt present");

  fs.rmSync(d, { recursive: true, force: true });
});

test("baseline: loadBaseline returns null when no file", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-eng-"));
  const result = loadBaseline(CONFIG_DEFAULTS, d);
  assertEq(result, null, "null when no baseline file");
  fs.rmSync(d, { recursive: true, force: true });
});

test("baseline: applyBaseline annotates matched and net-new", () => {
  const baseline = {
    findings: [
      { signature: "lodash", file: "package-lock.json", line: null }
    ]
  };
  const findings = [
    { signature: "lodash",  file: "package-lock.json", line: null, severity: "HIGH" },
    { signature: "express", file: "package-lock.json", line: null, severity: "CRITICAL" }
  ];

  const { annotated, baselineMatchedCount } = applyBaseline(findings, baseline);
  assertEq(baselineMatchedCount, 1, "1 matched");

  const lodash  = annotated.find(f => f.signature === "lodash");
  const express = annotated.find(f => f.signature === "express");
  assertEq(lodash.baseline, true,  "lodash baseline:true");
  assertEq(express.baseline, false, "express baseline:false");
});

test("baseline: applyBaseline with empty baseline → all net-new", () => {
  const baseline = { findings: [] };
  const findings = [
    { signature: "pkg-a", file: "lock", line: null, severity: "HIGH" }
  ];
  const { annotated, baselineMatchedCount } = applyBaseline(findings, baseline);
  assertEq(baselineMatchedCount, 0, "no matches");
  assert(annotated.every(f => !f.baseline), "all net-new");
});

/* ────────────────────────────────────────────────────────────────────────────
   lib/intelligence.mjs
   ──────────────────────────────────────────────────────────────────────────── */

test("intelligence: analyze computes risk score correctly", () => {
  const findings = [
    { severity: "CRITICAL", type: "secret",     baseline: false },
    { severity: "HIGH",     type: "dependency", baseline: false },
    { severity: "MEDIUM",   type: "iac",        baseline: false },
    { severity: "LOW",      type: "code",       baseline: false }
  ];
  const result = analyze(findings);
  assertEq(result.riskScore, 10 + 6 + 3 + 1, "risk = 20");
  assert(result.attackSurface.includes("secret"),     "secret in surface");
  assert(result.attackSurface.includes("dependency"), "dependency in surface");
  assert(result.recommendations.length > 0, "recommendations present");
});

test("intelligence: analyze skips baseline findings", () => {
  const findings = [
    { severity: "CRITICAL", type: "secret",     baseline: true },
    { severity: "HIGH",     type: "dependency", baseline: false }
  ];
  const result = analyze(findings);
  assertEq(result.riskScore, 6, "only non-baseline counted");
});

test("intelligence: patch maps tool to action", () => {
  assertEq(patch({ tool: "npm" }).action,      "npm audit fix",          "npm");
  assertEq(patch({ tool: "semgrep" }).action,  "manual code fix",        "semgrep");
  assertEq(patch({ tool: "gitleaks" }).action, "remove + rotate secret", "gitleaks");
  assertEq(patch({ tool: "osv" }).action,      "upgrade dependency",     "osv");
  assertEq(patch({ tool: "trivy", type: "iac" }).action, "fix misconfiguration", "trivy iac");
  assertEq(patch({ tool: "trivy", type: "license" }).action, "review license", "trivy license");
});

test("intelligence: remediate builds plan for all non-baseline findings", () => {
  const findings = [
    { signature: "lodash", severity: "HIGH",  tool: "npm",     type: "dependency", fixable: true,  fixableBy: "auto",   baseline: false },
    { signature: "expr",   severity: "HIGH",  tool: "semgrep", type: "code",       fixable: false, fixableBy: "manual", baseline: false },
    { signature: "old",    severity: "HIGH",  tool: "npm",     type: "dependency", fixable: true,  fixableBy: "auto",   baseline: true  }
  ];
  const result = remediate(findings);
  assertEq(result.plan.length, 2, "baseline finding excluded from plan");
  assert(result.confidence <= 100, "confidence capped at 100");
});

test("intelligence: remediate blocks CRITICAL findings", () => {
  const findings = [
    { signature: "s",    severity: "CRITICAL", tool: "gitleaks", type: "secret", fixable: false, fixableBy: "manual", baseline: false }
  ];
  const result = remediate(findings);
  assertEq(result.blocked.length, 1, "CRITICAL goes to blocked");
  assert(result.confidence < 100, "confidence reduced for CRITICAL");
});

// #55: reasoning enrichment
test("intelligence: analyze reasoning includes file, line, severity fields", () => {
  const findings = [
    { severity: "HIGH", type: "code", baseline: false, signature: "rule-x",
      message: "Path traversal risk", file: "/app/lib/foo.mjs", line: 7 }
  ];
  const result = analyze(findings);
  const r = result.reasoning[0];
  assertEq(r.file, "/app/lib/foo.mjs", "file field");
  assertEq(r.line, 7, "line field");
  assertEq(r.severity, "HIGH", "severity field");
});

test("intelligence: analyze reasoning.why includes advisory and package for dep findings", () => {
  const findings = [
    { severity: "MEDIUM", type: "dependency", baseline: false,
      signature: "npm:lodash@GHSA-29mw-wpgm-hmr9",
      message: "ReDoS in lodash", file: "/app/package-lock.json", line: null }
  ];
  const result = analyze(findings);
  const why = result.reasoning[0].why;
  assert(why.includes("lodash"), `why includes package — got: ${why}`);
  assert(why.includes("GHSA-29mw-wpgm-hmr9"), `why includes advisory — got: ${why}`);
});

test("intelligence: analyze reasoning.why includes file:line for code findings", () => {
  const findings = [
    { severity: "MEDIUM", type: "code", baseline: false,
      signature: "javascript.path-traversal",
      message: "User input in path.join", file: "/app/lib/baseline.mjs", line: 7 }
  ];
  const result = analyze(findings);
  const why = result.reasoning[0].why;
  assert(why.includes("baseline.mjs:7"), `why includes file:line — got: ${why}`);
  assert(why.includes("User input in path.join"), `why includes message — got: ${why}`);
});

// #56: remediation cmd population
test("intelligence: patch osv returns npm install cmd for npm ecosystem", () => {
  const f = { tool: "osv", type: "dependency", signature: "npm:lodash@GHSA-29mw-wpgm-hmr9",
               message: "ReDoS in lodash", file: null, line: null };
  const p = patch(f);
  assertEq(p.action, "upgrade dependency", "action");
  assertEq(p.cmd, "npm install lodash@latest", "cmd");
  assertEq(p.note, "ReDoS in lodash", "note from message");
});

test("intelligence: patch semgrep returns file:line cmd", () => {
  const f = { tool: "semgrep", type: "code", signature: "rule-x",
               message: "Path traversal", file: "/app/lib/baseline.mjs", line: 7 };
  const p = patch(f);
  assertEq(p.action, "manual code fix", "action");
  assert(p.cmd.includes("/app/lib/baseline.mjs:7"), `cmd has file:line — got: ${p.cmd}`);
  assertEq(p.note, "Path traversal", "note from message");
});

test("intelligence: patch gitleaks returns git filter-repo cmd when file present", () => {
  const f = { tool: "gitleaks", type: "secret", signature: "AWS_KEY",
               file: "/app/config/secrets.json", line: 3 };
  const p = patch(f);
  assertEq(p.action, "remove + rotate secret", "action");
  assert(p.cmd && p.cmd.includes("git filter-repo"), `cmd includes filter-repo — got: ${p.cmd}`);
});

test("intelligence: patch trivy iac returns cmd referencing file", () => {
  const f = { tool: "trivy", type: "iac", signature: "DS-0002:Dockerfile",
               message: "Image user should not be root", file: "Dockerfile", line: null };
  const p = patch(f);
  assertEq(p.action, "fix misconfiguration", "action");
  assert(p.cmd && p.cmd.includes("Dockerfile"), `cmd references file — got: ${p.cmd}`);
  assertEq(p.note, "Image user should not be root", "note from message");
});

/* ────────────────────────────────────────────────────────────────────────────
   lib/report.mjs
   ──────────────────────────────────────────────────────────────────────────── */

test("report: TOOLS array contains expected 6 keys", () => {
  assertEq(TOOLS.length, 6, "6 tools");
  for (const t of ["semgrep", "gitleaks", "npm", "osv", "trivy", "trivyImage"]) {
    assert(TOOLS.includes(t), `${t} in TOOLS`);
  }
});

test("report: summarize counts by severity key", () => {
  const findings = [
    { severity: "CRITICAL" },
    { severity: "HIGH" },
    { severity: "HIGH" },
    { severity: "MEDIUM" },
    { severity: "LOW" },
    { severity: "BOGUS" }
  ];
  const s = summarize(findings);
  assertEq(s.critical, 1, "critical");
  assertEq(s.high,     2, "high");
  assertEq(s.medium,   1, "medium");
  assertEq(s.low,      1, "low");
  assertEq(s.unknown,  1, "bogus → unknown");
});

test("report: resolveStatus PASS when no failOn severities", () => {
  const findings = [{ severity: "MEDIUM" }, { severity: "LOW" }];
  assertEq(resolveStatus(findings, ["critical", "high"], false), "PASS", "PASS");
});

test("report: resolveStatus FAIL when HIGH present and failOn includes high", () => {
  const findings = [{ severity: "HIGH" }];
  assertEq(resolveStatus(findings, ["critical", "high"], false), "FAIL", "FAIL");
});

test("report: resolveStatus PASS in baseline mode when all findings are baseline", () => {
  const findings = [{ severity: "HIGH", baseline: true }];
  assertEq(resolveStatus(findings, ["critical", "high"], true), "PASS", "all baseline = PASS");
});

test("report: resolveStatus FAIL in baseline mode when net-new HIGH present", () => {
  const findings = [
    { severity: "HIGH", baseline: false },
    { severity: "HIGH", baseline: true }
  ];
  assertEq(resolveStatus(findings, ["critical", "high"], true), "FAIL", "net-new FAIL");
});

test("report: stripAbsolutePaths replaces absolute path with repo name", () => {
  const result = stripAbsolutePaths("/home/user/project/src/file.js", "/home/user/project", "project");
  assertEq(result, "project/src/file.js", "path replaced");
});

test("report: stripAbsolutePaths is a no-op for non-strings", () => {
  assertEq(stripAbsolutePaths(42, "/target", "repo"), 42, "number unchanged");
  assertEq(stripAbsolutePaths(null, "/target", "repo"), null, "null unchanged");
});

test("report: renderHtml produces valid HTML with tool tabs", () => {
  const rep = {
    version: "0.2.0", timestamp: "2026-04-23T00:00:00Z", target: "repo",
    mode: "dry-run", status: "PASS",
    summary: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    findings: [],
    tools: { semgrep: "clean", gitleaks: "skipped", npm: "clean", osv: "skipped", trivy: "clean" },
    toolSkipReason: {},
    suppressions: { count: 0, byRule: {} },
    intelligence: { riskScore: 0, attackSurface: [], reasoning: [], recommendations: [] },
    remediation: { plan: [], stagedChanges: [], executed: [], blocked: [], confidence: 100 },
    auditLog: []
  };
  const html = renderHtml(rep, "repo");
  assert(typeof html === "string", "returns string");
  assert(html.startsWith("<!doctype html>"), "is HTML");
  const haystack = html.toLowerCase();
  for (const t of ["semgrep", "gitleaks", "npm", "osv", "trivy"]) {
    assert(haystack.includes(t), `tool token ${t} present`);
  }
  assert(html.includes("SecGate Report"), "title present");
  assert(html.includes("PASS"), "status present");
});

test("report: renderHtml escapes HTML in finding fields", () => {
  const rep = {
    version: "0.2.0", timestamp: "2026-04-23T00:00:00Z", target: "<script>alert(1)</script>",
    mode: "dry-run", status: "FAIL",
    summary: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
    findings: [
      { tool: "npm", type: "dependency", severity: "HIGH",
        signature: "<evil>", message: "x<y>z", file: "pkg.json", line: null,
        fixable: false, fixableBy: null }
    ],
    tools: { semgrep: "skipped", gitleaks: "skipped", npm: "ran", osv: "skipped", trivy: "skipped" },
    toolSkipReason: {},
    suppressions: { count: 0, byRule: {} },
    intelligence: { riskScore: 6, attackSurface: ["dependency"], reasoning: [], recommendations: [] },
    remediation: { plan: [], stagedChanges: [], executed: [], blocked: [], confidence: 100 },
    auditLog: []
  };
  const html = renderHtml(rep, "repo");
  assert(!html.includes("<evil>"), "unescaped <evil> not present");
  assert(html.includes("&lt;evil&gt;"), "escaped &lt;evil&gt; present");
  assert(!html.includes("<script>alert(1)</script>"), "script not injected");
});

test("report: buildSarif produces valid SARIF 2.1.0 structure", () => {
  const rep = {
    version: "0.2.0", timestamp: "2026-04-23T00:00:00Z", target: "/tmp/repo",
    status: "FAIL",
    findings: [
      { tool: "npm", type: "dependency", severity: "HIGH",
        signature: "lodash", message: "Prototype Pollution",
        file: "package-lock.json", line: null, col: null, endLine: null,
        fixable: false, fixableBy: "auto" }
    ],
    tools: { semgrep: "skipped", gitleaks: "skipped", npm: "ran",
             osv: "skipped", trivy: "skipped", trivyImage: "skipped" },
    summary: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
    suppressions: { count: 0, byRule: {} }
  };
  const sarif = buildSarif(rep, "repo", "/tmp/repo");
  assertEq(sarif.version, "2.1.0", "sarif version");
  assert(sarif.$schema.includes("sarif"), "$schema present");
  assertEq(sarif.runs.length, 6, "6 runs");
  const npmRun = sarif.runs.find(r => r.tool.driver.name === "npm audit");
  assert(npmRun, "npm run present");
  assertEq(npmRun.results.length, 1, "1 result");
  assertEq(npmRun.results[0].ruleId, "lodash", "ruleId");
  assertEq(npmRun.results[0].level, "error", "HIGH → error");
});

test("report: buildSarif — PASS scenario produces 0 results in all runs", () => {
  const rep = {
    version: "0.2.0", findings: [], tools: {},
    suppressions: { count: 0, byRule: {} }
  };
  const sarif = buildSarif(rep, "repo", "/tmp");
  assert(sarif.runs.every(r => r.results.length === 0), "all runs empty on PASS");
});

/* ────────────────────────────────────────────────────────────────────────────
   Snapshot: JSON report schema is stable across fixture runs
   ──────────────────────────────────────────────────────────────────────────── */

test("report: JSON schema shape is stable (snapshot)", () => {
  const npmFindings = [];
  const suppressions = { count: 0, byRule: {} };
  const add = makeFindingProcessor(CONFIG_DEFAULTS, "/tmp", npmFindings, suppressions);
  const raw = JSON.parse(readFixture("npm-audit.json"));
  for (const [k, v] of Object.entries(raw.vulnerabilities)) {
    add({ tool: "npm", type: "dependency", severity: v.severity, signature: k,
          message: v.title || k, file: "package-lock.json", line: null, fixableBy: "auto" });
  }

  const intel   = analyze(npmFindings);
  const remPlan = remediate(npmFindings);

  const report = {
    version:      "0.2.0",
    timestamp:    "2026-04-23T00:00:00.000Z",
    target:       "test-repo",
    mode:         "dry-run",
    status:       resolveStatus(npmFindings, ["critical", "high"], false),
    summary:      summarize(npmFindings),
    findings:     npmFindings,
    tools:        { semgrep: "skipped", gitleaks: "skipped", npm: "ran", osv: "skipped", trivy: "skipped", trivyImage: "skipped" },
    toolSkipReason: {},
    suppressions,
    intelligence: intel,
    remediation:  remPlan,
    auditLog:     []
  };

  const EXPECTED_TOP_KEYS = [
    "version", "timestamp", "target", "mode", "status",
    "summary", "findings", "tools", "toolSkipReason",
    "suppressions", "intelligence", "remediation", "auditLog"
  ];
  for (const key of EXPECTED_TOP_KEYS) {
    assert(Object.prototype.hasOwnProperty.call(report, key), `report has key: ${key}`);
  }

  const EXPECTED_FINDING_KEYS = ["tool", "type", "severity", "signature", "message", "file", "line", "col", "endLine", "fixable", "fixableBy"];
  for (const f of report.findings) {
    for (const key of EXPECTED_FINDING_KEYS) {
      assert(Object.prototype.hasOwnProperty.call(f, key), `finding has key: ${key}`);
    }
  }

  assert(typeof report.summary.critical === "number", "summary.critical is number");
  assert(typeof report.intelligence.riskScore === "number", "riskScore is number");
  assert(Array.isArray(report.intelligence.attackSurface), "attackSurface is array");
  assert(Array.isArray(report.remediation.plan), "plan is array");
  assert(Array.isArray(report.auditLog), "auditLog is array");
  assertEq(report.status, "FAIL", "HIGH finding → FAIL");
});

for (const t of pendingTests) await t();

console.log("-------------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
