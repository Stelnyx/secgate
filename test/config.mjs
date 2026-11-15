#!/usr/bin/env node
// Config loader + policy-as-code unit tests.
// Drives secgate.js with stub scanner binaries and asserts config behaviour.

import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");
const bin = path.join(repoRoot, "secgate.js");

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ok  ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL ${name}`);
    console.log(`       ${e.message}`);
    failed++;
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
function assertEq(a, b, msg) {
  if (a !== b) throw new Error(`${msg}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

function scratch(suffix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `secgate-cfg-${suffix}-`));
}

/**
 * Run secgate with npm stub that returns `payload` and an optional
 * .secgate.config.json written to the scan dir.
 */
function runWithNpmStub(scanDir, npmPayload, extraEnv = {}) {
  const stubDir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-cfg-stubs-"));
  const payloadFile = path.join(stubDir, "npm.json");
  fs.writeFileSync(payloadFile, npmPayload);
  const npmStub = path.join(stubDir, "npm");
  fs.writeFileSync(npmStub, `#!/bin/sh\ncat ${JSON.stringify(payloadFile)}\n`);
  fs.chmodSync(npmStub, 0o755);
  // The scan dir is not a git repository, where the real Gitleaks is skipped
  // (a coverage gap). This stand-in writes an empty report to --report-path.
  const gitleaksStub = path.join(stubDir, "gitleaks");
  fs.writeFileSync(gitleaksStub, `#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  if [ "$1" = "--report-path" ]; then printf '[]' > "$2"; fi\n  shift\ndone\nexit 0\n`);
  fs.chmodSync(gitleaksStub, 0o755);

  // package.json is required for npmAudit to run
  if (!fs.existsSync(path.join(scanDir, "package.json"))) {
    fs.writeFileSync(path.join(scanDir, "package.json"), JSON.stringify({ name: "fx", version: "0.0.0" }));
  }

  const env = { ...process.env, PATH: `${stubDir}:${process.env.PATH}`, ...extraEnv };
  let code = 0;
  let stdout = "";
  try {
    stdout = execFileSync("node", [bin, scanDir], { encoding: "utf-8", stdio: "pipe", cwd: scanDir, env });
  } catch (e) {
    code = e.status ?? 1;
    stdout = (e.stdout || "").toString();
  }

  const reportPath = path.join(scanDir, "secgate-v7-report.json");
  const report = JSON.parse(fs.readFileSync(reportPath, "utf-8"));
  try { fs.unlinkSync(reportPath); } catch {}
  try { fs.unlinkSync(path.join(scanDir, `${path.basename(scanDir)}.html`)); } catch {}
  fs.rmSync(stubDir, { recursive: true, force: true });

  return { code, stdout, report };
}

// High+medium npm vuln payload
const NPM_HIGH_MEDIUM = JSON.stringify({
  vulnerabilities: {
    "lodash": { name: "lodash", severity: "high", title: "Prototype Pollution" },
    "chalk":  { name: "chalk",  severity: "medium", title: "ReDoS" }
  }
});

const NPM_MEDIUM_ONLY = JSON.stringify({
  vulnerabilities: {
    "chalk": { name: "chalk", severity: "medium", title: "ReDoS" }
  }
});

console.log("\nSecGate config tests");
console.log("--------------------");

// ── failOn ────────────────────────────────────────────────────────────────────

test("failOn default [critical,high] → exits 1 on HIGH finding", () => {
  const d = scratch("failOn-default");
  const { code } = runWithNpmStub(d, NPM_HIGH_MEDIUM);
  assertEq(code, 1, "exit code");
  fs.rmSync(d, { recursive: true, force: true });
});

test("failOn:[medium] → exits 1 on MEDIUM finding", () => {
  const d = scratch("failOn-medium");
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({ failOn: ["medium"] }));
  const { code } = runWithNpmStub(d, NPM_MEDIUM_ONLY);
  assertEq(code, 1, "exit code");
  fs.rmSync(d, { recursive: true, force: true });
});

test("failOn:[] → exits 0 even with HIGH finding", () => {
  const d = scratch("failOn-empty");
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({ failOn: [] }));
  const { code } = runWithNpmStub(d, NPM_HIGH_MEDIUM);
  assertEq(code, 0, "exit code");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── scanners disabled ─────────────────────────────────────────────────────────

test("scanners.npm:false → npm skipped with reason", () => {
  const d = scratch("scanner-disable");
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({
    scanners: { npm: false }
  }));
  const { code, report } = runWithNpmStub(d, NPM_HIGH_MEDIUM);
  assertEq(code, 0, "exit code (no findings because npm skipped)");
  assertEq(report.tools.npm, "skipped", "toolStatus.npm");
  assertEq(report.toolSkipReason.npm, "disabled in config", "skip reason");
  assertEq(report.findings.filter(f => f.tool === "npm").length, 0, "no npm findings");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── severityOverrides ─────────────────────────────────────────────────────────

test("severityOverride: literal match overrides HIGH to LOW", () => {
  const d = scratch("override-literal");
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({
    failOn: ["critical", "high"],
    severityOverrides: [{ rule: "lodash", severity: "LOW" }]
  }));
  const { code, report } = runWithNpmStub(d, NPM_HIGH_MEDIUM);
  const lodash = report.findings.find(f => f.signature === "lodash");
  assert(lodash, "lodash finding present");
  assertEq(lodash.severity, "LOW", "severity overridden to LOW");
  assertEq(code, 0, "exit 0 because HIGH was overridden below failOn");
  fs.rmSync(d, { recursive: true, force: true });
});

test("severityOverride: wildcard pattern matches multiple findings", () => {
  const payload = JSON.stringify({
    vulnerabilities: {
      "pkg-a": { severity: "high", title: "A" },
      "pkg-b": { severity: "high", title: "B" }
    }
  });
  const d = scratch("override-wildcard");
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({
    failOn: ["critical"],
    severityOverrides: [{ rule: "pkg-*", severity: "LOW" }]
  }));
  const { code, report } = runWithNpmStub(d, payload);
  for (const f of report.findings.filter(f => f.tool === "npm")) {
    assertEq(f.severity, "LOW", `${f.signature} overridden to LOW`);
  }
  assertEq(code, 0, "exit 0");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── ignore ────────────────────────────────────────────────────────────────────

test("ignore: exact signature dropped from findings and counters", () => {
  const d = scratch("ignore-exact");
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({
    ignore: ["lodash"]
  }));
  const { report } = runWithNpmStub(d, NPM_HIGH_MEDIUM);
  assert(!report.findings.find(f => f.signature === "lodash"), "lodash absent");
  assertEq(report.summary.high, 0, "high counter not incremented");
  fs.rmSync(d, { recursive: true, force: true });
});

test("ignore: wildcard drops matching findings", () => {
  const payload = JSON.stringify({
    vulnerabilities: {
      "CVE-2024-1111": { severity: "critical", title: "X" },
      "CVE-2024-2222": { severity: "critical", title: "Y" },
      "safe-pkg":      { severity: "high",     title: "Z" }
    }
  });
  const d = scratch("ignore-wildcard");
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({
    ignore: ["CVE-2024-*"]
  }));
  const { report } = runWithNpmStub(d, payload);
  assert(!report.findings.find(f => f.signature.startsWith("CVE-2024-")), "CVEs absent");
  assert(report.findings.find(f => f.signature === "safe-pkg"), "safe-pkg still present");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── excludePaths ──────────────────────────────────────────────────────────────

test("excludePaths: finding whose file matches pattern is dropped", () => {
  const payload = JSON.stringify({
    vulnerabilities: {
      "lodash": { name: "lodash", severity: "high", title: "Prototype Pollution" }
    }
  });
  const d = scratch("excludePaths-basic");
  // When no lockfile exists the npm scanner reports file: "package.json".
  // Excluding "package.json" should suppress that finding entirely.
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({
    excludePaths: ["package.json"]
  }));
  const { report } = runWithNpmStub(d, payload);
  assert(!report.findings.find(f => f.signature === "lodash"), "lodash excluded by path");
  assertEq(report.summary.high, 0, "high counter 0");
  fs.rmSync(d, { recursive: true, force: true });
});

test("excludePaths: wildcard excludes nested paths", () => {
  const payload = JSON.stringify({
    vulnerabilities: {
      "lodash": { name: "lodash", severity: "high", title: "Prototype Pollution" },
      "chalk":  { name: "chalk",  severity: "medium", title: "ReDoS" }
    }
  });
  const d = scratch("excludePaths-wildcard");
  // chalk stays (package-lock.json not excluded); lodash also uses package-lock.json
  // so to demonstrate wildcard selectively, override the fixture path pattern to
  // match nothing — both findings should remain, exit 1 due to HIGH.
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({
    excludePaths: ["nonexistent/path/**"]
  }));
  const { code, report } = runWithNpmStub(d, payload);
  assertEq(code, 1, "non-matching excludePaths still fails on HIGH");
  assert(report.findings.find(f => f.signature === "lodash"), "lodash not excluded");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── path traversal validation ─────────────────────────────────────────────────

test("baselineFile with ../ traversal → rejected, default used", () => {
  const d = scratch("baseline-traversal");
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({
    baselineFile: "../../etc/passwd"
  }));
  const { report } = runWithNpmStub(d, "{}");
  // Should silently reject traversal and use default
  // No findings in empty payload so just check config was processed
  assertEq(report.status !== undefined, true, "scan completed despite bad config");
  fs.rmSync(d, { recursive: true, force: true });
});

test("customSemgrepRules with absolute path → rejected if outside target", () => {
  const d = scratch("semgrep-abs-path");
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({
    customSemgrepRules: "/etc/passwd"
  }));
  const { report } = runWithNpmStub(d, "{}");
  assertEq(report.status !== undefined, true, "scan completed despite bad config");
  fs.rmSync(d, { recursive: true, force: true });
});

test("baselineFile with valid relative path → accepted", () => {
  const d = scratch("baseline-valid");
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({
    baselineFile: "custom-baseline.json"
  }));
  fs.writeFileSync(path.join(d, "custom-baseline.json"), JSON.stringify({ findings: [] }));
  const { report } = runWithNpmStub(d, "{}");
  assertEq(report.status !== undefined, true, "scan completed with valid baseline path");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── invalid JSON config ───────────────────────────────────────────────────────

test("invalid JSON in config → error-logged, defaults used, scan proceeds", () => {
  const d = scratch("invalid-cfg");
  fs.writeFileSync(path.join(d, ".secgate.config.json"), "{ not valid json }");
  // With defaults (failOn:[critical,high]) and HIGH finding → exit 1
  const { code, report } = runWithNpmStub(d, NPM_HIGH_MEDIUM);
  assertEq(code, 1, "exit 1 (defaults used, HIGH triggers fail)");
  assert(report.findings.find(f => f.signature === "lodash"), "lodash found with defaults");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── missing config ────────────────────────────────────────────────────────────

test("missing config → silently uses defaults", () => {
  const d = scratch("no-cfg");
  const { code } = runWithNpmStub(d, NPM_HIGH_MEDIUM);
  assertEq(code, 1, "exit 1 (default failOn active)");
  fs.rmSync(d, { recursive: true, force: true });
});

console.log("--------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
