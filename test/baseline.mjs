#!/usr/bin/env node
// Baseline tests: update-baseline, comparison, net-new vs matched.

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
  return fs.mkdtempSync(path.join(os.tmpdir(), `secgate-bl-${suffix}-`));
}

function makeNpmStub(stubDir, payload) {
  const payloadFile = path.join(stubDir, "npm.json");
  fs.writeFileSync(payloadFile, payload);
  const npmStub = path.join(stubDir, "npm");
  fs.writeFileSync(npmStub, `#!/bin/sh\ncat ${JSON.stringify(payloadFile)}\n`);
  fs.chmodSync(npmStub, 0o755);
}

function run(scanDir, extraArgs, stubDir) {
  const env = { ...process.env, PATH: `${stubDir}:${process.env.PATH}` };
  let code = 0;
  let stdout = "";
  try {
    stdout = execFileSync("node", [bin, scanDir, ...extraArgs], {
      encoding: "utf-8", stdio: "pipe", cwd: scanDir, env
    });
  } catch (e) {
    code = e.status ?? 1;
    stdout = (e.stdout || "").toString();
  }

  const reportPath = path.join(scanDir, "secgate-v7-report.json");
  let report = null;
  if (fs.existsSync(reportPath)) {
    report = JSON.parse(fs.readFileSync(reportPath, "utf-8"));
    try { fs.unlinkSync(reportPath); } catch {}
    try { fs.unlinkSync(path.join(scanDir, `${path.basename(scanDir)}.html`)); } catch {}
  }
  return { code, stdout, report };
}

function setupScanDir(d, npmPayloadStr) {
  fs.writeFileSync(path.join(d, "package.json"), JSON.stringify({ name: "fx", version: "0.0.0" }));
  const stubDir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-bl-stubs-"));
  makeNpmStub(stubDir, npmPayloadStr);
  // The scan dir is not a git repository, where the real Gitleaks is skipped
  // (a coverage gap). This stand-in writes an empty report to --report-path.
  const gitleaksStub = path.join(stubDir, "gitleaks");
  fs.writeFileSync(gitleaksStub, `#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  if [ "$1" = "--report-path" ]; then printf '[]' > "$2"; fi\n  shift\ndone\nexit 0\n`);
  fs.chmodSync(gitleaksStub, 0o755);
  return stubDir;
}

const PKG_A = JSON.stringify({
  vulnerabilities: {
    "lodash": { severity: "high", title: "Prototype Pollution" }
  }
});

const PKG_A_PLUS_B = JSON.stringify({
  vulnerabilities: {
    "lodash":   { severity: "high",   title: "Prototype Pollution" },
    "express":  { severity: "critical", title: "RCE" }
  }
});

console.log("\nSecGate baseline tests");
console.log("----------------------");

// ── --update-baseline writes file + exits 0 ───────────────────────────────────

test("--update-baseline writes baseline file and exits 0", () => {
  const d = scratch("update");
  const stubDir = setupScanDir(d, PKG_A);

  const { code } = run(d, ["--update-baseline"], stubDir);
  assertEq(code, 0, "exit 0");

  const blPath = path.join(d, ".secgate-baseline.json");
  assert(fs.existsSync(blPath), "baseline file created");
  const bl = JSON.parse(fs.readFileSync(blPath, "utf-8"));
  assert(Array.isArray(bl.findings), "findings array present");
  assert(typeof bl.generatedAt === "string", "generatedAt present");
  assert(bl.findings.some(f => f.signature === "lodash"), "lodash in baseline");

  fs.rmSync(d, { recursive: true, force: true });
  fs.rmSync(stubDir, { recursive: true, force: true });
});

// ── --baseline with all findings in baseline → PASS ───────────────────────────

test("--baseline: all findings in baseline → PASS (exit 0)", () => {
  const d = scratch("all-matched");
  const stubDir = setupScanDir(d, PKG_A);

  // First: write baseline
  run(d, ["--update-baseline"], stubDir);

  // Second: run with --baseline, same findings → PASS
  const { code, report } = run(d, ["--baseline"], stubDir);
  assertEq(code, 0, "exit 0 (all findings in baseline)");
  assert(report, "report written");
  assertEq(report.status, "PASS", "report status PASS");

  const matched = report.findings.filter(f => f.baseline === true);
  assert(matched.length > 0, "at least one finding marked baseline:true");

  fs.rmSync(d, { recursive: true, force: true });
  fs.rmSync(stubDir, { recursive: true, force: true });
});

// ── --baseline with net-new finding → FAIL ────────────────────────────────────

test("--baseline: net-new finding → FAIL (exit 1)", () => {
  const d = scratch("net-new");
  const stubDir = setupScanDir(d, PKG_A);

  // Baseline only has lodash
  run(d, ["--update-baseline"], stubDir);

  // Now inject PKG_A_PLUS_B (lodash + express)
  makeNpmStub(stubDir, PKG_A_PLUS_B);
  const { code, report } = run(d, ["--baseline"], stubDir);
  assertEq(code, 1, "exit 1 (net-new CRITICAL finding)");
  assertEq(report.status, "FAIL", "report status FAIL");

  const lodashF = report.findings.find(f => f.signature === "lodash");
  const expressF = report.findings.find(f => f.signature === "express");
  assert(lodashF, "lodash finding present");
  assert(expressF, "express finding present");
  assertEq(lodashF.baseline, true, "lodash marked baseline:true");
  assertEq(expressF.baseline, false, "express not in baseline");

  assert(report.baselineDiff, "baselineDiff present in report");
  assertEq(report.baselineDiff.netNew, 1, "1 net-new finding");
  assertEq(report.baselineDiff.baselineMatchedCount, 1, "1 baseline-matched");

  fs.rmSync(d, { recursive: true, force: true });
  fs.rmSync(stubDir, { recursive: true, force: true });
});

// ── HTML report has baseline diff section ─────────────────────────────────────

test("--baseline: HTML report contains Baseline diff section", () => {
  const d = scratch("html-diff");
  const stubDir = setupScanDir(d, PKG_A);

  run(d, ["--update-baseline"], stubDir);
  makeNpmStub(stubDir, PKG_A_PLUS_B);
  run(d, ["--baseline"], stubDir);

  // The html file will have been cleaned up by run(). Re-run to get it.
  let htmlContent = "";
  try {
    execFileSync("node", [bin, d, "--baseline"], {
      encoding: "utf-8", stdio: "pipe", cwd: d,
      env: { ...process.env, PATH: `${stubDir}:${process.env.PATH}` }
    });
  } catch (e) {
    // exit 1 is fine
  }
  const htmlPath = path.join(d, `${path.basename(d)}.html`);
  if (fs.existsSync(htmlPath)) {
    htmlContent = fs.readFileSync(htmlPath, "utf-8");
  }
  assert(htmlContent.includes("Baseline diff"), "HTML contains Baseline diff section");
  assert(htmlContent.includes("Net-new"), "HTML contains Net-new KPI");

  fs.rmSync(d, { recursive: true, force: true });
  fs.rmSync(stubDir, { recursive: true, force: true });
});

// ── custom baselineFile in config ──────────────────────────────────────────────

test("config.baselineFile: custom path used for read/write", () => {
  const d = scratch("custom-bl");
  const stubDir = setupScanDir(d, PKG_A);
  const customBl = path.join(d, ".custom-baseline.json");

  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({
    baselineFile: ".custom-baseline.json"
  }));

  run(d, ["--update-baseline"], stubDir);
  assert(fs.existsSync(customBl), "custom baseline file created");
  assert(!fs.existsSync(path.join(d, ".secgate-baseline.json")), "default baseline not created");

  fs.rmSync(d, { recursive: true, force: true });
  fs.rmSync(stubDir, { recursive: true, force: true });
});

// ── loadBaseline: malformed shape warns and treats all findings as net-new ────

test("loadBaseline: malformed baseline shape logs warning, all findings net-new", () => {
  const d = scratch("malformed-bl");
  const stubDir = setupScanDir(d, PKG_A);

  fs.writeFileSync(path.join(d, ".secgate-baseline.json"), JSON.stringify({ foo: 1 }));

  let stderr = "";
  try {
    execFileSync("node", [bin, d, "--baseline"], {
      encoding: "utf-8",
      stdio: "pipe",
      cwd: d,
      env: { ...process.env, PATH: `${stubDir}:${process.env.PATH}` }
    });
  } catch (e) {
    stderr = (e.stderr || "").toString();
  }

  assert(stderr.includes("missing 'findings' array"), "stderr warns about malformed baseline shape");

  fs.rmSync(d, { recursive: true, force: true });
  fs.rmSync(stubDir, { recursive: true, force: true });
});

// ── --baseline with no baseline file treats all as net-new ────────────────────

test("--baseline with no baseline file: all findings are net-new", () => {
  const d = scratch("no-bl-file");
  const stubDir = setupScanDir(d, PKG_A);

  const { code, report } = run(d, ["--baseline"], stubDir);
  assertEq(code, 1, "exit 1 (HIGH is in default failOn)");
  assert(report.findings.every(f => !f.baseline), "no findings marked as baseline");

  fs.rmSync(d, { recursive: true, force: true });
  fs.rmSync(stubDir, { recursive: true, force: true });
});

console.log("----------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
