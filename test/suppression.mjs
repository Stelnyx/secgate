#!/usr/bin/env node
// Inline suppression tests.
// Uses semgrep stub so we can control file + line in the finding.

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
  return fs.mkdtempSync(path.join(os.tmpdir(), `secgate-sup-${suffix}-`));
}

/**
 * Build a semgrep JSON payload where finding is at `filePath`, `line`.
 */
function semgrepPayload(filePath, line, checkId = "test.rule.sqli", severity = "ERROR") {
  return JSON.stringify({
    results: [
      {
        check_id: checkId,
        path: filePath,
        start: { line, col: 1 },
        end: { line, col: 20 },
        extra: {
          severity,
          message: "Potential SQL injection",
          metadata: {}
        }
      }
    ],
    errors: []
  });
}

function runWithSemgrepStub(scanDir, semgrepPayloadStr) {
  const stubDir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-sup-stubs-"));
  const payloadFile = path.join(stubDir, "semgrep.json");
  fs.writeFileSync(payloadFile, semgrepPayloadStr);
  const stub = path.join(stubDir, "semgrep");
  fs.writeFileSync(stub, `#!/bin/sh\ncat ${JSON.stringify(payloadFile)}\n`);
  fs.chmodSync(stub, 0o755);
  // The scan dir is not a git repository, where the real Gitleaks is skipped
  // (a coverage gap). This stand-in writes an empty report to --report-path.
  const gitleaksStub = path.join(stubDir, "gitleaks");
  fs.writeFileSync(gitleaksStub, `#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  if [ "$1" = "--report-path" ]; then printf '[]' > "$2"; fi\n  shift\ndone\nexit 0\n`);
  fs.chmodSync(gitleaksStub, 0o755);

  const env = { ...process.env, PATH: `${stubDir}:${process.env.PATH}` };
  let code = 0;
  let stdout = "";
  try {
    stdout = execFileSync("node", [bin, scanDir], {
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
  fs.rmSync(stubDir, { recursive: true, force: true });
  return { code, stdout, report };
}

console.log("\nSecGate suppression tests");
console.log("-------------------------");

// ── hash-comment suppression (same line) ──────────────────────────────────────

test("# secgate:ignore on same line suppresses finding", () => {
  const d = scratch("hash-same");
  const srcFile = path.join(d, "app.js");
  // Rule ID is on line 3; suppression is also on line 3 (trailing comment).
  const src = [
    "const x = 1;",
    "const y = 2;",
    "db.query(input); // secgate:ignore test.rule.sqli",
    "const z = 3;"
  ].join("\n");
  fs.writeFileSync(srcFile, src);

  const { code, report } = runWithSemgrepStub(d, semgrepPayload(srcFile, 3));
  assertEq(code, 0, "exit 0 (suppressed)");
  assert(report, "report written");
  assertEq(report.findings.filter(f => f.tool === "semgrep").length, 0, "no semgrep findings");
  assertEq(report.suppressions.count, 1, "suppression counted");
  assert("test.rule.sqli" in report.suppressions.byRule, "byRule entry");
  assertEq(report.suppressions.byRule["test.rule.sqli"], 1, "byRule count");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── hash-comment suppression (line N-1) ───────────────────────────────────────

test("# secgate:ignore on preceding line suppresses finding", () => {
  const d = scratch("hash-prev");
  const srcFile = path.join(d, "app.js");
  const src = [
    "const x = 1;",
    "# secgate:ignore test.rule.sqli",
    "db.query(input);"
  ].join("\n");
  fs.writeFileSync(srcFile, src);

  const { code, report } = runWithSemgrepStub(d, semgrepPayload(srcFile, 3));
  assertEq(code, 0, "exit 0");
  assertEq(report.findings.filter(f => f.tool === "semgrep").length, 0, "no findings");
  assertEq(report.suppressions.count, 1, "suppression counted");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── C-style comment suppression ───────────────────────────────────────────────

test("/* secgate:ignore */ suppresses finding", () => {
  const d = scratch("cstyle");
  const srcFile = path.join(d, "app.js");
  const src = [
    "/* secgate:ignore test.rule.sqli */",
    "db.query(input);"
  ].join("\n");
  fs.writeFileSync(srcFile, src);

  const { code, report } = runWithSemgrepStub(d, semgrepPayload(srcFile, 2));
  assertEq(code, 0, "exit 0");
  assertEq(report.findings.filter(f => f.tool === "semgrep").length, 0, "no findings");
  assertEq(report.suppressions.count, 1, "suppression counted");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── slash-slash comment suppression ───────────────────────────────────────────

test("// secgate:ignore suppresses finding", () => {
  const d = scratch("slashslash");
  const srcFile = path.join(d, "app.js");
  const src = [
    "// secgate:ignore test.rule.sqli",
    "db.query(input);"
  ].join("\n");
  fs.writeFileSync(srcFile, src);

  const { code, report } = runWithSemgrepStub(d, semgrepPayload(srcFile, 2));
  assertEq(code, 0, "exit 0");
  assertEq(report.findings.filter(f => f.tool === "semgrep").length, 0, "no findings");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── wrong rule ID → NOT suppressed ────────────────────────────────────────────

test("suppression with wrong rule ID does not suppress finding", () => {
  const d = scratch("wrong-rule");
  const srcFile = path.join(d, "app.js");
  const src = [
    "// secgate:ignore test.rule.OTHER",
    "db.query(input);"
  ].join("\n");
  fs.writeFileSync(srcFile, src);

  const { code, report } = runWithSemgrepStub(d, semgrepPayload(srcFile, 2));
  assertEq(code, 1, "exit 1 (finding not suppressed)");
  assertEq(report.findings.filter(f => f.tool === "semgrep").length, 1, "finding present");
  assertEq(report.suppressions.count, 0, "no suppressions");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── suppression on line too far away → NOT suppressed ────────────────────────

test("suppression comment 2 lines before does not suppress", () => {
  const d = scratch("far-comment");
  const srcFile = path.join(d, "app.js");
  const src = [
    "// secgate:ignore test.rule.sqli",
    "const noop = 1;",
    "db.query(input);"   // line 3 — suppression is line 1, too far
  ].join("\n");
  fs.writeFileSync(srcFile, src);

  const { code, report } = runWithSemgrepStub(d, semgrepPayload(srcFile, 3));
  assertEq(code, 1, "exit 1 (suppression too far)");
  assertEq(report.findings.filter(f => f.tool === "semgrep").length, 1, "finding present");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── no file on finding → suppression skipped gracefully ──────────────────────

test("finding with no file path skips suppression check gracefully", () => {
  const d = scratch("no-file");
  // Payload references a non-existent absolute path → fs.readFileSync fails silently
  const payload = semgrepPayload("/nonexistent/path/that/does/not/exist.js", 5);
  const { report } = runWithSemgrepStub(d, payload);
  // No crash, finding is present (no suppression applied)
  assertEq(report.findings.filter(f => f.tool === "semgrep").length, 1, "finding present");
  assertEq(report.suppressions.count, 0, "no suppression counted");
  fs.rmSync(d, { recursive: true, force: true });
});

// ── suppression in JSON report ─────────────────────────────────────────────────

test("report.suppressions structure is correct", () => {
  const d = scratch("report-struct");
  const srcFile = path.join(d, "app.js");
  const src = [
    "// secgate:ignore test.rule.sqli",
    "db.query(input);"
  ].join("\n");
  fs.writeFileSync(srcFile, src);

  const { report } = runWithSemgrepStub(d, semgrepPayload(srcFile, 2));
  assert(typeof report.suppressions === "object", "suppressions object");
  assert(typeof report.suppressions.count === "number", "count is number");
  assert(typeof report.suppressions.byRule === "object", "byRule is object");
  fs.rmSync(d, { recursive: true, force: true });
});

console.log("-------------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
