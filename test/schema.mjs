#!/usr/bin/env node
// Schema unit tests — drive each scanner parser with a stubbed binary that
// prints a fixture payload, then inspect secgate-v7-report.json.

import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");
const bin = path.join(repoRoot, "secgate.js");
const fixDir = path.join(here, "fixtures/schema");

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

/**
 * Run secgate.js against `scanDir` with a PATH prefixed by `stubDir`, so the
 * given scanner shims override the real binaries.
 */
function runWithStubs(scanDir, stubs) {
  const stubDir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-stubs-"));

  for (const [name, payload] of Object.entries(stubs)) {
    const p = path.join(stubDir, name);
    // Use a POSIX shell shim that prints the payload verbatim. Gitleaks
    // writes its report to --report-path instead, so its shim copies it there.
    const file = path.join(stubDir, `${name}.json`);
    fs.writeFileSync(file, payload);
    const body = name === "gitleaks"
      ? `while [ $# -gt 0 ]; do\n  if [ "$1" = "--report-path" ]; then cp ${JSON.stringify(file)} "$2"; fi\n  shift\ndone\nexit 1`
      : `cat ${JSON.stringify(file)}`;
    fs.writeFileSync(p, `#!/bin/sh\n${body}\n`);
    fs.chmodSync(p, 0o755);
  }

  // Also stub `which` lookups by making sure PATH starts with stubDir and
  // ensure `which`, `node`, `npm` come from the system. PATH prepend is enough.
  const env = {
    ...process.env,
    PATH: `${stubDir}:${process.env.PATH}`
  };

  let stdout = "";
  let code = 0;
  try {
    stdout = execFileSync("node", [bin, scanDir], {
      encoding: "utf-8",
      stdio: "pipe",
      cwd: scanDir,
      env
    });
  } catch (e) {
    code = e.status ?? 1;
    stdout = (e.stdout || "").toString();
  }

  const reportPath = path.join(scanDir, "secgate-v7-report.json");
  const report = JSON.parse(fs.readFileSync(reportPath, "utf-8"));

  // cleanup generated report + html
  try { fs.unlinkSync(reportPath); } catch {}
  try {
    const html = path.join(scanDir, `${path.basename(scanDir)}.html`);
    fs.unlinkSync(html);
  } catch {}
  fs.rmSync(stubDir, { recursive: true, force: true });

  return { code, stdout, report };
}

function scratchDir(suffix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), `secgate-${suffix}-`));
  return d;
}

function readFixture(name) {
  return fs.readFileSync(path.join(fixDir, name), "utf-8");
}

console.log("\nSecGate schema tests");
console.log("--------------------");

test("gitleaks: extracts file + line + CRITICAL severity", () => {
  const d = scratchDir("gitleaks");
  const { report } = runWithStubs(d, { gitleaks: readFixture("gitleaks.json") });
  const gl = report.findings.filter(f => f.tool === "gitleaks");
  assertEq(gl.length, 2, "gitleaks finding count");
  assertEq(gl[0].severity, "CRITICAL", "severity");
  assertEq(gl[0].file, "src/config/aws.js", "file");
  assertEq(gl[0].line, 42, "line");
  assertEq(gl[0].endLine, 42, "endLine");
  assertEq(gl[0].fixableBy, "manual", "fixableBy");
  assert(gl[0].fixable === false, "manual fixes should not be flagged fixable");
  fs.rmSync(d, { recursive: true, force: true });
});

test("semgrep: tiered severity, secret override, file/line/col", () => {
  const d = scratchDir("semgrep");
  // Pass --config=auto so semgrep stub ignores args; shim just prints fixture.
  const { report } = runWithStubs(d, { semgrep: readFixture("semgrep.json") });
  const sg = report.findings.filter(f => f.tool === "semgrep");
  assertEq(sg.length, 3, "semgrep finding count");

  const sqli = sg.find(f => f.signature.includes("sqli"));
  assertEq(sqli.severity, "HIGH", "ERROR → HIGH");
  assertEq(sqli.file, "src/db.js", "file");
  assertEq(sqli.line, 23, "line");
  assertEq(sqli.col, 5, "col");
  assertEq(sqli.endLine, 25, "endLine");

  const pwd = sg.find(f => f.signature.includes("hardcoded-password"));
  assertEq(pwd.severity, "CRITICAL", "hardcoded-password override to CRITICAL");
  assertEq(pwd.line, 8, "line");

  const info = sg.find(f => f.signature.includes("unused-var"));
  assertEq(info.severity, "LOW", "INFO → LOW");

  assert(sg.every(f => f.fixable === false), "semgrep must not be auto-fixable");
  fs.rmSync(d, { recursive: true, force: true });
});

test("osv: CVSS vector, database_specific, UNKNOWN fallback", () => {
  const d = scratchDir("osv");
  const { report } = runWithStubs(d, { "osv-scanner": readFixture("osv.json") });
  const osv = report.findings.filter(f => f.tool === "osv");
  assertEq(osv.length, 4, "osv finding count");

  const [crit, ddos, mod, unk] = [
    osv.find(f => f.signature.includes("GHSA-jf85-cpcp-j695")),
    osv.find(f => f.signature.includes("GHSA-xxxx-1234-v3v3")),
    osv.find(f => f.signature.includes("GHSA-low-rating")),
    osv.find(f => f.signature.includes("GHSA-unknown"))
  ];

  assertEq(crit.severity, "CRITICAL", "database_specific CRITICAL");
  assertEq(ddos.severity, "HIGH", "CVSS base 7.5 → HIGH");
  assertEq(mod.severity, "MEDIUM", "MODERATE → MEDIUM");
  assertEq(unk.severity, "UNKNOWN", "no info → UNKNOWN");

  for (const f of osv) {
    assertEq(f.file, "package-lock.json", "lock-file path on all osv findings");
    assert(f.fixable === false, "osv is not auto-fixable");
  }
  fs.rmSync(d, { recursive: true, force: true });
});

test("trivy: Target as file, CauseMetadata line", () => {
  const d = scratchDir("trivy");
  const { report } = runWithStubs(d, { trivy: readFixture("trivy.json") });
  const tr = report.findings.filter(f => f.tool === "trivy");
  assertEq(tr.length, 2, "trivy finding count");

  const mis = tr.find(f => f.type === "iac");
  assertEq(mis.severity, "HIGH", "misconfig severity");
  assertEq(mis.file, "Dockerfile", "file = Target");
  assertEq(mis.line, 5, "line from CauseMetadata");

  const lic = tr.find(f => f.type === "license");
  assertEq(lic.severity, "MEDIUM", "license severity");
  assertEq(lic.file, "vendor/some-pkg/LICENSE", "license file path");
  fs.rmSync(d, { recursive: true, force: true });
});

test("npm audit: lock-file path, auto fixable, unknown severity → UNKNOWN", () => {
  const d = scratchDir("npm");
  // npmAudit requires package.json in target.
  fs.writeFileSync(
    path.join(d, "package.json"),
    JSON.stringify({ name: "fx", version: "0.0.0" })
  );
  fs.writeFileSync(path.join(d, "package-lock.json"), "{}");

  const { report } = runWithStubs(d, { npm: readFixture("npm-audit.json") });
  const npm = report.findings.filter(f => f.tool === "npm");
  assertEq(npm.length, 3, "npm finding count");

  const high = npm.find(f => f.signature === "lodash");
  assertEq(high.severity, "HIGH", "high");
  assertEq(high.file, "package-lock.json", "lock file");
  assertEq(high.fixableBy, "auto", "fixableBy auto");
  assert(high.fixable === true, "fixable true for npm");

  const mod = npm.find(f => f.signature === "some-pkg");
  assertEq(mod.severity, "MEDIUM", "moderate → MEDIUM");

  const weird = npm.find(f => f.signature === "weird-pkg");
  assertEq(weird.severity, "UNKNOWN", "unknown upstream → UNKNOWN");

  assertEq(report.summary.unknown, 1, "unknown counter incremented");
  fs.rmSync(d, { recursive: true, force: true });
});

test("summary guards unexpected severity keys (no crash)", () => {
  const d = scratchDir("guard");
  fs.writeFileSync(
    path.join(d, "package.json"),
    JSON.stringify({ name: "fx", version: "0.0.0" })
  );
  const payload = JSON.stringify({
    vulnerabilities: {
      "foo": { name: "foo", severity: "bogus", title: "weird" }
    }
  });
  const { report } = runWithStubs(d, { npm: payload });
  assertEq(report.summary.unknown, 1, "unknown counter");
  assertEq(report.summary.critical, 0, "critical untouched");
  fs.rmSync(d, { recursive: true, force: true });
});

console.log("--------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
