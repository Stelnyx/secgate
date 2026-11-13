#!/usr/bin/env node
// Tests for no-lockfile policy finding emitted when package.json exists
// but no lockfile is present (npm audit returns ENOLOCK).

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

function scratchDir(suffix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `secgate-${suffix}-`));
}

function runWithStubs(scanDir, stubs) {
  const stubDir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-stubs-"));

  for (const [name, payload] of Object.entries(stubs)) {
    const p = path.join(stubDir, name);
    const file = path.join(stubDir, `${name}.json`);
    fs.writeFileSync(file, payload);
    fs.writeFileSync(p, `#!/bin/sh\ncat ${JSON.stringify(file)}\n`);
    fs.chmodSync(p, 0o755);
  }

  const fullEnv = {
    ...process.env,
    PATH: `${stubDir}:${process.env.PATH}`
  };

  let code = 0;
  let stdout = "";
  try {
    stdout = execFileSync("node", [bin, scanDir], {
      encoding: "utf-8",
      stdio: "pipe",
      cwd: scanDir,
      env: fullEnv
    });
  } catch (e) {
    code = e.status ?? 1;
    stdout = (e.stdout || "").toString();
  }

  const reportPath = path.join(scanDir, "secgate-v7-report.json");
  const report = JSON.parse(fs.readFileSync(reportPath, "utf-8"));

  try { fs.unlinkSync(reportPath); } catch {}
  try {
    const html = path.join(scanDir, `${path.basename(scanDir)}.html`);
    fs.unlinkSync(html);
  } catch {}
  fs.rmSync(stubDir, { recursive: true, force: true });

  return { code, stdout, report };
}

// npm audit ENOLOCK response shape
const ENOLOCK_PAYLOAD = JSON.stringify({
  error: {
    code: "ENOLOCK",
    summary: "This command requires an existing lockfile.",
    detail: "Try creating one first with: npm i --package-lock-only"
  }
});

console.log("\nSecGate no-lockfile tests");
console.log("-------------------------");

test("no-lockfile finding emitted with MEDIUM severity", () => {
  const d = scratchDir("nolockfile");
  fs.writeFileSync(
    path.join(d, "package.json"),
    JSON.stringify({ name: "test-pkg", version: "1.0.0" })
  );
  // No package-lock.json, yarn.lock, or npm-shrinkwrap.json

  const { report } = runWithStubs(d, { npm: ENOLOCK_PAYLOAD });

  const f = report.findings.find(x => x.signature === "no-lockfile");
  assert(f != null, "no-lockfile finding must be present");
  assertEq(f.severity, "MEDIUM", "severity must be MEDIUM");
  assertEq(f.tool, "secgate", "tool must be secgate");
  assertEq(f.type, "policy", "type must be policy");
  assertEq(f.file, "package.json", "file must be package.json");
  assertEq(f.fixableBy, "manual", "fixableBy must be manual");
  assert(
    f.message.includes("no lockfile"),
    `message should mention lockfile, got: ${f.message}`
  );

  fs.rmSync(d, { recursive: true, force: true });
});

test("no-lockfile finding increments medium counter", () => {
  const d = scratchDir("nolockfile-counter");
  fs.writeFileSync(
    path.join(d, "package.json"),
    JSON.stringify({ name: "test-pkg", version: "1.0.0" })
  );

  const { report } = runWithStubs(d, { npm: ENOLOCK_PAYLOAD });

  assert(report.summary.medium >= 1, `medium counter must be >= 1, got ${report.summary.medium}`);

  fs.rmSync(d, { recursive: true, force: true });
});

test("no-lockfile finding does not cause FAIL status (MEDIUM only)", () => {
  const d = scratchDir("nolockfile-status");
  fs.writeFileSync(
    path.join(d, "package.json"),
    JSON.stringify({ name: "test-pkg", version: "1.0.0" })
  );

  const { report } = runWithStubs(d, { npm: ENOLOCK_PAYLOAD });

  // MEDIUM alone does not FAIL; npm audit could not run, so it is not a PASS.
  assertEq(report.status, "INCOMPLETE", "no lockfile: npm audit did not run, so INCOMPLETE, not FAIL or PASS");

  fs.rmSync(d, { recursive: true, force: true });
});

test("npm status is skipped when ENOLOCK", () => {
  const d = scratchDir("nolockfile-toolstatus");
  fs.writeFileSync(
    path.join(d, "package.json"),
    JSON.stringify({ name: "test-pkg", version: "1.0.0" })
  );

  const { report } = runWithStubs(d, { npm: ENOLOCK_PAYLOAD });

  assertEq(report.tools.npm, "skipped", "npm toolStatus must be skipped on ENOLOCK");

  fs.rmSync(d, { recursive: true, force: true });
});

test("lockfile present → no no-lockfile finding", () => {
  const d = scratchDir("has-lockfile");
  fs.writeFileSync(
    path.join(d, "package.json"),
    JSON.stringify({ name: "test-pkg", version: "1.0.0" })
  );
  fs.writeFileSync(path.join(d, "package-lock.json"), "{}");

  // npm audit returns empty vulns (no ENOLOCK)
  const cleanAudit = JSON.stringify({ vulnerabilities: {} });
  const { report } = runWithStubs(d, { npm: cleanAudit });

  const f = report.findings.find(x => x.signature === "no-lockfile");
  assert(f == null, "no-lockfile finding must NOT be emitted when lockfile exists");

  fs.rmSync(d, { recursive: true, force: true });
});

test("no package.json → no no-lockfile finding", () => {
  const d = scratchDir("no-pkgjson");
  // No package.json at all

  const { report } = runWithStubs(d, { npm: ENOLOCK_PAYLOAD });

  const f = report.findings.find(x => x.signature === "no-lockfile");
  assert(f == null, "no-lockfile finding must NOT be emitted when package.json absent");
  assertEq(report.tools.npm, "skipped", "npm skipped when no package.json");

  fs.rmSync(d, { recursive: true, force: true });
});

console.log("-------------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
