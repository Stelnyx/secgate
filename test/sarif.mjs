#!/usr/bin/env node
// Unit tests for the SARIF 2.1.0 serializer.
// Runs the SARIF serializer by invoking secgate with --format sarif against a
// scratch directory with stubbed scanner binaries, then asserts structure.

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

// Synthetic findings payload for npm (simplest stub — needs package.json in dir).
const npmPayload = JSON.stringify({
  vulnerabilities: {
    "lodash": {
      name: "lodash",
      severity: "critical",
      title: "Prototype Pollution in lodash"
    },
    "axios": {
      name: "axios",
      severity: "high",
      title: "SSRF vulnerability in axios"
    },
    "minimist": {
      name: "minimist",
      severity: "medium",
      title: "Prototype Pollution in minimist"
    }
  }
});

// Semgrep payload with file/line/col data.
const semgrepPayload = JSON.stringify({
  results: [
    {
      check_id: "javascript.sqli.detected",
      path: "src/db.js",
      start: { line: 23, col: 5 },
      end: { line: 25, col: 10 },
      extra: {
        severity: "ERROR",
        message: "SQL injection detected",
        metadata: { category: "security" }
      }
    },
    {
      check_id: "javascript.hardcoded-password",
      path: "src/config.js",
      start: { line: 8, col: 1 },
      end: { line: 8, col: 30 },
      extra: {
        severity: "WARNING",
        message: "Hardcoded password found",
        metadata: {
          category: "security",
          cwe: ["CWE-259"]
        }
      }
    }
  ],
  errors: []
});

function runWithStubs(scanDir, stubs, args = []) {
  const stubDir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-sarif-stubs-"));

  for (const [name, payload] of Object.entries(stubs)) {
    const jsonFile = path.join(stubDir, `${name}.json`);
    fs.writeFileSync(jsonFile, payload);
    const shimPath = path.join(stubDir, name);
    fs.writeFileSync(shimPath, `#!/bin/sh\ncat ${JSON.stringify(jsonFile)}\n`);
    fs.chmodSync(shimPath, 0o755);
  }

  const env = { ...process.env, PATH: `${stubDir}:${process.env.PATH}` };

  let code = 0;
  try {
    execFileSync("node", [bin, scanDir, ...args], {
      encoding: "utf-8",
      stdio: "pipe",
      cwd: scanDir,
      env
    });
  } catch (e) {
    code = e.status ?? 1;
  }

  const dirName = path.basename(scanDir);
  const sarifPath = path.join(scanDir, `${dirName}.sarif.json`);
  const reportPath = path.join(scanDir, "secgate-v7-report.json");

  let sarif = null;
  if (fs.existsSync(sarifPath)) {
    sarif = JSON.parse(fs.readFileSync(sarifPath, "utf-8"));
  }

  try { fs.unlinkSync(reportPath); } catch {}
  try { fs.unlinkSync(sarifPath); } catch {}
  try { fs.unlinkSync(path.join(scanDir, `${dirName}.html`)); } catch {}
  fs.rmSync(stubDir, { recursive: true, force: true });

  return { code, sarif };
}

function scratchDir(suffix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `secgate-sarif-${suffix}-`));
}

console.log("\nSecGate SARIF tests");
console.log("-------------------");

test("SARIF file not written without --format sarif", () => {
  const d = scratchDir("no-sarif");
  fs.writeFileSync(path.join(d, "package.json"), JSON.stringify({ name: "fx", version: "0.0.0" }));
  const { sarif } = runWithStubs(d, { npm: npmPayload }, []);
  assert(sarif === null, "sarif file should not exist without --format sarif");
  fs.rmSync(d, { recursive: true, force: true });
});

test("SARIF file written with --format sarif", () => {
  const d = scratchDir("write");
  fs.writeFileSync(path.join(d, "package.json"), JSON.stringify({ name: "fx", version: "0.0.0" }));
  const { sarif } = runWithStubs(d, { npm: npmPayload }, ["--format", "sarif"]);
  assert(sarif !== null, "sarif file must be written");
  fs.rmSync(d, { recursive: true, force: true });
});

test("SARIF top-level: version 2.1.0 and $schema", () => {
  const d = scratchDir("toplevel");
  fs.writeFileSync(path.join(d, "package.json"), JSON.stringify({ name: "fx", version: "0.0.0" }));
  const { sarif } = runWithStubs(d, { npm: npmPayload }, ["--format", "sarif"]);
  assertEq(sarif.version, "2.1.0", "version");
  assert(typeof sarif.$schema === "string" && sarif.$schema.includes("sarif"), "$schema present");
  assert(Array.isArray(sarif.runs), "runs array");
  fs.rmSync(d, { recursive: true, force: true });
});

test("SARIF has one runs[] entry per scanner (6 total)", () => {
  const d = scratchDir("runs");
  fs.writeFileSync(path.join(d, "package.json"), JSON.stringify({ name: "fx", version: "0.0.0" }));
  const { sarif } = runWithStubs(d, { npm: npmPayload }, ["--format", "sarif"]);
  assertEq(sarif.runs.length, 6, "runs count");
  const names = sarif.runs.map(r => r.tool.driver.name);
  assert(names.includes("npm audit"), "npm run present");
  assert(names.includes("Semgrep"), "semgrep run present");
  assert(names.includes("Gitleaks"), "gitleaks run present");
  assert(names.includes("osv-scanner"), "osv run present");
  assert(names.includes("Trivy"), "trivy run present");
  fs.rmSync(d, { recursive: true, force: true });
});

test("SARIF tool.driver has name, version, informationUri", () => {
  const d = scratchDir("driver");
  fs.writeFileSync(path.join(d, "package.json"), JSON.stringify({ name: "fx", version: "0.0.0" }));
  const { sarif } = runWithStubs(d, { npm: npmPayload }, ["--format", "sarif"]);
  for (const run of sarif.runs) {
    const drv = run.tool.driver;
    assert(typeof drv.name === "string" && drv.name.length > 0, `name present: ${drv.name}`);
    assert(typeof drv.version === "string", `version is string: ${drv.name}`);
    assert(typeof drv.informationUri === "string", `informationUri: ${drv.name}`);
  }
  fs.rmSync(d, { recursive: true, force: true });
});

test("SARIF npm run: ruleId, level, message, properties.security-severity", () => {
  const d = scratchDir("npmrun");
  fs.writeFileSync(path.join(d, "package.json"), JSON.stringify({ name: "fx", version: "0.0.0" }));
  const { sarif } = runWithStubs(d, { npm: npmPayload }, ["--format", "sarif"]);
  const npmRun = sarif.runs.find(r => r.tool.driver.name === "npm audit");
  assert(npmRun.results.length === 3, `expected 3 npm results, got ${npmRun.results.length}`);

  const lodash = npmRun.results.find(r => r.ruleId === "lodash");
  assert(lodash !== undefined, "lodash result present");
  assertEq(lodash.level, "error", "CRITICAL → error");
  assert(typeof lodash.message.text === "string", "message.text");
  assertEq(lodash.properties["security-severity"], "9.5", "CRITICAL score 9.5");

  const axios = npmRun.results.find(r => r.ruleId === "axios");
  assertEq(axios.level, "error", "HIGH → error");
  assertEq(axios.properties["security-severity"], "7.5", "HIGH score 7.5");

  const minimist = npmRun.results.find(r => r.ruleId === "minimist");
  assertEq(minimist.level, "warning", "MEDIUM → warning");
  assertEq(minimist.properties["security-severity"], "5", "MEDIUM score 5");
  fs.rmSync(d, { recursive: true, force: true });
});

test("SARIF semgrep run: physicalLocation with file, startLine, startColumn, endLine", () => {
  const d = scratchDir("semgreprun");
  const { sarif } = runWithStubs(d, { semgrep: semgrepPayload }, ["--format", "sarif"]);
  const sgRun = sarif.runs.find(r => r.tool.driver.name === "Semgrep");
  assert(sgRun.results.length === 2, `expected 2 semgrep results, got ${sgRun.results.length}`);

  const sqli = sgRun.results.find(r => r.ruleId === "javascript.sqli.detected");
  assert(sqli !== undefined, "sqli result present");
  assertEq(sqli.level, "error", "HIGH → error");
  const loc = sqli.locations[0].physicalLocation;
  assertEq(loc.artifactLocation.uri, "src/db.js", "file uri");
  assertEq(loc.region.startLine, 23, "startLine");
  assertEq(loc.region.startColumn, 5, "startColumn");
  assertEq(loc.region.endLine, 25, "endLine");

  const pwd = sgRun.results.find(r => r.ruleId === "javascript.hardcoded-password");
  assertEq(pwd.level, "error", "CRITICAL → error");
  assertEq(pwd.properties["security-severity"], "9.5", "CRITICAL score");
  fs.rmSync(d, { recursive: true, force: true });
});

test("SARIF rules array deduplicates by ruleId", () => {
  const d = scratchDir("dedup");
  fs.writeFileSync(path.join(d, "package.json"), JSON.stringify({ name: "fx", version: "0.0.0" }));
  // npm payload has 3 distinct packages → 3 distinct rules
  const { sarif } = runWithStubs(d, { npm: npmPayload }, ["--format", "sarif"]);
  const npmRun = sarif.runs.find(r => r.tool.driver.name === "npm audit");
  const ruleIds = npmRun.tool.driver.rules.map(r => r.id);
  const unique = new Set(ruleIds);
  assertEq(unique.size, ruleIds.length, "no duplicate rule IDs");
  fs.rmSync(d, { recursive: true, force: true });
});

test("SARIF marks runs of scanners disabled by the target config (#84)", () => {
  const d = scratchDir("disabled");
  fs.writeFileSync(path.join(d, ".secgate.config.json"), JSON.stringify({ scanners: { semgrep: false } }));
  const { sarif } = runWithStubs(d, {}, ["--format", "sarif"]);
  const semgrepRun = sarif.runs.find(r => r.tool.driver.name === "Semgrep");
  const gitleaksRun = sarif.runs.find(r => r.tool.driver.name === "Gitleaks");
  assertEq(semgrepRun.properties.disabledByConfig, true, "semgrep disabledByConfig");
  assertEq(gitleaksRun.properties.disabledByConfig, undefined, "gitleaks has no disabledByConfig");
  fs.rmSync(d, { recursive: true, force: true });
});
test("SARIF LOW severity maps to level: note", () => {
  const lowPayload = JSON.stringify({
    results: [
      {
        check_id: "javascript.unused-var",
        path: "src/utils.js",
        start: { line: 10, col: 1 },
        end: { line: 10, col: 20 },
        extra: {
          severity: "INFO",
          message: "Unused variable",
          metadata: {}
        }
      }
    ],
    errors: []
  });
  const d = scratchDir("low");
  const { sarif } = runWithStubs(d, { semgrep: lowPayload }, ["--format", "sarif"]);
  const sgRun = sarif.runs.find(r => r.tool.driver.name === "Semgrep");
  const r = sgRun.results.find(r => r.ruleId === "javascript.unused-var");
  assertEq(r.level, "note", "LOW → note");
  assertEq(r.properties["security-severity"], "2", "LOW score 2");
  fs.rmSync(d, { recursive: true, force: true });
});

console.log("-------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
