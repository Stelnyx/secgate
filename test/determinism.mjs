#!/usr/bin/env node
// Determinism contract: identical inputs MUST produce identical outputs.
//
// Aggregation is the chokepoint where five scanner outputs become one report.
// Map iteration order, Set insertion order, or implicit time-based fields
// could silently flake the output across reruns. This test pins every
// observable surface of the aggregation pipeline.
//
// Surfaces locked here:
//   1. makeFindingProcessor — dedup, suppression, severity-override, exclude-path
//   2. computeScore / computeToolScores
//   3. summarize / resolveStatus
//   4. JSON.stringify(findings) byte equality across two independent runs

import fs from "fs";
import os from "os";
import path from "path";
import { spawnSync } from "child_process";
import { fileURLToPath } from "url";

const libDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "lib");

const { makeFindingProcessor } = await import(`${libDir}/scanners.mjs`);
const { computeScore, computeToolScores } = await import(`${libDir}/score.mjs`);
const { summarize, resolveStatus, TOOLS } = await import(`${libDir}/report.mjs`);
const { CONFIG_DEFAULTS } = await import(`${libDir}/config.mjs`);

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
  if (a !== b) throw new Error(`${msg ?? "eq"}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

console.log("\nSecGate determinism tests");
console.log("-------------------------");

// Synthetic raw scanner outputs — deliberately mixed order, mixed severity
// casing, duplicate hits, suppression candidates, override candidates.
function rawFindings() {
  return [
    { tool: "semgrep",  type: "code",       severity: "high",     signature: "javascript.lang.security.eval-detected", message: "eval", file: "src/a.js", line: 12 },
    { tool: "gitleaks", type: "secret",     severity: "CRITICAL", signature: "aws-access-token",                       message: "AKIA…", file: ".env",     line: 3  },
    { tool: "npm",      type: "dependency", severity: "MEDIUM",   signature: "npm-audit.lodash",                       message: "ReDoS",  file: "package.json", line: null },
    { tool: "osv",      type: "dependency", severity: "Low",      signature: "GHSA-abcd-1234-efgh",                    message: "advisory", file: "package-lock.json", line: 220 },
    { tool: "trivy",    type: "iac",        severity: "MEDIUM",   signature: "AVD-AWS-0028",                            message: "S3 public",  file: "infra/s3.tf", line: 8 },
    { tool: "semgrep",  type: "code",       severity: "HIGH",     signature: "javascript.lang.security.eval-detected", message: "eval", file: "src/a.js", line: 12 },
    { tool: "trivy",    type: "license",    severity: "UNKNOWN",  signature: "license-LGPL-3.0",                        message: "license", file: null,        line: null }
  ];
}

const target = "/tmp/secgate-determinism-fixture";

function makeConfig() {
  return {
    ...CONFIG_DEFAULTS,
    severityOverrides: [
      { rule: "npm-audit.lodash", severity: "LOW" }
    ],
    ignore: ["license-LGPL-*"],
    excludePaths: []
  };
}

function runAggregation() {
  const findings = [];
  const suppressions = { count: 0, byRule: {} };
  const config = makeConfig();
  const addFinding = makeFindingProcessor(config, target, findings, suppressions);
  for (const f of rawFindings()) addFinding(f);
  return { findings, suppressions };
}

/* ── findings array byte-equal across two runs ── */

test("determinism: makeFindingProcessor produces byte-identical findings on two runs", () => {
  const a = JSON.stringify(runAggregation().findings);
  const b = JSON.stringify(runAggregation().findings);
  assertEq(a, b, "JSON serialization equal");
});

test("determinism: dedup is order-stable (same signature+file+line collapses to one)", () => {
  const { findings } = runAggregation();
  const evalHits = findings.filter(f =>
    f.tool === "semgrep" &&
    f.signature === "javascript.lang.security.eval-detected" &&
    f.file === "src/a.js" &&
    f.line === 12
  );
  assertEq(evalHits.length, 1, "duplicate eval finding collapsed to one");
});

test("determinism: severity override applied identically each run", () => {
  const a = runAggregation().findings.find(f => f.signature === "npm-audit.lodash");
  const b = runAggregation().findings.find(f => f.signature === "npm-audit.lodash");
  assertEq(a.severity, "LOW", "lodash overridden to LOW");
  assertEq(b.severity, "LOW", "lodash overridden to LOW (second run)");
});

test("determinism: ignore glob drops the same finding each run", () => {
  const a = runAggregation().findings.find(f => f.signature === "license-LGPL-3.0");
  const b = runAggregation().findings.find(f => f.signature === "license-LGPL-3.0");
  assertEq(a, undefined, "LGPL license dropped (run 1)");
  assertEq(b, undefined, "LGPL license dropped (run 2)");
});

/* ── derived metrics ── */

test("determinism: computeScore equal across two runs", () => {
  const a = computeScore(runAggregation().findings);
  const b = computeScore(runAggregation().findings);
  assertEq(a, b, "score equal");
});

test("determinism: computeToolScores equal across two runs", () => {
  const a = JSON.stringify(computeToolScores(runAggregation().findings, TOOLS));
  const b = JSON.stringify(computeToolScores(runAggregation().findings, TOOLS));
  assertEq(a, b, "toolScores JSON equal");
});

test("determinism: summarize equal across two runs", () => {
  const a = JSON.stringify(summarize(runAggregation().findings));
  const b = JSON.stringify(summarize(runAggregation().findings));
  assertEq(a, b, "summary equal");
});

test("determinism: resolveStatus equal across two runs", () => {
  const failOn = ["critical", "high"];
  const a = resolveStatus(runAggregation().findings, failOn, false);
  const b = resolveStatus(runAggregation().findings, failOn, false);
  assertEq(a, b, "status equal");
});

/* ── input order independence (regression guard) ── */

test("determinism: reversing input order does not change deduped result set", () => {
  const forward = rawFindings();
  const reverse = [...forward].reverse();

  function aggregateFrom(raws) {
    const findings = [];
    const suppressions = { count: 0, byRule: {} };
    const addFinding = makeFindingProcessor(makeConfig(), target, findings, suppressions);
    for (const f of raws) addFinding(f);
    return findings;
  }

  // Sort by stable key — dedup keeps "first seen" so order matters for which
  // physical record wins, but the set of unique (tool, signature, file, line)
  // keys must be identical.
  function keys(arr) {
    return arr.map(f => `${f.tool}|${f.signature}|${f.file ?? ""}|${f.line ?? ""}`).sort();
  }

  const a = keys(aggregateFrom(forward));
  const b = keys(aggregateFrom(reverse));
  assertEq(JSON.stringify(a), JSON.stringify(b), "unique key set equal regardless of input order");
});

/* ── end-to-end: report files are byte-reproducible (issue #75) ── */
const bin = path.resolve(libDir, "..", "secgate.js");
// One fixed scan dir for every run: the report embeds the target path, so
// "same inputs" means the same directory.
const scan = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-det-scan-"));
fs.writeFileSync(path.join(scan, "package.json"), JSON.stringify({ name: "det-pkg", version: "1.0.0" }));
function runCli(env) {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-det-out-"));
  const childEnv = { ...process.env, ...env };
  delete childEnv.SECGATE_TIMESTAMP;
  delete childEnv.SOURCE_DATE_EPOCH;
  Object.assign(childEnv, env);
  const r = spawnSync("node", [bin, scan, "--output-dir", out], { encoding: "utf-8", env: childEnv, timeout: 120000 });
  const files = fs.existsSync(out) ? fs.readdirSync(out).sort() : [];
  const read = ext => {
    const f = files.find(n => n.endsWith(ext));
    return f ? fs.readFileSync(path.join(out, f)) : null;
  };
  const res = { status: r.status, stderr: r.stderr, json: read(".json"), html: read(".html") };
  fs.rmSync(out, { recursive: true, force: true });
  return res;
}
test("determinism: SECGATE_TIMESTAMP makes JSON and HTML byte-identical across runs", () => {
  const env = { SECGATE_TIMESTAMP: "2026-01-01T00:00:00Z" };
  const a = runCli(env);
  const b = runCli(env);
  assert(a.json && a.html && b.json && b.html, `report files written (exit ${a.status}): ${a.stderr.slice(0, 200)}`);
  assert(a.json.equals(b.json), "JSON reports are byte-identical");
  assert(a.html.equals(b.html), "HTML reports are byte-identical");
  const rep = JSON.parse(a.json.toString());
  assertEq(rep.timestamp, "2026-01-01T00:00:00.000Z", "report.timestamp");
  assert(rep.auditLog.every(e => e.timestamp === "2026-01-01T00:00:00.000Z"), "audit-log timestamps pinned");
});
test("determinism: SOURCE_DATE_EPOCH is the fallback, SECGATE_TIMESTAMP wins", () => {
  const a = runCli({ SOURCE_DATE_EPOCH: "1767225600" });
  assertEq(JSON.parse(a.json.toString()).timestamp, "2026-01-01T00:00:00.000Z", "epoch timestamp");
  const b = runCli({ SECGATE_TIMESTAMP: "2026-02-03T04:05:06Z", SOURCE_DATE_EPOCH: "1767225600" });
  assertEq(JSON.parse(b.json.toString()).timestamp, "2026-02-03T04:05:06.000Z", "explicit variable wins");
});
test("determinism: unparsable SECGATE_TIMESTAMP or SOURCE_DATE_EPOCH exits 2", () => {
  for (const env of [{ SECGATE_TIMESTAMP: "not-a-date" }, { SOURCE_DATE_EPOCH: "abc" }]) {
    const r = runCli(env);
    assertEq(r.status, 2, `exit code for ${JSON.stringify(env)}`);
    assert(/SECGATE_TIMESTAMP|SOURCE_DATE_EPOCH/.test(r.stderr), "error names the variable");
  }
});
test("determinism: without the variables, timestamp is wall-clock", () => {
  const a = runCli({});
  const t = Date.parse(JSON.parse(a.json.toString()).timestamp);
  assert(Math.abs(Date.now() - t) < 300000, "timestamp is current time");
});
fs.rmSync(scan, { recursive: true, force: true });
console.log("-------------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
