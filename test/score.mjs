#!/usr/bin/env node
// Unit tests for lib/score.mjs
// Covers: zero findings, single CRITICAL, boundary cases, floor at 0,
// determinism across two calls, per-tool breakdown.

import path from "path";
import { fileURLToPath } from "url";

const libDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "lib");

const {
  SCORE_VERSION,
  SEVERITY_PENALTY,
  computeScore,
  computeToolScores
} = await import(`${libDir}/score.mjs`);

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

function assertEq(a, b, msg) {
  if (a !== b) throw new Error(`${msg ?? "eq"}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

console.log("\nSecGate score unit tests");
console.log("------------------------");

/* ── SEVERITY_PENALTY constants ── */

test("SEVERITY_PENALTY: CRITICAL is 25", () => {
  assertEq(SEVERITY_PENALTY.CRITICAL, 25, "CRITICAL penalty");
});

test("SEVERITY_PENALTY: HIGH is 10", () => {
  assertEq(SEVERITY_PENALTY.HIGH, 10, "HIGH penalty");
});

test("SEVERITY_PENALTY: MEDIUM is 3", () => {
  assertEq(SEVERITY_PENALTY.MEDIUM, 3, "MEDIUM penalty");
});

test("SEVERITY_PENALTY: LOW is 1", () => {
  assertEq(SEVERITY_PENALTY.LOW, 1, "LOW penalty");
});

test("SEVERITY_PENALTY: INFO and UNKNOWN are 0", () => {
  assertEq(SEVERITY_PENALTY.INFO,    0, "INFO penalty");
  assertEq(SEVERITY_PENALTY.UNKNOWN, 0, "UNKNOWN penalty");
});

/* ── computeScore: baseline cases ── */

test("score: zero findings → 100", () => {
  assertEq(computeScore([]), 100, "empty = 100");
});

test("score: one CRITICAL → 75 (100 - 25)", () => {
  assertEq(computeScore([{ severity: "CRITICAL" }]), 75, "one CRITICAL");
});

test("score: one HIGH → 90 (100 - 10)", () => {
  assertEq(computeScore([{ severity: "HIGH" }]), 90, "one HIGH");
});

test("score: one MEDIUM → 97 (100 - 3)", () => {
  assertEq(computeScore([{ severity: "MEDIUM" }]), 97, "one MEDIUM");
});

test("score: one LOW → 99 (100 - 1)", () => {
  assertEq(computeScore([{ severity: "LOW" }]), 99, "one LOW");
});

test("score: INFO and UNKNOWN carry no penalty", () => {
  assertEq(computeScore([{ severity: "INFO" }, { severity: "UNKNOWN" }]), 100, "INFO+UNKNOWN = 100");
});

/* ── computeScore: boundary / combined ── */

test("score: 4 CRITICAL → floor at 0 (100 - 100 = 0)", () => {
  const findings = Array.from({ length: 4 }, () => ({ severity: "CRITICAL" }));
  assertEq(computeScore(findings), 0, "4 CRITICAL = 0");
});

test("score: floor never goes below 0 (5 CRITICAL would be -25 without floor)", () => {
  const findings = Array.from({ length: 5 }, () => ({ severity: "CRITICAL" }));
  assertEq(computeScore(findings), 0, "floor at 0");
});

test("score: mixed severities sum correctly", () => {
  const findings = [
    { severity: "CRITICAL" },
    { severity: "HIGH" },
    { severity: "MEDIUM" },
    { severity: "LOW" }
  ];
  // 100 - 25 - 10 - 3 - 1 = 61
  assertEq(computeScore(findings), 61, "mixed = 61");
});

test("score: case-insensitive severity input", () => {
  assertEq(computeScore([{ severity: "critical" }]), 75, "lowercase critical");
  assertEq(computeScore([{ severity: "High"    }]), 90, "mixed-case High");
});

test("score: missing/null severity treated as UNKNOWN (no penalty)", () => {
  assertEq(computeScore([{ severity: null }]),      100, "null severity");
  assertEq(computeScore([{ severity: undefined }]), 100, "undefined severity");
  assertEq(computeScore([{}]),                      100, "no severity key");
});

/* ── determinism ── */

test("score: deterministic — same input produces same score across two calls", () => {
  const findings = [
    { severity: "CRITICAL" },
    { severity: "HIGH" },
    { severity: "MEDIUM" }
  ];
  const a = computeScore(findings);
  const b = computeScore(findings);
  assertEq(a, b, "two calls equal");
  assertEq(a, 100 - 25 - 10 - 3, "correct value");
});

/* ── SCORE_VERSION ── */

test("SCORE_VERSION is 'v1'", () => {
  assertEq(SCORE_VERSION, "v1", "version string");
});

/* ── computeToolScores ── */

test("toolScores: each tool gets independent score", () => {
  const findings = [
    { severity: "CRITICAL", tool: "gitleaks" },
    { severity: "HIGH",     tool: "npm" },
    { severity: "MEDIUM",   tool: "semgrep" }
  ];
  const ts = computeToolScores(findings, ["semgrep", "gitleaks", "npm", "osv", "trivy"]);
  assertEq(ts.gitleaks, 75,  "gitleaks: one CRITICAL");
  assertEq(ts.npm,      90,  "npm: one HIGH");
  assertEq(ts.semgrep,  97,  "semgrep: one MEDIUM");
  assertEq(ts.osv,      100, "osv: no findings");
  assertEq(ts.trivy,    100, "trivy: no findings");
});

test("toolScores: tool with no findings is 100", () => {
  const ts = computeToolScores([], ["semgrep", "gitleaks", "npm", "osv", "trivy"]);
  for (const key of ["semgrep", "gitleaks", "npm", "osv", "trivy"]) {
    assertEq(ts[key], 100, `${key} = 100`);
  }
});

test("toolScores: tool floor at 0 (multiple CRITICAL)", () => {
  const findings = Array.from({ length: 5 }, () => ({ severity: "CRITICAL", tool: "semgrep" }));
  const ts = computeToolScores(findings, ["semgrep"]);
  assertEq(ts.semgrep, 0, "tool score floor = 0");
});

test("toolScores: tools that did not run score null, never 100", () => {
  const findings = [{ severity: "HIGH", tool: "gitleaks" }];
  const ts = computeToolScores(findings, ["semgrep", "gitleaks", "npm", "osv", "trivy"], ["semgrep", "osv"]);
  assertEq(ts.semgrep,  null, "semgrep not run → null");
  assertEq(ts.osv,      null, "osv not run → null");
  assertEq(ts.gitleaks, 90,   "gitleaks ran → scored");
  assertEq(ts.npm,      100,  "npm ran clean → 100");
});

console.log("------------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
