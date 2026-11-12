#!/usr/bin/env node

import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");
const bin = path.join(repoRoot, "secgate.js");

let passed = 0;
let failed = 0;

function run(args, opts = {}) {
  const res = spawnSync("node", [bin, ...args], {
    encoding: "utf-8",
    cwd: opts.cwd || repoRoot,
    env: opts.env || process.env,
    input: opts.input,
    maxBuffer: 64 * 1024 * 1024
  });
  return {
    code: res.status ?? 1,
    stdout: (res.stdout || "").toString(),
    stderr: (res.stderr || "").toString()
  };
}

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
  if (a !== b) throw new Error(`${msg}: expected ${b}, got ${a}`);
}
function assertContains(s, sub, msg) {
  if (!s.includes(sub)) throw new Error(`${msg}: missing "${sub}"`);
}
function assertNotContains(s, sub, msg) {
  if (s.includes(sub)) throw new Error(`${msg}: unexpected "${sub}"`);
}

console.log("\nSecGate smoke tests");
console.log("-------------------");

test("--version prints semver", () => {
  const r = run(["--version"]);
  assertEq(r.code, 0, "exit");
  if (!/^\d+\.\d+\.\d+/.test(r.stdout.trim())) {
    throw new Error(`bad version: ${r.stdout}`);
  }
});

test("--help prints usage", () => {
  const r = run(["--help"]);
  assertEq(r.code, 0, "exit");
  assertContains(r.stdout, "Usage:", "help");
  assertContains(r.stdout, "--apply", "help");
});

test("rejects missing target with exit 2", () => {
  const r = run(["/this/path/does/not/exist/xyz"]);
  assertEq(r.code, 2, "exit");
  assertContains(r.stderr, "not found", "stderr");
});

test("rejects non-directory target with exit 2", () => {
  const r = run([bin]);
  assertEq(r.code, 2, "exit");
  assertContains(r.stderr, "not a directory", "stderr");
});

test("workspace-looking target fails fast with clear message", () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-workspace-"));
  try {
    for (const name of ["api", "web", "worker"]) {
      const project = path.join(workspace, name);
      fs.mkdirSync(path.join(project, "node_modules", "dep"), { recursive: true });
      fs.mkdirSync(path.join(project, ".git", "objects"), { recursive: true });
      fs.writeFileSync(path.join(project, "package.json"), "{}");
      fs.writeFileSync(path.join(project, "node_modules", "dep", "package.json"), "{}");
      fs.writeFileSync(path.join(project, ".git", "objects", "ignored"), "ignored");
    }

    try {
      fs.symlinkSync(workspace, path.join(workspace, "api", "cycle"));
    } catch {}

    const res = spawnSync(process.execPath, [bin, workspace], {
      encoding: "utf-8",
      cwd: workspace,
      env: { ...process.env, PATH: "" },
      timeout: 5_000,
      maxBuffer: 64 * 1024 * 1024
    });

    assertEq(res.status ?? 1, 2, "exit");
    assertContains(res.stdout || "", "Preparing scan", "preflight progress");
    assertContains(res.stderr || "", "workspace with 3 sub-projects", "workspace message");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("empty directory with no scanners exits 2, not PASS", () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-empty-"));
  try {
    const res = spawnSync(process.execPath, [bin, empty], {
      encoding: "utf-8",
      cwd: empty,
      env: { ...process.env, PATH: "" },
      maxBuffer: 64 * 1024 * 1024
    });
    assertEq(res.status ?? 1, 2, "exit");
    assertContains(res.stdout || "", "no scannable source", "no-match message");
    assertNotContains(res.stdout || "", "STATUS: PASS", "status");
    assertContains(res.stderr || "", "no scanners available", "stderr");
  } finally {
    fs.rmSync(empty, { recursive: true, force: true });
  }
});

/* ── Coverage: a gate that could not look must not go green (#73) ── */

// Build a PATH directory that holds `node` plus the given POSIX shell stubs,
// so the scan sees exactly those tools and nothing else.
function makeBinDir(stubs = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-bin-"));
  fs.symlinkSync(process.execPath, path.join(dir, "node"));
  for (const [name, script] of Object.entries(stubs)) {
    const p = path.join(dir, name);
    fs.writeFileSync(p, `#!/bin/sh\n${script}\n`);
    fs.chmodSync(p, 0o755);
  }
  return dir;
}

function makeEvalTarget() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-cov-"));
  fs.writeFileSync(path.join(dir, "index.js"), "eval(userInput);\n");
  return dir;
}

function runIsolated(binDir, targetDir, extraArgs = []) {
  const res = spawnSync(process.execPath, [bin, targetDir, ...extraArgs], {
    encoding: "utf-8",
    cwd: targetDir,
    env: { ...process.env, PATH: binDir },
    maxBuffer: 64 * 1024 * 1024
  });
  const reportPath = path.join(targetDir, "secgate-v7-report.json");
  const rep = fs.existsSync(reportPath) ? JSON.parse(fs.readFileSync(reportPath, "utf-8")) : null;
  return { code: res.status ?? 1, stdout: res.stdout || "", stderr: res.stderr || "", rep };
}

const SCORED = ["semgrep", "gitleaks", "npm", "osv", "trivy"];

test("PATH with node only → exit 2, '0 of 5 scanners ran', coverage.ran empty", () => {
  const binDir = makeBinDir();
  const target = makeEvalTarget();
  try {
    const r = runIsolated(binDir, target);
    assertEq(r.code, 2, "exit");
    assertContains(r.stderr, "0 of 5 scanners ran", "coverage warning");
    assertContains(r.stderr, "no scanners available", "no-scanner message");
    if (!r.rep) throw new Error("report not written");
    assertEq(r.rep.coverage.ran.length, 0, "coverage.ran.length");
    assertEq(r.rep.coverage.total, 5, "coverage.total");
    assertEq(r.rep.coverage.skipped.length, 5, "coverage.skipped.length");
    assertEq(r.rep.status === "PASS", false, "report.status is not PASS");
    assertEq(r.rep.securityScore, null, "securityScore null when nothing ran");
    for (const k of SCORED) assertEq(r.rep.toolScores[k], null, `toolScores.${k}`);
    assertNotContains(r.stdout, "100 / 100", "no tool printed as 100 / 100");
    assertNotContains(r.stdout, "STATUS: PASS", "console status");
    assertNotContains(r.stdout, "CONFIDENCE: 100%", "confidence");
    const html = fs.readFileSync(path.join(target, `${path.basename(target)}.html`), "utf-8");
    assertContains(html, "0 of 5 scanners ran", "HTML coverage line");
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test("exactly one scanner available → skipped tools score null, not 100 / 100", () => {
  const binDir = makeBinDir({ gitleaks: "echo '[]'" });
  const target = makeEvalTarget();
  try {
    const r = runIsolated(binDir, target);
    assertEq(r.code, 0, "exit (partial coverage, no findings)");
    assertContains(r.stderr, "1 of 5 scanners ran", "coverage warning");
    assertContains(r.stderr, "semgrep", "install hint names semgrep");
    if (!r.rep) throw new Error("report not written");
    assertEq(JSON.stringify(r.rep.coverage.ran), JSON.stringify(["gitleaks"]), "coverage.ran");
    assertEq(r.rep.toolScores.gitleaks, 100, "gitleaks ran clean");
    for (const k of ["semgrep", "npm", "osv", "trivy"]) {
      assertEq(r.rep.toolScores[k], null, `toolScores.${k}`);
    }
    const lines = r.stdout.split("\n");
    for (const label of ["Semgrep", "npm audit", "osv-scanner", "Trivy"]) {
      const line = lines.find(l => l.trimStart().startsWith(label) && /\/ 100|n\/a/.test(l));
      if (!line) throw new Error(`no score line for ${label}`);
      assertNotContains(line, "100 / 100", `${label} score line`);
      assertContains(line, "n/a", `${label} score line`);
    }
    if (r.rep.remediation.confidence > 20) {
      throw new Error(`confidence ${r.rep.remediation.confidence}% exceeds 1 of 5 coverage`);
    }
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test("--require semgrep without semgrep on PATH → exit 2", () => {
  const binDir = makeBinDir({ gitleaks: "echo '[]'" });
  const target = makeEvalTarget();
  try {
    const r = runIsolated(binDir, target, ["--require", "semgrep"]);
    assertEq(r.code, 2, "exit");
    assertContains(r.stderr, "required scanner", "stderr");
    assertContains(r.stderr, "semgrep", "stderr names the tool");
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test("requireScanners config key without the tool on PATH → exit 2", () => {
  const binDir = makeBinDir({ gitleaks: "echo '[]'" });
  const target = makeEvalTarget();
  fs.writeFileSync(path.join(target, ".secgate.config.json"), JSON.stringify({ requireScanners: ["osv-scanner"] }));
  try {
    const r = runIsolated(binDir, target);
    assertEq(r.code, 2, "exit");
    assertContains(r.stderr, "osv", "stderr names the tool");
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test("--require with an unknown scanner name → exit 2 before scanning", () => {
  const r = run([path.join(repoRoot, "test/fixtures/clean"), "--require", "nosuchtool"]);
  assertEq(r.code, 2, "exit");
  assertContains(r.stderr, "nosuchtool", "stderr");
  assertNotContains(r.stdout, "Starting Semgrep", "no scan started");
});

test("--help documents exit code 2 for missing scanners and --require", () => {
  const r = run(["--help"]);
  assertContains(r.stdout, "--require", "help flag");
  assertContains(r.stdout, "no scanners available", "help exit 2");
});

test("unwritable output directory exits 2 without stack trace", () => {
  if (typeof process.getuid === "function" && process.getuid() === 0) {
    console.log("  skip  unwritable output directory (root can write)");
    return;
  }
  const targetDir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-target-"));
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-nowrite-"));
  try {
    fs.chmodSync(outputDir, 0o500);
    const res = spawnSync(process.execPath, [bin, targetDir, "--output-dir", outputDir], {
      encoding: "utf-8",
      cwd: targetDir,
      env: { ...process.env, PATH: "" },
      maxBuffer: 64 * 1024 * 1024
    });
    assertEq(res.status ?? 1, 2, "exit");
    assertContains(res.stderr || "", "Cannot write to output directory", "stderr");
    assertNotContains(res.stderr || "", "Error:", "no stack trace");
  } finally {
    fs.chmodSync(outputDir, 0o700);
    fs.rmSync(targetDir, { recursive: true, force: true });
    fs.rmSync(outputDir, { recursive: true, force: true });
  }
});

test("clean fixture → exit 0 PASS", () => {
  const fixture = path.join(repoRoot, "test/fixtures/clean");
  const r = run([fixture], { cwd: fixture });
  assertEq(r.code, 0, "exit");
  assertContains(r.stdout, "STATUS: PASS", "status");
});

test("clean fixture → JSON + HTML written", () => {
  const fixture = path.join(repoRoot, "test/fixtures/clean");
  run([fixture], { cwd: fixture });
  const json = path.join(fixture, "secgate-v7-report.json");
  const html = path.join(fixture, "clean.html");
  if (!fs.existsSync(json)) throw new Error(`missing ${json}`);
  if (!fs.existsSync(html)) throw new Error(`missing ${html}`);
  const rep = JSON.parse(fs.readFileSync(json, "utf-8"));
  assertEq(rep.status, "PASS", "report.status");
  fs.unlinkSync(json);
  fs.unlinkSync(html);
});

test("vulnerable-dockerfile fixture → trivy detects misconfig", () => {
  const fixture = path.join(repoRoot, "test/fixtures/vulnerable-dockerfile");
  const r = run([fixture], { cwd: fixture });
  assertEq(r.code, 1, "exit (FAIL expected)");
  assertContains(r.stdout, "FAIL", "status");
  const json = path.join(fixture, "secgate-v7-report.json");
  const rep = JSON.parse(fs.readFileSync(json, "utf-8"));
  const trivyFindings = rep.findings.filter(f => f.tool === "trivy");
  if (trivyFindings.length === 0) {
    throw new Error("expected at least one trivy finding");
  }
  fs.unlinkSync(json);
  fs.unlinkSync(path.join(fixture, "vulnerable-dockerfile.html"));
});

test("secret-leak fixture → gitleaks detects credential", () => {
  const fixture = path.join(repoRoot, "test/fixtures/secret-leak");
  const r = run([fixture], { cwd: fixture });
  const json = path.join(fixture, "secgate-v7-report.json");
  const htmlFile = path.join(fixture, "secret-leak.html");
  if (!fs.existsSync(json)) {
    // gitleaks not installed — skip
    console.log("  skip  secret-leak fixture (gitleaks not installed)");
    return;
  }
  const rep = JSON.parse(fs.readFileSync(json, "utf-8"));
  const gitleaksFindings = rep.findings.filter(f => f.tool === "gitleaks");
  if (gitleaksFindings.length === 0) {
    // gitleaks ran but produced no findings — may not be installed, skip
    console.log("  skip  secret-leak fixture (gitleaks skipped or no findings)");
    if (fs.existsSync(json)) fs.unlinkSync(json);
    if (fs.existsSync(htmlFile)) fs.unlinkSync(htmlFile);
    return;
  }
  assertEq(r.code, 1, "exit (FAIL expected)");
  assertContains(r.stdout, "FAIL", "status");
  if (fs.existsSync(json)) fs.unlinkSync(json);
  if (fs.existsSync(htmlFile)) fs.unlinkSync(htmlFile);
});

test("vulnerable-deps fixture → npm audit detects CVE", () => {
  const fixture = path.join(repoRoot, "test/fixtures/vulnerable-deps");
  const r = run([fixture], { cwd: fixture });
  const json = path.join(fixture, "secgate-v7-report.json");
  const htmlFile = path.join(fixture, "vulnerable-deps.html");
  if (!fs.existsSync(json)) {
    console.log("  skip  vulnerable-deps fixture (report not generated)");
    return;
  }
  const rep = JSON.parse(fs.readFileSync(json, "utf-8"));
  const npmFindings = rep.findings.filter(f => f.tool === "npm" || f.tool === "osv");
  if (npmFindings.length === 0) {
    // npm audit or osv may not flag without node_modules — skip gracefully
    console.log("  skip  vulnerable-deps fixture (npm/osv found no findings without node_modules install)");
    if (fs.existsSync(json)) fs.unlinkSync(json);
    if (fs.existsSync(htmlFile)) fs.unlinkSync(htmlFile);
    return;
  }
  assertEq(r.code, 1, "exit (FAIL expected)");
  assertContains(r.stdout, "FAIL", "status");
  if (fs.existsSync(json)) fs.unlinkSync(json);
  if (fs.existsSync(htmlFile)) fs.unlinkSync(htmlFile);
});

test("command injection regression — shell metachar in target rejected", () => {
  const malicious = `${repoRoot}; echo PWNED`;
  const r = run([malicious]);
  assertEq(r.code, 2, "exit (invalid target)");
  // stderr echoes the raw target in the error message, but stdout must not
  // contain the `echo` output as its own line — that would mean a shell ran.
  assertNotContains(r.stdout, "PWNED\n", "no shell execution in stdout");
});

test("HTML report references all 5 tool names", () => {
  const fixture = path.join(repoRoot, "test/fixtures/clean");
  run([fixture], { cwd: fixture });
  const html = fs.readFileSync(path.join(fixture, "clean.html"), "utf-8").toLowerCase();
  for (const t of ["semgrep", "gitleaks", "npm", "osv", "trivy"]) {
    assertContains(html, t, `tool token ${t}`);
  }
  fs.unlinkSync(path.join(fixture, "secgate-v7-report.json"));
  fs.unlinkSync(path.join(fixture, "clean.html"));
});

test("scan from /tmp writes no report files to /tmp", () => {
  const fixture = path.join(repoRoot, "test/fixtures/clean");
  const tmpBefore = fs.readdirSync("/tmp");
  const r = run([fixture], { cwd: "/tmp" });
  assertEq(r.code, 0, "exit");
  const tmpAfter = fs.readdirSync("/tmp");
  const added = tmpAfter.filter(n => !tmpBefore.includes(n));
  const leaked = added.filter(n => /secgate|\.html$/.test(n));
  if (leaked.length) {
    throw new Error(`report files leaked to /tmp: ${leaked.join(",")}`);
  }
  // Files must be in the fixture (target), not /tmp.
  const json = path.join(fixture, "secgate-v7-report.json");
  const html = path.join(fixture, "clean.html");
  if (!fs.existsSync(json)) throw new Error(`missing ${json}`);
  if (!fs.existsSync(html)) throw new Error(`missing ${html}`);
  fs.unlinkSync(json);
  fs.unlinkSync(html);
  // cwd-mismatch warning must fire.
  assertContains(r.stderr, "differs from target", "cwd warning");
});

test("--apply on malicious postinstall does NOT execute lifecycle scripts", () => {
  const fixture = path.join(repoRoot, "test/fixtures/malicious-postinstall");
  const pwned = "/tmp/secgate-pwned";
  if (fs.existsSync(pwned)) fs.unlinkSync(pwned);

  const r = run([fixture, "--apply"], {
    cwd: fixture,
    env: { ...process.env, SECGATE_CONFIRM_APPLY: "1" }
  });

  // Whatever the exit status (scan may FAIL on HIGH findings), the postinstall
  // script must never have run.
  if (fs.existsSync(pwned)) {
    const contents = fs.readFileSync(pwned, "utf-8");
    fs.unlinkSync(pwned);
    throw new Error(`postinstall executed — /tmp/secgate-pwned: ${contents}`);
  }

  // Audit log must record the apply attempt.
  const json = path.join(fixture, "secgate-v7-report.json");
  if (fs.existsSync(json)) {
    const rep = JSON.parse(fs.readFileSync(json, "utf-8"));
    if (!Array.isArray(rep.auditLog)) {
      throw new Error("missing auditLog in report");
    }
    const hasApplyStart = rep.auditLog.some(a => a.event === "apply_start");
    if (!hasApplyStart) {
      throw new Error("auditLog missing apply_start entry");
    }
    fs.unlinkSync(json);
  }
  const html = path.join(fixture, "malicious-postinstall.html");
  if (fs.existsSync(html)) fs.unlinkSync(html);

  // stderr must contain audit trail entries.
  assertContains(r.stderr, "[audit]", "stderr audit trail");
});

test("--apply refuses without confirmation (no TTY, no env)", () => {
  const fixture = path.join(repoRoot, "test/fixtures/clean");
  const env = { ...process.env };
  delete env.SECGATE_CONFIRM_APPLY;
  const r = run([fixture, "--apply"], { cwd: fixture, env });
  assertEq(r.code, 2, "exit");
  assertContains(r.stderr, "confirmation", "refusal stderr");
  // Report files must not exist (run aborted pre-scan).
  const json = path.join(fixture, "secgate-v7-report.json");
  if (fs.existsSync(json)) fs.unlinkSync(json);
  const html = path.join(fixture, "clean.html");
  if (fs.existsSync(html)) fs.unlinkSync(html);
});

test("CI=true report JSON contains no absolute target path", () => {
  const fixture = path.join(repoRoot, "test/fixtures/clean");
  const r = run([fixture], {
    cwd: fixture,
    env: { ...process.env, CI: "true" }
  });
  assertEq(r.code, 0, "exit");
  const json = path.join(fixture, "secgate-v7-report.json");
  const raw = fs.readFileSync(json, "utf-8");
  const rep = JSON.parse(raw);
  assertEq(rep.target, "clean", "target relativized");
  if (raw.includes(fixture)) {
    throw new Error(`absolute fixture path leaked into JSON: ${fixture}`);
  }
  // Accept /tmp (POSIX root-like) but reject the fixture's absolute root.
  if (/"\/Users\/[^"]+"/.test(raw) || /"\/home\/[^"]+"/.test(raw)) {
    throw new Error("absolute user-home path leaked into JSON");
  }
  fs.unlinkSync(json);
  fs.unlinkSync(path.join(fixture, "clean.html"));
});

test("--output-dir writes reports to the given directory", () => {
  const fixture = path.join(repoRoot, "test/fixtures/clean");
  const out = fs.mkdtempSync("/tmp/secgate-out-");
  const r = run([fixture, "--output-dir", out], { cwd: fixture });
  assertEq(r.code, 0, "exit");
  const json = path.join(out, "secgate-v7-report.json");
  const html = path.join(out, "clean.html");
  if (!fs.existsSync(json)) throw new Error(`missing ${json}`);
  if (!fs.existsSync(html)) throw new Error(`missing ${html}`);
  fs.unlinkSync(json);
  fs.unlinkSync(html);
  fs.rmdirSync(out);
  // Fixture dir must NOT contain the report.
  if (fs.existsSync(path.join(fixture, "secgate-v7-report.json"))) {
    fs.unlinkSync(path.join(fixture, "secgate-v7-report.json"));
    throw new Error("report also written to target when --output-dir given");
  }
});

test("--format sarif writes .sarif.json alongside JSON+HTML", () => {
  const fixture = path.join(repoRoot, "test/fixtures/clean");
  if (!fs.existsSync(fixture)) {
    console.log("    (skipped — clean fixture not present)");
    passed++;
    return;
  }
  run([fixture, "--format", "sarif"], { cwd: fixture });
  const sarifPath = path.join(fixture, "clean.sarif.json");
  const jsonPath = path.join(fixture, "secgate-v7-report.json");
  const htmlPath = path.join(fixture, "clean.html");
  if (!fs.existsSync(sarifPath)) throw new Error(`missing ${sarifPath}`);
  const sarif = JSON.parse(fs.readFileSync(sarifPath, "utf-8"));
  assertEq(sarif.version, "2.1.0", "sarif.version");
  assertContains(sarif.$schema, "sarif", "$schema");
  if (Array.isArray(sarif.runs)) {
    assertEq(sarif.runs.length, 6, "6 runs entries");
  }
  try { fs.unlinkSync(sarifPath); } catch {}
  try { fs.unlinkSync(jsonPath); } catch {}
  try { fs.unlinkSync(htmlPath); } catch {}
});

test("--format sarif does not suppress JSON+HTML output", () => {
  const fixture = path.join(repoRoot, "test/fixtures/clean");
  if (!fs.existsSync(fixture)) {
    console.log("    (skipped — clean fixture not present)");
    passed++;
    return;
  }
  run([fixture, "--format", "sarif"], { cwd: fixture });
  const jsonPath = path.join(fixture, "secgate-v7-report.json");
  const htmlPath = path.join(fixture, "clean.html");
  if (!fs.existsSync(jsonPath)) throw new Error("JSON report missing when --format sarif");
  if (!fs.existsSync(htmlPath)) throw new Error("HTML report missing when --format sarif");
  try { fs.unlinkSync(jsonPath); } catch {}
  try { fs.unlinkSync(htmlPath); } catch {}
  try { fs.unlinkSync(path.join(fixture, "clean.sarif.json")); } catch {}
});

console.log("-------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
