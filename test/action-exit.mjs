// Runs the real "Run SecGate" step script of the bundled composite action
// (.github/actions/secgate/action.yml) against a stub CLI and checks the step's
// exit code. The script is read from the YAML, so the test breaks if the shipped
// step changes behavior. See issue #81: the fail-on filter must never turn a
// CLI exit 2 (INCOMPLETE, no scanners, missing --require'd scanner) into exit 0.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ACTION = readFileSync(join(ROOT, ".github/actions/secgate/action.yml"), "utf8");

function extractRunScript(yaml) {
  const lines = yaml.split("\n");
  const stepAt = lines.findIndex(l => /^\s*id:\s*run-secgate\s*$/.test(l));
  assert.ok(stepAt >= 0, "action.yml has a step with id run-secgate");
  const runAt = lines.findIndex((l, i) => i > stepAt && /^\s*run:\s*\|\s*$/.test(l));
  assert.ok(runAt >= 0, "run-secgate step has a literal block `run: |`");
  const runIndent = lines[runAt].match(/^\s*/)[0].length;
  const body = [];
  for (const l of lines.slice(runAt + 1)) {
    if (l.trim() !== "" && l.match(/^\s*/)[0].length <= runIndent) break;
    body.push(l.slice(runIndent + 2));
  }
  const script = body.join("\n");
  assert.ok(!script.includes("${{"), "run script has no ${{ }} expressions (inputs go through env)");
  return script;
}

const SCRIPT = extractRunScript(ACTION);

// Stub CLI: records argv, writes an optional report into the cwd, exits with STUB_EXIT.
const STUB = `
import { writeFileSync } from "node:fs";
writeFileSync(process.env.STUB_ARGS_FILE, JSON.stringify(process.argv.slice(2)));
if (process.env.STUB_REPORT) writeFileSync("secgate-v7-report.json", process.env.STUB_REPORT);
process.exit(Number(process.env.STUB_EXIT));
`;

const tmp = mkdtempSync(join(tmpdir(), "secgate-action-"));
writeFileSync(join(tmp, "stub.mjs"), STUB);
writeFileSync(join(tmp, "step.sh"), SCRIPT);

let n = 0;
function runStep({ exit, report, failOn = "critical,high", require = "", format = "json,html", stale }) {
  const work = join(tmp, `case${++n}`);
  spawnSync("mkdir", ["-p", work]);
  const out = join(work, "github_output");
  const argsFile = join(work, "args.json");
  writeFileSync(out, "");
  if (stale) writeFileSync(join(work, "secgate-v7-report.json"), JSON.stringify(stale));
  // Same shell flags GitHub Actions uses for `shell: bash`.
  const r = spawnSync("bash", ["--noprofile", "--norc", "-e", "-o", "pipefail", join(tmp, "step.sh")], {
    cwd: work,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      GITHUB_OUTPUT: out,
      SECGATE_TARGET: ".",
      SECGATE_APPLY: "false",
      SECGATE_FORMAT: format,
      SECGATE_FAIL_ON: failOn,
      SECGATE_REQUIRE: require,
      SECGATE_PATH: join(tmp, "stub.mjs"),
      STUB_EXIT: String(exit),
      STUB_ARGS_FILE: argsFile,
      STUB_REPORT: report ? JSON.stringify(report) : ""
    }
  });
  return {
    status: r.status,
    stdout: r.stdout,
    stderr: r.stderr,
    output: readFileSync(out, "utf8"),
    args: existsSync(argsFile) ? JSON.parse(readFileSync(argsFile, "utf8")) : null
  };
}

const clean = { summary: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 } };
const oneHigh = { summary: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 } };

try {
  // The bug: a report exists with no blocking findings, the CLI says exit 2.
  {
    const r = runStep({ exit: 2, report: clean });
    assert.equal(r.status, 2, `CLI exit 2 + clean report must fail the step with 2, got ${r.status}\n${r.stdout}${r.stderr}`);
    assert.match(r.stdout, /::error::SecGate exited with code 2/);
    assert.match(r.output, /report-path=secgate-v7-report\.json/, "outputs are still written so upload steps work");
    console.log("  ok  CLI exit 2 with a clean report → step exits 2");
  }
  {
    const r = runStep({ exit: 2, report: oneHigh });
    assert.equal(r.status, 2, "exit 2 wins over the fail-on filter (which would say 1)");
    console.log("  ok  CLI exit 2 with blocking findings → step exits 2, not 1");
  }
  {
    const r = runStep({ exit: 2 });
    assert.equal(r.status, 2, "CLI exit 2 with no report → 2");
    console.log("  ok  CLI exit 2 without a report → step exits 2");
  }
  {
    const r = runStep({ exit: 2, report: clean, failOn: "critical" });
    assert.equal(r.status, 2, "exit 2 is independent of fail-on");
    console.log("  ok  CLI exit 2 with fail-on=critical → step exits 2");
  }
  // Crash codes must not be swallowed by a stale report from an earlier run.
  for (const code of [127, 137]) {
    const r = runStep({ exit: code, stale: clean });
    assert.equal(r.status, code, `CLI exit ${code} with a stale clean report must fail with ${code}, got ${r.status}`);
  }
  console.log("  ok  CLI crash codes (127, 137) with a stale report → step keeps the code");

  // Existing behavior stays.
  {
    const r = runStep({ exit: 0, report: clean });
    assert.equal(r.status, 0, `PASS must stay green, got ${r.status}\n${r.stdout}${r.stderr}`);
    console.log("  ok  CLI exit 0 with a clean report → step exits 0");
  }
  {
    const r = runStep({ exit: 1, report: oneHigh });
    assert.equal(r.status, 1, "blocking finding → 1");
    assert.match(r.stdout, /::error::SecGate found 1 HIGH finding/);
    console.log("  ok  CLI exit 1 with a HIGH finding and fail-on=critical,high → step exits 1");
  }
  {
    const r = runStep({ exit: 1, report: oneHigh, failOn: "critical" });
    assert.equal(r.status, 0, "fail-on filter still narrows exit 1");
    console.log("  ok  CLI exit 1 with only a HIGH finding and fail-on=critical → step exits 0 (filter kept)");
  }
  {
    const r = runStep({ exit: 1 });
    assert.equal(r.status, 1, "exit 1 with no report → 1");
    console.log("  ok  CLI exit 1 without a report → step exits 1");
  }
  {
    const r = runStep({ exit: 0, report: clean, format: "json,sarif" });
    assert.match(r.output, /sarif-path=case\d+\.sarif\.json/);
    console.log("  ok  sarif-path output still written");
  }

  // `require` input is passed through as --require, and omitted when empty.
  {
    const r = runStep({ exit: 0, report: clean, require: "semgrep,gitleaks" });
    const i = r.args.indexOf("--require");
    assert.ok(i >= 0 && r.args[i + 1] === "semgrep,gitleaks", `--require semgrep,gitleaks passed, got ${JSON.stringify(r.args)}`);
    const none = runStep({ exit: 0, report: clean });
    assert.ok(!none.args.includes("--require"), "no --require when the input is empty");
    console.log("  ok  require input → --require <list>; empty → flag omitted");
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

console.log("✓ action step: CLI exit 2 fails the step before the fail-on filter");
