import path from "path";
import { runTool } from "./utils.mjs";

// "npm:lodash@GHSA-29mw-wpgm-hmr9" → "lodash"
function extractPkg(sig) {
  const m = String(sig).match(/^[^:]+:([^@]+)@/);
  return m ? m[1] : null;
}

// "npm:lodash@GHSA-29mw-wpgm-hmr9" → "npm install lodash@latest"
function depUpgradeCmd(sig) {
  const m = String(sig).match(/^(npm|go|python|cargo|maven):([^@]+)@/);
  if (!m) return null;
  const [, eco, pkg] = m;
  if (eco === "npm")    return `npm install ${pkg}@latest`;
  if (eco === "go")     return `go get ${pkg}@latest`;
  if (eco === "python") return `pip install --upgrade ${pkg}`;
  if (eco === "cargo")  return `cargo update ${pkg}`;
  return null;
}

function buildWhy(f) {
  const base = f.file ? path.basename(f.file) : null;
  const loc  = base && f.line ? `${base}:${f.line}` : base || "";

  switch (f.type) {
    case "secret":
      return `Credential exposed${loc ? " in " + loc : ""} — rotate immediately`;
    case "dependency": {
      const sig      = String(f.signature || "");
      const advisory = sig.includes("@") ? sig.split("@").pop() : "";
      const pkg      = extractPkg(sig);
      const msg      = f.message || "";
      return `${msg}${advisory ? " (" + advisory + ")" : ""}${pkg ? " — package: " + pkg : ""}`;
    }
    case "code":
      return `${f.message || "Unsafe code pattern"}${loc ? " at " + loc : ""}`;
    case "iac":
      return `${f.message || "Infrastructure misconfiguration"}${loc ? " in " + loc : ""}`;
    case "license":
      return `License issue: ${f.message || f.signature || "unknown"}`;
    default:
      return f.message || "Unsafe code pattern";
  }
}

export function analyze(findings) {
  let risk = 0;
  const surface = new Set();
  const reasoning = [];
  const recs = [];

  for (const f of findings) {
    if (f.baseline) continue;

    const weight =
      f.severity === "CRITICAL" ? 10
      : f.severity === "HIGH"   ? 6
      : f.severity === "MEDIUM" ? 3
      : f.severity === "LOW"    ? 1
      : 0;

    risk += weight;
    surface.add(f.type);

    reasoning.push({
      issue:    f.signature,
      why:      buildWhy(f),
      file:     f.file  || null,
      line:     f.line  || null,
      severity: f.severity
    });

    if (f.type === "secret")     recs.push("Rotate credentials immediately");
    if (f.type === "dependency") recs.push("Upgrade affected packages");
    if (f.type === "code")       recs.push("Refactor insecure code");
    if (f.type === "iac")        recs.push("Harden infrastructure configuration");
    if (f.type === "license")    recs.push("Review third-party licenses");
  }

  return {
    riskScore:      risk,
    attackSurface:  [...surface],
    reasoning,
    recommendations: [...new Set(recs)]
  };
}

export function patch(f) {
  if (f.tool === "npm") {
    const pkg = extractPkg(f.signature);
    return {
      action: "npm audit fix",
      cmd:    pkg ? `npm install ${pkg}@latest` : null,
      exec: {
        binary: "npm",
        args:   ["audit", "fix", "--ignore-scripts"],
        cwd:    null
      }
    };
  }

  if (f.tool === "osv") {
    const cmd  = depUpgradeCmd(f.signature);
    return {
      action: "upgrade dependency",
      cmd,
      note: f.message || null
    };
  }

  if (f.tool === "semgrep") {
    const loc = f.file && f.line ? `${f.file}:${f.line}` : f.file || null;
    return {
      action: "manual code fix",
      cmd:    loc ? `# Fix: ${loc}` : null,
      note:   f.message || null
    };
  }

  if (f.tool === "gitleaks") {
    return {
      action: "remove + rotate secret",
      cmd:    f.file ? `git filter-repo --path "${f.file}" --invert-paths  # rotate credential first` : null
    };
  }

  if (f.tool === "trivy") {
    if (f.type === "license") return { action: "review license", cmd: null };
    return {
      action: "fix misconfiguration",
      cmd:    f.file ? `# ${f.message || "Fix misconfiguration"} — edit ${f.file}` : null,
      note:   f.message || null
    };
  }

  return { action: "manual", cmd: null };
}

/**
 * @param {object[]} findings
 * @param {object}   opts
 * @param {boolean}  opts.apply         - execute fixable remediations
 * @param {string}   opts.target        - absolute path to scan target
 * @param {string}   opts.reportTarget  - display path (may be relativized)
 * @param {Function} opts.auditLog      - (event, detail) => void
 */
export function remediate(findings, opts = {}) {
  const { apply = false, target = null, reportTarget = null, auditLog = () => {} } = opts;
  let confidence = 100;
  const plan = [];
  const staged = [];
  const executed = [];
  const blocked = [];
  const groups = new Map();

  for (const f of findings) {
    if (f.baseline) continue;

    const p = patch(f);

    if (f.tool === "npm" && p.exec) {
      p.cmd = `npm audit fix --ignore-scripts (cwd=${reportTarget || target || ""})`;
      if (p.exec) p.exec.cwd = target;
    }

    plan.push({ issue: f.signature, patch: p });

    if (f.severity === "CRITICAL") {
      blocked.push(p);
      confidence -= 30;
      continue;
    }

    if (f.fixable && p.exec) {
      staged.push(p);

      if (apply && p.exec.cwd) {
        // The fix command works on the whole project, so identical commands
        // are collected here and executed once after the loop.
        const key = JSON.stringify([p.exec.binary, p.exec.args, p.exec.cwd]);
        let group = groups.get(key);
        if (!group) {
          group = { exec: p.exec, tool: f.tool, signatures: [], patches: [] };
          groups.set(key, group);
        }
        group.signatures.push(f.signature);
        group.patches.push(p);
      }
    }
  }

  for (const group of groups.values()) {
    const { exec, tool, signatures, patches } = group;
    auditLog("apply_exec", {
      tool,
      signatures,
      binary: exec.binary,
      args:   exec.args,
      cwd:    exec.cwd
    });
    try {
      const result = runTool(exec.binary, exec.args, {
        cwd: exec.cwd,
        env: { ...process.env, npm_config_ignore_scripts: "true" }
      });
      if (result.timedOut) {
        const seconds = Math.round((result.timeoutMs || 0) / 1000);
        throw new Error(`npm audit fix timed out after ${seconds}s - result inconclusive`);
      }
      if (result.error) {
        throw result.error;
      }
      executed.push(patches[0].action);
      auditLog("apply_ok", { tool, signatures });
    } catch (e) {
      blocked.push(...patches);
      auditLog("apply_fail", {
        tool,
        signatures,
        error: String(e && e.message ? e.message : e)
      });
    }
  }

  return {
    plan,
    stagedChanges: staged,
    executed,
    blocked,
    confidence: Math.max(confidence, 0)
  };
}
