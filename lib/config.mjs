import fs from "fs";
import path from "path";

export const CONFIG_DEFAULTS = {
  failOn: ["critical", "high"],
  scanners: { semgrep: true, gitleaks: true, npm: true, osv: true, trivy: true },
  severityOverrides: [],
  ignore: [],
  excludePaths: [],
  baselineFile: ".secgate-baseline.json",
  customSemgrepRules: null,
  /**
   * Scanners that must run. If any listed scanner is skipped or errors,
   * SecGate exits 2. Names: semgrep, gitleaks, npm, osv (or osv-scanner), trivy.
   */
  requireScanners: [],
  /**
   * Confidence profile applied during report rendering:
   *   - "curated" (default): demotes known-noisy rules + stale CVEs +
   *                          base-image OS packages to "informational"
   *   - "strict":            no demotion; every finding rendered actionable
   * Findings are never dropped — only re-classified for display ordering.
   */
  profile: "curated"
};

// Keys --ignore-target-policy takes away from the scanned repo's config.
export const TARGET_POLICY_KEYS = ["failOn", "ignore", "excludePaths", "severityOverrides"];
const VALID_PROFILES = new Set(["curated", "strict"]);

export function isWithinTarget(targetDir, relPath) {
  if (!relPath) return true;
  // secgate:ignore javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  const resolved = path.resolve(targetDir, relPath);
  // secgate:ignore javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  const targetResolved = path.resolve(targetDir);
  return resolved.startsWith(targetResolved + path.sep) || resolved === targetResolved;
}

export function loadConfig(targetDir, { ignoreTargetPolicy = false } = {}) {
  const { setKeys, ...config } = readConfig(targetDir, ignoreTargetPolicy);
  // Only with the flag: the verdict names the keys the repo tried to set.
  return ignoreTargetPolicy ? { ...config, ignoredTargetPolicy: setKeys } : config;
}
function readConfig(targetDir, ignoreTargetPolicy) {
  // secgate:ignore javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  const cfgPath = path.join(targetDir, ".secgate.config.json");
  if (!fs.existsSync(cfgPath)) return { ...CONFIG_DEFAULTS, setKeys: [] };

  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
  } catch {
    console.error(`[secgate] Invalid JSON in ${cfgPath} — using defaults`);
    return { ...CONFIG_DEFAULTS, setKeys: [] };
  }

  const setKeys = raw !== null && typeof raw === "object"
    ? TARGET_POLICY_KEYS.filter(k => Object.hasOwn(raw, k))
    : [];
  let baselineFile = CONFIG_DEFAULTS.baselineFile;
  if (typeof raw.baselineFile === "string") {
    if (isWithinTarget(targetDir, raw.baselineFile)) {
      baselineFile = raw.baselineFile;
    } else {
      console.warn(`[secgate] baselineFile '${raw.baselineFile}' escapes target directory — using default`);
    }
  }

  let customSemgrepRules = null;
  if (typeof raw.customSemgrepRules === "string") {
    if (isWithinTarget(targetDir, raw.customSemgrepRules)) {
      customSemgrepRules = raw.customSemgrepRules;
    } else {
      console.warn(`[secgate] customSemgrepRules '${raw.customSemgrepRules}' escapes target directory — using default`);
    }
  }

  let profile = CONFIG_DEFAULTS.profile;
  if (typeof raw.profile === "string") {
    if (VALID_PROFILES.has(raw.profile)) {
      profile = raw.profile;
    } else {
      console.warn(`[secgate] profile '${raw.profile}' invalid — using '${CONFIG_DEFAULTS.profile}'`);
    }
  }

  const policy = ignoreTargetPolicy
    ? {
        failOn: [...CONFIG_DEFAULTS.failOn],
        severityOverrides: [],
        ignore: [],
        excludePaths: []
      }
    : {
        failOn: Array.isArray(raw.failOn) ? raw.failOn.map(s => String(s).toLowerCase()) : CONFIG_DEFAULTS.failOn,
        severityOverrides: Array.isArray(raw.severityOverrides) ? raw.severityOverrides : [],
        ignore: Array.isArray(raw.ignore) ? raw.ignore : [],
        excludePaths: Array.isArray(raw.excludePaths) ? raw.excludePaths : []
      };
  return {
    ...policy,
    scanners: typeof raw.scanners === "object" && raw.scanners !== null
      ? { ...CONFIG_DEFAULTS.scanners, ...raw.scanners }
      : CONFIG_DEFAULTS.scanners,
    baselineFile,
    customSemgrepRules,
    // Passed through as-is: the CLI rejects a non-array or unknown names with
    // exit 2. Dropping a bad value here would let a required scanner go missing.
    requireScanners: raw.requireScanners === undefined ? [] : raw.requireScanners,
    profile,
    setKeys
  };
}
