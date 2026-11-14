/**
 * Security Score — 0-100 continuous readiness metric.
 *
 * Formula: start at 100, subtract per-finding penalties by severity, floor at 0.
 * Deterministic: same input findings → same output every time (no randomness,
 * no time-based variance). Penalties are exported constants so they can be
 * tuned without touching the algorithm.
 *
 *   CRITICAL  -25   (one finding immediately signals serious posture risk)
 *   HIGH      -10
 *   MEDIUM    -3
 *   LOW       -1
 *   INFO/UNKNOWN  0   (informational; no penalty)
 *
 * Intended to sit alongside (not replace) the binary PASS/FAIL gate.
 * The gate still controls CI exit code; the score provides a continuous
 * signal suitable for charting, trending, and demo alongside the other
 * Stelnyx product scores.
 *
 * Rule version: "v1"
 */

export const SCORE_VERSION = "v1";

/** Per-finding penalty table, keyed by normalized severity string. */
export const SEVERITY_PENALTY = Object.freeze({
  CRITICAL: 25,
  HIGH:     10,
  MEDIUM:   3,
  LOW:      1,
  UNKNOWN:  0,
  INFO:     0
});

/**
 * Compute the Security Score (0-100) from a findings array.
 *
 * @param {Array<{severity: string}>} findings  Normalized findings (severity is
 *   one of CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN).
 * @returns {number} Integer in [0, 100].
 */
export function computeScore(findings) {
  let score = 100;
  for (const f of findings) {
    const sev = String(f.severity || "UNKNOWN").toUpperCase();
    score -= (SEVERITY_PENALTY[sev] ?? 0);
  }
  return Math.max(0, score);
}

/**
 * Compute per-tool scores (0-100) for each named scanner.
 *
 * A tool that did not run is never scored: it gets `null`, because a score of
 * 100 would claim a clean result for code nobody looked at.
 *
 * @param {Array<{severity: string, tool: string}>} findings
 * @param {string[]} toolKeys  List of tool keys to compute scores for.
 * @param {string[]} notRun    Tool keys that were skipped or errored.
 * @returns {Record<string, number|null>}
 */
export function computeToolScores(findings, toolKeys, notRun = []) {
  const skipped = new Set(notRun);
  const result = {};
  for (const key of toolKeys) {
    if (skipped.has(key)) {
      result[key] = null;
      continue;
    }
    const toolFindings = findings.filter(f => f.tool === key);
    result[key] = computeScore(toolFindings);
  }
  return result;
}
