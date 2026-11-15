#!/usr/bin/env bash
#
# verify-release.sh - Verify a SecGate release end-to-end.
#
# Checks:
#   1. SBOM presence + valid CycloneDX JSON
#   2. cosign keyless signature over tarball + SBOM (Sigstore transparency log)
#   3. SLSA L3 provenance attestation via slsa-verifier
#
# Usage:
#   scripts/verify-release.sh <version>
#   scripts/verify-release.sh v0.3.0
#
# Requires: cosign (>=2.0), slsa-verifier (>=2.4), jq, curl, sha256sum
#
# All auth is OIDC-based (keyless). No pre-shared keys required.
#
set -euo pipefail

REPO_SLUG="${REPO_SLUG:-Stelnyx/secgate}"
EXPECTED_IDENTITY_REGEX="${EXPECTED_IDENTITY_REGEX:-^https://github\.com/${REPO_SLUG}/\.github/workflows/release\.yml@refs/tags/.*}"
EXPECTED_ISSUER="${EXPECTED_ISSUER:-https://token.actions.githubusercontent.com}"

log()  { printf '[verify-release] %s\n' "$*" >&2; }
die()  { printf '[verify-release] ERROR: %s\n' "$*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_cmd cosign
require_cmd slsa-verifier
require_cmd jq
require_cmd curl
require_cmd sha256sum

VERSION="${1:-}"
[ -n "$VERSION" ] || die "usage: $0 <version>  (e.g. v0.3.0)"
case "$VERSION" in
  v*) ;;
  *)  VERSION="v${VERSION}" ;;
esac

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

TARBALL="secgate-${VERSION#v}.tgz"
SBOM="secgate-${VERSION#v}.sbom.cdx.json"
ATTESTATION="secgate-${VERSION}.intoto.jsonl"

BASE_URL="https://github.com/${REPO_SLUG}/releases/download/${VERSION}"

fetch() {
  local name="$1"
  log "downloading ${name}"
  curl -fsSL -o "$name" "${BASE_URL}/${name}" \
    || die "failed to download ${name} from ${BASE_URL}"
}

log "verifying SecGate release ${VERSION} from ${REPO_SLUG}"

# --- 1. download all artifacts ---
for f in \
  "$TARBALL" "${TARBALL}.sig" "${TARBALL}.pem" "${TARBALL}.cosign.bundle" \
  "$SBOM"    "${SBOM}.sig"    "${SBOM}.pem"    "${SBOM}.cosign.bundle" \
  "$ATTESTATION" "SHA256SUMS"; do
  fetch "$f"
done

# --- 2. SBOM presence + shape ---
log "checking SBOM presence + CycloneDX shape"
[ -s "$SBOM" ] || die "SBOM missing or empty: $SBOM"
BOM_FORMAT=$(jq -r '.bomFormat // empty' "$SBOM")
[ "$BOM_FORMAT" = "CycloneDX" ] || die "SBOM bomFormat is not CycloneDX: got '${BOM_FORMAT}'"

# --- 3. SHA256SUMS integrity ---
log "verifying SHA256SUMS"
sha256sum -c SHA256SUMS

# --- 4. cosign keyless verification ---
log "verifying cosign signature on ${TARBALL}"
cosign verify-blob \
  --bundle "${TARBALL}.cosign.bundle" \
  --certificate "${TARBALL}.pem" \
  --signature "${TARBALL}.sig" \
  --certificate-identity-regexp "$EXPECTED_IDENTITY_REGEX" \
  --certificate-oidc-issuer "$EXPECTED_ISSUER" \
  "$TARBALL"

log "verifying cosign signature on ${SBOM}"
cosign verify-blob \
  --bundle "${SBOM}.cosign.bundle" \
  --certificate "${SBOM}.pem" \
  --signature "${SBOM}.sig" \
  --certificate-identity-regexp "$EXPECTED_IDENTITY_REGEX" \
  --certificate-oidc-issuer "$EXPECTED_ISSUER" \
  "$SBOM"

# --- 5. SLSA L3 provenance ---
log "verifying SLSA L3 attestation"
slsa-verifier verify-artifact \
  --provenance-path "$ATTESTATION" \
  --source-uri "github.com/${REPO_SLUG}" \
  --source-tag "$VERSION" \
  "$TARBALL"

slsa-verifier verify-artifact \
  --provenance-path "$ATTESTATION" \
  --source-uri "github.com/${REPO_SLUG}" \
  --source-tag "$VERSION" \
  "$SBOM"

log "OK - release ${VERSION} verified: SBOM + cosign + SLSA L3"
