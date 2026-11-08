#!/usr/bin/env bash
# Same evidence lifecycle for hosted scans and success/failure smoke probes.
set -euo pipefail
: "${RUNNER_TEMP:?}" "${CALLER_REPO:?}" "${SCANNERS:?}" "${GAIA_SECURITY_ROOT:?}"
evidence="$RUNNER_TEMP/gaia-evidence"
# Do not take ownership of an existing directory or follow a preexisting symlink.
mkdir -m 700 -- "$evidence"
cleanup() {
  local result=$?
  trap - EXIT
  rm -rf -- "$evidence" || exit 2
  test ! -e "$evidence" || exit 2
  printf '%s\n' 'Restricted evidence cleanup verified'
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 700 -- "$evidence/tmp"
export TMPDIR="$evidence/tmp"
python3 -m gaia_security scan --repo "$CALLER_REPO" --path "${1:?target path required}" \
  --scanners "$SCANNERS" --output-json "$evidence/report.json" --output-md "$evidence/report.md"
