#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${GH_TOKEN:-}" ]]; then
  echo 'Missing CATALOG_IMMUTABILITY_READ_TOKEN with Administration: read; no release will be published.' >&2
  exit 1
fi
if ! gh api --method GET "repos/${GITHUB_REPOSITORY:?}/immutable-releases" \
    --jq '.enabled == true' | grep -qx true; then
  echo 'Cannot confirm immutable releases are enabled. Check the repository setting and the read-only Administration token (issue #6).' >&2
  exit 1
fi
