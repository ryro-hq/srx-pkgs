#!/usr/bin/env bash
# Read-only with respect to the input checkout; candidate edits stay in a disposable clone.
set -euo pipefail
export LC_ALL=C

output=${1:?usage: prepare-updates.sh NEW_OUTPUT_DIRECTORY [PACKAGE VERSION]}
shift
[[ $# == 0 || $# == 2 ]]
mkdir -- "$output"
output=$(realpath -- "$output")
root=$(git rev-parse --show-toplevel)
base=$(git -C "$root" rev-parse HEAD)
scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/catalog-update.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
srx=${SRX:-srx}

maintenance() {
  local tree=$1
  shift
  if [[ "${CATALOG_UPDATE_CONTAINER:-}" == true ]]; then
    local readonly=true
    if [[ "$1" == add ]]; then readonly=false; fi
    docker run --rm --user "$(id -u):$(id -g)" --dns-option single-request \
      --mount "type=bind,src=$tree,dst=/catalog,readonly=$readonly" \
      --mount "type=bind,src=$root/.core/target/catalog-candidate/srx,dst=/usr/local/bin/srx,readonly" \
      syrox-maintenance:ci /usr/local/bin/srx catalog "$1" /catalog "${@:2}"
  else
    "$srx" catalog "$1" "$tree" "${@:2}"
  fi
}

if [[ $# == 2 ]]; then
  jq -n --arg package "$1" --arg version "$2" '[[$package, $version]]' > "$scratch/request.json"
else
  # The feed is untrusted until the candidate's version-specific signature verifies.
  maintenance "$root" updates > "$scratch/request.json" || {
    echo 'Upstream discovery failed; no candidate artifacts were admitted.' >&2
    exit 1
  }
fi

jq -e 'type == "array" and all(.[]; type == "array" and length == 2 and
  (.[0] | type == "string" and test("^[a-z][a-z0-9_]{0,63}$")) and
  (.[1] | type == "string" and length <= 64 and test("^(0|[1-9][0-9]*)(\\.(0|[1-9][0-9]*)){1,3}$")))' \
  "$scratch/request.json" >/dev/null
jq -r '.[] | @tsv' "$scratch/request.json" > "$scratch/requests"
jq -n '[]' > "$output/index.json"
jq -n '[]' > "$output/failures.json"

while IFS=$'\t' read -r name version; do
  checkout=$(mktemp -d "$scratch/candidate.XXXXXXXX")
  git clone --quiet --shared --no-checkout "$root" "$checkout"
  git -C "$checkout" -c core.hooksPath=/dev/null checkout --quiet --detach "$base"
  existing=$(jq -r --arg name "$name" '.versions[].package | select(.name == $name) | .version' "$checkout/Catalog.lock" | sort -V | tail -n 1)
  if [[ -z "$existing" || "$existing" == "$version" || "$(printf '%s\n' "$existing" "$version" | sort -V | tail -n 1)" != "$version" ]]; then
    if [[ $# == 0 && -n "$existing" ]]; then
      printf 'Skipped %s %s: not newer than pinned %s.\n' "$name" "$version" "$existing"
      continue
    fi
    echo "Refusing $name $version: not newer than the latest registered exact version." >&2
    exit 1
  fi
  if ! maintenance "$checkout" add "$name" "$version"; then
    echo "Could not authenticate or prepare $name $version; no PR will be opened." >&2
    jq --arg name "$name" --arg version "$version" '. + [{name:$name,version:$version}]' \
      "$output/failures.json" > "$scratch/failures.new"
    mv -- "$scratch/failures.new" "$output/failures.json"
    if [[ $# == 2 ]]; then exit 1; fi
    continue
  fi
  maintenance "$checkout" generate --check
  maintenance "$checkout" check
  maintenance "$checkout" lock --check
  change="changes/$name-$version.json"
  # Also enforce the signed-channel contract while the catalog runs an older core.
  jq -e --arg name "$name" --arg version "$version" \
    '.name == $name and .version == $version and
    (.signing_authority.signing_key | type == "string" and test("^[A-F0-9]{40}$")) and
    (.combinations | length > 0 and all(.[].package;
      .name == $name and .version == $version and
      (.source_sha256 | type == "string" and test("^[a-f0-9]{64}$")) and
      (.source_url | type == "string" and startswith("https://")) and
      (.signature_url | type == "string" and startswith("https://"))))' \
    "$checkout/$change" >/dev/null
  jq '{name,version,signing_key:.signing_authority.signing_key,
    pins:([.combinations[].package | {source_url,source_sha256,source_maximum_bytes,signature_url}] | unique)}' \
    "$checkout/$change"
  cp -- "$checkout/$change" "$output/$name-$version.json"
  git -C "$checkout" add -- catalog.toml Catalog.lock Syrox.lock "recipes/packages/$name/releases.srx" "$change"
  patch="$output/$name-$version.patch"
  git -C "$checkout" diff --cached --no-ext-diff --binary --full-index > "$patch"
  pin=$(sha256sum "$patch" | cut -d' ' -f1)
  jq --arg name "$name" --arg version "$version" --arg pin "$pin" \
    '. + [{name:$name,version:$version,sha256:$pin}]' "$output/index.json" > "$scratch/index.new"
  mv -- "$scratch/index.new" "$output/index.json"
done < "$scratch/requests"
