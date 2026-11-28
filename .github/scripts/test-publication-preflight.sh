#!/usr/bin/env bash
set -euo pipefail

scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
cat > "$scratch/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
test "$*" = 'api --method GET repos/owner/catalog/immutable-releases --jq .enabled == true'
test "$GH_TOKEN" = mock-read-only
case "$RESPONSE" in
  forbidden) echo 'HTTP 403' >&2; exit 1 ;;
  not-found) echo 'HTTP 404' >&2; exit 1 ;;
  enabled) echo true ;;
  disabled) echo false ;;
  malformed) echo '{"unexpected":true}' ;;
  *) exit 1 ;;
esac
EOF
chmod 755 "$scratch/gh"
export PATH="$scratch:$PATH"
export GITHUB_REPOSITORY=owner/catalog
check=.github/scripts/require-immutable-releases.sh
for response in forbidden not-found disabled malformed; do
  if GH_TOKEN=mock-read-only RESPONSE="$response" bash "$check" 2>"$scratch/error"; then
    echo "Unexpectedly accepted $response" >&2
    exit 1
  fi
  grep -q 'Cannot confirm immutable releases' "$scratch/error"
done
if GH_TOKEN='' RESPONSE=enabled bash "$check" 2>"$scratch/error"; then
  exit 1
fi
grep -q 'Missing CATALOG_IMMUTABILITY_READ_TOKEN' "$scratch/error"
GH_TOKEN=mock-read-only RESPONSE=enabled bash "$check"
echo 'publication preflight: missing credentials, 403, 404, disabled, malformed and enabled cases passed'
