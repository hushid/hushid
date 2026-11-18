#!/usr/bin/env bash
# Publish the hushid library from a crate checkout.
# Usage: publish-crates.sh [crate-dir]
set -euo pipefail

crate_dir=${1:-.}
cd "$crate_dir"

name=hushid
version=$(
  cargo metadata --format-version 1 --no-deps --locked \
    | jq -r --arg name "$name" '.packages[] | select(.name == $name) | .version'
)
if [ -z "$version" ] || [ "$version" = "null" ]; then
  echo "missing version for ${name}" >&2
  exit 1
fi

url="https://crates.io/api/v1/crates/${name}/${version}"
code=$(curl -sS -A "hushid-publish" -o /tmp/hushid-crate.json -w "%{http_code}" "$url" || true)
if [ "$code" = "200" ]; then
  echo "already published ${name} ${version}"
  exit 0
fi

attempt=1
while [ "$attempt" -le 3 ]; do
  set +e
  out=$(cargo publish -p "$name" --locked 2>&1)
  status=$?
  set -e
  printf '%s\n' "$out"
  if [ "$status" -eq 0 ]; then
    echo "published ${name} ${version}"
    exit 0
  fi
  if printf '%s' "$out" | grep -q "already exists"; then
    echo "already published ${name} ${version}"
    exit 0
  fi
  if printf '%s' "$out" | grep -q "429"; then
    echo "crates.io asked us to wait (attempt ${attempt})"
    sleep 30
    attempt=$((attempt + 1))
    continue
  fi
  exit "$status"
done
echo "gave up publishing ${name} ${version}" >&2
exit 1
