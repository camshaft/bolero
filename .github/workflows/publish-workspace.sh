#!/usr/bin/env bash
# Publish every publishable crate in the CURRENT Cargo workspace (the working directory) to
# crates.io, in intra-workspace dependency order, idempotently.
#
# Order is computed dynamically from `cargo metadata` (topologically sorted by intra-workspace
# normal/build dependencies) so a newly added crate is picked up automatically in the right place —
# no hand-maintained list to fall out of date. Idempotent: a crate whose current version is already
# on the crates.io sparse index is skipped, so the job re-runs safely (a partial earlier run, or a
# crate whose Trusted Publisher was registered later). `cargo publish` blocks until each version is
# live on the index before returning, so the next crate resolves it.
#
# Requires CARGO_REGISTRY_TOKEN in the environment (provided by the OIDC auth step).
set -euo pipefail

cargo metadata --no-deps --format-version 1 > /tmp/meta.json
mapfile -t MEMBERS < <(jq -r '.packages[].name' /tmp/meta.json | sort)

# Emit "<dep> <crate>" edges for intra-workspace, non-dev dependencies (dev-deps do not gate publish
# — the verify build skips them), then `tsort` yields a dependency-first total order. Members with no
# edges are appended afterward.
jq -r '
  (.packages | map(.name)) as $members
  | .packages[]
  | .name as $crate
  | .dependencies[]
  | select(.kind != "dev")
  | select(.name as $d | $members | index($d))
  | "\(.name) \($crate)"
' /tmp/meta.json | sort -u > /tmp/edges.txt

ORDER="$(tsort /tmp/edges.txt)"
for m in "${MEMBERS[@]}"; do
  grep -qxF "$m" <<<"$ORDER" || ORDER="$ORDER"$'\n'"$m"
done
echo "Publish order:"; echo "$ORDER" | sed '/^$/d' | nl

published_version() {
  local crate="$1"
  jq -r --arg c "$crate" '.packages[] | select(.name==$c) | .version' /tmp/meta.json
}
is_publishable() {
  # `.publish == null` → any registry; `.publish == []` → publish disabled; a list → allowed set.
  local crate="$1"
  jq -e --arg c "$crate" '
    .packages[] | select(.name==$c)
    | (.publish == null) or (.publish | index("crates-io") != null)
  ' /tmp/meta.json >/dev/null 2>&1
}
already_on_cratesio() {
  local crate="$1" version="$2"
  # crates.io sparse index path for a 5+ char name: {c0c1}/{c2c3}/{name}. All bolero crate names are
  # >4 chars. The file lists one JSON object per published version.
  local url="https://index.crates.io/${crate:0:2}/${crate:2:2}/${crate}"
  curl -fsSL -A "bolero-release-ci" "$url" 2>/dev/null \
    | jq -re --arg v "$version" 'select(.vers == $v) | .vers' >/dev/null 2>&1
}

while IFS= read -r crate; do
  [ -n "$crate" ] || continue
  if ! is_publishable "$crate"; then
    echo "$crate: publish disabled in Cargo.toml; skipping."
    continue
  fi
  version="$(published_version "$crate")"
  if already_on_cratesio "$crate" "$version"; then
    echo "$crate $version already on crates.io; skipping."
  else
    echo "Publishing $crate $version ..."
    # No --locked: bolero is a library workspace that does not commit Cargo.lock, so the publish
    # job's fresh checkout has none to honor; cargo resolves for the verify build.
    cargo publish -p "$crate"
  fi
done <<<"$ORDER"
