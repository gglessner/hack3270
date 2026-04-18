#!/usr/bin/env bash
# Refresh vendored copies of hackterm-core and Endevor-MCP from their
# canonical GitHub repos. Run from the hack3270 repo root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

vendor() {
  local url="$1" dest="$2" subset="${3:-}"
  echo "==> $url -> $dest"
  git clone --depth 1 "$url" "$TMP/clone"
  local sha; sha="$(cd "$TMP/clone" && git rev-parse HEAD)"
  if [ -n "$subset" ]; then
    rm -rf "$dest"
    mkdir -p "$dest"
    cp -r "$TMP/clone/$subset/." "$dest/"
  else
    find "$dest" -mindepth 1 -maxdepth 1 ! -name UPSTREAM.txt -exec rm -rf {} +
    cp -r "$TMP/clone/." "$dest/"
    rm -rf "$dest/.git"
  fi
  {
    echo "upstream: $url"
    echo "pinned_commit: $sha"
    date -u +"pinned_at: %Y-%m-%dT%H:%M:%SZ"
  } > "$dest/UPSTREAM.txt"
  rm -rf "$TMP/clone"
}

vendor https://github.com/gglessner/hackterm-core "$ROOT/hackterm-core"
vendor https://github.com/gglessner/Endevor-MCP   "$ROOT/MCPs/endevor_mcp" "endevor_mcp"

echo "done. (hackterm-core is loaded via sys.path from ./hackterm-core — no pip install needed)"
