#!/usr/bin/env bash
# Dump the public Metaplex Token Metadata program for the local validator.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
dest="$root/anchor-tests/fixtures/mpl_token_metadata.so"
if [[ -f "$dest" && -s "$dest" ]]; then
  mkdir -p "$root/programs/fizzcaps-onchain/tests/fixtures"
  cp -n "$dest" "$root/programs/fizzcaps-onchain/tests/fixtures/mpl_token_metadata.so" 2>/dev/null || \
    cp "$dest" "$root/programs/fizzcaps-onchain/tests/fixtures/mpl_token_metadata.so"
  exit 0
fi
node "$root/scripts/fetch-metadata-program.js"
