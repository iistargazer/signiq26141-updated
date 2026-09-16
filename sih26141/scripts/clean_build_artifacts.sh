#!/bin/bash
# Post-judging cleanup: reclaims ~1.6 GB of regenerable build artifacts.
#
# What it deletes (all automatically regenerable):
#   target/                 — Rust build cache (1.5 GB)  → `cargo build` restores
#   frontend/node_modules/  — npm dependencies (121 MB)  → `npm install` restores
#
# What it KEEPS:
#   frontend/dist/          — the built dashboard (661 KB). The server serves
#                             this directly, so keep it unless you also want
#                             to rebuild the frontend (then `npm install &&
#                             npm run build` restores it).
#
# After running this, the project folder shrinks to roughly 1 MB of pure
# source. To get a working dashboard again afterwards:
#   cargo build --workspace          # or just: cargo run -p server
#   (npm install && npm run build)   # only if frontend/dist was deleted

set -euo pipefail
cd "$(dirname "$0")/.."

echo "Size before:"
du -sh . 2>/dev/null || true

rm -rf target
rm -rf frontend/node_modules

echo
echo "Size after:"
du -sh . 2>/dev/null || true
echo
echo "Done. Regenerate anytime with:"
echo "  cargo build --workspace        # rebuilds target/"
echo "  (cd frontend && npm install)   # restores node_modules (only needed to rebuild the UI)"
