#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Building SIH26141 Secure Rust Workspace..."
cargo build --workspace
echo "Running Unit and Integration Test Suites..."
cargo test --workspace
echo "Running End-to-End Demonstration Binary..."
cargo run -p main_app

echo "Building dashboard frontend (requires node/npm)..."
if command -v npm >/dev/null 2>&1; then
    (cd frontend && npm install && npm run build)
    echo "Starting API server with dashboard at http://127.0.0.1:8080 ..."
    PORT=8080 cargo run -p server
else
    echo "npm not found — starting API server in API-only mode..."
    PORT=8080 cargo run -p server
fi
