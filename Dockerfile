# Repo-root Dockerfile — Render compatibility shim.
#
# WHY THIS EXISTS: Render's Docker services resolve `./Dockerfile` relative to
# the repo root by default, and a deployed service keeps the blueprint config
# from its last Blueprint SYNC — pushed render.yaml edits do not re-apply on a
# plain redeploy. This file makes that default resolution succeed with no
# dashboard action required. It is the same multi-stage build as
# sih26141/Dockerfile, with sih26141/ path prefixes for the build context.
# Keep the two files in sync when the build changes.

# ---- Stage 1: build the React dashboard -----------------------------------
FROM node:20-alpine AS frontend
WORKDIR /app/frontend
COPY sih26141/frontend/package.json sih26141/frontend/package-lock.json* ./
RUN npm ci
COPY sih26141/frontend/ ./
# The build inlines nothing from the API at build time; the dashboard talks
# same-origin (window.location.origin) in production.
RUN npm run build

# ---- Stage 2: build the Rust server ----------------------------------------
# NOTE: deliberately `rust:1` (floating major), NOT a pinned minor — a frozen
# rust:1.82-slim broke the build when dependencies started using newer-cargo
# features (edition-2024 support). See sih26141/Dockerfile for the same note.
FROM rust:1-slim AS backend
# The context is the REPO ROOT, so the project lands at /app/sih26141/sih26141.
WORKDIR /app
COPY . .
WORKDIR /app/sih26141
# Full workspace copy: the root Cargo.toml lists every member crate, so a
# partial copy would break the workspace manifest. .dockerignore keeps the
# context small (no target/, no node_modules/, no git, no agent workspaces).
RUN cargo build --release -p server

# ---- Stage 3: runtime -------------------------------------------------------
FROM debian:bookworm-slim
WORKDIR /app
# reqwest uses rustls (no openssl needed); ca-certificates for HTTPS P2P.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=backend /app/sih26141/target/release/server /usr/local/bin/server
COPY --from=frontend /app/frontend/dist /app/frontend/dist
ENV PORT=8080 \
    HOST=0.0.0.0 \
    FRONTEND_DIST=/app/frontend/dist \
    AUDIT_LOG=/data/audit_log.jsonl \
    USERS_FILE=/data/users.json \
    QDS_EVENT_LOG=/data/qds_events.jsonl
# /data is mountable as a Render persistent disk so accounts + audit
# ledgers survive deploys. Create it (works fine unmounted too).
RUN mkdir -p /data
VOLUME /data
EXPOSE 8080
CMD ["server"]
