# Multi-stage build: dashboard (Node) + API server (Rust) in one image.
# Used by the Render blueprint (render.yaml). Produces ONE service that
# serves both the API and the built dashboard — the simplest way to get a
# single URL that works from any laptop with no CORS and no body limits.

# ---- Stage 1: build the React dashboard -----------------------------------
FROM node:20-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci
COPY frontend/ ./
# The build inlines nothing from the API at build time; the dashboard talks
# same-origin (window.location.origin) in production.
RUN npm run build

# ---- Stage 2: build the Rust server ----------------------------------------
FROM rust:1.82-slim AS backend
WORKDIR /app
# Full workspace copy: the root Cargo.toml lists every member crate, so a
# partial copy would break the workspace manifest. .dockerignore keeps the
# context small (no target/, no node_modules/, no git).
COPY . .
RUN cargo build --release -p server

# ---- Stage 3: runtime -------------------------------------------------------
FROM debian:bookworm-slim
WORKDIR /app
# reqwest uses rustls (no openssl needed); ca-certificates for HTTPS P2P.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=backend /app/target/release/server /usr/local/bin/server
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
