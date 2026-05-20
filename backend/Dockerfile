# ── Build ─────────────────────────────────────────────────────────────────────
FROM rust:1.82 AS builder

WORKDIR /app

# Cache dependency compilation separately from source
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs && cargo build --release && rm -r src

COPY src ./src
# Touch main.rs so cargo re-links
RUN touch src/main.rs && cargo build --release

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/gateway ./

CMD ["./gateway"]
