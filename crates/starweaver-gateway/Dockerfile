# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS chef
WORKDIR /workspace

RUN cargo install cargo-chef --locked

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust:1-bookworm AS builder
WORKDIR /workspace

RUN cargo install cargo-chef --locked

COPY --from=chef /workspace/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    cargo chef cook --release --locked --recipe-path recipe.json

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    cargo build --release --locked --bin starweaver-gateway && \
    cp /workspace/target/release/starweaver-gateway /usr/local/bin/starweaver-gateway

FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libgcc-s1 && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system --gid 10001 starweaver && \
    useradd \
        --system \
        --uid 10001 \
        --gid starweaver \
        --home-dir /nonexistent \
        --shell /usr/sbin/nologin \
        starweaver

COPY --from=builder /usr/local/bin/starweaver-gateway /usr/local/bin/starweaver-gateway

USER 10001:10001
WORKDIR /app

ENV STARWEAVER_GATEWAY_LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/starweaver-gateway"]
