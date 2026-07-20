# Docker image for the Wormward GitHub Action (see action.yml). Builds the read-only `wormward`
# CLI from source and runs it against the checked-out repository.
FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p wormward-cli

FROM debian:stable-slim
# `git` is needed for --deep / --history (git object reads); ca-certificates for the (optional)
# --online OSM lookups. No build toolchain in the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/wormward /usr/local/bin/wormward
COPY .github/action-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
