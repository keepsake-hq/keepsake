# Keepsake hub for a Linux server — build the daemon + CLI, run the daemon.
#
#   docker build -t keepsake-hub .
#   docker run --rm -e KEEPSAKE_MNEMONIC="<your 24 words>" \
#       -e KEEPSAKE_TCP=0.0.0.0:8765 -p 8765:8765 \
#       -v keepsake:/home/keepsake/.keepsake keepsake-hub
#
# Mint a scoped token for an agent:  docker run --rm -e KEEPSAKE_MNEMONIC="…" \
#       --entrypoint keepsake keepsake-hub token
# First run downloads the local embedding model (~500 MB) into the mounted volume; afterwards
# the hub runs offline. The hub over TCP REQUIRES a capability token on every request.

FROM rust:1-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p keepsake-daemon -p keepsake-cli

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home keepsake
COPY --from=build /src/target/release/keepsake-daemon /usr/local/bin/keepsake-daemon
COPY --from=build /src/target/release/keepsake /usr/local/bin/keepsake
USER keepsake
ENV KEEPSAKE_DB=/home/keepsake/.keepsake/vault.db \
    KEEPSAKE_SOCKET=/home/keepsake/.keepsake/daemon.sock
# Requires KEEPSAKE_MNEMONIC at runtime; set KEEPSAKE_TCP to expose the hub over the network.
ENTRYPOINT ["keepsake-daemon"]
