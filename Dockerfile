# mpm-syncd — self-hostable mypassman sync relay.
#   docker build -t mpm-syncd .
#   docker run -d --name syncd -p 8787:8787 \
#     -e MPM_SETUP_KEY=<random-long-secret> -v mpm-syncd:/data mpm-syncd
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates crates
RUN cargo build --release -p mpm-syncd

FROM debian:bookworm-slim
RUN useradd -r -u 10001 mpm && mkdir -p /data && chown mpm /data
COPY --from=build /src/target/release/mpm-syncd /usr/local/bin/mpm-syncd
USER mpm
ENV MPM_SYNC_DATA=/data MPM_SYNC_BIND=0.0.0.0:8787
VOLUME /data
EXPOSE 8787
ENTRYPOINT ["mpm-syncd"]
