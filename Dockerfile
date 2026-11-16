# syntax=docker/dockerfile:1
# Base images are pinned by digest (resolved with `docker pull` + `docker inspect`);
# bump tag and digest together.
FROM rust:1.98-trixie@sha256:a8a5f0a1e5fe7dfe1d352591e4a1c7dd2c08fd70475cae872cf3458ba0df0546 AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      tesseract-ocr tesseract-ocr-deu tesseract-ocr-eng poppler-utils \
 && rm -rf /var/lib/apt/lists/*
# German OCR data must be present, otherwise the OCR tests would not cover it.
RUN tesseract --list-langs | grep -qx deu
WORKDIR /src

# Dependency cache layer: build dummy sources from the manifests only.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
 && echo 'fn main() {}' > src/main.rs \
 && touch src/lib.rs \
 && cargo build --release --locked \
 && cargo test --release --locked --no-run --lib \
 && rm -rf src

COPY src ./src
COPY templates ./templates
COPY static ./static
COPY tests ./tests
# Make sure cargo rebuilds the crate itself over the dummy artifacts.
RUN touch src/main.rs src/lib.rs

# Tests run with output shown; an OCR test that printed SKIP fails the build.
RUN cargo test --release --locked -- --nocapture > /tmp/test.log 2>&1; rc=$?; \
    tail -n 40 /tmp/test.log; \
    [ "$rc" -eq 0 ] || exit 1; \
    ! grep -q SKIP /tmp/test.log
RUN cargo build --release --locked

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      tesseract-ocr tesseract-ocr-deu tesseract-ocr-eng poppler-utils \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 pm \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin pm \
 && mkdir -p /data && chown 10001:10001 /data \
 # The app needs no setuid/setgid helpers (su, mount, passwd, ...).
 && find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec chmod a-s {} +
COPY --from=build /src/target/release/personal-media /usr/local/bin/personal-media
ENV PM_DATA_DIR=/data \
    PM_BIND=127.0.0.1:8080
WORKDIR /data
USER 10001:10001
# Documentation only: the container runs with host networking.
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["personal-media", "healthcheck"]
ENTRYPOINT ["personal-media"]
CMD ["serve"]
