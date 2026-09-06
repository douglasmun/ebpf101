FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev make python3 file binutils coreutils procps xxd \
        strace openssl fsverity attr dash \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
