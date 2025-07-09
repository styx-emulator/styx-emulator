FROM messense/manylinux_2_28-cross:x86_64 AS builder

RUN apt update && apt install -y \
    protobuf-compiler \
    libprotobuf-dev \
    pkgconf \
    && rm -rf /var/lib/apt/lists/* \
    && curl https://sh.rustup.rs -sSf | bash -s -- -y \
    && . $HOME/.cargo/env \
    && cargo install --locked maturin

# TODO: decide how we want to handle reproducible builds
# RUN PB_REL="https://github.com/protocolbuffers/protobuf/releases" \
#     # $(curl -sL $PB_REL/latest | grep -o 'tag/[v.0-9]*' | sed 's/tag\///g' | head -n 1) \
#     && PB_VER=25.1 \
#     && curl -sL $PB_REL/download/v$PB_VER/protoc-$PB_VER-linux-x86_64.zip -o /tmp/protoc.zip \
#     && unzip /tmp/protoc.zip -d /usr/local \
#     && rm -f /tmp/protoc.zip \
#    && chmod +x /usr/local/bin/protoc
