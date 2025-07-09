FROM debian:bookworm-slim

ADD tools.tar.gz /

ENV DEBIAN_FRONTEND=noninteractive PATH=/tools/bin:$PATH

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc-multilib \
    git \
    make \
    wget \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN git clone --no-checkout https://github.com/FreeRTOS/FreeRTOS.git && \
    cd FreeRTOS && git checkout V8.2.3

COPY src /build/src

ENTRYPOINT ["/bin/bash"]
