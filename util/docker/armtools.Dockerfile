FROM ubuntu:22.04@sha256:bace9fb0d5923a675c894d5c815da75ffe35e24970166a48a4460a48ae6e0d19

ARG DEBIAN_FRONTEND=noninteractive

# install GDB + GCC for ARM
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-arm-none-eabi \
    gdb-multiarch
