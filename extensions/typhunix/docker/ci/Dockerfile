# syntax=docker/dockerfile:1
#-------------------------------------------------------------------------------
# Styx::typhunix (aka typhunix) CICD image from `ubuntu:22.04`
#   - cargo v1.77.2
#   - jdk v17
#   - gradle7.5
#   - google protobuf 21.5
#   - X11 libs
#   - build/dev tools
#   - python3 and venv
#-------------------------------------------------------------------------------

FROM ubuntu:22.04

ARG RUST_VERSION

ENV RUST_VERSION=${RUST_VERSION}
ENV VIRTUAL_ENV=/opt/python3.10-venv
COPY rust/typhunix-python-bindings/requirements.txt /tmp/requirements.txt

# Run layer 1 - somewhat stable dependencies
RUN DEBIAN_FRONTEND=noninteractive \
    ##################################
    # APT
    ##################################
    apt-get update && apt-get install -yqq --no-install-recommends \
    # APT: JDK, wget, curl, unzip
    openjdk-17-jdk wget curl unzip git tree \
    xvfb libxrender1 libxtst6 libxi6 \
    software-properties-common apt-utils \
    python3 build-essential libffi-dev python3-dev python3-venv python3-pip \
    ca-certificates build-essential cmake clang libclang-dev pkg-config && \
    # end APT
    ##################################
    # RUSTUP
    ##################################
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    CARGO_HOME=/opt/cargo RUSTUP_HOME=/opt/rustup sh -s -- --default-toolchain \
    ${RUST_VERSION} -y --component nightly clippy-preview rustfmt && \
    mkdir /tmp/install && cd /tmp/install  && \
    ##################################
    # GRADLE
    ##################################
    wget -nv https://services.gradle.org/distributions/gradle-7.5-bin.zip && unzip gradle-7.5-bin.zip -d /opt && \
    mv /opt/gradle-7.5 /opt/gradle && \
    ##################################
    # PROTOBUF
    ##################################
    wget -nv https://github.com/protocolbuffers/protobuf/releases/download/v21.5/protoc-21.5-linux-x86_64.zip && \
    unzip protoc-21.5-linux-x86_64.zip && cp bin/* /usr/bin/ && cp -r include/* /usr/include/ && \
    ##################################
    # MINIO client
    ##################################
    curl https://dl.min.io/client/mc/release/linux-amd64/mc \
    --create-dirs -o /usr/local/bin/mc && \
    chmod +x /usr/local/bin/mc && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get update && apt-add-repository -y ppa:deadsnakes/ppa || true && \
    apt-add-repository -y ppa:deadsnakes/ppa && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -yqq --no-install-recommends \
    python3.8-dev  python3.8-venv  python3.8-distutils \
    python3.9-dev  python3.9-venv  python3.9-distutils \
    python3.11-dev python3.11-venv python3.11-distutils && \
    ##################################
    # Cleanup temp
    ##################################
    /usr/bin/rm -rf /tmp/install

##################################
# PIP dependencies in virtual envs (python 3.8, 3.9, 3.10, 3.11, 3.12)
##################################
# Run layer 2 - pip dependencies and app-specific things
RUN python3 -m venv $VIRTUAL_ENV && \
    ${VIRTUAL_ENV}/bin/pip install -r /tmp/requirements.txt  && \
    # 3.8
    python3.8 -m venv --upgrade /opt/python3.8-venv &&  \
    VIRTUAL_ENV=/opt/python3.8-venv /opt/python3.8-venv/bin/pip install -r  /tmp/requirements.txt  && \
    # 3.9
    python3.9 -m venv --upgrade /opt/python3.9-venv &&  \
    VIRTUAL_ENV=/opt/python3.9-venv /opt/python3.9-venv/bin/pip install -r  /tmp/requirements.txt  && \
    # 3.11
    python3.11 -m venv --upgrade /opt/python3.11-venv &&  \
    VIRTUAL_ENV=/opt/python3.11-venv /opt/python3.11-venv/bin/pip install -r  /tmp/requirements.txt  && \
    # allow git operations on /build and /builds
    for dir in /build /builds; do \
    git config --global --add safe.directory ${dir}; done

ENV PATH=/opt/cargo/bin:/opt/gradle/bin:$VIRTUAL_ENV/bin:$PATH \
    RUSTUP_HOME=/opt/rustup \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
