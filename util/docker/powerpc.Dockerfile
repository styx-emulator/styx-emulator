# Default ubuntu image adds ubuntu user which will conflict with ours
# This ensures compatibility with toolbox
FROM quay.io/toolbx/ubuntu-toolbox:24.04

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y \
    vim \
    gcc-powerpc-linux-gnu \
    binutils-powerpc-linux-gnu
