FROM alpine:3.21

# install packages
RUN apk add --no-cache git libc6-compat make wget

# install aarch64 toolchain, add some links
RUN wget https://developer.arm.com/-/media/Files/downloads/gnu/14.2.rel1/binrel/arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf.tar.xz && \
    tar -xJf arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf.tar.xz -C /usr/bin && \
    ln -s /usr/bin/arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-as /usr/bin/aarch64-none-elf-as && \
    ln -s /usr/bin/arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-ld /usr/bin/aarch64-none-elf-ld && \
    ln -s /usr/bin/arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-objcopy /usr/bin/aarch64-none-elf-objcopy

ENTRYPOINT [ "sh" ]
