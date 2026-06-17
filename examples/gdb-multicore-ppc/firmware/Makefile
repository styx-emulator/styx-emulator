# SPDX-License-Identifier: BSD-2-Clause
#
# Build the example firmware, mostly to inspect while writing.
#
# The example's build.rs assembles firmware.S and embeds the `.text` bytes
# via include_bytes! (see ../src/lib.rs). These targets are only for eyeballing
# the encoding while editing the assembly. build.rs builds the firmware for the
# example.
#
#   make dis           # full objdump disassembly
#   make firmware.bin  # just the raw .text bytes
#   make clean
#
# Needs a big-endian PowerPC toolchain. Defaults to a locally installed cross
# toolchain (powerpc-linux-gnu-*). To use the repo's podman image instead,
# override RUN:
#   make dis RUN='podman run --rm -v $(PWD):$(PWD):z --workdir $(PWD) powerpc-compiler:latest'
#
# Make the podman image from styx root:
#    make -C styx/processors/ppc/styx-ppc4xx-processor/test-data/ container

RUN     ?=
PREFIX  ?= powerpc-linux-gnu-
AS      := $(RUN) $(PREFIX)as
OBJCOPY := $(RUN) $(PREFIX)objcopy
OBJDUMP := $(RUN) $(PREFIX)objdump

firmware.o: firmware.S
	$(AS) -many -o $@ $<

firmware.bin: firmware.o
	$(OBJCOPY) -O binary --only-section=.text $< $@

.PHONY: dis
dis: firmware.o
	$(OBJDUMP) -d $<

.PHONY: clean
clean:
	rm -f firmware.o firmware.bin
