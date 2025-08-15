##
##  Copyright(c) 2019-2023 Qualcomm Innovation Center, Inc. All Rights Reserved.
##
##  This program is free software; you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation; either version 2 of the License, or
##  (at your option) any later version.
##
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with this program; if not, see <http://www.gnu.org/licenses/>.
##
##
## This file has modifications.
##
## Modifications:
## - Lennon Anderson - 2025-08-20

# For reference, this file is from: tests/tcg/hexagon/Makefile.target

# CFLAGS from various makefiles in the qemu test web of makefiles
CFLAGS += -Wno-incompatible-pointer-types -Wno-undefined-internal
CFLAGS += -fno-unroll-loops -fno-stack-protector
CFLAGS+=-Wall -Werror -O0 -g -fno-strict-aliasing -mv73
CFLAGS += -O2 -static
LDFLAGS+=-static
EXTRA_CFLAGS += -ffreestanding -fno-stack-protector
EXTRA_CFLAGS += -include stdbool.h

HEX_SRC=./src
VPATH += $(HEX_SRC)

build/%: $(HEX_SRC)/%.S $(HEX_SRC)/crt.S
	$(CC) -static -mv67 -nostdlib $^ -o $@
build/%: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $< -o $@ $(LDFLAGS)


HEX_TESTS = first
HEX_TESTS += hex_sigsegv
HEX_TESTS += misc
HEX_TESTS += usr
HEX_TESTS += preg_alias
HEX_TESTS += dual_stores
HEX_TESTS += multi_result
HEX_TESTS += mem_noshuf
HEX_TESTS += mem_noshuf_exception
HEX_TESTS += circ
HEX_TESTS += brev
HEX_TESTS += load_unpack
HEX_TESTS += load_align
HEX_TESTS += atomics
HEX_TESTS += fpstuff
HEX_TESTS += overflow
HEX_TESTS += signal_context
HEX_TESTS += reg_mut
HEX_TESTS += read_write_overlap
HEX_TESTS += vector_add_int
HEX_TESTS += scatter_gather
HEX_TESTS += hvx_misc
HEX_TESTS += hvx_histogram
HEX_TESTS += invalid-slots
HEX_TESTS += unaligned_pc

run-and-check-exception = $(call run-test,$2,$3 2>$2.stderr; \
	test $$? -eq 1 && grep -q "exception $(strip $1)" $2.stderr)

run-invalid-slots: invalid-slots
	$(call run-and-check-exception, 0x15, $@, $(QEMU) $(QEMU_OPTS) $<)

HEX_TESTS += test_abs
HEX_TESTS += test_bitcnt
HEX_TESTS += test_bitsplit
HEX_TESTS += test_call
HEX_TESTS += test_clobber
HEX_TESTS += test_cmp
HEX_TESTS += test_dotnew
HEX_TESTS += test_ext
HEX_TESTS += test_fibonacci
HEX_TESTS += test_hl
HEX_TESTS += test_hwloops
HEX_TESTS += test_jmp
HEX_TESTS += test_lsr
HEX_TESTS += test_mpyi
HEX_TESTS += test_packet
HEX_TESTS += test_reorder
HEX_TESTS += test_round
HEX_TESTS += test_vavgw
HEX_TESTS += test_vcmpb
HEX_TESTS += test_vcmpw
HEX_TESTS += test_vlsrw
HEX_TESTS += test_vmaxh
HEX_TESTS += test_vminh
HEX_TESTS += test_vpmpyh
HEX_TESTS += test_vspliceb

HEX_TESTS += v68_scalar
HEX_TESTS += v68_hvx
HEX_TESTS += v69_hvx
HEX_TESTS += v73_scalar

TESTS += $(patsubst %, build/%, $(HEX_TESTS))

.PHONY: all
all: $(TESTS)

.PHONY: clean
clean:
	rm build/*


build/atomics: atomics.c hex_test.h
build/brev: brev.c hex_test.h
build/circ: circ.c hex_test.h
build/dual_stores: dual_stores.c hex_test.h
build/fpstuff: fpstuff.c hex_test.h
build/hex_sigsegv: hex_sigsegv.c hex_test.h
build/load_align: load_align.c hex_test.h
build/load_unpack: load_unpack.c hex_test.h
build/mem_noshuf_exception: mem_noshuf_exception.c hex_test.h
build/mem_noshuf: mem_noshuf.c hex_test.h
build/misc: misc.c hex_test.h
build/multi_result: multi_result.c hex_test.h
build/overflow: overflow.c hex_test.h
build/preg_alias: preg_alias.c hex_test.h
build/read_write_overlap: read_write_overlap.c hex_test.h
build/reg_mut: reg_mut.c hex_test.h
build/unaligned_pc: unaligned_pc.c

# This test has to be compiled for the -mv67t target
build/usr: usr.c hex_test.h
	$(CC) $(CFLAGS) -mv67t -O2 -Wno-inline-asm -Wno-expansion-to-defined $< -o $@ $(LDFLAGS)

# Build this test with -mv71 to exercise the CABAC instruction
build/misc: misc.c
	$(CC) $(CFLAGS) -mv71 -O2 $< -o $@ $(LDFLAGS)
build/scatter_gather: CFLAGS += -mhvx
build/vector_add_int: CFLAGS += -mhvx -fvectorize
build/hvx_misc: hvx_misc.c hvx_misc.h
build/hvx_misc: CFLAGS += -mhvx
build/hvx_histogram: CFLAGS += -mhvx -Wno-gnu-folding-constant
build/v68_hvx: v68_hvx.c hvx_misc.h v6mpy_ref.c.inc
build/v68_hvx: CFLAGS += -mhvx -Wno-unused-function
build/v69_hvx: v69_hvx.c hvx_misc.h
build/v69_hvx: CFLAGS += -mhvx -Wno-unused-function
build/v73_scalar: CFLAGS += -Wno-unused-function

build/hvx_histogram: hvx_histogram.c hvx_histogram_row.S
	$(CC) $(CFLAGS) $(CROSS_CC_GUEST_CFLAGS) $^ -o $@ $(LDFLAGS)
