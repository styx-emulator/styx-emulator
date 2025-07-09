#****************************************************************************
#
# Copyright 2013-2020 Altera Corporation. All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#****************************************************************************

#
# $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-ECCL2-CV-GNU/Makefile#3 $
#

COMPILER := GNU
#COMPILER := ARMCC

MEMORY ?= ddr
#MEMORY ?= ocr

SEMIHOSTED ?= 1
#SEMIHOSTED ?= 0

HWLIBS_ROOT := ../../../armv7a/hwlib
NEWLIB_ROOT := ../../../tools/newlib/usr/local/arm-eabi

ADD_CFLAGS_GNU :=
ADD_CFLAGS_ARMCC :=

EXAMPLE_SRC := main.c socfpga_eccl2.c socfpga_int.c socfpga_pagetable.c

ELF := application.axf

# These parameters can be overriden
# LINKER_SCRIPT
HWLIBS_SRC := alt_clock_manager.c alt_cache.c alt_interrupt.c alt_mmu.c alt_16550_uart.c

include Makefile.inc
