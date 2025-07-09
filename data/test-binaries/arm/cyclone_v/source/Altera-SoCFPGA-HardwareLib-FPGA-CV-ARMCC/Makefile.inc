#*****************************************************************************
#
# Copyright 2013-2020 Intel Corporation. All Rights Reserved.
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
#*****************************************************************************

#
# $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-FPGA-CV-ARMCC/Makefile.inc#3 $
#

ALT_DEVICE := CYCLONEV
ALT_DEVICE_FAMILY := soc_cv_av

ifeq ($(COMPILER), GNU)
ALT_BRIDGE_F2S := alt_bridge_f2s_gnu
else
ALT_BRIDGE_F2S := alt_bridge_f2s_armcc
endif

HWLIBS_SRC ?= alt_bridge_manager.c alt_clock_manager.c alt_ecc.c alt_fpga_manager.c alt_reset_manager.c alt_sdram.c alt_system_manager.c  alt_16550_uart.c alt_cache.c alt_dma.c alt_ethernet.c alt_generalpurpose_io.c alt_i2c.c alt_mmu.c alt_qspi.c alt_spi.c alt_watchdog.c  alt_address_space.c alt_can.c alt_dma_program.c alt_eth_phy_ksz9031.c alt_globaltmr.c alt_interrupt.c alt_nand.c alt_sdmmc.c alt_timers.c alt_safec.c

# if it is semihosted, printf goes to semihosting console otherwise to UART
ifeq ($(SEMIHOSTED), 1)
  UART_DEFINES ?= -DPRINTF_HOST
else
  UART_DEFINES ?= -DPRINTF_UART
  HWLIBS_SRC += alt_printf.c alt_p2uart.c
endif

ifeq ($(COMPILER),GNU)
  HWLIBS_SRC += alt_base.c
else
  HWLIBS_SRC += alt_interrupt_armcc.s
endif

ifneq ($(MAKECMDGOALS),clean)
  ifeq ($(SOCEDS_DEST_ROOT),)
    SOCEDS_DEST_ROOT = $(error ERROR: SOCEDS_DEST_ROOT not set. ARM DS-5 must be started from the Embedded Command Shell)
  endif
endif

ALL_SRC = $(HWLIBS_SRC) $(EXAMPLE_SRC)

OBJ_DIR ?= objs_$(COMPILER)_$(ALT_DEVICE)
OBJ     := $(patsubst %.c,$(OBJ_DIR)/%.o,$(ALL_SRC))
OBJ     := $(patsubst %.s,$(OBJ_DIR)/%.o,$(OBJ))

SOCEDS_ROOT ?= $(SOCEDS_DEST_ROOT)

HWLIBS_SRC_ROOT = hwlib

INCLUDE_DIRS := -Ilib \
                -I$(HWLIBS_SRC_ROOT)/include \
                -I$(HWLIBS_SRC_ROOT)/include/$(ALT_DEVICE_FAMILY) \
                -I$(HWLIBS_SRC_ROOT)/include/$(ALT_DEVICE_FAMILY)/socal \
                -I$(NEWLIB_ROOT)/include

# set search path for source files
SRC_PATH = $(subst $() $(),:,$(dir $(ALL_SRC)))
VPATH = $(HWLIBS_SRC_ROOT)/src/hwmgr/:$(HWLIBS_SRC_ROOT)/src/hwmgr/$(ALT_DEVICE_FAMILY):$(HWLIBS_SRC_ROOT)/src/utils:$(SRC_PATH)

ifeq ($(COMPILER), GNU)
  CROSS_COMPILE := arm-eabi-
  CC := $(CROSS_COMPILE)gcc
  LD := $(CROSS_COMPILE)g++
  NM := $(CROSS_COMPILE)nm
  OD := $(CROSS_COMPILE)objdump
  OC := $(CROSS_COMPILE)objcopy
  AS := $(CROSS_COMPILE)as
  LINKER_SCRIPT := $(HWLIBS_SRC_ROOT)/src/linkerscripts/cvav-$(MEMORY).ld
  MULTILIBFLAGS := -mcpu=cortex-a9 -mfloat-abi=softfp -mfpu=neon
  CFLAGS  := -g -O0 -Wall $(MULTILIBFLAGS) $(INCLUDE_DIRS) -D$(ALT_DEVICE_FAMILY) $(UART_DEFINES) -D$(ALT_DEVICE) -fdata-sections -ffunction-sections -DALT_FPGA_ENABLE_DMA_SUPPORT=1 -DALT_BRIDGE_PROVISION_F2S_SUPPORT $(ADD_CFLAGS_GNU)
  ifeq ($(SEMIHOSTED), 1)
    LDFLAGS := -T$(LINKER_SCRIPT) $(MULTILIBFLAGS) -Wl,--gc-sections -Xlinker --require-defined=__auto_semihosting
  else
    LDFLAGS := -T$(LINKER_SCRIPT) $(MULTILIBFLAGS) -B$(NEWLIB_ROOT)/lib --sysroot=$(NEWLIB_ROOT)/lib --specs=nosys.specs -Wl,--gc-sections
  endif
  OBJ     := $(OBJ)
  ODFLAGS := -DS
  OCFLAGS := -O binary #Note - This line MUST end with a space
else
  CROSS_COMPILE := arm-eabi-
  CC := armcc
  AS := armasm
  LD := armlink
  NM := $(CROSS_COMPILE)nm
  OD := $(CROSS_COMPILE)objdump
  OC := $(CROSS_COMPILE)objcopy

  LINKER_SCRIPT := $(HWLIBS_SRC_ROOT)/src/linkerscripts/cvav-$(MEMORY).scat
  MULTILIBFLAGS := --diag_error=warning --diag_suppress=9931 --cpu=Cortex-A9 --no_unaligned_access
  CFLAGS   := -g -O0 --c99 --strict $(MULTILIBFLAGS) $(INCLUDE_DIRS) -D$(ALT_DEVICE_FAMILY) -DALT_FPGA_ENABLE_DMA_SUPPORT=1 -D_USE_STDLIB -DALT_BRIDGE_PROVISION_F2S_SUPPORT -D$(ALT_DEVICE) $(UART_DEFINES) $(ADD_CFLAGS_ARMCC)
  ASMFLAGS := -g $(MULTILIBFLAGS)
  LDFLAGS  := --strict $(MULTILIBFLAGS) --entry=alt_interrupt_vector --scatter=$(LINKER_SCRIPT)
  ifeq ($(SEMIHOSTED), 1)
    LDFLAGS += --keep=__auto_semihosting
  endif
  ODFLAGS  := -d
  OCFLAGS  := --bin --output=
endif

ifeq ($(or $(COMSPEC),$(ComSpec)),)
  RM := rm -rf
else
  RM := cs-rm -rf
endif

CP := cp -f

.PHONY: all
all:
	@$(MAKE) copy_hwlib soc_system.sof $(ALT_BRIDGE_F2S).s $(OBJ_DIR)
	@$(MAKE) $(ELF)

.PHONY: clean
clean:
	$(RM) $(OBJ_DIR) $(ELF) *.objdump *.map

.PHONY: help
help:
	@echo "make COMPILER=(ARMCC/GNU) MEMORY=(ddr/ocr) SEMIHOSTED=(0/1)"

.PHONY: copy_hwlib
copy_hwlib: hwlib.stamp

hwlib.stamp:
	cp $(HWLIBS_ROOT) . -rnL
	touch $@

remove_hwlib:
	rm -rf hwlib hwlib.stamp

soc_system.sof: $(SOCEDS_ROOT)/examples/hardware/cv_soc_devkit_ghrd/output_files/soc_system.sof
	$(CP) $< $@

$(ALT_BRIDGE_F2S).s: $(HWLIBS_ROOT)/src/hwmgr/soc_cv_av/$(ALT_BRIDGE_F2S).s
	$(CP) $< $@

# No Data Compression
soc_system_nodc.rbf: soc_system.sof
	quartus_cpf -c $< $@

# With Data Compression
soc_system_dc.rbf: soc_system.sof
	$(RM) cpf_option.txt
	echo bitstream_compression=on > cpf_option.txt
	quartus_cpf -c -o cpf_option.txt $< $@
	$(RM) cpf_option.txt

soc_system_nodc.o: soc_system_nodc.rbf
	$(OC) --input-target binary --output-target elf32-little --alt-machine-code 40 $< $@

soc_system_dc.o: soc_system_dc.rbf
	$(OC) --input-target binary --output-target elf32-little --alt-machine-code 40 $< $@

$(ALT_BRIDGE_F2S).o: $(ALT_BRIDGE_F2S).s
	$(AS) $(ASMFLAGS) -o $(ALT_BRIDGE_F2S).o $(ALT_BRIDGE_F2S).s

$(OBJ_DIR) :
	mkdir $@

$(OBJ_DIR)/%.o: %.c Makefile Makefile.inc
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: %.s  Makefile Makefile.inc
	$(AS) $(ASMFLAGS) $< -o $@

$(ELF): $(OBJ) soc_system_dc.o $(ALT_BRIDGE_F2S).o
	$(LD) $(LDFLAGS) $(OBJ) soc_system_dc.o $(ALT_BRIDGE_F2S).o -o $@
	$(OD) $(ODFLAGS) $@ > $@.objdump
