ifndef RTOS_DIR
$(error RTOS_DIR is not set (path to FreeRTOS source))
endif

ifndef XILINX_DIR
$(error XILINX_DIR is not set (path to generated Xilinx files))
endif

PROJECT_NAME = freertos

CC        = powerpc-eabi-gcc
LD        = powerpc-eabi-ld
CP        = powerpc-eabi-objcopy
SIZE      = powerpc-eabi-size

LINKER_SCRIPT = $(RTOS_DIR)/FreeRTOS/Demo/PPC405_Xilinx_Virtex4_GCC/RTOSDemo/RTOSDemo_linker_script.ld

BUILD_DIR = build

LIBRARIES =  $(XILINX_DIR)/lib/libxil.a

LIBPATH = -L$(XILINX_DIR)/lib/

HEADERS = $(RTOS_DIR)/FreeRTOS/Demo/PPC405_Xilinx_Virtex4_GCC/RTOSDemo/FreeRTOSConfig.h

# Demo source files
# from github FreeRTOS/FreeRTOS/tree/V8.2.3/FreeRTOS/Demo/PPC405_Xilinx_Virtex4_GCC/RTOSDemo
DEMO_SRC_DIR = $(RTOS_DIR)/FreeRTOS/Demo/PPC405_Xilinx_Virtex4_GCC/RTOSDemo

DEMO_SOURCE = $(DEMO_SRC_DIR)/main.c $(DEMO_SRC_DIR)/serial/serial.c \
	$(DEMO_SRC_DIR)/partest/partest.c $(DEMO_SRC_DIR)/flop/flop.c \
	$(DEMO_SRC_DIR)/flop/flop-reg-test.c

DEMO_INCLUDE = -I$(DEMO_SRC_DIR)/ -I$(DEMO_SRC_DIR)/flop

# Demo common files
# from github FreeRTOS/FreeRTOS/tree/V8.2.3/FreeRTOS/Demo/Common
COMMON_DIR = $(RTOS_DIR)/FreeRTOS/Demo/Common
DEMO_COMMON = $(COMMON_DIR)/Minimal/BlockQ.c $(COMMON_DIR)/Minimal/blocktim.c $(COMMON_DIR)/Minimal/comtest.c $(COMMON_DIR)/Minimal/countsem.c $(COMMON_DIR)/Minimal/death.c \
	$(COMMON_DIR)/Minimal/dynamic.c $(COMMON_DIR)/Minimal/flash.c $(COMMON_DIR)/Minimal/GenQTest.c $(COMMON_DIR)/Minimal/integer.c $(COMMON_DIR)/Minimal/QPeek.c \
	$(COMMON_DIR)/Minimal/recmutex.c $(COMMON_DIR)/Minimal/semtest.c

COMMON_INCLUDE = -I$(RTOS_DIR)/FreeRTOS/Demo/Common/include

# FreeRTOS source files
# from github FreeRTOS/FreeRTOS/tree/V8.2.3/FreeRTOS/Source
RTOS_SOURCE = $(RTOS_DIR)/FreeRTOS/Source/tasks.c $(RTOS_DIR)/FreeRTOS/Source/list.c $(RTOS_DIR)/FreeRTOS/Source/queue.c \
	$(RTOS_DIR)/FreeRTOS/Source/portable/GCC/PPC405_Xilinx/port.c $(RTOS_DIR)/FreeRTOS/Source/portable/GCC/PPC405_Xilinx/portasm.S $(RTOS_DIR)/FreeRTOS/Source/portable/MemMang/heap_2.c

RTOS_INCLUDE = -I$(RTOS_DIR)/FreeRTOS/Source/portable/GCC/PPC405_Xilinx -I$(RTOS_DIR)/FreeRTOS/Source/include

XILINX_SRC = $(XILINX_DIR)/libsrc/intc_v1_11_a/xintc.c $(XILINX_DIR)/libsrc/intc_v1_11_a/xintc_g.c

XILINX_INCLUDE = -I$(XILINX_DIR)/libsrc/intc_v1_11_a -I$(XILINX_DIR)/include

SOURCES = $(DEMO_SOURCE) $(DEMO_COMMON) $(RTOS_SOURCE) $(XILINX_SRC)
INCLUDES = $(DEMO_INCLUDE) $(COMMON_INCLUDE) $(RTOS_INCLUDE) $(XILINX_INCLUDE)

CC_OPT  =  -O0 -g
CFLAGS  = $(INCLUDES) -D GCC_PPC405 -mregnames
LDFLAGS = -Wl,-T -Wl,$(LINKER_SCRIPT)
CPFLAGS = -Obinary

all: elf bin

elf: $(BUILD_DIR)/$(PROJECT_NAME).elf
bin: $(BUILD_DIR)/$(PROJECT_NAME).bin

$(BUILD_DIR)/$(PROJECT_NAME).bin: $(BUILD_DIR)/$(PROJECT_NAME).elf
	$(CP) $(CPFLAGS) $^ $@

$(BUILD_DIR)/$(PROJECT_NAME).elf: $(HEADERS) | $(SOURCES) $(LINKER_SCRIPT) $(LIBRARIES)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CC_OPT) $(CFLAGS) $(SOURCES) -o $@ $(LIBPATH) $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)/*

size:
	$(SIZE) $(BUILD_DIR)/$(PROJECT_NAME).elf

.PHONY: all elf bin clean size
