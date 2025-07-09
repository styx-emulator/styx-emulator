PROJECT_NAME = uart_demo

# Declare command line tools - assume these are in the path
CC        = arm-none-eabi-gcc
LD        = arm-none-eabi-ld
CP        = arm-none-eabi-objcopy
SIZE      = arm-none-eabi-size

INC_DIR = inc
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj

HAL_DRIVERS = $(INC_DIR)/STM32F4xx_HAL_Driver/Src

CFLAGS = -DUSE_FULL_LL_DRIVER=1 -I$(INC_DIR) -I$(INC_DIR)/CMSIS -I$(INC_DIR)/STM32F4xx -I$(INC_DIR)/STM32F4xx_HAL_Driver/Inc -mcpu=cortex-m4 -mthumb -fdata-sections -g -O0 -fno-common
LDFLAGS = -Tstm32_flash.ld -Wl,--gc-sections
CPFLAGS = -Obinary

COMMON_FILES = system_stm32f4xx.c
COMMON_FILES += startup_stm32f4xx.s
COMMON_FILES += $(HAL_DRIVERS)/stm32f4xx_ll_usart.c
COMMON_FILES += $(HAL_DRIVERS)/stm32f4xx_ll_rcc.c

all: elf bin

elf: $(BUILD_DIR)/$(PROJECT_NAME).elf
bin: $(BUILD_DIR)/$(PROJECT_NAME).bin

$(BUILD_DIR)/$(PROJECT_NAME).elf: $(COMMON_FILES)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ main.c $^

$(BUILD_DIR)/$(PROJECT_NAME).bin: $(BUILD_DIR)/$(PROJECT_NAME).elf
	$(CP) $(CPFLAGS) $^ $@

$(HAL_DRIVERS)/%.c:
	$(CC) $(CFLAGS) -c $@

clean:
	rm -rf $(BUILD_DIR)/*

size:
	$(SIZE) $(BUILD_DIR)/$(PROJECT_NAME).elf

.PHONY: all elf bin clean size
