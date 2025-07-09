# XXX Note, this makefile is not perfect, since it doesn't track the files in
# the bin directory. This is because the directory structure for the various
# examples varies, so we can't predict/structure things right. We could
# probably split the examples into groups to treat them differently, but it
# wasn't worth the time.

####################################################
##### Add new target example directories here. #####
TARGET_BUILD_DIRS += demo_apps/adc16_low_power
TARGET_BUILD_DIRS += demo_apps/bubble
TARGET_BUILD_DIRS += demo_apps/dac_adc
TARGET_BUILD_DIRS += demo_apps/emvl1
TARGET_BUILD_DIRS += demo_apps/emvl1_freertos
TARGET_BUILD_DIRS += demo_apps/hello_world
TARGET_BUILD_DIRS += demo_apps/fuzz_example
TARGET_BUILD_DIRS += demo_apps/mbedtls/mbedtls_selftest
TARGET_BUILD_DIRS += demo_apps/power_manager
TARGET_BUILD_DIRS += demo_apps/power_mode_switch
TARGET_BUILD_DIRS += demo_apps/rtc_func
TARGET_BUILD_DIRS += demo_apps/sai
TARGET_BUILD_DIRS += demo_apps/shell
TARGET_BUILD_DIRS += demo_apps/wolfssl/wolfssl_benchmark
TARGET_BUILD_DIRS += demo_apps/wolfssl/wolfssl_selftest
TARGET_BUILD_DIRS += rtos_examples/freertos_dspi
TARGET_BUILD_DIRS += rtos_examples/freertos_event
TARGET_BUILD_DIRS += rtos_examples/freertos_generic
TARGET_BUILD_DIRS += rtos_examples/freertos_hello
TARGET_BUILD_DIRS += rtos_examples/freertos_i2c
TARGET_BUILD_DIRS += rtos_examples/freertos_mutex
TARGET_BUILD_DIRS += rtos_examples/freertos_queue
TARGET_BUILD_DIRS += rtos_examples/freertos_sem
TARGET_BUILD_DIRS += rtos_examples/freertos_swtimer
TARGET_BUILD_DIRS += rtos_examples/freertos_tickless
TARGET_BUILD_DIRS += rtos_examples/freertos_uart
TARGET_BUILD_DIRS += driver_examples/gpio/led_output
TARGET_BUILD_DIRS += driver_examples/uart/polling-analysis-deez
TARGET_BUILD_DIRS += driver_examples/uart/polling-analysis-eelz
TARGET_BUILD_DIRS += driver_examples/uart/interrupt_proc
TARGET_BUILD_DIRS += driver_examples/uart/interrupt_hackme
####################################################

# We build debug by default.
# To build release, run:
#   make RELEASE=1
ifdef RELEASE
	BUILD_TYPE=release
else
	BUILD_TYPE=debug
endif

SDK_PATH=twrk21f120m-sdk/boards/twrk21f120m/
TARGET_BUILD_DIRS := $(addprefix $(SDK_PATH),$(TARGET_BUILD_DIRS))
TARGET_BINS = $(foreach TARGET_BASE,            \
			            $(TARGET_BUILD_DIRS),   \
			            $(addsuffix /armgcc/$(BUILD_TYPE)/$(notdir $(TARGET_BASE)),$(TARGET_BASE)))
TARGET_BINS := $(addsuffix .bin,$(TARGET_BINS))

all: $(TARGET_BINS)

%.bin: %.elf | bin
	arm-none-eabi-objcopy -Obinary $< $@
	mkdir -p bin/$(*F)
	cp $@ bin/$(*F)/$(*F)_$(BUILD_TYPE)$(suffix $@)
	cp $< bin/$(*F)/$(*F)_$(BUILD_TYPE)$(suffix $<)

# Build the executable and copy into the bin directory.
%.elf:
	cd $(dir $(@D)) && ./build_$(BUILD_TYPE).sh
	# Hax! If there's a name mismatch between the directory and the executable
	# file, we just make a copy.
	if ! [ -f $@ ]; then cp $(@D)/*.elf $@; fi

bin:
	mkdir -p $@

clean:
	for build_path in $(TARGET_BUILD_DIRS); do \
		cd $$build_path/armgcc && ./clean.sh && cd - 1>/dev/null; \
	done
	rm -rf bin

.SILENT:
.SECONDARY:
.PHONY: all clean
