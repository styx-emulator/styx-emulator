pushd ../../data/test-binaries/arm/kinetis_21/
make clean
make
popd

mkdir -p bin/

# proc
cp ../../data/test-binaries/arm/kinetis_21/twrk21f120m-sdk/boards/twrk21f120m/driver_examples/uart/interrupt_proc/uart_interrupt.c bin/proc.c
cp ../../data/test-binaries/arm/kinetis_21/bin/interrupt_proc/interrupt_proc_debug.bin bin/proc.bin
cp ../../data/test-binaries/arm/kinetis_21/bin/interrupt_proc/interrupt_proc_debug.elf bin/proc.elf
arm-none-eabi-objdump -D bin/proc.elf >bin/proc.list

# hackme
cp ../../data/test-binaries/arm/kinetis_21/twrk21f120m-sdk/boards/twrk21f120m/driver_examples/uart/interrupt_hackme/uart_interrupt.c bin/hackme.c
cp ../../data/test-binaries/arm/kinetis_21/bin/interrupt_hackme/interrupt_hackme_debug.bin bin/hackme.bin
cp ../../data/test-binaries/arm/kinetis_21/bin/interrupt_hackme/interrupt_hackme_debug.elf bin/hackme.elf
arm-none-eabi-objdump -D bin/hackme.elf >bin/hackme.list
