.. _unicorn_replacement:

Styx as a Replacement for Unicorn
#################################

Styx can be used as a replacement for Unicorn i.e. purely as a CPU emulator.  The following examples show how to emulate 32 bit Arm code using either Rust or Python.  Both examples produce identical results.

Rust Example
============

.. code-block:: rust

    use std::borrow::Cow;

    use styx_emulator::core::cpu::arch::arm::{ArmRegister, ArmVariants};
    use styx_emulator::core::processor::executor::Executor;
    use styx_emulator::core::cpu::hooks::StyxHook;
    use styx_emulator::prelude::*;
    use styx_emulator::processors::RawProcessor;

    use keystone_engine::Keystone;

    /*
        MOV     R0, #5                ; Load 5 into register R0
        MOV     R1, #3                ; Load 3 into register R1
        MUL     R2, R0, R1            ; Multiply R0 by R1, store result in R2
        SVC     #0                    ; Trigger a software interrupt
    */
    const THUMB_CODE: &str = "MOV R0, #5; MOV R1, #3; MUL R2, R0, R1; SVC #0";

    /// Uses Keystone to assemble some Arm instructions and return the resulting bytes
    fn assemble_code() -> Vec<u8> {
        let ks = Keystone::new(keystone_engine::Arch::ARM, keystone_engine::Mode::THUMB)
            .expect("Could not initialize Keystone engine");
        let asm = ks
            .asm(THUMB_CODE.to_string(), 0x4000)
            .expect("Could not assemble");

        println!("Assembled {} instructions", asm.stat_count);
        asm.bytes
    }

    /// Callback for tracing instructions
    fn hook_code(cpu: CpuBackend) {
        println!(">>> Tracing instruction at 0x{:x}", cpu.pc().unwrap());
    }

    /// Callback for tracing basic blocks
    fn hook_block(_cpu: CpuBackend, address: u64, size: u32) {
        println!(">>> Tracing basic block at 0x{:x}, block size = {}", address, size);
    }

    /// Callback for tracing interrupts
    fn hook_interrupts(cpu: CpuBackend, intno: i32) {
        println!(">>> Tracing interrupt at 0x{:x}, interrupt number = {}", cpu.pc().unwrap(), intno);
        // quit emulation
        cpu.stop().unwrap();
    }

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // create a RawProcessor (i.e. minimal processor) for 32 bit Arm LE, using the PCode backend
        let proc = ProcessorBuilder::default()
            .with_backend(Backend::Pcode)
            .with_endian(ArchEndian::LittleEndian)
            .with_variant(ArmVariants::ArmCortexM4)
            .with_loader(RawLoader)
            .with_executor(Executor::default())
            .with_input_bytes(Cow::Owned(assemble_code()))
            .build::<RawProcessor>()?;

        // add hooks for instructions, basic blocks, and interrupts
        proc.add_hook(StyxHook::Code { start: u64::MIN, end: u64::MAX, callback: Box::new(hook_code) })?;
        proc.add_hook(StyxHook::Block { callback: Box::new(hook_block) })?;
        proc.add_hook(StyxHook::Interrupt { callback: Box::new(hook_interrupts) })?;

        // start emulation
        proc.start()?;

        // check that R2 holds the value 15 to see if emulation was successful
        assert_eq!(proc.read_register::<u32>(ArmRegister::R2).unwrap(), 15_u32);

        Ok(())
    }

Python Example
==============

.. code-block:: python

    from styx_emulator.cpu import ArchEndian, Backend, CpuBackend
    from styx_emulator.cpu.hooks import CodeHook, BlockHook, InterruptHook
    from styx_emulator.processor import ProcessorBuilder, Target
    from styx_emulator.loader import RawLoader
    from styx_emulator.executor import DefaultExecutor
    from styx_emulator.arch.arm import ArmVariant, ArmRegister

    from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB

    '''
        MOV     R0, #5                ; Load 5 into register R0
        MOV     R1, #3                ; Load 3 into register R1
        MUL     R2, R0, R1            ; Multiply R0 by R1, store result in R2
        SVC     #0                    ; Trigger a software interrupt
    '''
    THUMB_CODE = "MOV R0, #5; MOV R1, #3; MUL R2, R0, R1; SVC #0"

    def assemble_code() -> bytes:
        '''
        Uses Keystone to assemble some Arm instructions and return the resulting bytes
        '''
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

        asm_bytes, asm_stat_count = ks.asm(THUMB_CODE)

        print(f"Assembled {asm_stat_count} instructions")

        return asm_bytes

    def hook_code(cpu: CpuBackend):
        '''
        Callback for tracing instructions
        '''
        print(f">>> Tracing instruction at 0x{cpu.pc:x}")

    def hook_block(_cpu: CpuBackend, address: int, size: int):
        '''
        Callback for tracing basic blocks
        '''
        print(f">>> Tracing basic block at 0x{address:x}, block size = {size}")

    def hook_interrupts(cpu: CpuBackend, intno: int):
        '''
        Callback for tracing interrupts
        '''
        print(f">>> Tracing interrupt at 0x{cpu.pc:x}, interrupt number = {intno}")
        # quit emulation
        cpu.stop()

    def main():
        # create a RawProcessor (i.e. minimal processor) for 32 bit Arm LE, using the PCode backend
        builder = ProcessorBuilder()
        builder.backend = Backend.Pcode
        builder.endian = ArchEndian.LittleEndian
        builder.variant = ArmVariant.ArmCortexM4
        builder.loader = RawLoader()
        builder.executor = DefaultExecutor()
        builder.input_bytes = bytes(assemble_code())
        proc = builder.build(Target.Raw)

        # add hooks for instructions, basic blocks, and interrupts
        proc.add_hook(CodeHook(0, 0xFFFFFFFFFFFFFFFF, hook_code))
        proc.add_hook(BlockHook(hook_block))
        proc.add_hook(InterruptHook(hook_interrupts))

        # start emulation
        proc.start()

        # check that R2 holds the value 15 to see if emulation was successful
        assert(proc.read_register(ArmRegister.R2) == 15)

    if __name__ == '__main__':
        main()
