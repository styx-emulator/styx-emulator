# SPDX-License-Identifier: BSD-2-Clause

# Uses `Styx` purely as a CPU emulator, like `Unicorn`.
from styx_emulator.cpu import ArchEndian, Backend, ProcessorCore
from styx_emulator.cpu.hooks import CodeHook, InterruptHook
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

def hook_code(cpu: ProcessorCore):
    '''
    Callback for tracing instructions
    '''
    print(f">>> Tracing instruction at 0x{cpu.pc:x}")

def hook_interrupts(cpu: ProcessorCore, intno: int):
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

    # add hooks for instructions and interrupts
    proc.add_hook(CodeHook(0, 0xFFFFFFFFFFFFFFFF, hook_code))
    proc.add_hook(InterruptHook(hook_interrupts))

    # start emulation and wait for the interrupt hook to stop it
    proc.start()
    proc.wait_for_stop()

    # check that R2 holds the value 15 to see if emulation was successful
    assert(proc.read_register(ArmRegister.R2) == 15)

if __name__ == '__main__':
    main()
