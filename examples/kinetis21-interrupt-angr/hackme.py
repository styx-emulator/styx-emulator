# BSD 2-Clause License
#
# Copyright (c) 2024, Styx Emulator Project
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from styx.cpu import ArchEndian
from styx.cpu.hooks import CodeHook
from styx.arch.arm import ArmVariant
from styx.processor import Processor, ProcessorBuilder, Target
from styx.loader import RawLoader
from styx.executor import DefaultExecutor
from styx.plugin import ProcessorTracingPlugin

from styx_symbion.backend import StyxConcreteTarget

import angr


def build_hackme_proc() -> Processor:
    builder = ProcessorBuilder()
    builder.endian = ArchEndian.LittleEndian
    builder.target_program = "bin/hackme.bin"
    builder.ipc_port = 16001
    builder.loader = RawLoader()
    builder.executor = DefaultExecutor()
    builder.variant = ArmVariant.ArmCortexM4
    builder.add_plugin(ProcessorTracingPlugin())
    cpu = builder.build(Target.Kinetis21)
    return cpu


# set up the processor
hackme = build_hackme_proc()
hackme_target = StyxConcreteTarget(hackme)
hackme_project = angr.Project(
    "bin/hackme.elf",
    concrete_target=hackme_target,
    use_sim_procedures=True,
    load_options={"arch": "ARMEL"},
)


def add_checkpoint(label, name, proc, proj):
    addr = name
    if type(name) is str:
        addr = proj.loader.find_symbol(name).rebased_addr - 1
    else:
        assert type(name) is int, "label must be str (fn name) | int (addr)"
    proc.add_hook(CodeHook(addr, addr, lambda _: print(f"[{label}]: hit {name}")))


# add some checkpoint prints for important places in the binary
add_checkpoint("hackme", "main", hackme, hackme_project)
add_checkpoint("hackme", "EnableIRQ", hackme, hackme_project)
add_checkpoint("hackme", "UART_ReadByte", hackme, hackme_project)

# run to UART_ReadByte in the irq handler, todo: wish this was more automatic (maybe look at different factory states)
irqh_state = hackme_project.factory.call_state("UART5_RX_TX_IRQHandler")
irqh_state.options.add(angr.options.SYMBION_SYNC_CLE)
irqh_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
symbion = angr.exploration_techniques.Symbion(
    find=[
        0xB74 - 1,
        0xB74,
        0xB74 + 1,
    ]
)
simgr = hackme_project.factory.simgr(irqh_state)
simgr.use_technique(symbion)
irqh_state = simgr.run().found[0]

# run to the place where the proc.bin value is put onto the stack
simgr = hackme_project.factory.simgr(irqh_state)
simgr.use_technique(angr.exploration_techniques.Explorer())
ex = simgr.explore(find=[0xB83, 0xB84, 0xB85])
irqh_state = ex.found[0]
# get the actual value sent over uart from memory
actual_value = irqh_state.mem[irqh_state.regs.r7 + 7].uint8_t
print(f"actual value is {actual_value}")

# run to the processing loop in the main function
simgr = hackme_project.factory.simgr(irqh_state)
symbion = angr.exploration_techniques.Symbion(
    find=[
        0xBF5,
        0xBF6,
        0xBF7,
    ]
)
simgr.use_technique(symbion)
ex = simgr.run()

# setup the main state to allow angr to be able to derive the possible values
state = ex.found[0]
# symbolic byte value for analysis
value = state.solver.BVS("byte", 8)
# these are pointer aliases or something at the end of main, one of these should be a pointer to a 1 instead of value
state.mem[0x00FF0128].uint8_t = value
state.mem[0xC38].uint32_t = 0x00FF0128
state.mem[0x00FF0124].uint8_t = value
state.mem[0xC3C].uint32_t = 0x00FF0124
# transmute constraints
# ideally, these would be transferred automatically but angr is annoying
state.solver.add(value >= "A")
state.solver.add(value <= "F")
simgr = hackme_project.factory.simgr(state)
simgr.use_technique(angr.exploration_techniques.Explorer())
# run to where the bytes are actually sent back
ex = simgr.explore(
    find=[
        0xC1B,
        0xC1C,
        0xC1D,
    ]
)
# use our constraints to find the "win" condition value
print(ex.found[0].solver.constraints)
win_value = ex.found[0].solver.eval_upto(value, 10)
print(f"win_value = {win_value}")

# todo: use the win_value to send back 'OK\n'

# run the cpu until it's c-z killed
hackme_target.run()

input("hit done: ...\n")
