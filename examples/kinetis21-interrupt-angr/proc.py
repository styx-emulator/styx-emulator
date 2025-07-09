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
from styx.arch.arm import ArmVariant, ArmRegister
from styx.processor import Processor, ProcessorBuilder, Target
from styx.loader import RawLoader
from styx.executor import DefaultExecutor
from styx.plugin import ProcessorTracingPlugin
from styx.peripherals import UartClient

from styx_symbion.backend import StyxConcreteTarget

import threading
import angr


def build_proc_proc() -> Processor:
    builder = ProcessorBuilder()
    builder.endian = ArchEndian.LittleEndian
    builder.target_program = "bin/proc.bin"
    builder.ipc_port = 16000
    builder.loader = RawLoader()
    builder.executor = DefaultExecutor()
    builder.variant = ArmVariant.ArmCortexM4
    builder.add_plugin(ProcessorTracingPlugin())
    cpu = builder.build(Target.Kinetis21)
    return cpu


# build our processor, angr backend, and processor project
proc = build_proc_proc()
proc_target = StyxConcreteTarget(proc)
proc_project = angr.Project(
    "bin/proc.elf",
    concrete_target=proc_target,
    use_sim_procedures=True,
    load_options={"arch": "ARMEL"},
)

# print out '[label] hit .name' when proc hits an address/symbol
def add_checkpoint(label, name, proc, proj):
    addr = name
    if type(name) is str:
        addr = proj.loader.find_symbol(name).rebased_addr - 1
    else:
        assert type(name) is int, "label must be str (fn name) | int (addr)"
    proc.add_hook(CodeHook(addr, addr, lambda _: print(f"[{label}]: hit {name}")))


# add some logs for import points in our program
add_checkpoint("proc", "main", proc, proc_project)
add_checkpoint("proc", "UART_ReadByte", proc, proc_project)
add_checkpoint("proc", "UART_WriteBlocking", proc, proc_project)
add_checkpoint("proc", "UART5_RX_TX_IRQHandler", proc, proc_project)

class UartThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.cancel = threading.Event()
        self.ready = threading.Event()

    def run(self):
        print("[UartThread] started")
        proc_client = UartClient("http://127.0.0.1:16000", 5)
        hackme_client = UartClient("http://127.0.0.1:16001", 5)
        print("[UartThread] connected")
        self.ready.set()

        # trolley data back and forth between cpu's
        while not self.cancel.is_set():
            data = proc_client.recv_nonblocking(1)
            if data is not None:
                print(f"proc -> hackme: {data}")
                hackme_client.send(data)

            data = hackme_client.recv_nonblocking(1)
            if data is not None:
                print(f"hackme -> proc: {data}")
                proc_client.send(data)
            self.cancel.wait(0.01)
        print("[UartThread]: bye!")


# int IPC (inter-processor communication)
# both devices will now try to send uart data to each other
uart_thread = UartThread()
uart_thread.start()

while not uart_thread.ready.is_set():
    uart_thread.ready.wait(0.01)
print("uart init!")

# setup the proc binary
entry_state = proc_project.factory.entry_state()
entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

simgr = proc_project.factory.simgr(entry_state)
# run to before we load the 'ch' value
symbion = angr.exploration_techniques.Symbion(find=[0xC15, 0xC16, 0xC17,])
simgr.use_technique(symbion)
ex = simgr.run()
main_ch_state = ex.found[0]

# create a symbolic ch and put it into r7+3 on the stack
ch = main_ch_state.solver.BVS("ch", 8)
print(f"sp + 3 = {main_ch_state.regs.sp + 3}")
main_ch_state.mem[main_ch_state.regs.sp + 3].uint8_t = ch
# run to just before proc.bin makes the ch decision
simgr = proc_project.factory.simgr(main_ch_state)
simgr.use_technique(angr.exploration_techniques.Explorer())
ex = simgr.explore(
    find=[
        0xC29,
        0xC2A,
        0xC2B,
    ]
)
main_ex_state = ex.found[0]
print(main_ex_state.solver.constraints)

# pick a random value that the binary will send
chosen_value = main_ex_state.solver.eval(ch)
addr = proc.read_register(ArmRegister.Sp) + 3
proc.write_memory(proc.read_register(ArmRegister.Sp) + 3, bytes([chosen_value]))
print(f"wrote {chosen_value} to x{addr:X}")

# revert back to the concrete state and send our chosen value
simgr = proc_project.factory.simgr(main_ch_state)
simgr.use_technique(
    angr.exploration_techniques.Symbion(
        find=[
            0xC2F,
            0xC30,
            0xC31,
        ]
    )
)
ex = simgr.run()

# uncomment: keep the cpu running to observe the response from hackme.bin
#proc.start()

input("hit done: ...\n")
uart_thread.cancel.set()
