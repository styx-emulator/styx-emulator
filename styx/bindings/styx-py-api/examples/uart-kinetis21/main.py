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

"""
This Python script demonstrates the emulation of a Kinetis21 microcontroller
using the Styx Emulator Project and its Python bindings.

It includes:
- FreeRTOS emulation
- UART communication
- Instruction counting
- Basic block tracking

The script sets up a processor, connects to a UART client, and runs the
emulator until a newline character is received, at which point it shuts down
the processor. During execution, it tracks and reports the number of
instructions executed, basic blocks hit, and UART communication.
"""

from typing import Iterator
from styx_emulator.cpu import Backend, ProcessorCore
from styx_emulator.cpu.hooks import CodeHook, BlockHook
from styx_emulator.processor import ProcessorBuilder, Target, Processor
from styx_emulator.loader import RawLoader
from styx_emulator.executor import DefaultExecutor
from styx_emulator.plugin import ProcessorTracingPlugin
from styx_emulator.peripherals import UartClient
import sys
import time
from pathlib import Path
from datetime import timedelta, datetime

TARGET_PROGRAM = "../../../../../data/test-binaries/arm/kinetis_21/bin/freertos_hello/freertos_hello_debug.bin"
IPC_PORT = 16001


def get_script_path() -> Path:
    """Get directory of this script."""
    return Path(sys.argv[0]).resolve().parent


def target_program_path() -> Path:
    """Get absolute target firmware path"""
    return get_script_path() / TARGET_PROGRAM


def io_transfer(cpu: ProcessorCore):
    """
    Code hook, called when target transfers serial character data.

    Used to show when target sends UART message over the line.
    """
    # character to send stored in r2
    c = cpu.read_register("r2")
    if c:
        print(f"target sent {c.to_bytes(1)}")
    else:
        print("no register r2 in target")


class Instructions:
    """
    Counts instructions and reports instructions per second for informational purposes.
    """

    instr_count: int
    """Number of instructions so far"""

    def __init__(self):
        self.instr_count = 0

    def inc(self):
        """Increment instruction count."""
        self.instr_count += 1

    def ips(self, duration: timedelta) -> float:
        """Instructions per second"""

        return self.instr_count / duration.total_seconds()

    def mips(self, duration: timedelta) -> float:
        """Million instructions per second"""

        return self.ips(duration) / 1000000


def ips(instr: Instructions, cpu: ProcessorCore):
    """Code hook for every instructions, counts executions."""
    instr.inc()


class Blocks:
    """
    Keeps track of basic blocks hit
    """

    blocks: dict[int, int]
    """Addr -> count"""

    def __init__(self):
        self.blocks = dict()

    def block_hit(self, addr: int):
        """Mark a block hit."""
        value = self.blocks.get(addr, 0)
        self.blocks[addr] = value + 1

    def sorted_and_filtered(self) -> Iterator[tuple[int, int]]:
        """List of blocks with >3 hits, in descending order."""
        return reversed(
            sorted(
                filter(lambda item: item[1] > 3, blocks.blocks.items()),
                key=lambda item: item[1],
            )
        )

    def hit_str(self) -> str:
        """List of hit blocks (>3 hits) in a formatted string."""
        return ", ".join(
            [f"0x{key:X} ({value})" for key, value in self.sorted_and_filtered()]
        )


def blocks_hook(blocks: Blocks, cpu: ProcessorCore, start: int, size: int):
    """Basic block hook, keeps track of hit basic blocks."""
    blocks.block_hit(start)


def build_processor():
    """
    Builds Kinetis21 processor

    LittleEndian
    firmware: FreeRTOS "hello world" (RawLoader)
    ipc_port: IPC_PORT (16001)
    cpu: ArmCortexM4 variant on Unicorn
    plugins:
        - ProcessorTracingPlugin
    """
    builder = ProcessorBuilder()
    builder.target_program = str(target_program_path())
    builder.ipc_port = IPC_PORT
    builder.loader = RawLoader()
    builder.executor = DefaultExecutor()
    # change this to pcode and see differences
    builder.backend = Backend.Unicorn
    builder.add_plugin(ProcessorTracingPlugin())
    return builder.build(Target.Kinetis21)


def start_uart_client(proc):
    """
    Connect UART client to processor and start UART monitor thread

    The UART client connects to the UART server started by the processor. In
    this example, it receives the "Hello World" message from the target after
    which it stops the processor.

    Repeatedly checks for received data using client.recv_nonblocking() and
    stops the processor when the whole message has been received, indicated
    by receiving a newline.
    """
    # connect to uart 5 that the firmware sets up
    DEBUG_UART_PORT = 5

    client = UartClient(f"http://127.0.0.1:{IPC_PORT}", DEBUG_UART_PORT)

    final_msg = ""
    while True:
        recv_char = client.recv_nonblocking(1)
        if recv_char:
            final_msg += recv_char.decode()
            if recv_char == b"\n":
                print("got newline, shutting down")
                print(f'received message: "{final_msg.strip()}"')
                proc.pause()
                break
        else:
            time.sleep(0.01)


def start_and_time(proc: Processor) -> timedelta:
    """Run processor and measure time to complete"""
    start_time = datetime.now()
    proc.start()
    start_uart_client(proc)
    end_time = datetime.now()
    return end_time - start_time


proc = build_processor()

# code hook that tracks the total number of instructions executed
instr = Instructions()
proc.add_hook(CodeHook(0x0, 0xFFFFFFFF, lambda cpu: ips(instr, cpu)))
# code hook that prints when a character is written to serial
# 0x00001AE8 is the io_transfer function that writes a single char
proc.add_hook(CodeHook(0x00001AE8, 0x00001AE8, io_transfer))
# basic block hook that tracks how many hits each basic block gets
blocks = Blocks()
proc.add_hook(BlockHook(lambda *args: blocks_hook(blocks, *args)))


# give time for processor and uart to connect, otherwise a race occurs
# between sending uart data and receiving.
time.sleep(0.1)

exec_duration = start_and_time(proc)

print("\n=== execution finished ===")
print(
    f"total instructions {instr.instr_count} executed in {exec_duration.total_seconds():.2f}s ({instr.mips(exec_duration):.2f} million i/s)"
)

print("basic blocks with more than 3 executions:")
print("\t" + blocks.hit_str())
