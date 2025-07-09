# SPDX-License-Identifier: BSD-2-Clause

"""
This Python script demonstrates testing workflow of emulation using pytest.

It includes:
- FreeRTOS emulation
- UART communication
- Tests to verify correct emulation

The script sets up a processor, connects to a UART client, and runs the
emulator until a newline character is received, at which point it shuts down
the processor. After execution, it asserts that the correct UART data was received.

## How to Run

```
$ . ../../venv/bin/activate

# Run all tests
$ pytest styx-py-api/examples/uart-integration-test/main.py

# Run only one test
$ pytest styx-py-api/examples/uart-integration-test/main.py -k "test_uart[backend1]"
```

"""

import pytest
from styx_emulator.cpu import Backend, ProcessorCore, MemFaultData, MemFaultDataType, MemoryPermissions
from styx_emulator.cpu.hooks import CodeHook, UnmappedFaultHook, ProtectionFaultHook
from styx_emulator.processor import ProcessorBuilder, Target, Processor, ProcessorState
from styx_emulator.loader import RawLoader
from styx_emulator.executor import DefaultExecutor
from styx_emulator.peripherals import UartClient
import sys
import time
import threading
from pathlib import Path
import datetime

# pytest is located in venv/bin so out target program is relative to that.
TARGET_PROGRAM = "../../data/test-binaries/arm/kinetis_21/bin/freertos_hello/freertos_hello_debug.bin"


def get_script_path() -> Path:
    """Get directory of this script."""
    return Path(sys.argv[0]).resolve().parent


def target_program_path() -> Path:
    """Get absolute target firmware path"""
    return get_script_path() / TARGET_PROGRAM


def build_processor(backend: Backend):
    """
    Builds Kinetis21 processor

    LittleEndian
    firmware: FreeRTOS "hello world" (RawLoader)
    cpu: ArmCortexM4 variant on chosen backend
    plugins:
        - ProcessorTracingPlugin
    """
    # builder pattern for configuring a new processor
    builder = ProcessorBuilder()

    # define the path to our firmware image
    builder.target_program = str(target_program_path())
    # select an open port for ipc
    builder.ipc_port = 0
    # firmware image is a raw memory dump, no mapping needed
    builder.loader = RawLoader()
    # default executor is okay
    builder.executor = DefaultExecutor()
    # set our chosen backend
    builder.backend = backend
    # plugin for capturing and printing logs (traces)
    # breaks if multiple threads are running at one time (this happens when using pytest)
    # builder.add_plugin(ProcessorTracingPlugin())
    # ^ make sure to add `from styx_emulator.plugin import ProcessorTracingPlugin`
    return builder.build(Target.Kinetis21)


def start_uart_client(proc: Processor) -> bytearray:
    """
    Connect UART client to processor and return bytearray with all received data.

    The UART client connects to the UART server started by the processor. In this example, it
    receives the "Hello World" message from the target after which it stops the processor.

    Repeatedly checks for received data using client.recv_nonblocking() and
    stops the processor when the whole message has been received, indicated
    by receiving a newline.

    UART data received is added by mutating the total_recv_bytes.
    """
    # create received bytes bytearray
    total_recv_bytes = bytearray()

    # create uart client
    # defined by the firmware, uses uart port 5
    DEBUG_UART_PORT = 5
    # ipc port of processor to connect to
    ipc_port = proc.ipc_port
    client = UartClient(f"http://127.0.0.1:{ipc_port}", DEBUG_UART_PORT)

    while True:
        # check for new UART data
        # bytes or None if no bytes are available
        current_recv_bytes = client.recv_nonblocking(1)
        if current_recv_bytes:
            # we got a byte, add to our list of received bytes
            total_recv_bytes.extend(current_recv_bytes)

            # newline indicates end of message
            if current_recv_bytes == b"\n":
                print("got newline, shutting down")
                print(f'received message: "{total_recv_bytes.decode().strip()}"')
                proc.pause()
                break
        else:
            # wait in between checks for new UART data
            time.sleep(0.01)

    # return received bytes bytearray
    return total_recv_bytes


def start_timeout(proc: Processor, seconds: float):
    """Stop processor after seconds passed."""

    def timeout(proc: Processor):
        time.sleep(seconds)
        proc.pause()

    thread = threading.Thread(target=timeout, args=(proc,), daemon=True)
    thread.start()


backends = [Backend.Unicorn, Backend.Pcode]


@pytest.mark.parametrize("backend", backends)
def test_build_proc(backend: Backend):
    proc = build_processor(backend)
    ipc_port = proc.ipc_port
    assert ipc_port != 0
    assert proc.processor_state == ProcessorState.Paused


@pytest.mark.parametrize("backend", backends)
def test_uart(backend: Backend):
    proc = build_processor(backend)
    # give time for processor and uart to connect, otherwise a race occurs
    # between sending uart data and receiving.
    time.sleep(0.1)

    start_timeout(proc, 5)

    proc.start()
    uart_recv = start_uart_client(proc)
    assert uart_recv == bytearray(b"Hello world.\r\n")


def test_instruction_timeout():
    total = dict(total=0)
    def inc_inst(proc: ProcessorCore):
        total["total"] += 1

    proc = build_processor(Backend.Pcode)
    proc.add_hook(CodeHook(0, 0xFFFFFFFF, inc_inst))

    proc.start(inst=1337)
    report = proc.wait_for_stop()
    assert total["total"] == 1337
    assert report.instructions == 1337
    assert not report.is_fatal


def test_timeout():
    proc = build_processor(Backend.Pcode)

    start_time = datetime.datetime.now()
    run_time = datetime.timedelta(microseconds=10)
    proc.start(timeout=run_time)
    total_time = datetime.datetime.now() - start_time
    proc.wait_for_stop()
    assert total_time > run_time


def test_memory_unmapped_fault():
    total = dict(total=0)
    def unmapped_fault_hook(proc: ProcessorCore, addr: int, size: int, fault_data: MemFaultData) -> bool:
        total["total"] += 1
        print("unmapped fault hit")

        # fault not fixed
        return False

    def protection_fault_hook(proc: ProcessorCore, addr: int, size: int, permissions: MemoryPermissions, fault_data: MemFaultData) -> bool:
        print("prot fault hit")
        total["total"] += 1
        assert fault_data.operation == MemFaultDataType.Read

        # fault not fixed
        return False


    proc = build_processor(Backend.Pcode)
    proc.add_hook(UnmappedFaultHook(0, 0xFFFFFFFF, unmapped_fault_hook))
    proc.add_hook(ProtectionFaultHook(0, 0xFFFFFFFF, protection_fault_hook))

    # unmapped address
    proc.pc = 0x100004
    proc.start(inst=10)
    report = proc.wait_for_stop()
    assert total["total"] == 1
    assert report.instructions == 0
    assert report.is_fatal


def test_protection_fault():
    total = dict(total=0)
    def protection_fault_hook(proc: ProcessorCore, addr: int, size: int, permissions: MemoryPermissions, fault_data: MemFaultData) -> bool:
        print("prot fault hit")
        assert fault_data.operation == MemFaultDataType.Read
        total["total"] += 1

        # fault not fixed
        return False

    proc = build_processor(Backend.Pcode)
    proc.add_hook(ProtectionFaultHook(0, 0xFFFFFFFF, protection_fault_hook))

    # address with no permissions
    proc.pc = 0xe0100000
    proc.start(inst=10)
    report = proc.wait_for_stop()
    assert total["total"] == 1
    assert report.instructions == 0
    assert report.is_fatal
