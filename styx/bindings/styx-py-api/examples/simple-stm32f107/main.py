# SPDX-License-Identifier: BSD-2-Clause

# note: CTL-C will do nothing, this script will need to be killed another way
from styx_emulator.cpu.hooks import CodeHook
from styx_emulator.processor import ProcessorBuilder, Target
from styx_emulator.loader import RawLoader
from styx_emulator.executor import DefaultExecutor
from styx_emulator.plugin import ProcessorTracingPlugin
from pathlib import Path
import sys

TARGET_PROGRAM = "../../../../../data/test-binaries/arm/stm32f107/bin/blink_flash/blink_flash.bin"

def get_script_path() -> Path:
    """Get directory of this script."""
    return Path(sys.argv[0]).resolve().parent


def target_program_path() -> Path:
    """Get absolute target firmware path"""
    return get_script_path() / TARGET_PROGRAM

def log_signal(_):
    print("ERROR: signal")

builder = ProcessorBuilder()
builder.target_program = str(target_program_path())
builder.ipc_port = 16001
builder.loader = RawLoader()
builder.executor = DefaultExecutor()
builder.add_plugin(ProcessorTracingPlugin())
proc = builder.build(Target.Stm32f107)

proc.add_hook(CodeHook(0x690C, 0x690D, log_signal))

proc.start()
