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
