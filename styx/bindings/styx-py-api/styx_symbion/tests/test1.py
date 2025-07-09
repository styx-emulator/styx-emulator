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

from styx_symbion.backend import StyxConcreteTarget
import angr
import logging
import monkeyhex

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.getLogger("angr").setLevel(logging.DEBUG)


def test_binary():
    elf = "../../data/test-binaries/arm/stm32f107/bin/timer/timer.elf"
    binary = "../../data/test-binaries/arm/stm32f107/bin/timer/timer.bin"
    logger.info(f" exploring {binary}")
    target = StyxConcreteTarget(binary)
    print(f"target {target}")
    p = angr.Project(
        elf,
        concrete_target=target,
        use_sim_procedures=True,
        load_options={
            "arch": "ARMEL",
            # "main_opts": {
            #     "base_addr": 0x59ac,
            # }
        },
    )
    logger.info(f"arch is {p.arch}")

    entry_state = p.factory.entry_state()
    entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
    entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

    target_fn = p.loader.find_symbol("init_led")
    main = p.loader.find_symbol("main")

    simgr = p.factory.simgr(entry_state)
    target.write_register("PC", main.rebased_addr)
    symbion = angr.exploration_techniques.Symbion(find=[target_fn.rebased_addr - 1])
    simgr.use_technique(symbion)
    simgr.run()

    sp = target.read_register("sp")
    assert sp == 0x20004FD8, "the init_led function should be at this address"

    return simgr, target, p


if __name__ == "__main__":
    test_binary()
