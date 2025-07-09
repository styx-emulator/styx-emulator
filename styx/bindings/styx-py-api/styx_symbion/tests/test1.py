# SPDX-License-Identifier: BSD-2-Clause

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
