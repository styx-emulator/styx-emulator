use super::ArchSpecBuilder;
use super::GeneratorHelper;
use super::PcManager;

mod helpers;
mod pc_manager;

pub use helpers::HexagonGeneratorHelper;
pub use pc_manager::StandardPcManager;
use styx_pcode_translator::sla;

// Adapted from PPC
pub fn build() -> ArchSpecBuilder<sla::Hexagon> {
    let mut spec = ArchSpecBuilder::default();

    // Generator + pc manager. For now use the default pc manager
    spec.set_generator(GeneratorHelper::Hexagon(HexagonGeneratorHelper::default()));
    spec.set_pc_manager(PcManager::Hexagon(StandardPcManager::default()));

    // TODO: callother manager for system instructions, reg manager
    // etc

    spec
}

#[cfg(test)]
mod tests {
    use keystone_engine::Keystone;
    use log::trace;
    use styx_cpu_type::{
        arch::hexagon::{HexagonRegister, HexagonVariants},
        Arch, ArchEndian, TargetExitReason,
    };
    use styx_processor::{
        event_controller::EventController,
        memory::{helpers::WriteExt, Mmu},
    };

    use crate::{register_manager::RegisterManager, PcodeBackend};
    use styx_processor::cpu::{CpuBackend, CpuBackendExt};

    fn setup_asm(
        asm_str: &str,
        expected_asm: Option<Vec<u8>>,
    ) -> (PcodeBackend, Mmu, EventController) {
        styx_util::logging::init_logging();
        // objdump from example ppc program
        // notably load/store operations are omitted because sleigh uses dynamic pointers
        //   to represent memory spaces which change run to run.
        let init_pc = 0x1000u64;

        // Assemble instructions
        // Processor default to thumb so we use that
        let ks = Keystone::new(
            keystone_engine::Arch::HEXAGON,
            keystone_engine::Mode::BIG_ENDIAN,
        )
        .expect("Could not initialize Keystone engine");
        let asm = ks
            .asm(asm_str.to_owned(), init_pc)
            .expect("Could not assemble");
        let code = asm.bytes;

        // Optional param
        if let Some(expected_asm) = expected_asm {
            assert_eq!(code, expected_asm);
        }
        trace!("bytes {:x?} asm {}", code, asm_str);

        // takes the objdump and extracts the binary from it
        //  duplex instruction:

        let mut cpu = PcodeBackend::new_engine(
            Arch::Hexagon,
            HexagonVariants::QDSP6V66,
            ArchEndian::BigEndian,
        );

        cpu.set_pc(init_pc).unwrap();

        let mut mmu = Mmu::default();
        let ev = EventController::default();
        mmu.code().write(init_pc).bytes(&code).unwrap();

        (cpu, mmu, ev)
    }

    // TODO: can you mix a duplex instruction with some other stuff in a packet?
    #[test]
    fn test_packet_instructions() {
        // Packet instructions are interesting, as they are reordered to reflect the
        // appropriate slots and such.
        let (mut cpu, mut mmu, mut ev) = setup_asm(
            "{ R1 = add(R0, #32); R2 = mpyi(R3, R4); R3 = add(R5, #10); }; ",
            None,
        );
        let r0 = 71;
        let r5 = 41272;
        let mult_opts = (92, 7);

        // truncate
        let initial_isa_pc = RegisterManager::read_register(&mut cpu, HexagonRegister::Pc.into())
            .unwrap()
            .to_u64()
            .unwrap() as u32;
        trace!("initial isa pc is {}", initial_isa_pc);
        cpu.write_register(HexagonRegister::R0, r0).unwrap();
        cpu.write_register(HexagonRegister::R3, mult_opts.0)
            .unwrap();
        cpu.write_register(HexagonRegister::R4, mult_opts.1)
            .unwrap();
        cpu.write_register(HexagonRegister::R5, r5).unwrap();

        // Packet is 3 insns long, let's get the PC in the middle
        // and ensure it's not moving within a packet.
        let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
        assert_eq!(exit, TargetExitReason::InstructionCountComplete);

        // truncate
        let mid_isa_pc = RegisterManager::read_register(&mut cpu, HexagonRegister::Pc.into())
            .unwrap()
            .to_u64()
            .unwrap() as u32;
        assert_eq!(mid_isa_pc, initial_isa_pc);

        // let's now finish up. The no op is because styx internally only
        // sets the pc manager's isa pc at the start of the next instruction.
        let exit = cpu.execute(&mut mmu, &mut ev, 2).unwrap();
        assert_eq!(exit, TargetExitReason::InstructionCountComplete);

        let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();
        let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
        let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();

        // This *should* be the ISA PC
        let end_isa_pc = RegisterManager::read_register(&mut cpu, HexagonRegister::Pc.into())
            .unwrap()
            .to_u64()
            .unwrap() as u32;

        assert_eq!(r1, r0 + 32);
        assert_eq!(r2, mult_opts.0 * mult_opts.1);
        assert_eq!(r3, r5 + 10);

        trace!("initial pc is {}, new pc is {}", initial_isa_pc, end_isa_pc);

        // TODO: test pc increment at end of packet
        assert_eq!(end_isa_pc - initial_isa_pc, 12);
    }

    #[test]
    fn test_duplex_instructions() {
        // [0x16, 0x30, 0x05, 0x30]
        let (mut cpu, mut mmu, mut ev) =
            setup_asm("{ r5 = r0; r6 = r1 }", Some(vec![0x16, 0x30, 0x05, 0x30]));
        cpu.write_register(HexagonRegister::R1, 0xdeadbeef_u32)
            .unwrap();
        cpu.write_register(HexagonRegister::R0, 0xcafeb0ba_u32)
            .unwrap();

        let exit = cpu.execute(&mut mmu, &mut ev, 2).unwrap();

        assert_eq!(exit, TargetExitReason::InstructionCountComplete);

        let r5 = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();
        let r6 = cpu.read_register::<u32>(HexagonRegister::R6).unwrap();
        assert_eq!(r6, 0xdeadbeef);
        assert_eq!(r5, 0xcafeb0ba);
    }
}
