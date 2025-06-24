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
    use styx_cpu_type::{
        arch::hexagon::{HexagonRegister, HexagonVariants},
        Arch, ArchEndian, TargetExitReason,
    };
    use styx_processor::{
        event_controller::EventController,
        memory::{helpers::WriteExt, Mmu},
    };

    use crate::PcodeBackend;
    use styx_processor::cpu::{CpuBackend, CpuBackendExt};

    #[test]
    fn test_duplex_instructions() {
        styx_util::logging::init_logging();
        // objdump from example ppc program
        // notably load/store operations are omitted because sleigh uses dynamic pointers
        //   to represent memory spaces which change run to run.
        let init_pc = 0x1000u64;
        // takes the objdump and extracts the binary from it
        //  duplex instruction: { r5 = r0; r6 = r1 }
        let code = vec![0x16, 0x30, 0x05, 0x30];

        let mut cpu = PcodeBackend::new_engine(
            Arch::Hexagon,
            HexagonVariants::QDSP6V66,
            ArchEndian::BigEndian,
        );

        cpu.set_pc(init_pc).unwrap();

        let mut mmu = Mmu::default();
        let mut ev = EventController::default();
        mmu.code().write(init_pc).bytes(&code).unwrap();

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
