// SPDX-License-Identifier: BSD-2-Clause
use styx_core::arch::aarch64::Aarch64Variants;
use styx_core::core::builder::{BuildProcessorImplArgs, ProcessorImpl};
use styx_core::core::ProcessorBundle;
use styx_core::cpu::{Backend, PcodeBackend};
use styx_core::event_controller::DummyEventController;
use styx_core::loader::LoaderHints;
use styx_core::memory::DummyTlb;
use styx_core::prelude::{CpuBackend, *};

/// A processor with no peripherals or event controller, purely instruction emulation.
#[derive(Default)]
pub struct Aarch64Processor {}

impl ProcessorImpl for Aarch64Processor {
    fn build(
        &self,
        args: &BuildProcessorImplArgs,
    ) -> Result<styx_core::prelude::ProcessorBundle, styx_core::prelude::UnknownError> {
        let cpu: Box<dyn CpuBackend> = match args.backend {
            Backend::Pcode => Box::new(PcodeBackend::new_engine(
                styx_core::cpu::Arch::Aarch64,
                Aarch64Variants::Generic,
                styx_core::cpu::ArchEndian::LittleEndian,
            )),
            _ => unimplemented!("not supported"),
        };

        let mut hints = LoaderHints::new();
        hints.insert(
            "arch".to_string().into_boxed_str(),
            Box::new(styx_core::cpu::Arch::Aarch64),
        );

        let memory = MemoryBackend::new_flat();
        let tlb = DummyTlb::new();

        Ok(ProcessorBundle {
            cpu,
            memory,
            tlb,
            event_controller: Box::new(DummyEventController::default()),
            peripherals: vec![],
            loader_hints: hints,
        })
    }
}

#[cfg(test)]
mod tests {
    use styx_core::errors::UnknownError;
    use styx_core::hooks::{CoreHandle, StyxHook};
    use styx_core::prelude::{Forever, ProcessorBuilder};
    use styx_core::util::resolve_test_bin;
    use test_case::test_case;

    use super::*;

    #[test_case("adds.bin")]
    #[test_case("addv.bin")]
    #[test_case("bit.bin")]
    #[test_case("cmtst.bin")]
    #[test_case("cnt.bin")]
    #[test_case("fcmXX.bin")]
    #[test_case("fcmp.bin")]
    #[test_case("fcsel.bin")]
    #[test_case("fcvtl.bin")]
    // #[test_case("fcvtz.bin")], sleigh definition is only correct for fp values in the range of [-signed int max, +signed int max] because they implement fcvtzu and fcvtzs the same way
    #[test_case("fminnm.bin")]
    #[test_case("fstur.bin")]
    #[test_case("ldn_multiple.bin")]
    #[test_case("ldn_single.bin")]
    #[test_case("ldnr.bin")]
    #[test_case("mla.bin")]
    #[test_case("mls.bin")]
    #[test_case("mul.bin")]
    #[test_case("pass.bin")]
    #[test_case("stn_multiple.bin")]
    #[test_case("stn_single.bin")]
    #[test_case("sumov.bin")]
    #[test_case("sumulh.bin")]
    #[test_case("tbnz.bin")]
    #[test_case("uzp.bin")]
    #[test_case("xtl.bin")]
    #[test_case("xtn.bin")]
    fn instruction_test(bin: &str) {
        let mut path = String::from("aarch64-gdbsim-data/testdata/");
        path.push_str(bin);

        let abs_path = resolve_test_bin(&path);

        // setup processor
        let mut proc = ProcessorBuilder::default()
            .with_builder(Aarch64Processor::default())
            .with_backend(Backend::Pcode)
            .build()
            .unwrap();

        // write code into memory and setup PC
        let test_bytes = std::fs::read(abs_path).unwrap();
        proc.core.mmu.write_code(0x1000, &test_bytes).unwrap();
        proc.core.set_pc(0x1000).unwrap();

        // add hooks for pass/fail
        let quit = |proc: CoreHandle| -> Result<(), UnknownError> {
            proc.cpu.stop();
            Ok(())
        };
        proc.core
            .cpu
            .add_hook(StyxHook::Code((0..0x15).into(), Box::new(quit)))
            .unwrap();

        // the test should exit by jumping to either 0x0 or 0x10
        proc.run(Forever).unwrap();

        // check address that we stopped at to see result of test
        if proc.core.pc().unwrap() != 0 {
            panic!("test failed");
        }
    }
}
