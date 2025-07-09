// SPDX-License-Identifier: BSD-2-Clause

use crate::{
    arch_spec::ArchSpecBuilder,
    call_other::handlers::{EmptyCallback, TraceCallOther},
    memory::sized_value::SizedValue,
    pcode_gen::RegisterTranslator,
    register_manager::{MappedRegister, RegisterCallback, RegisterHandleError},
};
use styx_cpu_type::arch::ppc32::{Ppc32Register, SpecialPpc32Register, SprRegister};
use styx_errors::anyhow::{anyhow, Context};
use styx_pcode_translator::sla;
use styx_pcode_translator::sla::Ppc324xxBeUserOps as UserOps;
use styx_processor::cpu::CpuBackendExt;

pub fn build() -> ArchSpecBuilder<sla::Ppc324xxBe> {
    let mut spec = ArchSpecBuilder::default();

    super::ppc_common(&mut spec);

    // Maps named SPRs to their SpecialRegister counterparts.
    // Needed because the pcode spec doesn't have all registers named.
    let mappings = [
        (Ppc32Register::Ccr0, 0x3B3),
        (Ppc32Register::Dbsr, 0x3F0),
        (Ppc32Register::Sgr, 0x3B9),
        (Ppc32Register::Evpr, 0x3D6),
        (Ppc32Register::Tcr, 0x3DA),
        (Ppc32Register::Tsr, 0x3D8),
        (Ppc32Register::Pit, 0x3DB),
        (Ppc32Register::Sprg3, 0x113),
    ];
    for (reg, spr_num) in mappings {
        spec.register_manager
            .add_handler(
                reg,
                MappedRegister::new(SpecialPpc32Register::SprRegister(
                    SprRegister::new(spr_num).unwrap(),
                )),
            )
            .unwrap();
    }

    spec.register_manager
        .add_handler(Ppc32Register::Cr, CrRegister)
        .unwrap();
    spec.register_manager
        .add_handler(Ppc32Register::Cr0, Cr0Register)
        .unwrap();
    spec.register_manager
        .add_handler(Ppc32Register::Cr7, Cr0Register)
        .unwrap();

    spec.call_other_manager
        .add_handler(
            UserOps::EnforceInOrderExecutionIo,
            TraceCallOther::new("EnforceInOrderExecutionIO".to_string().into_boxed_str()),
        )
        .unwrap();

    spec.call_other_manager
        .add_handler(UserOps::Syscall, super::call_other::SystemCall)
        .unwrap();

    spec.call_other_manager
        .add_handler(
            UserOps::ReturnFromInterrupt,
            super::call_other::ReturnFromInterrupt,
        )
        .unwrap();

    spec.call_other_manager
        .add_handler(UserOps::DataCacheCongruenceClassInvalidate, EmptyCallback)
        .unwrap();
    spec.call_other_manager
        .add_handler(UserOps::InstructionSynchronize, EmptyCallback)
        .unwrap();
    spec.call_other_manager
        .add_handler(UserOps::Sync, EmptyCallback)
        .unwrap();
    spec.call_other_manager
        .add_handler(UserOps::TlbInvalidateAll, EmptyCallback)
        .unwrap();

    spec
}

#[derive(Debug)]
struct Cr0Register;
impl RegisterCallback for Cr0Register {
    fn read(
        &mut self,
        register: styx_cpu_type::arch::backends::ArchRegister,
        cpu: &mut crate::PcodeBackend,
    ) -> Result<SizedValue, crate::register_manager::RegisterHandleError> {
        let cr0_varnode = cpu
            .pcode_generator
            .get_register(&register)
            .context("no cr0 register")?;
        let value = cpu
            .space_manager
            .read(cr0_varnode)
            .context("could not read cr0 varnode")?;

        Ok(value.resize(4))
    }

    fn write(
        &mut self,
        register: styx_cpu_type::arch::backends::ArchRegister,
        value: SizedValue,
        cpu: &mut crate::PcodeBackend,
    ) -> Result<(), crate::register_manager::RegisterHandleError> {
        let cr0_varnode = cpu
            .pcode_generator
            .get_register(&register)
            .context("no cr0 register")?;
        cpu.space_manager
            .write(cr0_varnode, value)
            .context("could not write cr0 varnode")?;

        Ok(())
    }
}

#[derive(Debug)]
struct CrRegister;
impl RegisterCallback for CrRegister {
    fn read(
        &mut self,
        _register: styx_cpu_type::arch::backends::ArchRegister,
        cpu: &mut crate::PcodeBackend,
    ) -> Result<crate::memory::sized_value::SizedValue, crate::register_manager::RegisterHandleError>
    {
        let cr0 = cpu
            .read_register::<u32>(Ppc32Register::Cr0)
            .with_context(|| "Couldnt't read")?;

        let result = cr0;

        Ok(SizedValue::from_u64(result as u64, 4))
    }

    fn write(
        &mut self,
        _register: styx_cpu_type::arch::backends::ArchRegister,
        value: crate::memory::sized_value::SizedValue,
        cpu: &mut crate::PcodeBackend,
    ) -> Result<(), crate::register_manager::RegisterHandleError> {
        if value.size() != 4 {
            return Err(RegisterHandleError::Other(anyhow!("bad")));
        }
        cpu.write_register(Ppc32Register::Cr0, value.to_u64().unwrap() as u32)
            .unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use styx_cpu_type::{arch::ppc32::Ppc32Variants, Arch};

    use crate::PcodeBackend;

    use super::*;

    #[test]
    fn test_name() {
        let mut cpu = PcodeBackend::new_engine(
            Arch::Ppc32,
            Ppc32Variants::Ppc405,
            styx_cpu_type::ArchEndian::BigEndian,
        );

        let res = cpu.read_register::<u32>(Ppc32Register::Sprg3).unwrap();
        assert_eq!(res, 0);
        cpu.write_register(Ppc32Register::Sprg3, 0x1447u32).unwrap();
        let res = cpu.read_register::<u32>(Ppc32Register::Sprg3).unwrap();
        assert_eq!(0x1447u32, res);
    }
}
