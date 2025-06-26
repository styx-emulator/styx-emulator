// SPDX-License-Identifier: BSD-2-Clause
use crate::{Loader, LoaderRequires, SleighTranslateError};
use rustc_hash::FxHashMap;
use std::collections::HashMap;
use std::hash::Hash;
use styx_cpu_type::{
    arch::{
        backends::{ArchRegister, ArchVariant},
        ArchitectureDef,
    },
    ArchEndian,
};
use styx_pcode::pcode::{Pcode, SpaceInfo, SpaceName, VarnodeData};
use styx_pcode::sla::SlaSpec;
use styx_pcode_sleigh_backend::{NewSleighError, Sleigh, UserOpInfo};
use styx_sla::SlaRegisters;
use tap::TapOptional;
use thiserror::Error;
use tracing::{debug, trace};

#[derive(Error, Debug)]
#[error(transparent)]
pub struct PcodeTranslatorError(NewSleighError);
impl From<NewSleighError> for PcodeTranslatorError {
    fn from(value: NewSleighError) -> Self {
        Self(value)
    }
}

/// Easy to use pcode translator.
///
/// Takes ownership of a [Loader] to get bytes to translate to pcode.
///
/// Sets default context variables based on architecture.
pub struct PcodeTranslator<L> {
    sleigh: Sleigh<L>,
    registers: HashMap<ArchRegister, VarnodeData>,
    registers_rev: FxHashMap<VarnodeData, Vec<ArchRegister>>,
    /// Holds a map between register varnode offsets and register names.
    register_offset_map: HashMap<u64, String>,

    user_ops: Vec<UserOpInfo>,
}

impl<L: Loader + LoaderRequires + 'static> PcodeTranslator<L> {
    /// Creates a new PcodeTranslator.
    ///
    /// The `arch` should match the given `SlaSpec`.
    ///
    /// An error value indicates an error in the sla spec or sleigh backend and
    /// cannot be handled gracefully.
    pub fn new<S: SlaSpec + SlaRegisters>(
        arch: &ArchVariant,
        loader: L,
    ) -> Result<Self, PcodeTranslatorError> {
        let sla = S::spec();
        let spec_file = styx_util::bytes_to_tmp_file(sla);

        let arch_def: Box<dyn ArchitectureDef> = arch.clone().into();
        // must be a reference to the NamedTempFile, otherwise it gets dropped before initializing
        let mut sleigh = Sleigh::new(loader, &spec_file)?;

        let registers = Self::generate_registers::<S>(arch_def.as_ref(), &mut sleigh);
        let registers_rev = reverse_hash(&registers).into_iter().collect();
        let register_offset_map = sleigh.get_register_offset_map();

        let user_ops = sleigh.get_user_ops();

        Ok(Self {
            sleigh,
            registers,
            registers_rev,
            register_offset_map,
            user_ops,
        })
    }
}

fn reverse_hash<K: Clone, V: Clone + Eq + Hash>(map: &HashMap<K, V>) -> HashMap<V, Vec<K>> {
    let mut new: HashMap<V, Vec<K>> = HashMap::new();
    for (k, v) in map.iter() {
        new.entry(v.clone()).or_default().push(k.clone());
    }
    new
}

impl<L: Loader + LoaderRequires + 'static> PcodeTranslator<L> {
    /// Translates an instruction at an address into a list of resulting pcodes and the number of
    /// bytes consumed. Appends to the give pcodes vector.
    pub fn get_pcode(
        &mut self,
        address: u64,
        pcodes: &mut Vec<Pcode>,
        data: L::LoadRequires<'_>,
    ) -> Result<u64, SleighTranslateError> {
        // will propagate/convert translate errors
        let num = self.sleigh.translate(address, pcodes, data)?;

        Ok(num as u64)
    }

    fn get_registers_option<'a, Sla: SlaRegisters>(
        arch_def: &dyn ArchitectureDef,
        sleigh: &'a mut Sleigh<L>,
    ) -> impl Iterator<Item = (ArchRegister, Option<VarnodeData>)> + 'a + use<'a, Sla, L> {
        let strings = arch_def
            .registers()
            .registers()
            .into_iter()
            .map(|r| (r.variant(), Sla::translate_register(&r)));

        strings.map(move |(register, name)| (register, sleigh.get_register(&name)))
    }

    fn generate_registers<Sla: SlaRegisters>(
        arch_def: &dyn ArchitectureDef,
        sleigh: &mut Sleigh<L>,
    ) -> HashMap<ArchRegister, VarnodeData> {
        let register_map = PcodeTranslator::get_registers_option::<Sla>(arch_def, sleigh)
            .filter_map(|(register, varnode_opt)| {
                varnode_opt.map(|varnode| (register, varnode)).tap_none(|| {
                    debug!("Register not found in pcode: {register}");
                })
            })
            .collect();

        trace!("Pcode registers: {:?}", &register_map);

        register_map
    }

    /// Gets the [VarnodeData] of register if it exists.
    pub fn get_register(&self, register: &ArchRegister) -> Option<&VarnodeData> {
        self.registers.get(register)
    }

    pub fn get_register_rev(&self, register: &VarnodeData) -> Option<&[ArchRegister]> {
        self.registers_rev.get(register).map(|list| list.as_ref())
    }

    pub fn get_registers(&self) -> impl Iterator<Item = (&ArchRegister, &VarnodeData)> {
        self.registers.iter()
    }

    pub fn get_register_from_offset(&self, offset: u64) -> Option<&String> {
        self.register_offset_map.get(&offset)
    }

    pub fn get_spaces(&self) -> HashMap<SpaceName, SpaceInfo> {
        self.sleigh.get_spaces()
    }

    pub fn endian(&self) -> ArchEndian {
        self.sleigh.endian()
    }

    pub fn set_context_option(&mut self, addr_off: u64, option: ContextOption) {
        // FIXME check validity (e.g. does this sla have this variable)
        let (variable_name, variable_value) = option.value();
        self.sleigh
            .set_variable(variable_name, addr_off, variable_value)
    }

    pub fn user_ops(&self) -> &[UserOpInfo] {
        &self.user_ops
    }
}

#[derive(Debug)]
pub enum ContextOption {
    ThumbMode(bool),
    HexagonPktStart(u32),
    HexagonPktNext(u32),
    HexagonSubinsn(u32),
    HexagonImmext(u32),
    HexagonDotnew(u32),
    HexagonHasnew(u32),
    HexagonEndloop(u32),
    HexagonPhase(u32),
    HexagonDuplexNext(u32),
    HexagonPart1(u32),
    HexagonPart2(u32),
}

impl ContextOption {
    fn value(&self) -> (&'static str, u32) {
        match self {
            ContextOption::ThumbMode(enabled) => ("TMode", *enabled as u32),
            ContextOption::HexagonImmext(value) => ("immext", *value),
            ContextOption::HexagonPktStart(value) => ("pkt_start", *value),
            ContextOption::HexagonPktNext(value) => ("pkt_next", *value),
            ContextOption::HexagonSubinsn(value) => ("subinsn", *value),
            ContextOption::HexagonEndloop(value) => ("endloop", *value),
            ContextOption::HexagonDotnew(value) => ("dotnew", *value),
            ContextOption::HexagonHasnew(value) => ("hasnew", *value),
            ContextOption::HexagonPhase(value) => ("phase", *value),
            ContextOption::HexagonDuplexNext(value) => ("duplex_next", *value),
            ContextOption::HexagonPart1(value) => ("part1", *value),
            ContextOption::HexagonPart2(value) => ("part2", *value),
        }
    }
}

#[cfg(test)]
mod tests {
    use styx_cpu_type::arch::arm::{variants::ArmCortexA7, ArmMetaVariants};
    use styx_pcode_sleigh_backend::VectorLoader;

    use super::*;

    struct BadSla;
    impl SlaSpec for BadSla {
        fn spec() -> &'static [u8] {
            &[0u8, 0u8]
        }

        fn name() -> &'static str {
            "bad sla"
        }
    }
    impl SlaRegisters for BadSla {}

    /// Test when specification is invalid.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_bad_spec() {
        let start = 0x1000;
        let data = vec![0xFFu8; 4];
        let load_image = VectorLoader { start, data };
        let translator = PcodeTranslator::new::<BadSla>(
            &ArchVariant::Arm(ArmMetaVariants::ArmCortexA7(ArmCortexA7 {})),
            load_image,
        );

        assert!(translator.is_err())
    }
}

#[cfg(test)]
#[cfg(feature = "arch_arm")]
mod arm_tests {
    use keystone_engine::Keystone;
    use styx_cpu_type::arch::{
        arm::{variants::ArmCortexA7, ArmMetaVariants},
        backends::ArchVariant,
    };
    use styx_pcode_sleigh_backend::{SleighTranslateError, VectorLoader};

    use super::PcodeTranslator;
    use crate::ContextOption;

    fn get_asm(instr: &str) -> Vec<u8> {
        // Assemble instructions
        // Processor default to thumb so we use that
        let ks = Keystone::new(keystone_engine::Arch::ARM, keystone_engine::Mode::THUMB)
            .expect("Could not initialize Keystone engine");
        let asm = ks
            .asm(instr.to_owned(), 0x1000)
            .expect("Could not assemble");
        asm.bytes
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_decompile_armv7() {
        let start = 0x1000;
        let data = get_asm("movs r2, 0xDE");
        let load_image = VectorLoader { start, data };
        let mut translator = PcodeTranslator::new::<styx_sla::Arm7Le>(
            &ArchVariant::Arm(ArmMetaVariants::ArmCortexA7(ArmCortexA7 {})),
            load_image,
        )
        .unwrap();
        translator.set_context_option(start, ContextOption::ThumbMode(true));

        let mut pcodes = Vec::new();
        let bytes_used = translator.get_pcode(start, &mut pcodes, ()).unwrap();

        // arm thumb instructions are 2 bytes
        assert_eq!(bytes_used, 2);
        assert_eq!(pcodes.len(), 5);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_decompile_error() {
        let start = 0x1000;
        let data = vec![0xFFu8; 4];
        let load_image = VectorLoader { start, data };
        let mut translator = PcodeTranslator::new::<styx_sla::Arm7Le>(
            &ArchVariant::Arm(ArmMetaVariants::ArmCortexA7(ArmCortexA7 {})),
            load_image,
        )
        .unwrap();
        translator.set_context_option(start, ContextOption::ThumbMode(true));

        let mut pcodes = Vec::new();
        let result = translator.get_pcode(start, &mut pcodes, ());
        assert!(matches!(result, Err(SleighTranslateError::BadDataError)));
    }
}

#[cfg(test)]
#[cfg(feature = "arch_hexagon")]
mod hexagon_tests {
    use keystone_engine::Keystone;
    use styx_cpu_type::arch::{
        backends::ArchVariant,
        hexagon::{variants::QDSP6V66, HexagonMetaVariants},
    };
    use styx_pcode_sleigh_backend::VectorLoader;

    use super::PcodeTranslator;
    use crate::ContextOption;

    fn get_asm(instr: &str) -> Vec<u8> {
        // Assemble instructions
        // Processor default to thumb so we use that
        let ks = Keystone::new(
            keystone_engine::Arch::HEXAGON,
            keystone_engine::Mode::BIG_ENDIAN,
        )
        .expect("Could not initialize Keystone engine");
        let asm = ks
            .asm(instr.to_owned(), 0x1000)
            .expect("Could not assemble");
        asm.bytes
    }

    fn manual_test_decompile(asm: &str) -> (u64, PcodeTranslator<VectorLoader>) {
        let start = 0x1000;
        let machine_code = get_asm(asm);

        // For debugging purposes.
        println!("asm {} code {:x?}", asm, machine_code);

        let loader = VectorLoader {
            start,
            data: machine_code,
        };

        (
            start,
            PcodeTranslator::new::<styx_sla::Hexagon>(
                &ArchVariant::Hexagon(HexagonMetaVariants::QDSP6V66(QDSP6V66 {})),
                loader,
            )
            .unwrap(),
        )
    }

    fn auto_test_decompile(asm: &str, expected_bytes_used: u64, expected_pcodes_len: usize) {
        let (start, mut translator) = manual_test_decompile(asm);
        // TODO: how to pass context options from the individual tests?
        translator.set_context_option(start, ContextOption::HexagonImmext(0xffffffff));

        let mut pcodes = Vec::new();
        let bytes_used = translator.get_pcode(start, &mut pcodes, ()).unwrap();

        assert_eq!(bytes_used, expected_bytes_used);
        assert_eq!(pcodes.len(), expected_pcodes_len);
    }

    // TODO: fix this
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_decompile_hexagon_packet() {
        let (start, mut translator) =
            manual_test_decompile("{ R1 = memh(R0); R5 = add(R4, R30); }");

        translator.set_context_option(start, ContextOption::HexagonImmext(0xffffffff));

        let mut pcodes = vec![];
        let bytes_used = translator.get_pcode(start, &mut pcodes, ()).unwrap();

        println!("(packet) First part of packet {:?}", pcodes);
        assert_eq!(pcodes.len(), 1);
        assert_eq!(bytes_used, 4);

        let bytes_used = translator
            .get_pcode(start + bytes_used, &mut pcodes, ())
            .unwrap();
        println!("(packet) Full packet {:?}", pcodes);

        // Cumulative length
        assert_eq!(pcodes.len(), 4);
        assert_eq!(bytes_used, 4);
    }

    // Hexagon duplex instructions basically encode 2 instructions in 32 bits
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_decompile_hexagon_duplex() {
        let (start, mut translator) = manual_test_decompile("{ R2 = R3; R3 = R2; }");
        translator.set_context_option(start, ContextOption::HexagonImmext(0xffffffff));
        translator.set_context_option(start, ContextOption::HexagonSubinsn(1));

        // TODO: assert that immext is right
        // The first get_pcode call will set immext, and won't return any pcodes

        let mut pcodes = vec![];
        let bytes_used = translator.get_pcode(start, &mut pcodes, ()).unwrap();

        println!("(duplex) First part of duplex pcode is {:?}", pcodes);
        assert_eq!(pcodes.len(), 1);
        assert_eq!(bytes_used, 2);

        let bytes_used = translator
            .get_pcode(start + bytes_used, &mut pcodes, ())
            .unwrap();

        println!(
            "(duplex) Full pcode for both instructions in duplex is {:?}",
            pcodes
        );
        assert_eq!(pcodes.len(), 2);
        assert_eq!(bytes_used, 2);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_decompile_hexagon_simple() {
        auto_test_decompile("{ R0 = add(R0, R1); }", 4, 1);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_decompile_hexagon_immediate() {
        // This is 0x12345678 in hex, for now, because
        // I can't figure out how to write an immediate in hex

        // The first four bytes used in immediate would be to set the context register
        // then the next four are for the actual instruction
        let (start, mut translator) = manual_test_decompile("{ R0 = add(R0, #305419896); }");
        translator.set_context_option(start, ContextOption::HexagonImmext(0xffffffff));

        // TODO: assert that immext is right
        // The first get_pcode call will set immext, and won't return any pcodes

        let mut pcodes = vec![];
        let bytes_used = translator.get_pcode(start, &mut pcodes, ()).unwrap();

        assert_eq!(pcodes.len(), 0);
        assert_eq!(bytes_used, 4);

        // This will be the actual instruction, now that immext is set
        let bytes_used = translator
            .get_pcode(start + bytes_used, &mut pcodes, ())
            .unwrap();

        println!("(immediate test) pcodes is now {:?}", pcodes);
        assert_eq!(pcodes.len(), 1);
        assert_eq!(bytes_used, 4);
    }

    // TODO: test hardware loop, and decompile error.

    /*#[cfg_attr(miri, ignore)]
    #[test]
    fn test_decompile_error() {
        let start = 0x1000;
        let data = vec![0xFFu8; 4];
        let load_image = VectorLoader { start, data };
        let mut translator = PcodeTranslator::new::<styx_sla::Arm7Le>(
            &ArchVariant::Arm(ArmMetaVariants::ArmCortexA7(ArmCortexA7 {})),
            load_image,
        )
        .unwrap();
        translator.set_context_option(ContextOption::ThumbMode(true));

        let mut pcodes = Vec::new();
        let result = translator.get_pcode(start, &mut pcodes, ());
        assert!(matches!(result, Err(SleighTranslateError::BadDataError)));
    }*/
}

#[cfg(test)]
#[cfg(feature = "arch_ppc")]
mod powerpc_tests {
    use super::*;
    use crate::sla::Ppc324xxBe;
    use crate::VectorLoader;
    use expect_test::{expect, expect_file};
    use styx_cpu_type::arch::{
        backends::ArchRegister,
        ppc32::{Ppc32MetaVariants, Ppc32Variants},
    };
    use styx_pcode::pcode::VarnodeData;
    use tap::Conv;

    /// Asserts that the styx -> sla register translation does not change. This also includes spr registers.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_ppc405_register_translation() {
        let start = 0x1000;
        let data = vec![0xFFu8; 4];
        let load_image = VectorLoader { start, data };
        let mut translator =
            PcodeTranslator::new::<Ppc324xxBe>(&Ppc32Variants::Ppc405.into(), load_image).unwrap();
        let mut translated_registers: Vec<(ArchRegister, Option<VarnodeData>)> =
            PcodeTranslator::get_registers_option::<Ppc324xxBe>(
                &Ppc32Variants::Ppc405.conv::<Ppc32MetaVariants>(),
                &mut translator.sleigh,
            )
            .collect();
        // sort to ensure consistent results
        translated_registers.sort_by_key(|(reg, _)| *reg);
        let expected_registers = expect_file!["../expect-test-data/ppc405-registers"];
        expected_registers.assert_debug_eq(&translated_registers);
    }

    /// Performs a snapshot test of powerpc instruction translation.
    ///
    /// The goal of this test is to detect changes in translation after a sla upgrade.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_ppc_translate() {
        // objdump from example ppc program
        // notably load/store operations are omitted because sleigh uses dynamic pointers
        //   to represent memory spaces which change run to run.
        let objdump = r#"
             10c:	7c 3f 0b 78 	mr      r31,r1
             110:	3d 20 00 00 	lis     r9,0
             114:	39 40 00 00 	li      r10,0
             11c:	39 20 00 00 	li      r9,0
             124:	48 00 00 28 	b       14c <main+0x4c>
             128:	3d 20 00 00 	lis     r9,0
             134:	7d 4a 4a 14 	add     r10,r10,r9
             138:	3d 20 00 00 	lis     r9,0
             144:	39 29 00 01 	addi    r9,r9,1
             150:	2c 09 27 0f 	cmpwi   r9,9999
             154:	40 81 ff d4 	ble     128 <main+0x28>
             158:	3d 20 00 00 	lis     r9,0
             160:	7d 2f 4b 78 	mr      r15,r9
             164:	60 00 00 00 	nop
             168:	60 00 00 00 	nop
             16c:	4b ff ff fc 	b       168 <main+0x68>
             "#;

        let init_pc = 0x1000u64;
        // this jumble of iterators takes the objdump and extracts the binary from it
        let code: Vec<u8> = styx_util::parse_objdump(objdump).unwrap();

        let loader = VectorLoader {
            start: init_pc,
            data: code,
        };
        let mut translator =
            PcodeTranslator::new::<Ppc324xxBe>(&Ppc32Variants::Ppc405.into(), loader).unwrap();

        // will hold the final list of pcodes
        let mut pcodes = Vec::new();
        let mut pc = init_pc;
        // translate all code to pcodes
        while let Ok(n) = translator.get_pcode(pc, &mut pcodes, ()) {
            pc += n;
        }

        let expected_pcodes = expect![[r#"
            [
                IntOr Register(0x04, 4), Register(0x04, 4) -> Register(0x7C, 4),
                IntLeft Constant(0x00, 4), Constant(0x10, 4) -> Register(0x24, 4),
                Copy Constant(0x00, 4) -> Register(0x28, 4),
                Copy Constant(0x00, 4) -> Register(0x24, 4),
                Branch Ram(0x1038, 4),
                IntLeft Constant(0x00, 4), Constant(0x10, 4) -> Register(0x24, 4),
                IntAdd Register(0x28, 4), Register(0x24, 4) -> Register(0x28, 4),
                IntLeft Constant(0x00, 4), Constant(0x10, 4) -> Register(0x24, 4),
                IntAdd Register(0x24, 4), Constant(0x01, 4) -> Register(0x24, 4),
                Copy Register(0x24, 4) -> Unique(0x14380, 4),
                Copy Constant(0x270F, 4) -> Unique(0x14400, 4),
                IntSLess Unique(0x14380, 4), Unique(0x14400, 4) -> Unique(0x14480, 1),
                IntLeft Unique(0x14480, 1), Constant(0x03, 4) -> Unique(0x14500, 1),
                IntSLess Unique(0x14400, 4), Unique(0x14380, 4) -> Unique(0x14580, 1),
                IntLeft Unique(0x14580, 1), Constant(0x02, 4) -> Unique(0x14600, 1),
                IntOr Unique(0x14500, 1), Unique(0x14600, 1) -> Unique(0x14680, 1),
                IntEqual Unique(0x14380, 4), Unique(0x14400, 4) -> Unique(0x14700, 1),
                IntLeft Unique(0x14700, 1), Constant(0x01, 4) -> Unique(0x14780, 1),
                IntOr Unique(0x14680, 1), Unique(0x14780, 1) -> Unique(0x14800, 1),
                IntAnd Register(0x400, 1), Constant(0x01, 1) -> Unique(0x14880, 1),
                IntOr Unique(0x14800, 1), Unique(0x14880, 1) -> Register(0x900, 1),
                Copy Constant(0x00, 1) -> Unique(0xB080, 1),
                IntSub Constant(0x03, 4), Constant(0x01, 4) -> Unique(0x800, 4),
                IntRight Register(0x900, 1), Unique(0x800, 4) -> Unique(0x900, 1),
                IntAnd Unique(0x900, 1), Constant(0x01, 1) -> Unique(0xB080, 1),
                BoolNegate Unique(0xB080, 1) -> Unique(0xB080, 1),
                CBranch Ram(0xFFC, 4), Unique(0xB080, 1),
                IntLeft Constant(0x00, 4), Constant(0x10, 4) -> Register(0x24, 4),
                IntOr Register(0x24, 4), Register(0x24, 4) -> Register(0x3C, 4),
                IntOr Register(0x00, 4), Constant(0x00, 4) -> Register(0x00, 4),
                IntOr Register(0x00, 4), Constant(0x00, 4) -> Register(0x00, 4),
                Branch Ram(0x1038, 4),
            ]
        "#]];
        expected_pcodes.assert_debug_eq(&pcodes);
    }
}

#[cfg(test)]
#[cfg(feature = "arch_mips32")]
mod mips32_tests {
    use expect_test::expect;
    use keystone_engine::Keystone;
    use styx_cpu_type::arch::mips32::{Mips32MetaVariants, Mips32Variants};
    use styx_pcode_sleigh_backend::VectorLoader;
    use tap::Conv;

    use super::PcodeTranslator;

    fn get_asm(instr: &str) -> Vec<u8> {
        // Assemble instructions
        let ks = Keystone::new(keystone_engine::Arch::MIPS, keystone_engine::Mode::MIPS32)
            .expect("Could not initialize Keystone engine");
        let asm = ks
            .asm(instr.to_owned(), 0x1000)
            .expect("Could not assemble");
        asm.bytes
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_decompile_trivial() {
        let start = 0x1000;
        let data = get_asm("ori     $t0, $zero, 3");
        let load_image = VectorLoader { start, data };
        let mut translator = PcodeTranslator::new::<styx_sla::Mips32le>(
            &(Mips32Variants::Mips32r1Generic.conv::<Mips32MetaVariants>()).into(),
            load_image,
        )
        .unwrap();

        let mut pcodes: Vec<styx_pcode::pcode::Pcode> = Vec::new();
        let bytes_used = translator.get_pcode(start, &mut pcodes, ()).unwrap();

        assert_eq!(bytes_used, 4);
        let expected_pcodes = expect![[r#"
            [
                IntOr Constant(0x00, 4), Constant(0x03, 4) -> Register(0x20, 4),
            ]
        "#]];
        expected_pcodes.assert_debug_eq(&pcodes);
    }
}
