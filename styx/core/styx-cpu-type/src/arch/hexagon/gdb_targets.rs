// SPDX-License-Identifier: BSD-2-Clause
use std::collections::BTreeMap;

use super::HexagonRegister;
use crate::arch::backends::{ArchRegister, BasicArchRegister};
use crate::arch::CpuRegister;
use std::marker::PhantomData;
use styx_macros::gdb_target_description;
use styx_sync::lazy_static;
use styx_util::gdb_xml::{HEXAGON_CORE, HEXAGON_HVX};

lazy_static! {
    // This mapping was generated from XML files in
    // https://github.com/quic/qemu/tree/hex-next/gdb-xml
    // and by reading how these XML files are used in
    // https://github.com/quic/qemu/blob/hex-next/target/hexagon/cpu.c,
    // https://github.com/quic/qemu/blob/hex-next/target/hexagon/gdbstub.c, and
    // https://github.com/quic/qemu/blob/hex-next/gdbstub/gdbstub.c

    // The following is an explanation of how the mappings work and how the XML was generated:
    //
    // Suppose we have 32 general purpose regs, and 16 system registers in a
    // made-up ISA.
    //
    // There are separate arrays of core/system registers (this split is called a GDB feature), which are read in
    // from the XML files. The ordering of registers for each type is generated from a Python script. You can generate this
    // by running `python scripts/feature_to_c.py gdb-xml/hexagon-*`. If you run this, it generates an array of GDBFeature.
    // Each GDBFeature contains the file name (eg. hexagon-hvx.xml), the XML contents, the name of the "gdb feature," an
    // array of the registers defined in that file, and the length of that array.
    //
    // The backend adds each array of register types to a bigger array (cpu->gdb_regs) in a certain order using gdb_register_coprocessor.
    // Eg. a backend may choose to add hexagon-core.xml, hexagon-sys.xml and hexagon-hvx.xml to the gdb_regs. See
    // https://github.com/quic/qemu/blob/hex-next/target/hexagon/cpu.c#L491, https://github.com/quic/qemu/blob/hex-next/gdbstub/gdbstub.c#L604,
    // and https://github.com/quic/qemu/blob/hex-next/gdbstub/gdbstub.c#L555.
    //
    // When QEMU goes to read/write a register at the request of GDB (gdb specifies the register number,
    // which is what we need), it looks at the registers that were added to cpu->gdb_regs. So, after the core
    // registers and gdb_register_coprocessor, might have general register names [0..31] in an array, and [0, 15] for sys
    // regs (in the made-up ISA). If we requested register 33, we would basically look to see if this is within the first
    // 32 registers (assume the core registers added first and sys registers added second) and if not subtract 32 from our
    // register request (so now we are at 1), then look at the second array of sys regs, specifically at the second register
    // in that array. As such, we would get the second register in this [0..15]. See
    // https://github.com/quic/qemu/blob/hex-next/gdbstub/gdbstub.c#L532 for details.
    //
    // So 0..31 would be mapped to the ordering of registers in the array inside the GDBFeature,
    // then 32..47 has the ordering of registers in the systems registers for the corresponding GDBFeature, etc.
    //
    // To understand where I got the Hexagon mappings from, run the python script mentioned above,
    // then look at the output and look at the arrays for the separate system/hvx/core regs. Also, looks
    // like from https://github.com/quic/qemu/blob/hex-next/target/hexagon/cpu.c#L491 that first we have core
    // (core is added/initialized elsewhere), then HVX, then system registers.

    pub static ref HEXAGON_CORE_CPU_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, HexagonRegister::R0.register()),
        (1, HexagonRegister::R1.register()),
        (2, HexagonRegister::R2.register()),
        (3, HexagonRegister::R3.register()),
        (4, HexagonRegister::R4.register()),
        (5, HexagonRegister::R5.register()),
        (6, HexagonRegister::R6.register()),
        (7, HexagonRegister::R7.register()),
        (8, HexagonRegister::R8.register()),
        (9, HexagonRegister::R9.register()),
        (10, HexagonRegister::R10.register()),
        (11, HexagonRegister::R11.register()),
        (12, HexagonRegister::R12.register()),
        (13, HexagonRegister::R13.register()),
        (14, HexagonRegister::R14.register()),
        (15, HexagonRegister::R15.register()),
        (16, HexagonRegister::R16.register()),
        (17, HexagonRegister::R17.register()),
        (18, HexagonRegister::R18.register()),
        (19, HexagonRegister::R19.register()),
        (20, HexagonRegister::R20.register()),
        (21, HexagonRegister::R21.register()),
        (22, HexagonRegister::R22.register()),
        (23, HexagonRegister::R23.register()),
        (24, HexagonRegister::R24.register()),
        (25, HexagonRegister::R25.register()),
        (26, HexagonRegister::R26.register()),
        (27, HexagonRegister::R27.register()),
        (28, HexagonRegister::R28.register()),
        (29, HexagonRegister::Sp.register()),
        (30, HexagonRegister::Fp.register()),
        (31, HexagonRegister::Lr.register()),
        // Start control registers
        (32, HexagonRegister::Sa0.register()),
        (33, HexagonRegister::Lc0.register()),
        (34, HexagonRegister::Sa1.register()),
        (35, HexagonRegister::Lc1.register()),
        (36, HexagonRegister::P3_0.register()),
        (37, HexagonRegister::C5.register()),
        (38, HexagonRegister::M0.register()),
        (39, HexagonRegister::M1.register()),
        (40, HexagonRegister::Usr.register()),
        (41, HexagonRegister::Pc.register()),
        (42, HexagonRegister::Ugp.register()),
        (43, HexagonRegister::Gp.register()),
        (44, HexagonRegister::Cs0.register()),
        (45, HexagonRegister::Cs1.register()),
        (46, HexagonRegister::UpcycleLo.register()),
        (47, HexagonRegister::UpcycleHi.register()),
        (48, HexagonRegister::FrameLimit.register()),
        (49, HexagonRegister::FrameKey.register()),
        (50, HexagonRegister::PktCountLo.register()),
        (51, HexagonRegister::PktCountHi.register()),
        // START Reserved registers!
        (52, HexagonRegister::EmuPktCount.register()),
        (53, HexagonRegister::EmuInsnCount.register()),
        (54, HexagonRegister::EmuHvxCount.register()),
        // END Reserved registers!
        (55, HexagonRegister::C23.register()),
        (56, HexagonRegister::C24.register()),
        (57, HexagonRegister::C25.register()),
        (58, HexagonRegister::C26.register()),
        (59, HexagonRegister::C27.register()),
        (60, HexagonRegister::C28.register()),
        (61, HexagonRegister::C29.register()),
        (62, HexagonRegister::UtimerLo.register()),
        (63, HexagonRegister::UtimerHi.register()),
        // Predicate registers
        (64, HexagonRegister::P0.register()),
        (65, HexagonRegister::P1.register()),
        (66, HexagonRegister::P2.register()),
        (67, HexagonRegister::P3.register()),
        // System registers
        (104, HexagonRegister::Sgp0.register()),
        (105, HexagonRegister::Sgp1.register()),
        (106, HexagonRegister::Stid.register()),
        (107, HexagonRegister::Elr.register()),
        (108, HexagonRegister::BadVa0.register()),
        (109, HexagonRegister::BadVa1.register()),
        (110, HexagonRegister::Ssr.register()),
        (111, HexagonRegister::Ccr.register()),
        (112, HexagonRegister::Htid.register()),
        (113, HexagonRegister::BadVa.register()),
        (114, HexagonRegister::Imask.register()),
        (115, HexagonRegister::Gevb.register()),
        (116, HexagonRegister::VwCtrl.register()),
        (117, HexagonRegister::S13.register()),
        (118, HexagonRegister::S14.register()),
        (119, HexagonRegister::S15.register()),
        (120, HexagonRegister::Evb.register()),
        (121, HexagonRegister::ModeCtl.register()),
        (122, HexagonRegister::SysCfg.register()),
        (123, HexagonRegister::Segment.register()),
        (124, HexagonRegister::Ipendad.register()),
        (125, HexagonRegister::Vid.register()),
        (126, HexagonRegister::Vid1.register()),
        (127, HexagonRegister::BestWait.register()),
        (128, HexagonRegister::S24.register()),
        (129, HexagonRegister::SchedCfg.register()),
        (130, HexagonRegister::S26.register()),
        (131, HexagonRegister::CfgBase.register()),
        (132, HexagonRegister::Diag.register()),
        (133, HexagonRegister::Rev.register()),
        (134, HexagonRegister::PcycleLo.register()),
        (135, HexagonRegister::PcycleHi.register()),
        (136, HexagonRegister::IsdbSt.register()),
        (137, HexagonRegister::IsdbCfg0.register()),
        (138, HexagonRegister::IsdbCfg1.register()),
        (139, HexagonRegister::Livelock.register()),
        (140, HexagonRegister::BrkptPc0.register()),
        (141, HexagonRegister::BrkptCfg0.register()),
        (142, HexagonRegister::BrkptPc1.register()),
        (143, HexagonRegister::BrkptCfg1.register()),
        (144, HexagonRegister::IsdbMbxIn.register()),
        (145, HexagonRegister::IsdbMbxOut.register()),
        (146, HexagonRegister::IsdbEn.register()),
        (147, HexagonRegister::IsdbGpr.register()),
        (148, HexagonRegister::PmuCnt4.register()),
        (149, HexagonRegister::PmuCnt5.register()),
        (150, HexagonRegister::PmuCnt6.register()),
        (151, HexagonRegister::PmuCnt7.register()),
        (152, HexagonRegister::PmuCnt0.register()),
        (153, HexagonRegister::PmuCnt1.register()),
        (154, HexagonRegister::PmuCnt2.register()),
        (155, HexagonRegister::PmuCnt3.register()),
        (156, HexagonRegister::PmuEvtCfg.register()),
        (157, HexagonRegister::PmuStId0.register()),
        (158, HexagonRegister::PmuEvtCfg1.register()),
        (159, HexagonRegister::PmuStId1.register()),
        (160, HexagonRegister::TimerLo.register()),
        (161, HexagonRegister::TimerHi.register()),
        (162, HexagonRegister::PmuCfg.register()),
        (163, HexagonRegister::Rgdr2.register()),
        (164, HexagonRegister::Rgdr.register()),
        (165, HexagonRegister::Turkey.register()),
        (166, HexagonRegister::Duck.register()),
        (167, HexagonRegister::Chicken.register()),
        (168, HexagonRegister::Commit1t.register()),
        (169, HexagonRegister::Commit2t.register()),
        (170, HexagonRegister::Commit3t.register()),
        (171, HexagonRegister::Commit4t.register()),
        (172, HexagonRegister::Commit5t.register()),
        (173, HexagonRegister::Commit6t.register()),
        (174, HexagonRegister::Pcycle1t.register()),
        (175, HexagonRegister::Pcycle2t.register()),
        (176, HexagonRegister::Pcycle3t.register()),
        (177, HexagonRegister::Pcycle4t.register()),
        (178, HexagonRegister::Pcycle5t.register()),
        (179, HexagonRegister::Pcycle6t.register()),
        (180, HexagonRegister::StfInst.register()),
        (181, HexagonRegister::IsdbCmd.register()),
        (182, HexagonRegister::IsdbVer.register()),
        (183, HexagonRegister::BrkptInfo.register()),
        (184, HexagonRegister::Rgdr3.register()),
        (185, HexagonRegister::Commit7t.register()),
        (186, HexagonRegister::Commit8t.register()),
        (187, HexagonRegister::Pcycle7t.register()),
        (188, HexagonRegister::Pcycle8t.register()),
        (189, HexagonRegister::Commit9t.register()),
        (190, HexagonRegister::Commit10t.register()),
        (191, HexagonRegister::Commit11t.register()),
        (192, HexagonRegister::Commit12t.register()),
        (193, HexagonRegister::Commit13t.register()),
        (194, HexagonRegister::Commit14t.register()),
        (195, HexagonRegister::Commit15t.register()),
        (196, HexagonRegister::Commit16t.register()),
        (197, HexagonRegister::Pcycle9t.register()),
        (198, HexagonRegister::Pcycle10t.register()),
        (199, HexagonRegister::Pcycle11t.register()),
        (200, HexagonRegister::Pcycle12t.register()),
        (201, HexagonRegister::Pcycle13t.register()),
        (202, HexagonRegister::Pcycle14t.register()),
        (203, HexagonRegister::Pcycle15t.register()),
        (204, HexagonRegister::Pcycle16t.register()),
        (205, HexagonRegister::Ipend.register()),
        (206, HexagonRegister::Iad.register()),
        (207, HexagonRegister::IsdbSt1.register()),
        (208, HexagonRegister::IsdbSt2.register()),
        (209, HexagonRegister::BrkptInfo1.register()),
        // Guest registers
        (210, HexagonRegister::Gelr.register()),
        (211, HexagonRegister::Gsr.register()),
        (212, HexagonRegister::Gosp.register()),
        (213, HexagonRegister::GbadVa.register()),
        (214, HexagonRegister::Gcommit1t.register()),
        (215, HexagonRegister::Gcommit2t.register()),
        (216, HexagonRegister::Gcommit3t.register()),
        (217, HexagonRegister::Gcommit4t.register()),
        (218, HexagonRegister::Gcommit5t.register()),
        (219, HexagonRegister::Gcommit6t.register()),
        (220, HexagonRegister::Gpcycle1t.register()),
        (221, HexagonRegister::Gpcycle2t.register()),
        (222, HexagonRegister::Gpcycle3t.register()),
        (223, HexagonRegister::Gpcycle4t.register()),
        (224, HexagonRegister::Gpcycle5t.register()),
        (225, HexagonRegister::Gpcycle6t.register()),
        (226, HexagonRegister::Gpmucnt4.register()),
        (227, HexagonRegister::Gpmucnt5.register()),
        (228, HexagonRegister::Gpmucnt6.register()),
        (229, HexagonRegister::Gpmucnt7.register()),
        (230, HexagonRegister::Gcommit7t.register()),
        (231, HexagonRegister::Gcommit8t.register()),
        (232, HexagonRegister::Gpcycle7t.register()),
        (233, HexagonRegister::Gpcycle8t.register()),
        (234, HexagonRegister::Gpcyclelo.register()),
        (235, HexagonRegister::Gpcyclehi.register()),
        (236, HexagonRegister::Gpmucnt0.register()),
        (237, HexagonRegister::Gpmucnt1.register()),
        (238, HexagonRegister::Gpmucnt2.register()),
        (239, HexagonRegister::Gpmucnt3.register()),
        (240, HexagonRegister::G30.register()),
        (241, HexagonRegister::G31.register()),
    ]);

    static ref HEXAGON_HVX_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (68, HexagonRegister::V0.register()),
        (69, HexagonRegister::V1.register()),
        (70, HexagonRegister::V2.register()),
        (71, HexagonRegister::V3.register()),
        (72, HexagonRegister::V4.register()),
        (73, HexagonRegister::V5.register()),
        (74, HexagonRegister::V6.register()),
        (75, HexagonRegister::V7.register()),
        (76, HexagonRegister::V8.register()),
        (77, HexagonRegister::V9.register()),
        (78, HexagonRegister::V10.register()),
        (79, HexagonRegister::V11.register()),
        (80, HexagonRegister::V12.register()),
        (81, HexagonRegister::V13.register()),
        (82, HexagonRegister::V14.register()),
        (83, HexagonRegister::V15.register()),
        (84, HexagonRegister::V16.register()),
        (85, HexagonRegister::V17.register()),
        (86, HexagonRegister::V18.register()),
        (87, HexagonRegister::V19.register()),
        (88, HexagonRegister::V20.register()),
        (89, HexagonRegister::V21.register()),
        (90, HexagonRegister::V22.register()),
        (91, HexagonRegister::V23.register()),
        (92, HexagonRegister::V24.register()),
        (93, HexagonRegister::V25.register()),
        (94, HexagonRegister::V26.register()),
        (95, HexagonRegister::V27.register()),
        (96, HexagonRegister::V28.register()),
        (97, HexagonRegister::V29.register()),
        (98, HexagonRegister::V30.register()),
        (99, HexagonRegister::V31.register()),
        (100, HexagonRegister::Q0.register()),
        (101, HexagonRegister::Q1.register()),
        (102, HexagonRegister::Q2.register()),
        (103, HexagonRegister::Q3.register()),
    ]);

    // Combine HVX register map and default register map
    pub static ref HEXAGON_CORE_HVX_CPU_REGISTER_MAP: BTreeMap<usize, CpuRegister> = HEXAGON_CORE_CPU_REGISTER_MAP
        .clone().into_iter().chain(HEXAGON_HVX_REGISTER_MAP.clone().into_iter()).collect();
}

#[gdb_target_description]
#[derive(Debug, Default)]
pub struct HexagonCpuTargetDescription {
    #[args(
        gdb_arch_name("hexagon-core"),
        gdb_feature_xml(HEXAGON_CORE),
        register_map(HEXAGON_CORE_CPU_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Hexagon(HexagonRegister::Pc))),
        endianness(ArchEndian::LittleEndian)
    )]
    args: PhantomData<()>,
}

#[gdb_target_description]
#[derive(Debug, Default)]
pub struct HexagonHvxCpuTargetDescription {
    #[args(
        gdb_arch_name("hexagon-hvx"),
        gdb_feature_xml(HEXAGON_HVX),
        register_map(HEXAGON_CORE_HVX_CPU_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Hexagon(HexagonRegister::Pc))),
        endianness(ArchEndian::LittleEndian)
    )]
    args: PhantomData<()>,
}
