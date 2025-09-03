// SPDX-License-Identifier: BSD-2-Clause
use styx_pcode_translator::sla::{Aarch64, Aarch64UserOps};

use crate::{
    arch_spec::{
        aarch64::call_other::{
            NeonAddvCallother, NeonBifCallother, NeonBitCallother, NeonBslCallother,
            NeonCmtestCallother, NeonCntCallother, NeonFcmeqCallother, NeonFcmgeCallother,
            NeonFcmgtCallother, NeonFcmleCallother, NeonFcmltCallother, NeonFminnmCallother,
            NeonRev64Callother,
        },
        ArchSpecBuilder,
    },
    PcodeBackend,
};

pub fn build() -> ArchSpecBuilder<Aarch64, PcodeBackend> {
    let mut spec = ArchSpecBuilder::default();

    spec.set_pc_manager(super::StandardPcManager::default().into());

    spec.set_generator(super::StandardGeneratorHelper.into());

    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonAddv, NeonAddvCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonCnt, NeonCntCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonBif, NeonBifCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonBit, NeonBitCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonBsl, NeonBslCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonRev64, NeonRev64Callother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonCmtst, NeonCmtestCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonFcmeq, NeonFcmeqCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonFcmle, NeonFcmleCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonFcmlt, NeonFcmltCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonFcmge, NeonFcmgeCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonFcmgt, NeonFcmgtCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonFminnm, NeonFminnmCallother)
        .unwrap();

    spec
}
