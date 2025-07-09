// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//! Testing of Blackfin architecture using the pcode backend.
//!
//! Tests are taken from binutils-gdb suite. The main testsuite.inc which is included in every test
//! has been modified to store the pass/fail value in R0. pass: R0=13. This was changed from 0 to
//! prevent false passes.
//!
//! To run:
//!
//! `cargo nextest run -p styx-cpu-pcode-backend -E "test(test_binutils_unittests::)" --failure-output never --run-ignored all --retries 0 --features blackfin-binutils-tests`
//!
#![cfg(feature = "blackfin-binutils-tests")]
#![cfg(not(feature = "disable-blackfin-tests"))] // hack for when using `--all-features`

use log::{debug, warn};
use styx_blackfin_testdata::{binutils_tests, TestData};
use styx_cpu_pcode_backend::PcodeBackend;
use styx_cpu_type::{
    arch::blackfin::{BlackfinRegister, BlackfinVariants},
    Arch, ArchEndian, TargetExitReason,
};
use styx_errors::UnknownError;
use styx_loader::{Loader, MemoryLoaderDesc};
use styx_processor::{
    cpu::{CpuBackend, CpuBackendExt},
    event_controller::EventController,
    hooks::{CoreHandle, Hookable, Resolution, StyxHook},
    memory::{
        helpers::{ReadExt, WriteExt},
        memory_region::MemoryRegion,
        MemoryPermissions, Mmu,
    },
};
use test_case::test_case;

// List all tests and remove their extension (to paste into here).
// ls -p src/styx-cpu-pcode-backend/data/blackfin_tests/bin | grep -v / |  awk -F '.' '{OFS=".";$NF=""; print $0}' | sed 's/\.$//'

// Don't run these tests unless explicitly asked to (they don't pass)
#[ignore]
#[test_case(binutils_tests::TEST_10272_SMALL)]
#[test_case(binutils_tests::TEST_10436)]
#[test_case(binutils_tests::TEST_10622)]
#[test_case(binutils_tests::TEST_10742)]
#[test_case(binutils_tests::TEST_10799)]
#[test_case(binutils_tests::TEST_11080)]
#[test_case(binutils_tests::TEST_7641)]
#[test_case(binutils_tests::TEST_PN_GENERATOR)]
#[test_case(binutils_tests::TEST_A0)]
#[test_case(binutils_tests::TEST_A1)]
#[test_case(binutils_tests::TEST_A10)]
#[test_case(binutils_tests::TEST_A12)]
#[test_case(binutils_tests::TEST_A2)]
#[test_case(binutils_tests::TEST_A21)]
#[test_case(binutils_tests::TEST_A22)]
#[test_case(binutils_tests::TEST_A23)]
#[test_case(binutils_tests::TEST_A24)]
#[test_case(binutils_tests::TEST_A25)]
#[test_case(binutils_tests::TEST_A26)]
#[test_case(binutils_tests::TEST_A3)]
#[test_case(binutils_tests::TEST_A30)]
#[test_case(binutils_tests::TEST_A4)]
#[test_case(binutils_tests::TEST_A5)]
#[test_case(binutils_tests::TEST_A6)]
#[test_case(binutils_tests::TEST_A7)]
#[test_case(binutils_tests::TEST_A8)]
#[test_case(binutils_tests::TEST_A9)]
#[test_case(binutils_tests::TEST_ABS_ACC)]
#[test_case(binutils_tests::TEST_ACC_ROT)]
#[test_case(binutils_tests::TEST_ACP5_19)]
#[test_case(binutils_tests::TEST_ACP5_4)]
#[test_case(binutils_tests::TEST_ADD_IMM7)]
#[test_case(binutils_tests::TEST_ADD_SUB_ACC)]
#[test_case(binutils_tests::TEST_ALGNBUG1)]
#[test_case(binutils_tests::TEST_ALGNBUG2)]
#[test_case(binutils_tests::TEST_ASHIFT)]
#[test_case(binutils_tests::TEST_ASHIFT_FLAGS)]
#[test_case(binutils_tests::TEST_ASHIFT_LEFT)]
#[test_case(binutils_tests::TEST_B1)]
#[test_case(binutils_tests::TEST_BRCC)]
#[test_case(binutils_tests::TEST_BREVADD)]
#[test_case(binutils_tests::TEST_BYTEOP16M)]
#[test_case(binutils_tests::TEST_BYTEOP16P)]
#[test_case(binutils_tests::TEST_BYTEOP1P)]
#[test_case(binutils_tests::TEST_BYTEOP2P)]
#[test_case(binutils_tests::TEST_BYTEOP3P)]
#[test_case(binutils_tests::TEST_BYTEUNPACK)]
#[test_case(binutils_tests::TEST_C_ALU2OP_ARITH_R_SFT)]
#[test_case(binutils_tests::TEST_C_ALU2OP_CONV_B)]
#[test_case(binutils_tests::TEST_C_ALU2OP_CONV_H)]
#[test_case(binutils_tests::TEST_C_ALU2OP_CONV_MIX)]
#[test_case(binutils_tests::TEST_C_ALU2OP_CONV_NEG)]
#[test_case(binutils_tests::TEST_C_ALU2OP_CONV_TOGGLE)]
#[test_case(binutils_tests::TEST_C_ALU2OP_CONV_XB)]
#[test_case(binutils_tests::TEST_C_ALU2OP_CONV_XH)]
#[test_case(binutils_tests::TEST_C_ALU2OP_DIVQ)]
#[test_case(binutils_tests::TEST_C_ALU2OP_DIVS)]
#[test_case(binutils_tests::TEST_C_ALU2OP_LOG_L_SFT)]
#[test_case(binutils_tests::TEST_C_ALU2OP_LOG_R_SFT)]
#[test_case(binutils_tests::TEST_C_ALU2OP_SHADD_1)]
#[test_case(binutils_tests::TEST_C_ALU2OP_SHADD_2)]
#[test_case(binutils_tests::TEST_C_BR_PREG_KILLED_AC)]
#[test_case(binutils_tests::TEST_C_BR_PREG_KILLED_EX1)]
#[test_case(binutils_tests::TEST_C_BR_PREG_STALL_AC)]
#[test_case(binutils_tests::TEST_C_BR_PREG_STALL_EX1)]
#[test_case(binutils_tests::TEST_C_BRCC_BP1)]
#[test_case(binutils_tests::TEST_C_BRCC_BP2)]
#[test_case(binutils_tests::TEST_C_BRCC_BP3)]
#[test_case(binutils_tests::TEST_C_BRCC_BP4)]
#[test_case(binutils_tests::TEST_C_BRCC_BRF_BP)]
#[test_case(binutils_tests::TEST_C_BRCC_BRF_BRT_BP)]
#[test_case(binutils_tests::TEST_C_BRCC_BRF_BRT_NBP)]
#[test_case(binutils_tests::TEST_C_BRCC_BRF_FBKWD)]
#[test_case(binutils_tests::TEST_C_BRCC_BRF_NBP)]
#[test_case(binutils_tests::TEST_C_BRCC_BRT_BP)]
#[test_case(binutils_tests::TEST_C_BRCC_BRT_NBP)]
#[test_case(binutils_tests::TEST_C_BRCC_KILLS_DHITS)]
#[test_case(binutils_tests::TEST_C_BRCC_KILLS_DMISS)]
#[test_case(binutils_tests::TEST_C_CACTRL_IFLUSH_PR)]
#[test_case(binutils_tests::TEST_C_CACTRL_IFLUSH_PR_PP)]
#[test_case(binutils_tests::TEST_C_CALLA_LJUMP)]
#[test_case(binutils_tests::TEST_C_CALLA_SUBR)]
#[test_case(binutils_tests::TEST_C_CC2DREG)]
#[test_case(binutils_tests::TEST_C_CC2STAT_CC_AN)]
#[test_case(binutils_tests::TEST_C_CC2STAT_CC_AQ)]
#[test_case(binutils_tests::TEST_C_CC2STAT_CC_AZ)]
#[test_case(binutils_tests::TEST_C_CC_FLAGDREG_MVBRSFT)]
#[test_case(binutils_tests::TEST_C_CC_FLAGDREG_MVBRSFT_S1)]
#[test_case(binutils_tests::TEST_C_CC_FLAGDREG_MVBRSFT_SN)]
#[test_case(binutils_tests::TEST_C_CC_REGMVLOGI_MVBRSFT)]
#[test_case(binutils_tests::TEST_C_CC_REGMVLOGI_MVBRSFT_S1)]
#[test_case(binutils_tests::TEST_C_CCFLAG_DR_DR)]
#[test_case(binutils_tests::TEST_C_CCFLAG_DR_DR_UU)]
#[test_case(binutils_tests::TEST_C_CCFLAG_DR_IMM3)]
#[test_case(binutils_tests::TEST_C_CCFLAG_DR_IMM3_UU)]
#[test_case(binutils_tests::TEST_C_CCFLAG_PR_IMM3)]
#[test_case(binutils_tests::TEST_C_CCFLAG_PR_IMM3_UU)]
#[test_case(binutils_tests::TEST_C_CCFLAG_PR_PR)]
#[test_case(binutils_tests::TEST_C_CCFLAG_PR_PR_UU)]
#[test_case(binutils_tests::TEST_C_CCMV_CC_DR_DR)]
#[test_case(binutils_tests::TEST_C_CCMV_CC_DR_PR)]
#[test_case(binutils_tests::TEST_C_CCMV_CC_PR_PR)]
#[test_case(binutils_tests::TEST_C_CCMV_NCC_DR_DR)]
#[test_case(binutils_tests::TEST_C_CCMV_NCC_DR_PR)]
#[test_case(binutils_tests::TEST_C_CCMV_NCC_PR_PR)]
#[test_case(binutils_tests::TEST_C_COMP3OP_DR_AND_DR)]
#[test_case(binutils_tests::TEST_C_COMP3OP_DR_MINUS_DR)]
#[test_case(binutils_tests::TEST_C_COMP3OP_DR_MIX)]
#[test_case(binutils_tests::TEST_C_COMP3OP_DR_OR_DR)]
#[test_case(binutils_tests::TEST_C_COMP3OP_DR_PLUS_DR)]
#[test_case(binutils_tests::TEST_C_COMP3OP_DR_XOR_DR)]
#[test_case(binutils_tests::TEST_C_COMP3OP_PR_PLUS_PR_SH1)]
#[test_case(binutils_tests::TEST_C_COMP3OP_PR_PLUS_PR_SH2)]
#[test_case(binutils_tests::TEST_C_COMPI2OPD_DR_ADD_I7_N)]
#[test_case(binutils_tests::TEST_C_COMPI2OPD_DR_ADD_I7_P)]
#[test_case(binutils_tests::TEST_C_COMPI2OPD_DR_EQ_I7_N)]
#[test_case(binutils_tests::TEST_C_COMPI2OPD_DR_EQ_I7_P)]
#[test_case(binutils_tests::TEST_C_COMPI2OPP_PR_ADD_I7_N)]
#[test_case(binutils_tests::TEST_C_COMPI2OPP_PR_ADD_I7_P)]
#[test_case(binutils_tests::TEST_C_COMPI2OPP_PR_EQ_I7_N)]
#[test_case(binutils_tests::TEST_C_COMPI2OPP_PR_EQ_I7_P)]
#[test_case(binutils_tests::TEST_C_DAGMODIK_LNZ_IMGEBL)]
#[test_case(binutils_tests::TEST_C_DAGMODIK_LNZ_IMLTBL)]
#[test_case(binutils_tests::TEST_C_DAGMODIK_LZ_INC_DEC)]
#[test_case(binutils_tests::TEST_C_DAGMODIM_LNZ_IMGEBL)]
#[test_case(binutils_tests::TEST_C_DAGMODIM_LNZ_IMLTBL)]
#[test_case(binutils_tests::TEST_C_DAGMODIM_LZ_INC_DEC)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_A0_PM_A1)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_A0A1S)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_A_ABS_A)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_A_NEG_A)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_AA_ABSABS)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_AA_NEGNEG)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_ABS)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_ABSABS)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_ALHWX)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_AWX)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_BYTEOP1EW)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_BYTEOP2)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_BYTEOP3)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_BYTEPACK)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_BYTEUNPACK)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_DISALNEXCPT)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_MAX)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_MAXMAX)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_MIN)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_MINMIN)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_MIX)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_R_LH_A0PA1)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_R_NEGNEG)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RH_M)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RH_P)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RH_RND12_M)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RH_RND12_P)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RH_RND20_M)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RH_RND20_P)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RL_M)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RL_P)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RL_RND12_M)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RL_RND12_P)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RL_RND20_M)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RL_RND20_P)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RLH_RND)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RM)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RMM)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RMP)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RP)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RPM)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RPP)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RR_LPH_A1A0)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RRPM)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RRPM_AA)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RRPMMP)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RRPMMP_SFT)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RRPMMP_SFT_X)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RRPPMM)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RRPPMM_SFT)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_RRPPMM_SFT_X)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_SAA)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_SEARCH)]
#[test_case(binutils_tests::TEST_C_DSP32ALU_SGN)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_A1A0)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_A1A0_IUW32)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_A1A0_M)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A0)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A0_I)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A0_IH)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A0_IS)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A0_IU)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A0_M)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A0_S)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A0_T)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A0_TU)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A0_U)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A1)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A1_I)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A1_IH)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A1_IS)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A1_IU)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A1_M)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A1_S)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A1_T)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A1_TU)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A1_U)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A1A0)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A1A0_IUTSH)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_DR_A1A0_M)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_MIX)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A0)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A0_I)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A0_IS)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A0_M)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A0_S)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A0_U)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A1)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A1_I)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A1_IS)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A1_M)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A1_S)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A1_U)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A1A0)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A1A0_I)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A1A0_IS)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A1A0_M)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A1A0_S)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_A1A0_U)]
#[test_case(binutils_tests::TEST_C_DSP32MAC_PAIR_MIX)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_I)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_IH)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_IS)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_IU)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_M)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_M_I)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_M_IUTSH)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_M_S)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_M_T)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_M_U)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_MIX)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_S)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_T)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_TU)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_DR_U)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_PAIR)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_PAIR_I)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_PAIR_IS)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_PAIR_M)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_PAIR_M_I)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_PAIR_M_IS)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_PAIR_M_S)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_PAIR_M_U)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_PAIR_S)]
#[test_case(binutils_tests::TEST_C_DSP32MULT_PAIR_U)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_A0ALR)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_AF)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_AF_S)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_AHALF_LN)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_AHALF_LN_S)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_AHALF_LP)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_AHALF_LP_S)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_AHALF_RN)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_AHALF_RN_S)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_AHALF_RP)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_AHALF_RP_S)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_AHH)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_AHH_S)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_ALIGN16)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_ALIGN24)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_ALIGN8)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_AMIX)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_BITMUX)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_BXOR)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_EXPADJ_H)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_EXPADJ_L)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_EXPADJ_R)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_EXPEXP_R)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_FDEPX)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_FEXTX)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_LF)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_LHALF_LN)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_LHALF_LP)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_LHALF_RN)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_LHALF_RP)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_LHH)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_LMIX)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_ONES)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_PACK)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_ROT)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_ROT_MIX)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_SIGNBITS_R)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_SIGNBITS_RH)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_SIGNBITS_RL)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_VMAX)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFT_VMAXVMAX)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_A0ALR)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_AF)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_AF_S)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_AHALF_LN)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_AHALF_LN_S)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_AHALF_LP)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_AHALF_LP_S)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_AHALF_RN)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_AHALF_RN_S)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_AHALF_RP)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_AHALF_RP_S)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_AHH)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_AHH_S)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_AMIX)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_LF)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_LHALF_LN)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_LHALF_LP)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_LHALF_RN)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_LHALF_RP)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_LHH)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_LMIX)]
#[test_case(binutils_tests::TEST_C_DSP32SHIFTIM_ROT)]
#[test_case(binutils_tests::TEST_C_DSPLDST_LD_DR_I)]
#[test_case(binutils_tests::TEST_C_DSPLDST_LD_DR_IPP)]
#[test_case(binutils_tests::TEST_C_DSPLDST_LD_DR_IPPM)]
#[test_case(binutils_tests::TEST_C_DSPLDST_LD_DRHI_I)]
#[test_case(binutils_tests::TEST_C_DSPLDST_LD_DRHI_IPP)]
#[test_case(binutils_tests::TEST_C_DSPLDST_LD_DRLO_I)]
#[test_case(binutils_tests::TEST_C_DSPLDST_LD_DRLO_IPP)]
#[test_case(binutils_tests::TEST_C_DSPLDST_ST_DR_I)]
#[test_case(binutils_tests::TEST_C_DSPLDST_ST_DR_IPP)]
#[test_case(binutils_tests::TEST_C_DSPLDST_ST_DR_IPPM)]
#[test_case(binutils_tests::TEST_C_DSPLDST_ST_DRHI_I)]
#[test_case(binutils_tests::TEST_C_DSPLDST_ST_DRHI_IPP)]
#[test_case(binutils_tests::TEST_C_DSPLDST_ST_DRLO_I)]
#[test_case(binutils_tests::TEST_C_DSPLDST_ST_DRLO_IPP)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_DREG)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_DRHI)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_DRLO)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_H_DR)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_H_IBML)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_H_PR)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_L_DR)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_L_IBML)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_L_PR)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_LZ_DR)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_LZ_IBML)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_LZ_PR)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_LZHI_DR)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_LZHI_IBML)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_LZHI_PR)]
#[test_case(binutils_tests::TEST_C_LDIMMHALF_PIBML)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_B)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_H)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_MM)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_MM_B)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_MM_H)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_MM_XB)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_MM_XH)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_PP)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_PP_B)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_PP_H)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_PP_XB)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_PP_XH)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_PPMM_HBX)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_XB)]
#[test_case(binutils_tests::TEST_C_LDST_LD_D_P_XH)]
#[test_case(binutils_tests::TEST_C_LDST_LD_P_P)]
#[test_case(binutils_tests::TEST_C_LDST_LD_P_P_MM)]
#[test_case(binutils_tests::TEST_C_LDST_LD_P_P_PP)]
#[test_case(binutils_tests::TEST_C_LDST_ST_P_D)]
#[test_case(binutils_tests::TEST_C_LDST_ST_P_D_B)]
#[test_case(binutils_tests::TEST_C_LDST_ST_P_D_H)]
#[test_case(binutils_tests::TEST_C_LDST_ST_P_D_MM)]
#[test_case(binutils_tests::TEST_C_LDST_ST_P_D_MM_B)]
#[test_case(binutils_tests::TEST_C_LDST_ST_P_D_MM_H)]
#[test_case(binutils_tests::TEST_C_LDST_ST_P_D_PP)]
#[test_case(binutils_tests::TEST_C_LDST_ST_P_D_PP_B)]
#[test_case(binutils_tests::TEST_C_LDST_ST_P_D_PP_H)]
#[test_case(binutils_tests::TEST_C_LDST_ST_P_P)]
#[test_case(binutils_tests::TEST_C_LDST_ST_P_P_MM)]
#[test_case(binutils_tests::TEST_C_LDST_ST_P_P_PP)]
#[test_case(binutils_tests::TEST_C_LDSTIDXL_LD_DR_B)]
#[test_case(binutils_tests::TEST_C_LDSTIDXL_LD_DR_H)]
#[test_case(binutils_tests::TEST_C_LDSTIDXL_LD_DR_XB)]
#[test_case(binutils_tests::TEST_C_LDSTIDXL_LD_DR_XH)]
#[test_case(binutils_tests::TEST_C_LDSTIDXL_LD_DREG)]
#[test_case(binutils_tests::TEST_C_LDSTIDXL_LD_PREG)]
#[test_case(binutils_tests::TEST_C_LDSTIDXL_ST_DR_B)]
#[test_case(binutils_tests::TEST_C_LDSTIDXL_ST_DR_H)]
#[test_case(binutils_tests::TEST_C_LDSTIDXL_ST_DREG)]
#[test_case(binutils_tests::TEST_C_LDSTIDXL_ST_PREG)]
#[test_case(binutils_tests::TEST_C_LDSTII_LD_DR_H)]
#[test_case(binutils_tests::TEST_C_LDSTII_LD_DR_XH)]
#[test_case(binutils_tests::TEST_C_LDSTII_LD_DREG)]
#[test_case(binutils_tests::TEST_C_LDSTII_LD_PREG)]
#[test_case(binutils_tests::TEST_C_LDSTII_ST_DR_H)]
#[test_case(binutils_tests::TEST_C_LDSTII_ST_DREG)]
#[test_case(binutils_tests::TEST_C_LDSTII_ST_PREG)]
#[test_case(binutils_tests::TEST_C_LDSTIIFP_LD_DREG)]
#[test_case(binutils_tests::TEST_C_LDSTIIFP_LD_PREG)]
#[test_case(binutils_tests::TEST_C_LDSTIIFP_ST_DREG)]
#[test_case(binutils_tests::TEST_C_LDSTIIFP_ST_PREG)]
#[test_case(binutils_tests::TEST_C_LDSTPMOD_LD_DR_HI)]
#[test_case(binutils_tests::TEST_C_LDSTPMOD_LD_DR_LO)]
#[test_case(binutils_tests::TEST_C_LDSTPMOD_LD_DREG)]
#[test_case(binutils_tests::TEST_C_LDSTPMOD_LD_H_XH)]
#[test_case(binutils_tests::TEST_C_LDSTPMOD_LD_LOHI)]
#[test_case(binutils_tests::TEST_C_LDSTPMOD_ST_DR_HI)]
#[test_case(binutils_tests::TEST_C_LDSTPMOD_ST_DR_LO)]
#[test_case(binutils_tests::TEST_C_LDSTPMOD_ST_DREG)]
#[test_case(binutils_tests::TEST_C_LDSTPMOD_ST_LOHI)]
#[test_case(binutils_tests::TEST_C_LINKAGE)]
#[test_case(binutils_tests::TEST_C_LOGI2OP_ALSHFT_MIX)]
#[test_case(binutils_tests::TEST_C_LOGI2OP_ARITH_SHFT)]
#[test_case(binutils_tests::TEST_C_LOGI2OP_BITCLR)]
#[test_case(binutils_tests::TEST_C_LOGI2OP_BITSET)]
#[test_case(binutils_tests::TEST_C_LOGI2OP_BITTGL)]
#[test_case(binutils_tests::TEST_C_LOGI2OP_BITTST)]
#[test_case(binutils_tests::TEST_C_LOGI2OP_LOG_L_SHFT)]
#[test_case(binutils_tests::TEST_C_LOGI2OP_LOG_R_SHFT)]
#[test_case(binutils_tests::TEST_C_LOGI2OP_NBITTST)]
#[test_case(binutils_tests::TEST_C_LOOPSETUP_NESTED)]
#[test_case(binutils_tests::TEST_C_LOOPSETUP_NESTED_BOT)]
#[test_case(binutils_tests::TEST_C_LOOPSETUP_NESTED_PRELC)]
#[test_case(binutils_tests::TEST_C_LOOPSETUP_NESTED_TOP)]
#[test_case(binutils_tests::TEST_C_LOOPSETUP_OVERLAP)]
#[test_case(binutils_tests::TEST_C_LOOPSETUP_PREG_DIV2_LC0)]
#[test_case(binutils_tests::TEST_C_LOOPSETUP_PREG_DIV2_LC1)]
#[test_case(binutils_tests::TEST_C_LOOPSETUP_PREG_LC0)]
#[test_case(binutils_tests::TEST_C_LOOPSETUP_PREG_LC1)]
#[test_case(binutils_tests::TEST_C_LOOPSETUP_PREG_STLD)]
#[test_case(binutils_tests::TEST_C_LOOPSETUP_PRELC)]
#[test_case(binutils_tests::TEST_C_LOOPSETUP_TOPBOTCNTR)]
#[test_case(binutils_tests::TEST_C_MMR_INTERR_CTL)]
#[test_case(binutils_tests::TEST_C_MULTI_ISSUE_DSP_LD_LD)]
#[test_case(binutils_tests::TEST_C_MULTI_ISSUE_DSP_LDST_1)]
#[test_case(binutils_tests::TEST_C_MULTI_ISSUE_DSP_LDST_2)]
#[test_case(binutils_tests::TEST_C_PROGCTRL_CALL_PCPR)]
#[test_case(binutils_tests::TEST_C_PROGCTRL_CALL_PR)]
#[test_case(binutils_tests::TEST_C_PROGCTRL_JUMP_PCPR)]
#[test_case(binutils_tests::TEST_C_PROGCTRL_JUMP_PR)]
#[test_case(binutils_tests::TEST_C_PROGCTRL_NOP)]
#[test_case(binutils_tests::TEST_C_PROGCTRL_RTS)]
#[test_case(binutils_tests::TEST_C_PTR2OP_PR_NEG_PR)]
#[test_case(binutils_tests::TEST_C_PTR2OP_PR_SFT_2_1)]
#[test_case(binutils_tests::TEST_C_PTR2OP_PR_SHADD_1_2)]
#[test_case(binutils_tests::TEST_C_PUSHPOPMULTIPLE_DP)]
#[test_case(binutils_tests::TEST_C_PUSHPOPMULTIPLE_DP_PAIR)]
#[test_case(binutils_tests::TEST_C_PUSHPOPMULTIPLE_DREG)]
#[test_case(binutils_tests::TEST_C_PUSHPOPMULTIPLE_PREG)]
#[test_case(binutils_tests::TEST_C_REGMV_ACC_ACC)]
#[test_case(binutils_tests::TEST_C_REGMV_DAG_LZ_DEP)]
#[test_case(binutils_tests::TEST_C_REGMV_DR_ACC_ACC)]
#[test_case(binutils_tests::TEST_C_REGMV_DR_DEP_NOSTALL)]
#[test_case(binutils_tests::TEST_C_REGMV_DR_DR)]
#[test_case(binutils_tests::TEST_C_REGMV_DR_IMLB)]
#[test_case(binutils_tests::TEST_C_REGMV_DR_PR)]
#[test_case(binutils_tests::TEST_C_REGMV_IMLB_DEP_NOSTALL)]
#[test_case(binutils_tests::TEST_C_REGMV_IMLB_DEP_STALL)]
#[test_case(binutils_tests::TEST_C_REGMV_IMLB_DR)]
#[test_case(binutils_tests::TEST_C_REGMV_IMLB_IMLB)]
#[test_case(binutils_tests::TEST_C_REGMV_IMLB_PR)]
#[test_case(binutils_tests::TEST_C_REGMV_PR_DEP_NOSTALL)]
#[test_case(binutils_tests::TEST_C_REGMV_PR_DEP_STALL)]
#[test_case(binutils_tests::TEST_C_REGMV_PR_DR)]
#[test_case(binutils_tests::TEST_C_REGMV_PR_IMLB)]
#[test_case(binutils_tests::TEST_C_REGMV_PR_PR)]
#[test_case(binutils_tests::TEST_C_UJUMP)]
#[test_case(binutils_tests::TEST_CC_ASTAT_BITS)]
#[test_case(binutils_tests::TEST_CC0)]
#[test_case(binutils_tests::TEST_CC1)]
#[test_case(binutils_tests::TEST_CEC_NON_OPERATING_ENV)]
#[test_case(binutils_tests::TEST_CIR)]
#[test_case(binutils_tests::TEST_CIR1)]
#[test_case(binutils_tests::TEST_CLI_STI)]
#[test_case(binutils_tests::TEST_CMPACC)]
#[test_case(binutils_tests::TEST_COMPARE)]
#[test_case(binutils_tests::TEST_CONV_ENC_GEN)]
#[test_case(binutils_tests::TEST_CYCLES)]
#[test_case(binutils_tests::TEST_D0)]
#[test_case(binutils_tests::TEST_D1)]
#[test_case(binutils_tests::TEST_D2)]
#[test_case(binutils_tests::TEST_DIV0)]
#[test_case(binutils_tests::TEST_DIVQ)]
#[test_case(binutils_tests::TEST_DOTPRODUCT)]
#[test_case(binutils_tests::TEST_DOTPRODUCT2)]
#[test_case(binutils_tests::TEST_DOUBLE_PREC_MULT)]
#[test_case(binutils_tests::TEST_DSP_A4)]
#[test_case(binutils_tests::TEST_DSP_A7)]
#[test_case(binutils_tests::TEST_DSP_A8)]
#[test_case(binutils_tests::TEST_DSP_D0)]
#[test_case(binutils_tests::TEST_DSP_D1)]
#[test_case(binutils_tests::TEST_DSP_S1)]
#[test_case(binutils_tests::TEST_E0)]
#[test_case(binutils_tests::TEST_EDN_SNAFU)]
#[test_case(binutils_tests::TEST_EU_DSP32MAC_S)]
#[test_case(binutils_tests::TEST_EVENTS)]
#[test_case(binutils_tests::TEST_F221)]
#[test_case(binutils_tests::TEST_FACT)]
#[test_case(binutils_tests::TEST_FIR)]
#[test_case(binutils_tests::TEST_FSM)]
#[test_case(binutils_tests::TEST_GREG2)]
#[test_case(binutils_tests::TEST_HWLOOP_BRANCH_IN)]
#[test_case(binutils_tests::TEST_HWLOOP_BRANCH_OUT)]
#[test_case(binutils_tests::TEST_HWLOOP_LT_BITS)]
#[test_case(binutils_tests::TEST_HWLOOP_NESTED)]
#[test_case(binutils_tests::TEST_I0)]
#[test_case(binutils_tests::TEST_IIR)]
#[test_case(binutils_tests::TEST_ISSUE103)]
#[test_case(binutils_tests::TEST_ISSUE109)]
#[test_case(binutils_tests::TEST_ISSUE112)]
#[test_case(binutils_tests::TEST_ISSUE113)]
#[test_case(binutils_tests::TEST_ISSUE117)]
#[test_case(binutils_tests::TEST_ISSUE118)]
#[test_case(binutils_tests::TEST_ISSUE119)]
#[test_case(binutils_tests::TEST_ISSUE121)]
#[test_case(binutils_tests::TEST_ISSUE123)]
#[test_case(binutils_tests::TEST_ISSUE124)]
#[test_case(binutils_tests::TEST_ISSUE125)]
#[test_case(binutils_tests::TEST_ISSUE126)]
#[test_case(binutils_tests::TEST_ISSUE127)]
#[test_case(binutils_tests::TEST_ISSUE129)]
#[test_case(binutils_tests::TEST_ISSUE142)]
#[test_case(binutils_tests::TEST_ISSUE144)]
#[test_case(binutils_tests::TEST_ISSUE175)]
#[test_case(binutils_tests::TEST_ISSUE205)]
#[test_case(binutils_tests::TEST_ISSUE257)]
#[test_case(binutils_tests::TEST_ISSUE83)]
#[test_case(binutils_tests::TEST_ISSUE89)]
#[test_case(binutils_tests::TEST_L0)]
#[test_case(binutils_tests::TEST_L0SHIFT)]
#[test_case(binutils_tests::TEST_L2_LOOP)]
#[test_case(binutils_tests::TEST_LINK_2)]
#[test_case(binutils_tests::TEST_LINK)]
#[test_case(binutils_tests::TEST_LOAD)]
#[test_case(binutils_tests::TEST_LOGIC)]
#[test_case(binutils_tests::TEST_LOOP_SNAFU)]
#[test_case(binutils_tests::TEST_LOOP_STRNCPY)]
#[test_case(binutils_tests::TEST_LP0)]
#[test_case(binutils_tests::TEST_LP1)]
#[test_case(binutils_tests::TEST_LSETUP)]
#[test_case(binutils_tests::TEST_M0BOUNDARY)]
#[test_case(binutils_tests::TEST_M10)]
#[test_case(binutils_tests::TEST_M11)]
#[test_case(binutils_tests::TEST_M12)]
#[test_case(binutils_tests::TEST_M13)]
#[test_case(binutils_tests::TEST_M14)]
#[test_case(binutils_tests::TEST_M15)]
#[test_case(binutils_tests::TEST_M16)]
#[test_case(binutils_tests::TEST_M17)]
#[test_case(binutils_tests::TEST_M2)]
#[test_case(binutils_tests::TEST_M3)]
#[test_case(binutils_tests::TEST_M4)]
#[test_case(binutils_tests::TEST_M5)]
#[test_case(binutils_tests::TEST_M6)]
#[test_case(binutils_tests::TEST_M7)]
#[test_case(binutils_tests::TEST_M8)]
#[test_case(binutils_tests::TEST_M9)]
#[test_case(binutils_tests::TEST_MATH)]
#[test_case(binutils_tests::TEST_MAX_MIN_FLAGS)]
#[test_case(binutils_tests::TEST_MC_S2)]
#[test_case(binutils_tests::TEST_MEM3)]
#[test_case(binutils_tests::TEST_MMR_EXCEPTION)]
#[test_case(binutils_tests::TEST_MOVE)]
#[test_case(binutils_tests::TEST_MSA_ACP_5_10)]
#[test_case(binutils_tests::TEST_MULT)]
#[test_case(binutils_tests::TEST_NSHIFT)]
#[test_case(binutils_tests::TEST_PR)]
#[test_case(binutils_tests::TEST_PUSH_POP_MULTIPLE)]
#[test_case(binutils_tests::TEST_PUSH_POP)]
#[test_case(binutils_tests::TEST_PUSHPOPREG_1)]
#[test_case(binutils_tests::TEST_QUADADDSUB)]
#[test_case(binutils_tests::TEST_RANDOM_0001)]
#[test_case(binutils_tests::TEST_S0)]
#[test_case(binutils_tests::TEST_S1)]
#[test_case(binutils_tests::TEST_S10)]
#[test_case(binutils_tests::TEST_S11)]
#[test_case(binutils_tests::TEST_S12)]
#[test_case(binutils_tests::TEST_S13)]
#[test_case(binutils_tests::TEST_S14)]
#[test_case(binutils_tests::TEST_S15)]
#[test_case(binutils_tests::TEST_S16)]
#[test_case(binutils_tests::TEST_S17)]
#[test_case(binutils_tests::TEST_S18)]
#[test_case(binutils_tests::TEST_S19)]
#[test_case(binutils_tests::TEST_S2)]
#[test_case(binutils_tests::TEST_S20)]
#[test_case(binutils_tests::TEST_S21)]
#[test_case(binutils_tests::TEST_S3)]
#[test_case(binutils_tests::TEST_S30)]
#[test_case(binutils_tests::TEST_S4)]
#[test_case(binutils_tests::TEST_S5)]
#[test_case(binutils_tests::TEST_S6)]
#[test_case(binutils_tests::TEST_S7)]
#[test_case(binutils_tests::TEST_S8)]
#[test_case(binutils_tests::TEST_S9)]
#[test_case(binutils_tests::TEST_SAATEST)]
#[test_case(binutils_tests::TEST_SE_RETS_HAZARD)]
#[test_case(binutils_tests::TEST_SEQSTAT)]
#[test_case(binutils_tests::TEST_SIGN)]
#[test_case(binutils_tests::TEST_SIMPLE0)]
#[test_case(binutils_tests::TEST_SRI)]
#[test_case(binutils_tests::TEST_STK)]
#[test_case(binutils_tests::TEST_STK2)]
#[test_case(binutils_tests::TEST_STK3)]
#[test_case(binutils_tests::TEST_STK4)]
#[test_case(binutils_tests::TEST_STK5)]
#[test_case(binutils_tests::TEST_STK6)]
#[test_case(binutils_tests::TEST_SYSCFG)]
#[test_case(binutils_tests::TEST_TAR10622)]
#[test_case(binutils_tests::TEST_TESTSET)]
#[test_case(binutils_tests::TEST_TESTSET2)]
#[test_case(binutils_tests::TEST_UP0)]
#[test_case(binutils_tests::TEST_VECADD)]
#[test_case(binutils_tests::TEST_VIT_MAX)]
#[test_case(binutils_tests::TEST_VIT_MAX2)]
#[test_case(binutils_tests::TEST_VITERBI2)]
#[test_case(binutils_tests::TEST_WTF)]
// Something weird here... This should add then artithmetic right shift but the test looks like it's
// not an arithmetic shift.
//
// imm32 r0, 0x40004000;
// imm32 r1, 0x40004000;
// R2 = R0 +|+ R1, R3 = R0 -|- R1 (S , ASR);
// checkreg r2, 0x40004000;
// checkreg r3, 0;
#[test_case(binutils_tests::TEST_X1)]
#[test_case(binutils_tests::TEST_ZCALL)]
#[test_case(binutils_tests::TEST_ZEROFLAGRND)]
fn test_binutils_unittests(test: TestData) {
    styx_util::logging::init_logging();

    let mut backend = PcodeBackend::new_engine(
        Arch::Blackfin,
        BlackfinVariants::Bf512,
        ArchEndian::LittleEndian,
    );
    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();

    // Load elf into memory and initial registers
    load_elf(&mut backend, &mut mmu, test.bytes());

    // Initialize a stack.
    let stack_base = 0x20000;
    let stack_size = 0x2000;
    initialize_stack(&mut backend, &mut mmu, stack_base, stack_size);

    let dbg_hook = |mut backend: CoreHandle| -> Result<Resolution, UnknownError> {
        let pc = backend.pc().unwrap();
        debug!("Invalid instruction hook triggered at at 0x{pc:X}");

        let mut debug_caught = false;
        while catch_debug_asserts(&mut backend) {
            warn!("Debug instruction caught");
            debug_caught = true;
        }

        if !debug_caught {
            warn!("Actual invalid instruction");
            Ok(Resolution::NotFixed)
        } else {
            Ok(Resolution::Fixed)
        }
    };
    backend
        .add_hook(StyxHook::invalid_instruction(dbg_hook))
        .unwrap();

    // Stop on interrupt
    let interrupt_stop_hook = |mut backend: CoreHandle, _irqn| {
        backend.stop();
        Ok(())
    };
    backend
        .add_hook(StyxHook::interrupt(interrupt_stop_hook))
        .unwrap();

    // increased instruction count because some tests are longer than 0x1000 instructions
    let exit_reason = backend.execute(&mut mmu, &mut ev, 0x10000).unwrap();
    assert_eq!(
        exit_reason,
        TargetExitReason::HostStopRequest,
        "Machine did not stop properly."
    );

    assert_eq!(
        backend.read_register::<u32>(BlackfinRegister::R0).unwrap(),
        13,
        "Test failed! Did not call pass."
    )
}

fn load_description(
    backend: &mut PcodeBackend,
    mmu: &mut Mmu,
    mut program_load_description: MemoryLoaderDesc,
) {
    for (reg, value) in program_load_description.take_registers().into_iter() {
        println!("setting {reg:?} to 0x{value:X}");
        backend.write_register(reg, value as u32).unwrap();
    }

    for mut region in program_load_description.take_memory_regions().into_iter() {
        unsafe {
            // add more bytes to region so there are no accidental unmapped memory operations
            region.align_size(0x1000, 0).unwrap();
        }
        mmu.add_memory_region(
            MemoryRegion::new(region.base(), region.size(), MemoryPermissions::all()).unwrap(),
        )
        .unwrap();
        // copy over data
        mmu.data()
            .write(region.base())
            .bytes(&region.read_data(region.base(), region.size()).unwrap())
            .unwrap();
    }
}
/// Loads prgram memory regions and intial registers (e.g. entry address)
fn load_elf(backend: &mut PcodeBackend, mmu: &mut Mmu, program: &[u8]) {
    let program_load_description = styx_loader::ElfLoader::default()
        .load_bytes(program.to_owned().into(), Default::default())
        .unwrap();

    load_description(backend, mmu, program_load_description)
}

/// Creates a stack at stack_base with a couple extra bytes of headroom.
fn initialize_stack(backend: &mut PcodeBackend, mmu: &mut Mmu, stack_base: u64, stack_size: u64) {
    mmu.memory_map(
        stack_base - stack_size,
        stack_size + 0x10, // A little extra for backend's extra reads
        MemoryPermissions::all(),
    )
    .unwrap();
    backend
        .write_register(BlackfinRegister::Sp, stack_base as u32)
        .unwrap();
}

/// Is this instruction a debug assert
fn is_instruction_debug_assert(instruction: &[u8; 2]) -> bool {
    instruction[1] & 0xF8 == 0xF0
}

fn catch_debug_asserts(backend: &mut CoreHandle) -> bool {
    let pc = backend.pc().unwrap();

    let mut buf = [0u8; 2];
    backend.mmu.code().read(pc).bytes(&mut buf).unwrap();

    if is_instruction_debug_assert(&buf) {
        assert_debug_instruction(backend);
        backend.set_pc(pc + 4).unwrap();
        true
    } else {
        false
    }
}

///  psedodbg_assert
/// +---+---+---+---|---+---+---+---|---+---+---+---|---+---+---+---+
/// | 1 | 1 | 1 | 1 | 0 | - | - | - | dbgop |.grp.......|.regtest...|
/// |.expected......................................................|
/// +---+---+---+---|---+---+---+---|---+---+---+---|---+---+---+---+
///
/// Top 16-bits of Debug Assert instruction.
#[bitfield_struct::bitfield(u16)]
struct PsedodbgAssert {
    #[bits(3)]
    regtest: u8,
    #[bits(3)]
    grp: u8,
    #[bits(2)]
    dbgop: u8,

    /// Padding
    __: u8,
}
fn assert_debug_instruction(backend: &mut CoreHandle) {
    let pc = backend.pc().unwrap();

    let mut iw0 = [0u8; 2];
    backend.mmu.code().read(pc).bytes(&mut iw0).unwrap();
    assert!(
        is_instruction_debug_assert(&iw0),
        "must be called when current instruction is debug assert"
    );

    //  psedodbg_assert
    // +---+---+---+---|---+---+---+---|---+---+---+---|---+---+---+---+
    // | 1 | 1 | 1 | 1 | 0 | - | - | - | dbgop |.grp.......|.regtest...|
    // |.expected......................................................|
    // +---+---+---+---|---+---+---+---|---+---+---+---|---+---+---+---+
    //
    let mut iw1 = [0u8; 2];
    backend.mmu.code().read(pc + 2).bytes(&mut iw1).unwrap();
    let expected = u16::from_le_bytes(iw1);

    let iw0_int = u16::from_le_bytes(iw0);
    let pda = PsedodbgAssert::from_bits(iw0_int);

    let group_reg = GroupReg::new(pda.grp(), pda.regtest());
    let test_register: BlackfinRegister = group_reg.into();
    println!("test register is {test_register}");

    let register_value = backend.cpu.read_register::<u32>(test_register).unwrap();
    let dbg_op = DbgOp::from(pda.dbgop());

    // take high/low 16-bits based on dbgop
    let actual = if dbg_op.is_upper() {
        register_value >> 16
    } else {
        register_value & 0xFFFF
    } as u16;

    assert_eq!(
        actual, expected,
        "actual {actual:#X} != expected {expected:#X} for register {test_register}"
    );
}

#[derive(Debug)]
struct GroupReg {
    grp: u8,
    reg: u8,
}

impl GroupReg {
    fn new(grp: u8, reg: u8) -> Self {
        Self { grp, reg }
    }
}

impl From<GroupReg> for BlackfinRegister {
    fn from(value: GroupReg) -> Self {
        // found in `bfin-sim.c:340`
        match (value.grp, value.reg) {
            (0, 0) => BlackfinRegister::R0,
            (0, 1) => BlackfinRegister::R1,
            (0, 2) => BlackfinRegister::R2,
            (0, 3) => BlackfinRegister::R3,
            (0, 4) => BlackfinRegister::R4,
            (0, 5) => BlackfinRegister::R5,
            (0, 6) => BlackfinRegister::R6,
            (0, 7) => BlackfinRegister::R7,

            (1, 0) => BlackfinRegister::P0,
            (1, 1) => BlackfinRegister::P1,
            (1, 2) => BlackfinRegister::P2,
            (1, 3) => BlackfinRegister::P3,
            (1, 4) => BlackfinRegister::P4,
            (1, 5) => BlackfinRegister::P5,
            (1, 6) => BlackfinRegister::Sp,
            (1, 7) => BlackfinRegister::Fp,

            (2, 0) => BlackfinRegister::I0,
            (2, 1) => BlackfinRegister::I1,
            (2, 2) => BlackfinRegister::I2,
            (2, 3) => BlackfinRegister::I3,
            (2, 4) => BlackfinRegister::M0,
            (2, 5) => BlackfinRegister::M1,
            (2, 6) => BlackfinRegister::M2,
            (2, 7) => BlackfinRegister::M3,

            (3, 0) => BlackfinRegister::B0,
            (3, 1) => BlackfinRegister::B1,
            (3, 2) => BlackfinRegister::B2,
            (3, 3) => BlackfinRegister::B3,
            (3, 4) => BlackfinRegister::L0,
            (3, 5) => BlackfinRegister::L1,
            (3, 6) => BlackfinRegister::L2,
            (3, 7) => BlackfinRegister::L3,

            (4, 0) => BlackfinRegister::A0x,
            (4, 1) => BlackfinRegister::A0w,
            (4, 2) => BlackfinRegister::A1x,
            (4, 3) => BlackfinRegister::A1w,
            (4, 6) => BlackfinRegister::ASTAT,
            (4, 7) => BlackfinRegister::RETS,

            (5, 0) => BlackfinRegister::LC0,
            (5, 1) => BlackfinRegister::LT0,
            (5, 2) => BlackfinRegister::LB0,
            (5, 3) => BlackfinRegister::LC1,
            (5, 4) => BlackfinRegister::LT1,
            (5, 5) => BlackfinRegister::LB1,
            // what are these?
            // (5, 6) => BlackfinRegister::CYCLES,
            // (5, 7) => BlackfinRegister::CYCLES2,
            // (6, 0) => BlackfinRegister::USP,
            // (6, 1) => BlackfinRegister::SEQSTAT,
            // (6, 2) => BlackfinRegister::SYSCFG,
            (6, 3) => BlackfinRegister::RETI,
            (6, 4) => BlackfinRegister::RETX,
            (6, 5) => BlackfinRegister::RETN,
            (6, 6) => BlackfinRegister::RETE,
            // (6, 7) => BlackfinRegister::EMUDAT,
            _ => panic!("Group not found : {value:?}"),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum DbgOp {
    DbgaDotL = 0,
    DbgaDotH = 1,
    DbgaL = 2,
    DbgaH = 3,
}

impl DbgOp {
    fn is_upper(self) -> bool {
        matches!(self, DbgOp::DbgaDotH | DbgOp::DbgaH)
    }
}

impl From<u8> for DbgOp {
    fn from(value: u8) -> Self {
        match value {
            0 => DbgOp::DbgaDotL,
            1 => DbgOp::DbgaDotH,
            2 => DbgOp::DbgaL,
            3 => DbgOp::DbgaH,
            _ => panic!("bad DbgOp type {value}"),
        }
    }
}
