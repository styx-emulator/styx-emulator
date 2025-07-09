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
//! Emulates the Clock Manager for the Cyclone V HPS.
use std::mem::size_of;
use styx_core::prelude::*;
use styx_cyclone_v_hps_sys::{clkmgr, generic::FromBytes, Clkmgr};

const CLKMGR_REG_BLOCK_SIZE: usize = size_of::<clkmgr::RegisterBlock>();

/// Hardware Abstraction Layer for the Clock Manager.
pub(crate) struct ClockManagerHal {
    base: u64,
    pub registers: clkmgr::RegisterBlock,
}

impl ClockManagerHal {
    fn new() -> Self {
        let init_bytes: [u8; CLKMGR_REG_BLOCK_SIZE] = [0u8; CLKMGR_REG_BLOCK_SIZE];
        let registers = unsafe { clkmgr::RegisterBlock::from_bytes(&init_bytes).unwrap() };
        Self {
            base: Clkmgr::BASE as u64,
            registers,
        }
    }

    fn reset(&mut self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        unsafe {
            self.registers.ctrl().sys_reset();
            self.registers.bypass().sys_reset();
            self.registers.inter().sys_reset();
            self.registers.intren().sys_reset();
            self.registers.dbctrl().sys_reset();
            self.registers.stat().sys_reset();
            self.registers.mainpllgrp_vco().sys_reset();
            self.registers.mainpllgrp_misc().sys_reset();
            self.registers.mainpllgrp_mpuclk().sys_reset();
            self.registers.mainpllgrp_mainclk().sys_reset();
            self.registers.mainpllgrp_dbgatclk().sys_reset();
            self.registers.mainpllgrp_mainqspiclk().sys_reset();
            self.registers.mainpllgrp_mainnandsdmmcclk().sys_reset();
            self.registers.mainpllgrp_cfgs2fuser0clk().sys_reset();
            self.registers.mainpllgrp_en().sys_reset();
            self.registers.mainpllgrp_maindiv().sys_reset();
            self.registers.mainpllgrp_dbgdiv().sys_reset();
            self.registers.mainpllgrp_tracediv().sys_reset();
            self.registers.mainpllgrp_l4src().sys_reset();
            self.registers.mainpllgrp_stat().sys_reset();
            self.registers.perpllgrp_vco().sys_reset();
            self.registers.perpllgrp_misc().sys_reset();
            self.registers.perpllgrp_emac0clk().sys_reset();
            self.registers.perpllgrp_emac1clk().sys_reset();
            self.registers.perpllgrp_perqspiclk().sys_reset();
            self.registers.perpllgrp_pernandsdmmcclk().sys_reset();
            self.registers.perpllgrp_perbaseclk().sys_reset();
            self.registers.perpllgrp_s2fuser1clk().sys_reset();
            self.registers.perpllgrp_en().sys_reset();
            self.registers.perpllgrp_div().sys_reset();
            self.registers.perpllgrp_gpiodiv().sys_reset();
            self.registers.perpllgrp_src().sys_reset();
            self.registers.perpllgrp_stat().sys_reset();
            self.registers.sdrpllgrp_vco().sys_reset();
            self.registers.sdrpllgrp_ctrl().sys_reset();
            self.registers.sdrpllgrp_ddrdqsclk().sys_reset();
            self.registers.sdrpllgrp_ddr2xdqsclk().sys_reset();
            self.registers.sdrpllgrp_ddrdqclk().sys_reset();
            self.registers.sdrpllgrp_s2fuser2clk().sys_reset();
            self.registers.sdrpllgrp_en().sys_reset();
            self.registers.sdrpllgrp_stat().sys_reset();
        }

        // Write the reset values back to memory.
        mmu.write_data(self.base, self.registers.as_bytes_ref())
            .unwrap();

        Ok(())
    }
}

pub struct ClockManager {
    _base_address: u64,
    inner_hal: ClockManagerHal,
}

impl ClockManager {
    pub fn new() -> Self {
        let hal = ClockManagerHal::new();
        Self {
            _base_address: hal.base,
            inner_hal: hal,
        }
    }
}

impl Peripheral for ClockManager {
    fn reset(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        mmu: &mut styx_core::prelude::Mmu,
    ) -> Result<(), UnknownError> {
        self.inner_hal.reset(mmu)?;
        Ok(())
    }

    fn post_event_hook(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut styx_core::prelude::Mmu,
        _event_controller: &mut dyn styx_core::prelude::EventControllerImpl,
        _irqn: styx_core::prelude::ExceptionNumber,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn init(
        &mut self,
        _proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "Clock Manager"
    }
}
