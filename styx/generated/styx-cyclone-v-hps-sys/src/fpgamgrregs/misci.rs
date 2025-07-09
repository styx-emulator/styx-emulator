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
#[doc = "Register `misci` reader"]
pub type R = crate::R<MisciSpec>;
#[doc = "Register `misci` writer"]
pub type W = crate::W<MisciSpec>;
#[doc = "Field `bootFPGAfail` reader - The value of the f2h_boot_from_fpga_on_failure signal from the FPGA fabric. If the FPGA is not in User Mode, the value of this field is undefined. 1 = Boot ROM will boot from FPGA if boot from normal boot device fails. 0 = Boot ROM will not boot from FPGA if boot from normal boot device fails."]
pub type BootFpgafailR = crate::BitReader;
#[doc = "Field `bootFPGAfail` writer - The value of the f2h_boot_from_fpga_on_failure signal from the FPGA fabric. If the FPGA is not in User Mode, the value of this field is undefined. 1 = Boot ROM will boot from FPGA if boot from normal boot device fails. 0 = Boot ROM will not boot from FPGA if boot from normal boot device fails."]
pub type BootFpgafailW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `bootFPGArdy` reader - The value of the f2h_boot_from_fpga_ready signal from the FPGA fabric. If the FPGA is not in User Mode, the value of this field is undefined. 1 = FPGA fabric is ready to accept AXI master requests from the HPS2FPGA bridge. 0 = FPGA fabric is not ready (probably still processing a reset)."]
pub type BootFpgardyR = crate::BitReader;
#[doc = "Field `bootFPGArdy` writer - The value of the f2h_boot_from_fpga_ready signal from the FPGA fabric. If the FPGA is not in User Mode, the value of this field is undefined. 1 = FPGA fabric is ready to accept AXI master requests from the HPS2FPGA bridge. 0 = FPGA fabric is not ready (probably still processing a reset)."]
pub type BootFpgardyW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - The value of the f2h_boot_from_fpga_on_failure signal from the FPGA fabric. If the FPGA is not in User Mode, the value of this field is undefined. 1 = Boot ROM will boot from FPGA if boot from normal boot device fails. 0 = Boot ROM will not boot from FPGA if boot from normal boot device fails."]
    #[inline(always)]
    pub fn boot_fpgafail(&self) -> BootFpgafailR {
        BootFpgafailR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - The value of the f2h_boot_from_fpga_ready signal from the FPGA fabric. If the FPGA is not in User Mode, the value of this field is undefined. 1 = FPGA fabric is ready to accept AXI master requests from the HPS2FPGA bridge. 0 = FPGA fabric is not ready (probably still processing a reset)."]
    #[inline(always)]
    pub fn boot_fpgardy(&self) -> BootFpgardyR {
        BootFpgardyR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - The value of the f2h_boot_from_fpga_on_failure signal from the FPGA fabric. If the FPGA is not in User Mode, the value of this field is undefined. 1 = Boot ROM will boot from FPGA if boot from normal boot device fails. 0 = Boot ROM will not boot from FPGA if boot from normal boot device fails."]
    #[inline(always)]
    #[must_use]
    pub fn boot_fpgafail(&mut self) -> BootFpgafailW<MisciSpec> {
        BootFpgafailW::new(self, 0)
    }
    #[doc = "Bit 1 - The value of the f2h_boot_from_fpga_ready signal from the FPGA fabric. If the FPGA is not in User Mode, the value of this field is undefined. 1 = FPGA fabric is ready to accept AXI master requests from the HPS2FPGA bridge. 0 = FPGA fabric is not ready (probably still processing a reset)."]
    #[inline(always)]
    #[must_use]
    pub fn boot_fpgardy(&mut self) -> BootFpgardyW<MisciSpec> {
        BootFpgardyW::new(self, 1)
    }
}
#[doc = "Provides a low-latency, low-performance, and simple way to read specific handshaking signals driven from the FPGA fabric.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`misci::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MisciSpec;
impl crate::RegisterSpec for MisciSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`misci::R`](R) reader structure"]
impl crate::Readable for MisciSpec {}
#[doc = "`reset()` method sets misci to value 0"]
impl crate::Resettable for MisciSpec {
    const RESET_VALUE: u32 = 0;
}
