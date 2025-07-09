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
#[doc = "Register `pinmuxgrp_RGMII1USEFPGA` reader"]
pub type R = crate::R<PinmuxgrpRgmii1usefpgaSpec>;
#[doc = "Register `pinmuxgrp_RGMII1USEFPGA` writer"]
pub type W = crate::W<PinmuxgrpRgmii1usefpgaSpec>;
#[doc = "Field `sel` reader - Select connection for RGMII1. 0 : RGMII1 uses HPS Pins. 1 : RGMII1 uses the FPGA Inteface."]
pub type SelR = crate::BitReader;
#[doc = "Field `sel` writer - Select connection for RGMII1. 0 : RGMII1 uses HPS Pins. 1 : RGMII1 uses the FPGA Inteface."]
pub type SelW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Select connection for RGMII1. 0 : RGMII1 uses HPS Pins. 1 : RGMII1 uses the FPGA Inteface."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Select connection for RGMII1. 0 : RGMII1 uses HPS Pins. 1 : RGMII1 uses the FPGA Inteface."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpRgmii1usefpgaSpec> {
        SelW::new(self, 0)
    }
}
#[doc = "Selection between HPS Pins and FPGA Interface for RGMII1 signals. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_rgmii1usefpga::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_rgmii1usefpga::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpRgmii1usefpgaSpec;
impl crate::RegisterSpec for PinmuxgrpRgmii1usefpgaSpec {
    type Ux = u32;
    const OFFSET: u64 = 1784u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_rgmii1usefpga::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpRgmii1usefpgaSpec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_rgmii1usefpga::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpRgmii1usefpgaSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_RGMII1USEFPGA to value 0"]
impl crate::Resettable for PinmuxgrpRgmii1usefpgaSpec {
    const RESET_VALUE: u32 = 0;
}
