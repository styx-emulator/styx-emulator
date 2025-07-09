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
#[doc = "Register `ctrlgrp_dramodt` reader"]
pub type R = crate::R<CtrlgrpDramodtSpec>;
#[doc = "Register `ctrlgrp_dramodt` writer"]
pub type W = crate::W<CtrlgrpDramodtSpec>;
#[doc = "Field `cfg_write_odt_chip` reader - This register controls which ODT pin is asserted during writes."]
pub type CfgWriteOdtChipR = crate::FieldReader;
#[doc = "Field `cfg_write_odt_chip` writer - This register controls which ODT pin is asserted during writes."]
pub type CfgWriteOdtChipW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `cfg_read_odt_chip` reader - This register controls which ODT pin is asserted during reads."]
pub type CfgReadOdtChipR = crate::FieldReader;
#[doc = "Field `cfg_read_odt_chip` writer - This register controls which ODT pin is asserted during reads."]
pub type CfgReadOdtChipW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - This register controls which ODT pin is asserted during writes."]
    #[inline(always)]
    pub fn cfg_write_odt_chip(&self) -> CfgWriteOdtChipR {
        CfgWriteOdtChipR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:7 - This register controls which ODT pin is asserted during reads."]
    #[inline(always)]
    pub fn cfg_read_odt_chip(&self) -> CfgReadOdtChipR {
        CfgReadOdtChipR::new(((self.bits >> 4) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - This register controls which ODT pin is asserted during writes."]
    #[inline(always)]
    #[must_use]
    pub fn cfg_write_odt_chip(&mut self) -> CfgWriteOdtChipW<CtrlgrpDramodtSpec> {
        CfgWriteOdtChipW::new(self, 0)
    }
    #[doc = "Bits 4:7 - This register controls which ODT pin is asserted during reads."]
    #[inline(always)]
    #[must_use]
    pub fn cfg_read_odt_chip(&mut self) -> CfgReadOdtChipW<CtrlgrpDramodtSpec> {
        CfgReadOdtChipW::new(self, 4)
    }
}
#[doc = "This register controls which ODT pin is asserted during reads or writes. Bits \\[1:0\\]
control which ODT pin is asserted during to accesses to chip select 0, bits \\[3:2\\]
which ODT pin is asserted during accesses to chip select 1. For example, a value of &amp;quot;1001&amp;quot; will cause ODT\\[0\\]
to be asserted for accesses to CS\\[0\\], and ODT\\[1\\]
to be asserted for access to CS\\[1\\]
pin. Set this to &amp;quot;0001&amp;quot; if there is only one chip select available.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramodt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramodt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpDramodtSpec;
impl crate::RegisterSpec for CtrlgrpDramodtSpec {
    type Ux = u32;
    const OFFSET: u64 = 20504u64;
}
#[doc = "`read()` method returns [`ctrlgrp_dramodt::R`](R) reader structure"]
impl crate::Readable for CtrlgrpDramodtSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_dramodt::W`](W) writer structure"]
impl crate::Writable for CtrlgrpDramodtSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_dramodt to value 0"]
impl crate::Resettable for CtrlgrpDramodtSpec {
    const RESET_VALUE: u32 = 0;
}
