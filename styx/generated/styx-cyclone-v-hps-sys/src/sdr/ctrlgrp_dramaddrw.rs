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
#[doc = "Register `ctrlgrp_dramaddrw` reader"]
pub type R = crate::R<CtrlgrpDramaddrwSpec>;
#[doc = "Register `ctrlgrp_dramaddrw` writer"]
pub type W = crate::W<CtrlgrpDramaddrwSpec>;
#[doc = "Field `colbits` reader - The number of column address bits for the memory devices in your memory interface."]
pub type ColbitsR = crate::FieldReader;
#[doc = "Field `colbits` writer - The number of column address bits for the memory devices in your memory interface."]
pub type ColbitsW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `rowbits` reader - The number of row address bits for the memory devices in your memory interface."]
pub type RowbitsR = crate::FieldReader;
#[doc = "Field `rowbits` writer - The number of row address bits for the memory devices in your memory interface."]
pub type RowbitsW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `bankbits` reader - The number of bank address bits for the memory devices in your memory interface."]
pub type BankbitsR = crate::FieldReader;
#[doc = "Field `bankbits` writer - The number of bank address bits for the memory devices in your memory interface."]
pub type BankbitsW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `csbits` reader - The number of chip select address bits for the memory devices in your memory interface."]
pub type CsbitsR = crate::FieldReader;
#[doc = "Field `csbits` writer - The number of chip select address bits for the memory devices in your memory interface."]
pub type CsbitsW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 0:4 - The number of column address bits for the memory devices in your memory interface."]
    #[inline(always)]
    pub fn colbits(&self) -> ColbitsR {
        ColbitsR::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bits 5:9 - The number of row address bits for the memory devices in your memory interface."]
    #[inline(always)]
    pub fn rowbits(&self) -> RowbitsR {
        RowbitsR::new(((self.bits >> 5) & 0x1f) as u8)
    }
    #[doc = "Bits 10:12 - The number of bank address bits for the memory devices in your memory interface."]
    #[inline(always)]
    pub fn bankbits(&self) -> BankbitsR {
        BankbitsR::new(((self.bits >> 10) & 7) as u8)
    }
    #[doc = "Bits 13:15 - The number of chip select address bits for the memory devices in your memory interface."]
    #[inline(always)]
    pub fn csbits(&self) -> CsbitsR {
        CsbitsR::new(((self.bits >> 13) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:4 - The number of column address bits for the memory devices in your memory interface."]
    #[inline(always)]
    #[must_use]
    pub fn colbits(&mut self) -> ColbitsW<CtrlgrpDramaddrwSpec> {
        ColbitsW::new(self, 0)
    }
    #[doc = "Bits 5:9 - The number of row address bits for the memory devices in your memory interface."]
    #[inline(always)]
    #[must_use]
    pub fn rowbits(&mut self) -> RowbitsW<CtrlgrpDramaddrwSpec> {
        RowbitsW::new(self, 5)
    }
    #[doc = "Bits 10:12 - The number of bank address bits for the memory devices in your memory interface."]
    #[inline(always)]
    #[must_use]
    pub fn bankbits(&mut self) -> BankbitsW<CtrlgrpDramaddrwSpec> {
        BankbitsW::new(self, 10)
    }
    #[doc = "Bits 13:15 - The number of chip select address bits for the memory devices in your memory interface."]
    #[inline(always)]
    #[must_use]
    pub fn csbits(&mut self) -> CsbitsW<CtrlgrpDramaddrwSpec> {
        CsbitsW::new(self, 13)
    }
}
#[doc = "This register configures the width of the various address fields of the DRAM. The values specified in this register must match the memory devices being used.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramaddrw::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramaddrw::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpDramaddrwSpec;
impl crate::RegisterSpec for CtrlgrpDramaddrwSpec {
    type Ux = u32;
    const OFFSET: u64 = 20524u64;
}
#[doc = "`read()` method returns [`ctrlgrp_dramaddrw::R`](R) reader structure"]
impl crate::Readable for CtrlgrpDramaddrwSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_dramaddrw::W`](W) writer structure"]
impl crate::Writable for CtrlgrpDramaddrwSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_dramaddrw to value 0"]
impl crate::Resettable for CtrlgrpDramaddrwSpec {
    const RESET_VALUE: u32 = 0;
}
