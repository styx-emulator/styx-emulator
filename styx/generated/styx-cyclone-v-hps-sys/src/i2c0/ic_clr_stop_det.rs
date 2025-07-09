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
#[doc = "Register `ic_clr_stop_det` reader"]
pub type R = crate::R<IcClrStopDetSpec>;
#[doc = "Register `ic_clr_stop_det` writer"]
pub type W = crate::W<IcClrStopDetSpec>;
#[doc = "Field `clr_stop_det` reader - Read this register to clear the clr_stop_det interrupt (bit 9) of the ic_raw_intr_stat register."]
pub type ClrStopDetR = crate::BitReader;
#[doc = "Field `clr_stop_det` writer - Read this register to clear the clr_stop_det interrupt (bit 9) of the ic_raw_intr_stat register."]
pub type ClrStopDetW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Read this register to clear the clr_stop_det interrupt (bit 9) of the ic_raw_intr_stat register."]
    #[inline(always)]
    pub fn clr_stop_det(&self) -> ClrStopDetR {
        ClrStopDetR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Read this register to clear the clr_stop_det interrupt (bit 9) of the ic_raw_intr_stat register."]
    #[inline(always)]
    #[must_use]
    pub fn clr_stop_det(&mut self) -> ClrStopDetW<IcClrStopDetSpec> {
        ClrStopDetW::new(self, 0)
    }
}
#[doc = "Clear Interrupts.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_stop_det::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcClrStopDetSpec;
impl crate::RegisterSpec for IcClrStopDetSpec {
    type Ux = u32;
    const OFFSET: u64 = 96u64;
}
#[doc = "`read()` method returns [`ic_clr_stop_det::R`](R) reader structure"]
impl crate::Readable for IcClrStopDetSpec {}
#[doc = "`reset()` method sets ic_clr_stop_det to value 0"]
impl crate::Resettable for IcClrStopDetSpec {
    const RESET_VALUE: u32 = 0;
}
