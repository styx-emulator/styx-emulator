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
#[doc = "Register `ic_clr_gen_call` reader"]
pub type R = crate::R<IcClrGenCallSpec>;
#[doc = "Register `ic_clr_gen_call` writer"]
pub type W = crate::W<IcClrGenCallSpec>;
#[doc = "Field `clr_gen_call` reader - Read this register to clear the GEN_CALL interrupt (bit 11) of ic_raw_intr_stat register."]
pub type ClrGenCallR = crate::BitReader;
#[doc = "Field `clr_gen_call` writer - Read this register to clear the GEN_CALL interrupt (bit 11) of ic_raw_intr_stat register."]
pub type ClrGenCallW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Read this register to clear the GEN_CALL interrupt (bit 11) of ic_raw_intr_stat register."]
    #[inline(always)]
    pub fn clr_gen_call(&self) -> ClrGenCallR {
        ClrGenCallR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Read this register to clear the GEN_CALL interrupt (bit 11) of ic_raw_intr_stat register."]
    #[inline(always)]
    #[must_use]
    pub fn clr_gen_call(&mut self) -> ClrGenCallW<IcClrGenCallSpec> {
        ClrGenCallW::new(self, 0)
    }
}
#[doc = "Clear GEN_CALL Interrupt Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_gen_call::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcClrGenCallSpec;
impl crate::RegisterSpec for IcClrGenCallSpec {
    type Ux = u32;
    const OFFSET: u64 = 104u64;
}
#[doc = "`read()` method returns [`ic_clr_gen_call::R`](R) reader structure"]
impl crate::Readable for IcClrGenCallSpec {}
#[doc = "`reset()` method sets ic_clr_gen_call to value 0"]
impl crate::Resettable for IcClrGenCallSpec {
    const RESET_VALUE: u32 = 0;
}
