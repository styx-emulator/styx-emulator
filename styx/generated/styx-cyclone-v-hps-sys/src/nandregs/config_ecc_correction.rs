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
#[doc = "Register `config_ecc_correction` reader"]
pub type R = crate::R<ConfigEccCorrectionSpec>;
#[doc = "Register `config_ecc_correction` writer"]
pub type W = crate::W<ConfigEccCorrectionSpec>;
#[doc = "Field `value` reader - The required correction capability can be a number less than the configured error correction capability. A smaller correction capability will lead to lesser number of ECC check-bits being written per ECC sector."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - The required correction capability can be a number less than the configured error correction capability. A smaller correction capability will lead to lesser number of ECC check-bits being written per ECC sector."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - The required correction capability can be a number less than the configured error correction capability. A smaller correction capability will lead to lesser number of ECC check-bits being written per ECC sector."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - The required correction capability can be a number less than the configured error correction capability. A smaller correction capability will lead to lesser number of ECC check-bits being written per ECC sector."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigEccCorrectionSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Correction capability required\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_ecc_correction::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_ecc_correction::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigEccCorrectionSpec;
impl crate::RegisterSpec for ConfigEccCorrectionSpec {
    type Ux = u32;
    const OFFSET: u64 = 432u64;
}
#[doc = "`read()` method returns [`config_ecc_correction::R`](R) reader structure"]
impl crate::Readable for ConfigEccCorrectionSpec {}
#[doc = "`write(|w| ..)` method takes [`config_ecc_correction::W`](W) writer structure"]
impl crate::Writable for ConfigEccCorrectionSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_ecc_correction to value 0x08"]
impl crate::Resettable for ConfigEccCorrectionSpec {
    const RESET_VALUE: u32 = 0x08;
}
