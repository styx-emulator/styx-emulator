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
#[doc = "Register `config_re_2_we` reader"]
pub type R = crate::R<ConfigRe2WeSpec>;
#[doc = "Register `config_re_2_we` writer"]
pub type W = crate::W<ConfigRe2WeSpec>;
#[doc = "Field `value` reader - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between read enable going high to write enable going low. The number of clocks is the function of device parameter Trhw and controller clock frequency."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between read enable going high to write enable going low. The number of clocks is the function of device parameter Trhw and controller clock frequency."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
impl R {
    #[doc = "Bits 0:5 - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between read enable going high to write enable going low. The number of clocks is the function of device parameter Trhw and controller clock frequency."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0x3f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:5 - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between read enable going high to write enable going low. The number of clocks is the function of device parameter Trhw and controller clock frequency."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigRe2WeSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Timing parameter between re high to we low (Trhw)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_re_2_we::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_re_2_we::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigRe2WeSpec;
impl crate::RegisterSpec for ConfigRe2WeSpec {
    type Ux = u32;
    const OFFSET: u64 = 288u64;
}
#[doc = "`read()` method returns [`config_re_2_we::R`](R) reader structure"]
impl crate::Readable for ConfigRe2WeSpec {}
#[doc = "`write(|w| ..)` method takes [`config_re_2_we::W`](W) writer structure"]
impl crate::Writable for ConfigRe2WeSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_re_2_we to value 0x32"]
impl crate::Resettable for ConfigRe2WeSpec {
    const RESET_VALUE: u32 = 0x32;
}
