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
#[doc = "Register `config_twhr2_and_we_2_re` reader"]
pub type R = crate::R<ConfigTwhr2AndWe2ReSpec>;
#[doc = "Register `config_twhr2_and_we_2_re` writer"]
pub type W = crate::W<ConfigTwhr2AndWe2ReSpec>;
#[doc = "Field `we_2_re` reader - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between write enable going high to read enable going low. The number of clocks is the function of device parameter Twhr and controller clock frequency."]
pub type We2ReR = crate::FieldReader;
#[doc = "Field `we_2_re` writer - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between write enable going high to read enable going low. The number of clocks is the function of device parameter Twhr and controller clock frequency."]
pub type We2ReW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `twhr2` reader - Signifies the number of controller clocks that should be introduced between the last command of a random data output command to the start of the data transfer."]
pub type Twhr2R = crate::FieldReader;
#[doc = "Field `twhr2` writer - Signifies the number of controller clocks that should be introduced between the last command of a random data output command to the start of the data transfer."]
pub type Twhr2W<'a, REG> = crate::FieldWriter<'a, REG, 6>;
impl R {
    #[doc = "Bits 0:5 - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between write enable going high to read enable going low. The number of clocks is the function of device parameter Twhr and controller clock frequency."]
    #[inline(always)]
    pub fn we_2_re(&self) -> We2ReR {
        We2ReR::new((self.bits & 0x3f) as u8)
    }
    #[doc = "Bits 8:13 - Signifies the number of controller clocks that should be introduced between the last command of a random data output command to the start of the data transfer."]
    #[inline(always)]
    pub fn twhr2(&self) -> Twhr2R {
        Twhr2R::new(((self.bits >> 8) & 0x3f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:5 - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between write enable going high to read enable going low. The number of clocks is the function of device parameter Twhr and controller clock frequency."]
    #[inline(always)]
    #[must_use]
    pub fn we_2_re(&mut self) -> We2ReW<ConfigTwhr2AndWe2ReSpec> {
        We2ReW::new(self, 0)
    }
    #[doc = "Bits 8:13 - Signifies the number of controller clocks that should be introduced between the last command of a random data output command to the start of the data transfer."]
    #[inline(always)]
    #[must_use]
    pub fn twhr2(&mut self) -> Twhr2W<ConfigTwhr2AndWe2ReSpec> {
        Twhr2W::new(self, 8)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_twhr2_and_we_2_re::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_twhr2_and_we_2_re::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigTwhr2AndWe2ReSpec;
impl crate::RegisterSpec for ConfigTwhr2AndWe2ReSpec {
    type Ux = u32;
    const OFFSET: u64 = 256u64;
}
#[doc = "`read()` method returns [`config_twhr2_and_we_2_re::R`](R) reader structure"]
impl crate::Readable for ConfigTwhr2AndWe2ReSpec {}
#[doc = "`write(|w| ..)` method takes [`config_twhr2_and_we_2_re::W`](W) writer structure"]
impl crate::Writable for ConfigTwhr2AndWe2ReSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_twhr2_and_we_2_re to value 0x1432"]
impl crate::Resettable for ConfigTwhr2AndWe2ReSpec {
    const RESET_VALUE: u32 = 0x1432;
}
