// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_re_2_re` reader"]
pub type R = crate::R<ConfigRe2ReSpec>;
#[doc = "Register `config_re_2_re` writer"]
pub type W = crate::W<ConfigRe2ReSpec>;
#[doc = "Field `value` reader - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between read enable going high to a bank to the read enable going low to the next bank. The number of clocks is the function of device parameter Trhz and controller clock frequency."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between read enable going high to a bank to the read enable going low to the next bank. The number of clocks is the function of device parameter Trhz and controller clock frequency."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
impl R {
    #[doc = "Bits 0:5 - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between read enable going high to a bank to the read enable going low to the next bank. The number of clocks is the function of device parameter Trhz and controller clock frequency."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0x3f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:5 - Signifies the number of bus interface nand_mp_clk clocks that should be introduced between read enable going high to a bank to the read enable going low to the next bank. The number of clocks is the function of device parameter Trhz and controller clock frequency."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigRe2ReSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Timing parameter between re high to re low (Trhz) for the next bank\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_re_2_re::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_re_2_re::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigRe2ReSpec;
impl crate::RegisterSpec for ConfigRe2ReSpec {
    type Ux = u32;
    const OFFSET: u64 = 656u64;
}
#[doc = "`read()` method returns [`config_re_2_re::R`](R) reader structure"]
impl crate::Readable for ConfigRe2ReSpec {}
#[doc = "`write(|w| ..)` method takes [`config_re_2_re::W`](W) writer structure"]
impl crate::Writable for ConfigRe2ReSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_re_2_re to value 0x32"]
impl crate::Resettable for ConfigRe2ReSpec {
    const RESET_VALUE: u32 = 0x32;
}
