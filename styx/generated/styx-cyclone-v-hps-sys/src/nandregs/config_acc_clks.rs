// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_acc_clks` reader"]
pub type R = crate::R<ConfigAccClksSpec>;
#[doc = "Register `config_acc_clks` writer"]
pub type W = crate::W<ConfigAccClksSpec>;
#[doc = "Field `value` reader - Signifies the number of bus interface nand_mp_clk clock cycles, controller should wait from read enable going low to sending out a strobe of nand_mp_clk for capturing of incoming data."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Signifies the number of bus interface nand_mp_clk clock cycles, controller should wait from read enable going low to sending out a strobe of nand_mp_clk for capturing of incoming data."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - Signifies the number of bus interface nand_mp_clk clock cycles, controller should wait from read enable going low to sending out a strobe of nand_mp_clk for capturing of incoming data."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Signifies the number of bus interface nand_mp_clk clock cycles, controller should wait from read enable going low to sending out a strobe of nand_mp_clk for capturing of incoming data."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigAccClksSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Timing parameter from read enable going low to capture read data\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_acc_clks::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_acc_clks::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigAccClksSpec;
impl crate::RegisterSpec for ConfigAccClksSpec {
    type Ux = u32;
    const OFFSET: u64 = 304u64;
}
#[doc = "`read()` method returns [`config_acc_clks::R`](R) reader structure"]
impl crate::Readable for ConfigAccClksSpec {}
#[doc = "`write(|w| ..)` method takes [`config_acc_clks::W`](W) writer structure"]
impl crate::Writable for ConfigAccClksSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_acc_clks to value 0"]
impl crate::Resettable for ConfigAccClksSpec {
    const RESET_VALUE: u32 = 0;
}
