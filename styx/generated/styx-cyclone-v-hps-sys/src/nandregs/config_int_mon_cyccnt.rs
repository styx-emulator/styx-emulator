// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_int_mon_cyccnt` reader"]
pub type R = crate::R<ConfigIntMonCyccntSpec>;
#[doc = "Register `config_int_mon_cyccnt` writer"]
pub type W = crate::W<ConfigIntMonCyccntSpec>;
#[doc = "Field `value` reader - In polling mode, sets the number of cycles Denali Flash Controller must wait before checking the status register. This register is only used when R/B pins are not available to NAND Flash Controller."]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - In polling mode, sets the number of cycles Denali Flash Controller must wait before checking the status register. This register is only used when R/B pins are not available to NAND Flash Controller."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - In polling mode, sets the number of cycles Denali Flash Controller must wait before checking the status register. This register is only used when R/B pins are not available to NAND Flash Controller."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - In polling mode, sets the number of cycles Denali Flash Controller must wait before checking the status register. This register is only used when R/B pins are not available to NAND Flash Controller."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigIntMonCyccntSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Interrupt monitor cycle count value\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_int_mon_cyccnt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_int_mon_cyccnt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigIntMonCyccntSpec;
impl crate::RegisterSpec for ConfigIntMonCyccntSpec {
    type Ux = u32;
    const OFFSET: u64 = 80u64;
}
#[doc = "`read()` method returns [`config_int_mon_cyccnt::R`](R) reader structure"]
impl crate::Readable for ConfigIntMonCyccntSpec {}
#[doc = "`write(|w| ..)` method takes [`config_int_mon_cyccnt::W`](W) writer structure"]
impl crate::Writable for ConfigIntMonCyccntSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_int_mon_cyccnt to value 0x01f4"]
impl crate::Resettable for ConfigIntMonCyccntSpec {
    const RESET_VALUE: u32 = 0x01f4;
}
