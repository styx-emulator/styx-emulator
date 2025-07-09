// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `indrdwater` reader"]
pub type R = crate::R<IndrdwaterSpec>;
#[doc = "Register `indrdwater` writer"]
pub type W = crate::W<IndrdwaterSpec>;
#[doc = "Field `level` reader - This represents the minimum fill level of the SRAM before a DMA peripheral access is permitted. When the SRAM fill level passes the watermark, an interrupt is also generated. This field can be disabled by writing a value of all zeroes. The units of this register are BYTES"]
pub type LevelR = crate::FieldReader<u32>;
#[doc = "Field `level` writer - This represents the minimum fill level of the SRAM before a DMA peripheral access is permitted. When the SRAM fill level passes the watermark, an interrupt is also generated. This field can be disabled by writing a value of all zeroes. The units of this register are BYTES"]
pub type LevelW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This represents the minimum fill level of the SRAM before a DMA peripheral access is permitted. When the SRAM fill level passes the watermark, an interrupt is also generated. This field can be disabled by writing a value of all zeroes. The units of this register are BYTES"]
    #[inline(always)]
    pub fn level(&self) -> LevelR {
        LevelR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This represents the minimum fill level of the SRAM before a DMA peripheral access is permitted. When the SRAM fill level passes the watermark, an interrupt is also generated. This field can be disabled by writing a value of all zeroes. The units of this register are BYTES"]
    #[inline(always)]
    #[must_use]
    pub fn level(&mut self) -> LevelW<IndrdwaterSpec> {
        LevelW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indrdwater::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indrdwater::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IndrdwaterSpec;
impl crate::RegisterSpec for IndrdwaterSpec {
    type Ux = u32;
    const OFFSET: u64 = 100u64;
}
#[doc = "`read()` method returns [`indrdwater::R`](R) reader structure"]
impl crate::Readable for IndrdwaterSpec {}
#[doc = "`write(|w| ..)` method takes [`indrdwater::W`](W) writer structure"]
impl crate::Writable for IndrdwaterSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets indrdwater to value 0"]
impl crate::Resettable for IndrdwaterSpec {
    const RESET_VALUE: u32 = 0;
}
