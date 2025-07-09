// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `remapaddr` reader"]
pub type R = crate::R<RemapaddrSpec>;
#[doc = "Register `remapaddr` writer"]
pub type W = crate::W<RemapaddrSpec>;
#[doc = "Field `value` reader - This offset is added to the incoming AHB address to determine the address used by the FLASH device."]
pub type ValueR = crate::FieldReader<u32>;
#[doc = "Field `value` writer - This offset is added to the incoming AHB address to determine the address used by the FLASH device."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This offset is added to the incoming AHB address to determine the address used by the FLASH device."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This offset is added to the incoming AHB address to determine the address used by the FLASH device."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<RemapaddrSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "This register is used to remap an incoming AHB address to a different address used by the FLASH device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`remapaddr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`remapaddr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RemapaddrSpec;
impl crate::RegisterSpec for RemapaddrSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`remapaddr::R`](R) reader structure"]
impl crate::Readable for RemapaddrSpec {}
#[doc = "`write(|w| ..)` method takes [`remapaddr::W`](W) writer structure"]
impl crate::Writable for RemapaddrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets remapaddr to value 0"]
impl crate::Resettable for RemapaddrSpec {
    const RESET_VALUE: u32 = 0;
}
