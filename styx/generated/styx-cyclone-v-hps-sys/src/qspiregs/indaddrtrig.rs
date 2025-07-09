// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `indaddrtrig` reader"]
pub type R = crate::R<IndaddrtrigSpec>;
#[doc = "Register `indaddrtrig` writer"]
pub type W = crate::W<IndaddrtrigSpec>;
#[doc = "Field `addr` reader - This is the base address that will be used by the AHB controller. When the incoming AHB read access address matches a range of addresses from this trigger address to the trigger address + 15, then the AHB request will be completed by fetching data from the Indirect Controllers SRAM."]
pub type AddrR = crate::FieldReader<u32>;
#[doc = "Field `addr` writer - This is the base address that will be used by the AHB controller. When the incoming AHB read access address matches a range of addresses from this trigger address to the trigger address + 15, then the AHB request will be completed by fetching data from the Indirect Controllers SRAM."]
pub type AddrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This is the base address that will be used by the AHB controller. When the incoming AHB read access address matches a range of addresses from this trigger address to the trigger address + 15, then the AHB request will be completed by fetching data from the Indirect Controllers SRAM."]
    #[inline(always)]
    pub fn addr(&self) -> AddrR {
        AddrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This is the base address that will be used by the AHB controller. When the incoming AHB read access address matches a range of addresses from this trigger address to the trigger address + 15, then the AHB request will be completed by fetching data from the Indirect Controllers SRAM."]
    #[inline(always)]
    #[must_use]
    pub fn addr(&mut self) -> AddrW<IndaddrtrigSpec> {
        AddrW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indaddrtrig::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indaddrtrig::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IndaddrtrigSpec;
impl crate::RegisterSpec for IndaddrtrigSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`indaddrtrig::R`](R) reader structure"]
impl crate::Readable for IndaddrtrigSpec {}
#[doc = "`write(|w| ..)` method takes [`indaddrtrig::W`](W) writer structure"]
impl crate::Writable for IndaddrtrigSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets indaddrtrig to value 0"]
impl crate::Resettable for IndaddrtrigSpec {
    const RESET_VALUE: u32 = 0;
}
