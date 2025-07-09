// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AR` reader"]
pub type R = crate::R<ArSpec>;
#[doc = "Register `AR` writer"]
pub type W = crate::W<ArSpec>;
#[doc = "Field `ADDRESS` reader - Address"]
pub type AddressR = crate::FieldReader<u32>;
#[doc = "Field `ADDRESS` writer - Address"]
pub type AddressW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Address"]
    #[inline(always)]
    pub fn address(&self) -> AddressR {
        AddressR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Address"]
    #[inline(always)]
    #[must_use]
    pub fn address(&mut self) -> AddressW<ArSpec> {
        AddressW::new(self, 0)
    }
}
#[doc = "address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ar::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ar::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ArSpec;
impl crate::RegisterSpec for ArSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`ar::R`](R) reader structure"]
impl crate::Readable for ArSpec {}
#[doc = "`write(|w| ..)` method takes [`ar::W`](W) writer structure"]
impl crate::Writable for ArSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AR to value 0"]
impl crate::Resettable for ArSpec {
    const RESET_VALUE: u32 = 0;
}
