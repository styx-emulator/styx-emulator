// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `POL` reader"]
pub type R = crate::R<PolSpec>;
#[doc = "Register `POL` writer"]
pub type W = crate::W<PolSpec>;
#[doc = "Field `POL` reader - Programmable polynomial"]
pub type PolR = crate::FieldReader<u32>;
#[doc = "Field `POL` writer - Programmable polynomial"]
pub type PolW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Programmable polynomial"]
    #[inline(always)]
    pub fn pol(&self) -> PolR {
        PolR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Programmable polynomial"]
    #[inline(always)]
    #[must_use]
    pub fn pol(&mut self) -> PolW<PolSpec> {
        PolW::new(self, 0)
    }
}
#[doc = "CRC polynomial\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pol::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pol::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PolSpec;
impl crate::RegisterSpec for PolSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`pol::R`](R) reader structure"]
impl crate::Readable for PolSpec {}
#[doc = "`write(|w| ..)` method takes [`pol::W`](W) writer structure"]
impl crate::Writable for PolSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets POL to value 0"]
impl crate::Resettable for PolSpec {
    const RESET_VALUE: u32 = 0;
}
