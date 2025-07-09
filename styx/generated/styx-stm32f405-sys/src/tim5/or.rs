// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OR` reader"]
pub type R = crate::R<OrSpec>;
#[doc = "Register `OR` writer"]
pub type W = crate::W<OrSpec>;
#[doc = "Field `IT4_RMP` reader - Timer Input 4 remap"]
pub type It4RmpR = crate::FieldReader;
#[doc = "Field `IT4_RMP` writer - Timer Input 4 remap"]
pub type It4RmpW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 6:7 - Timer Input 4 remap"]
    #[inline(always)]
    pub fn it4_rmp(&self) -> It4RmpR {
        It4RmpR::new(((self.bits >> 6) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 6:7 - Timer Input 4 remap"]
    #[inline(always)]
    #[must_use]
    pub fn it4_rmp(&mut self) -> It4RmpW<OrSpec> {
        It4RmpW::new(self, 6)
    }
}
#[doc = "TIM5 option register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`or::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`or::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OrSpec;
impl crate::RegisterSpec for OrSpec {
    type Ux = u32;
    const OFFSET: u64 = 80u64;
}
#[doc = "`read()` method returns [`or::R`](R) reader structure"]
impl crate::Readable for OrSpec {}
#[doc = "`write(|w| ..)` method takes [`or::W`](W) writer structure"]
impl crate::Writable for OrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OR to value 0"]
impl crate::Resettable for OrSpec {
    const RESET_VALUE: u32 = 0;
}
