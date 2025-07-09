// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `usrid` reader"]
pub type R = crate::R<UsridSpec>;
#[doc = "Register `usrid` writer"]
pub type W = crate::W<UsridSpec>;
#[doc = "Field `usr_id` reader - User identification field; Value is 0x7967797."]
pub type UsrIdR = crate::FieldReader<u32>;
#[doc = "Field `usr_id` writer - User identification field; Value is 0x7967797."]
pub type UsrIdW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - User identification field; Value is 0x7967797."]
    #[inline(always)]
    pub fn usr_id(&self) -> UsrIdR {
        UsrIdR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - User identification field; Value is 0x7967797."]
    #[inline(always)]
    #[must_use]
    pub fn usr_id(&mut self) -> UsrIdW<UsridSpec> {
        UsrIdW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`usrid::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`usrid::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct UsridSpec;
impl crate::RegisterSpec for UsridSpec {
    type Ux = u32;
    const OFFSET: u64 = 104u64;
}
#[doc = "`read()` method returns [`usrid::R`](R) reader structure"]
impl crate::Readable for UsridSpec {}
#[doc = "`write(|w| ..)` method takes [`usrid::W`](W) writer structure"]
impl crate::Writable for UsridSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets usrid to value 0x0796_7797"]
impl crate::Resettable for UsridSpec {
    const RESET_VALUE: u32 = 0x0796_7797;
}
