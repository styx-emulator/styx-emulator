// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MACMIIDR` reader"]
pub type R = crate::R<MacmiidrSpec>;
#[doc = "Register `MACMIIDR` writer"]
pub type W = crate::W<MacmiidrSpec>;
#[doc = "Field `TD` reader - TD"]
pub type TdR = crate::FieldReader<u16>;
#[doc = "Field `TD` writer - TD"]
pub type TdW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - TD"]
    #[inline(always)]
    pub fn td(&self) -> TdR {
        TdR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - TD"]
    #[inline(always)]
    #[must_use]
    pub fn td(&mut self) -> TdW<MacmiidrSpec> {
        TdW::new(self, 0)
    }
}
#[doc = "Ethernet MAC MII data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`macmiidr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`macmiidr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MacmiidrSpec;
impl crate::RegisterSpec for MacmiidrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`macmiidr::R`](R) reader structure"]
impl crate::Readable for MacmiidrSpec {}
#[doc = "`write(|w| ..)` method takes [`macmiidr::W`](W) writer structure"]
impl crate::Writable for MacmiidrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACMIIDR to value 0"]
impl crate::Resettable for MacmiidrSpec {
    const RESET_VALUE: u32 = 0;
}
