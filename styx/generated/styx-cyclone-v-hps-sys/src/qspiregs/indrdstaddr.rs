// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `indrdstaddr` reader"]
pub type R = crate::R<IndrdstaddrSpec>;
#[doc = "Register `indrdstaddr` writer"]
pub type W = crate::W<IndrdstaddrSpec>;
#[doc = "Field `addr` reader - This is the start address from which the indirect access will commence its READ operation."]
pub type AddrR = crate::FieldReader<u32>;
#[doc = "Field `addr` writer - This is the start address from which the indirect access will commence its READ operation."]
pub type AddrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This is the start address from which the indirect access will commence its READ operation."]
    #[inline(always)]
    pub fn addr(&self) -> AddrR {
        AddrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This is the start address from which the indirect access will commence its READ operation."]
    #[inline(always)]
    #[must_use]
    pub fn addr(&mut self) -> AddrW<IndrdstaddrSpec> {
        AddrW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indrdstaddr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indrdstaddr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IndrdstaddrSpec;
impl crate::RegisterSpec for IndrdstaddrSpec {
    type Ux = u32;
    const OFFSET: u64 = 104u64;
}
#[doc = "`read()` method returns [`indrdstaddr::R`](R) reader structure"]
impl crate::Readable for IndrdstaddrSpec {}
#[doc = "`write(|w| ..)` method takes [`indrdstaddr::W`](W) writer structure"]
impl crate::Writable for IndrdstaddrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets indrdstaddr to value 0"]
impl crate::Resettable for IndrdstaddrSpec {
    const RESET_VALUE: u32 = 0;
}
