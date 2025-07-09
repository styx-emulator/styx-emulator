// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR29` reader"]
pub type R = crate::R<Csr29Spec>;
#[doc = "Register `CSR29` writer"]
pub type W = crate::W<Csr29Spec>;
#[doc = "Field `CSR29` reader - CSR29"]
pub type Csr29R = crate::FieldReader<u32>;
#[doc = "Field `CSR29` writer - CSR29"]
pub type Csr29W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR29"]
    #[inline(always)]
    pub fn csr29(&self) -> Csr29R {
        Csr29R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR29"]
    #[inline(always)]
    #[must_use]
    pub fn csr29(&mut self) -> Csr29W<Csr29Spec> {
        Csr29W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr29::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr29::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr29Spec;
impl crate::RegisterSpec for Csr29Spec {
    type Ux = u32;
    const OFFSET: u64 = 364u64;
}
#[doc = "`read()` method returns [`csr29::R`](R) reader structure"]
impl crate::Readable for Csr29Spec {}
#[doc = "`write(|w| ..)` method takes [`csr29::W`](W) writer structure"]
impl crate::Writable for Csr29Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR29 to value 0"]
impl crate::Resettable for Csr29Spec {
    const RESET_VALUE: u32 = 0;
}
