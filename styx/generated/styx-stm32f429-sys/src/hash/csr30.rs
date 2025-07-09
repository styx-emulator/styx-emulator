// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR30` reader"]
pub type R = crate::R<Csr30Spec>;
#[doc = "Register `CSR30` writer"]
pub type W = crate::W<Csr30Spec>;
#[doc = "Field `CSR30` reader - CSR30"]
pub type Csr30R = crate::FieldReader<u32>;
#[doc = "Field `CSR30` writer - CSR30"]
pub type Csr30W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR30"]
    #[inline(always)]
    pub fn csr30(&self) -> Csr30R {
        Csr30R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR30"]
    #[inline(always)]
    #[must_use]
    pub fn csr30(&mut self) -> Csr30W<Csr30Spec> {
        Csr30W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr30::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr30::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr30Spec;
impl crate::RegisterSpec for Csr30Spec {
    type Ux = u32;
    const OFFSET: u64 = 368u64;
}
#[doc = "`read()` method returns [`csr30::R`](R) reader structure"]
impl crate::Readable for Csr30Spec {}
#[doc = "`write(|w| ..)` method takes [`csr30::W`](W) writer structure"]
impl crate::Writable for Csr30Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR30 to value 0"]
impl crate::Resettable for Csr30Spec {
    const RESET_VALUE: u32 = 0;
}
