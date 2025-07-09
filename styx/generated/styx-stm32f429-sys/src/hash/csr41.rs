// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR41` reader"]
pub type R = crate::R<Csr41Spec>;
#[doc = "Register `CSR41` writer"]
pub type W = crate::W<Csr41Spec>;
#[doc = "Field `CSR41` reader - CSR41"]
pub type Csr41R = crate::FieldReader<u32>;
#[doc = "Field `CSR41` writer - CSR41"]
pub type Csr41W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR41"]
    #[inline(always)]
    pub fn csr41(&self) -> Csr41R {
        Csr41R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR41"]
    #[inline(always)]
    #[must_use]
    pub fn csr41(&mut self) -> Csr41W<Csr41Spec> {
        Csr41W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr41::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr41::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr41Spec;
impl crate::RegisterSpec for Csr41Spec {
    type Ux = u32;
    const OFFSET: u64 = 412u64;
}
#[doc = "`read()` method returns [`csr41::R`](R) reader structure"]
impl crate::Readable for Csr41Spec {}
#[doc = "`write(|w| ..)` method takes [`csr41::W`](W) writer structure"]
impl crate::Writable for Csr41Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR41 to value 0"]
impl crate::Resettable for Csr41Spec {
    const RESET_VALUE: u32 = 0;
}
