// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR24` reader"]
pub type R = crate::R<Csr24Spec>;
#[doc = "Register `CSR24` writer"]
pub type W = crate::W<Csr24Spec>;
#[doc = "Field `CSR24` reader - CSR24"]
pub type Csr24R = crate::FieldReader<u32>;
#[doc = "Field `CSR24` writer - CSR24"]
pub type Csr24W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR24"]
    #[inline(always)]
    pub fn csr24(&self) -> Csr24R {
        Csr24R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR24"]
    #[inline(always)]
    #[must_use]
    pub fn csr24(&mut self) -> Csr24W<Csr24Spec> {
        Csr24W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr24::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr24::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr24Spec;
impl crate::RegisterSpec for Csr24Spec {
    type Ux = u32;
    const OFFSET: u64 = 344u64;
}
#[doc = "`read()` method returns [`csr24::R`](R) reader structure"]
impl crate::Readable for Csr24Spec {}
#[doc = "`write(|w| ..)` method takes [`csr24::W`](W) writer structure"]
impl crate::Writable for Csr24Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR24 to value 0"]
impl crate::Resettable for Csr24Spec {
    const RESET_VALUE: u32 = 0;
}
