// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR1` reader"]
pub type R = crate::R<Csr1Spec>;
#[doc = "Register `CSR1` writer"]
pub type W = crate::W<Csr1Spec>;
#[doc = "Field `CSR1` reader - CSR1"]
pub type Csr1R = crate::FieldReader<u32>;
#[doc = "Field `CSR1` writer - CSR1"]
pub type Csr1W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR1"]
    #[inline(always)]
    pub fn csr1(&self) -> Csr1R {
        Csr1R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR1"]
    #[inline(always)]
    #[must_use]
    pub fn csr1(&mut self) -> Csr1W<Csr1Spec> {
        Csr1W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr1Spec;
impl crate::RegisterSpec for Csr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 252u64;
}
#[doc = "`read()` method returns [`csr1::R`](R) reader structure"]
impl crate::Readable for Csr1Spec {}
#[doc = "`write(|w| ..)` method takes [`csr1::W`](W) writer structure"]
impl crate::Writable for Csr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR1 to value 0"]
impl crate::Resettable for Csr1Spec {
    const RESET_VALUE: u32 = 0;
}
