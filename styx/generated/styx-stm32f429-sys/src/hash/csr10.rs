// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR10` reader"]
pub type R = crate::R<Csr10Spec>;
#[doc = "Register `CSR10` writer"]
pub type W = crate::W<Csr10Spec>;
#[doc = "Field `CSR10` reader - CSR10"]
pub type Csr10R = crate::FieldReader<u32>;
#[doc = "Field `CSR10` writer - CSR10"]
pub type Csr10W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR10"]
    #[inline(always)]
    pub fn csr10(&self) -> Csr10R {
        Csr10R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR10"]
    #[inline(always)]
    #[must_use]
    pub fn csr10(&mut self) -> Csr10W<Csr10Spec> {
        Csr10W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr10::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr10::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr10Spec;
impl crate::RegisterSpec for Csr10Spec {
    type Ux = u32;
    const OFFSET: u64 = 288u64;
}
#[doc = "`read()` method returns [`csr10::R`](R) reader structure"]
impl crate::Readable for Csr10Spec {}
#[doc = "`write(|w| ..)` method takes [`csr10::W`](W) writer structure"]
impl crate::Writable for Csr10Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR10 to value 0"]
impl crate::Resettable for Csr10Spec {
    const RESET_VALUE: u32 = 0;
}
