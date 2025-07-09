// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR27` reader"]
pub type R = crate::R<Csr27Spec>;
#[doc = "Register `CSR27` writer"]
pub type W = crate::W<Csr27Spec>;
#[doc = "Field `CSR27` reader - CSR27"]
pub type Csr27R = crate::FieldReader<u32>;
#[doc = "Field `CSR27` writer - CSR27"]
pub type Csr27W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR27"]
    #[inline(always)]
    pub fn csr27(&self) -> Csr27R {
        Csr27R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR27"]
    #[inline(always)]
    #[must_use]
    pub fn csr27(&mut self) -> Csr27W<Csr27Spec> {
        Csr27W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr27::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr27::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr27Spec;
impl crate::RegisterSpec for Csr27Spec {
    type Ux = u32;
    const OFFSET: u64 = 356u64;
}
#[doc = "`read()` method returns [`csr27::R`](R) reader structure"]
impl crate::Readable for Csr27Spec {}
#[doc = "`write(|w| ..)` method takes [`csr27::W`](W) writer structure"]
impl crate::Writable for Csr27Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR27 to value 0"]
impl crate::Resettable for Csr27Spec {
    const RESET_VALUE: u32 = 0;
}
