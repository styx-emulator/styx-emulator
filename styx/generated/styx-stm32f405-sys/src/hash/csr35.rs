// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR35` reader"]
pub type R = crate::R<Csr35Spec>;
#[doc = "Register `CSR35` writer"]
pub type W = crate::W<Csr35Spec>;
#[doc = "Field `CSR35` reader - CSR35"]
pub type Csr35R = crate::FieldReader<u32>;
#[doc = "Field `CSR35` writer - CSR35"]
pub type Csr35W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR35"]
    #[inline(always)]
    pub fn csr35(&self) -> Csr35R {
        Csr35R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR35"]
    #[inline(always)]
    #[must_use]
    pub fn csr35(&mut self) -> Csr35W<Csr35Spec> {
        Csr35W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr35::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr35::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr35Spec;
impl crate::RegisterSpec for Csr35Spec {
    type Ux = u32;
    const OFFSET: u64 = 388u64;
}
#[doc = "`read()` method returns [`csr35::R`](R) reader structure"]
impl crate::Readable for Csr35Spec {}
#[doc = "`write(|w| ..)` method takes [`csr35::W`](W) writer structure"]
impl crate::Writable for Csr35Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR35 to value 0"]
impl crate::Resettable for Csr35Spec {
    const RESET_VALUE: u32 = 0;
}
