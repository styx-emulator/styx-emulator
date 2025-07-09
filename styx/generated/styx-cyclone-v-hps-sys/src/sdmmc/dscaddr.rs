// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dscaddr` reader"]
pub type R = crate::R<DscaddrSpec>;
#[doc = "Register `dscaddr` writer"]
pub type W = crate::W<DscaddrSpec>;
#[doc = "Field `hda` reader - Cleared on reset. Pointer updated by IDMAC during operation. This register points to the start address of the current descriptor read by the IDMAC."]
pub type HdaR = crate::FieldReader<u32>;
#[doc = "Field `hda` writer - Cleared on reset. Pointer updated by IDMAC during operation. This register points to the start address of the current descriptor read by the IDMAC."]
pub type HdaW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Cleared on reset. Pointer updated by IDMAC during operation. This register points to the start address of the current descriptor read by the IDMAC."]
    #[inline(always)]
    pub fn hda(&self) -> HdaR {
        HdaR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Cleared on reset. Pointer updated by IDMAC during operation. This register points to the start address of the current descriptor read by the IDMAC."]
    #[inline(always)]
    #[must_use]
    pub fn hda(&mut self) -> HdaW<DscaddrSpec> {
        HdaW::new(self, 0)
    }
}
#[doc = "See Field Description.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dscaddr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DscaddrSpec;
impl crate::RegisterSpec for DscaddrSpec {
    type Ux = u32;
    const OFFSET: u64 = 148u64;
}
#[doc = "`read()` method returns [`dscaddr::R`](R) reader structure"]
impl crate::Readable for DscaddrSpec {}
#[doc = "`reset()` method sets dscaddr to value 0"]
impl crate::Resettable for DscaddrSpec {
    const RESET_VALUE: u32 = 0;
}
