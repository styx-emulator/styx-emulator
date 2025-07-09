// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `bufaddr` reader"]
pub type R = crate::R<BufaddrSpec>;
#[doc = "Register `bufaddr` writer"]
pub type W = crate::W<BufaddrSpec>;
#[doc = "Field `hba` reader - Cleared on Reset. Pointer updated by IDMAC during operation. This register points to the current Data Buffer Address being accessed by the IDMAC."]
pub type HbaR = crate::FieldReader<u32>;
#[doc = "Field `hba` writer - Cleared on Reset. Pointer updated by IDMAC during operation. This register points to the current Data Buffer Address being accessed by the IDMAC."]
pub type HbaW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Cleared on Reset. Pointer updated by IDMAC during operation. This register points to the current Data Buffer Address being accessed by the IDMAC."]
    #[inline(always)]
    pub fn hba(&self) -> HbaR {
        HbaR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Cleared on Reset. Pointer updated by IDMAC during operation. This register points to the current Data Buffer Address being accessed by the IDMAC."]
    #[inline(always)]
    #[must_use]
    pub fn hba(&mut self) -> HbaW<BufaddrSpec> {
        HbaW::new(self, 0)
    }
}
#[doc = "See Field Description.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bufaddr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BufaddrSpec;
impl crate::RegisterSpec for BufaddrSpec {
    type Ux = u32;
    const OFFSET: u64 = 152u64;
}
#[doc = "`read()` method returns [`bufaddr::R`](R) reader structure"]
impl crate::Readable for BufaddrSpec {}
#[doc = "`reset()` method sets bufaddr to value 0"]
impl crate::Resettable for BufaddrSpec {
    const RESET_VALUE: u32 = 0;
}
