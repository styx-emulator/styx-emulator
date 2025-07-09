// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `verid` reader"]
pub type R = crate::R<VeridSpec>;
#[doc = "Register `verid` writer"]
pub type W = crate::W<VeridSpec>;
#[doc = "Field `ver_id` reader - Synopsys version id. Current value is 32'h5342240a"]
pub type VerIdR = crate::FieldReader<u32>;
#[doc = "Field `ver_id` writer - Synopsys version id. Current value is 32'h5342240a"]
pub type VerIdW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Synopsys version id. Current value is 32'h5342240a"]
    #[inline(always)]
    pub fn ver_id(&self) -> VerIdR {
        VerIdR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Synopsys version id. Current value is 32'h5342240a"]
    #[inline(always)]
    #[must_use]
    pub fn ver_id(&mut self) -> VerIdW<VeridSpec> {
        VerIdW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`verid::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct VeridSpec;
impl crate::RegisterSpec for VeridSpec {
    type Ux = u32;
    const OFFSET: u64 = 108u64;
}
#[doc = "`read()` method returns [`verid::R`](R) reader structure"]
impl crate::Readable for VeridSpec {}
#[doc = "`reset()` method sets verid to value 0x5342_240a"]
impl crate::Resettable for VeridSpec {
    const RESET_VALUE: u32 = 0x5342_240a;
}
