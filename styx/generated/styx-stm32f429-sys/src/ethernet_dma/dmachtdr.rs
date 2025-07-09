// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DMACHTDR` reader"]
pub type R = crate::R<DmachtdrSpec>;
#[doc = "Register `DMACHTDR` writer"]
pub type W = crate::W<DmachtdrSpec>;
#[doc = "Field `HTDAP` reader - HTDAP"]
pub type HtdapR = crate::FieldReader<u32>;
#[doc = "Field `HTDAP` writer - HTDAP"]
pub type HtdapW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - HTDAP"]
    #[inline(always)]
    pub fn htdap(&self) -> HtdapR {
        HtdapR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - HTDAP"]
    #[inline(always)]
    #[must_use]
    pub fn htdap(&mut self) -> HtdapW<DmachtdrSpec> {
        HtdapW::new(self, 0)
    }
}
#[doc = "Ethernet DMA current host transmit descriptor register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmachtdr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmachtdrSpec;
impl crate::RegisterSpec for DmachtdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 72u64;
}
#[doc = "`read()` method returns [`dmachtdr::R`](R) reader structure"]
impl crate::Readable for DmachtdrSpec {}
#[doc = "`reset()` method sets DMACHTDR to value 0"]
impl crate::Resettable for DmachtdrSpec {
    const RESET_VALUE: u32 = 0;
}
