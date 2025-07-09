// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pldmnd` reader"]
pub type R = crate::R<PldmndSpec>;
#[doc = "Register `pldmnd` writer"]
pub type W = crate::W<PldmndSpec>;
#[doc = "Field `pd` reader - If the OWN bit of a descriptor is not set, the FSM goes to the Suspend state. The host needs to write any value into this register for the IDMAC FSM to resume normal descriptor fetch operation."]
pub type PdR = crate::FieldReader<u32>;
#[doc = "Field `pd` writer - If the OWN bit of a descriptor is not set, the FSM goes to the Suspend state. The host needs to write any value into this register for the IDMAC FSM to resume normal descriptor fetch operation."]
pub type PdW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - If the OWN bit of a descriptor is not set, the FSM goes to the Suspend state. The host needs to write any value into this register for the IDMAC FSM to resume normal descriptor fetch operation."]
    #[inline(always)]
    pub fn pd(&self) -> PdR {
        PdR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - If the OWN bit of a descriptor is not set, the FSM goes to the Suspend state. The host needs to write any value into this register for the IDMAC FSM to resume normal descriptor fetch operation."]
    #[inline(always)]
    #[must_use]
    pub fn pd(&mut self) -> PdW<PldmndSpec> {
        PdW::new(self, 0)
    }
}
#[doc = "See Field Description.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pldmnd::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PldmndSpec;
impl crate::RegisterSpec for PldmndSpec {
    type Ux = u32;
    const OFFSET: u64 = 132u64;
}
#[doc = "`write(|w| ..)` method takes [`pldmnd::W`](W) writer structure"]
impl crate::Writable for PldmndSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pldmnd to value 0"]
impl crate::Resettable for PldmndSpec {
    const RESET_VALUE: u32 = 0;
}
