// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `slavegrp_emac0_write_qos` reader"]
pub type R = crate::R<SlavegrpEmac0WriteQosSpec>;
#[doc = "Register `slavegrp_emac0_write_qos` writer"]
pub type W = crate::W<SlavegrpEmac0WriteQosSpec>;
#[doc = "Field `pri` reader - QoS (Quality of Service) value for the write channel. A higher value has a higher priority."]
pub type PriR = crate::FieldReader;
#[doc = "Field `pri` writer - QoS (Quality of Service) value for the write channel. A higher value has a higher priority."]
pub type PriW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - QoS (Quality of Service) value for the write channel. A higher value has a higher priority."]
    #[inline(always)]
    pub fn pri(&self) -> PriR {
        PriR::new((self.bits & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - QoS (Quality of Service) value for the write channel. A higher value has a higher priority."]
    #[inline(always)]
    #[must_use]
    pub fn pri(&mut self) -> PriW<SlavegrpEmac0WriteQosSpec> {
        PriW::new(self, 0)
    }
}
#[doc = "QoS (Quality of Service) value for the write channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_emac0_write_qos::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_emac0_write_qos::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SlavegrpEmac0WriteQosSpec;
impl crate::RegisterSpec for SlavegrpEmac0WriteQosSpec {
    type Ux = u32;
    const OFFSET: u64 = 295172u64;
}
#[doc = "`read()` method returns [`slavegrp_emac0_write_qos::R`](R) reader structure"]
impl crate::Readable for SlavegrpEmac0WriteQosSpec {}
#[doc = "`write(|w| ..)` method takes [`slavegrp_emac0_write_qos::W`](W) writer structure"]
impl crate::Writable for SlavegrpEmac0WriteQosSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets slavegrp_emac0_write_qos to value 0"]
impl crate::Resettable for SlavegrpEmac0WriteQosSpec {
    const RESET_VALUE: u32 = 0;
}
