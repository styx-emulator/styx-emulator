// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `slavegrp_usb0_read_qos` reader"]
pub type R = crate::R<SlavegrpUsb0ReadQosSpec>;
#[doc = "Register `slavegrp_usb0_read_qos` writer"]
pub type W = crate::W<SlavegrpUsb0ReadQosSpec>;
#[doc = "Field `pri` reader - QoS (Quality of Service) value for the read channel. A higher value has a higher priority."]
pub type PriR = crate::FieldReader;
#[doc = "Field `pri` writer - QoS (Quality of Service) value for the read channel. A higher value has a higher priority."]
pub type PriW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - QoS (Quality of Service) value for the read channel. A higher value has a higher priority."]
    #[inline(always)]
    pub fn pri(&self) -> PriR {
        PriR::new((self.bits & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - QoS (Quality of Service) value for the read channel. A higher value has a higher priority."]
    #[inline(always)]
    #[must_use]
    pub fn pri(&mut self) -> PriW<SlavegrpUsb0ReadQosSpec> {
        PriW::new(self, 0)
    }
}
#[doc = "QoS (Quality of Service) value for the read channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_usb0_read_qos::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_usb0_read_qos::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SlavegrpUsb0ReadQosSpec;
impl crate::RegisterSpec for SlavegrpUsb0ReadQosSpec {
    type Ux = u32;
    const OFFSET: u64 = 303360u64;
}
#[doc = "`read()` method returns [`slavegrp_usb0_read_qos::R`](R) reader structure"]
impl crate::Readable for SlavegrpUsb0ReadQosSpec {}
#[doc = "`write(|w| ..)` method takes [`slavegrp_usb0_read_qos::W`](W) writer structure"]
impl crate::Writable for SlavegrpUsb0ReadQosSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets slavegrp_usb0_read_qos to value 0"]
impl crate::Resettable for SlavegrpUsb0ReadQosSpec {
    const RESET_VALUE: u32 = 0;
}
