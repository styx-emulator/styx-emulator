// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_DVBUSPULSE` reader"]
pub type R = crate::R<OtgHsDvbuspulseSpec>;
#[doc = "Register `OTG_HS_DVBUSPULSE` writer"]
pub type W = crate::W<OtgHsDvbuspulseSpec>;
#[doc = "Field `DVBUSP` reader - Device VBUS pulsing time"]
pub type DvbuspR = crate::FieldReader<u16>;
#[doc = "Field `DVBUSP` writer - Device VBUS pulsing time"]
pub type DvbuspW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:11 - Device VBUS pulsing time"]
    #[inline(always)]
    pub fn dvbusp(&self) -> DvbuspR {
        DvbuspR::new((self.bits & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - Device VBUS pulsing time"]
    #[inline(always)]
    #[must_use]
    pub fn dvbusp(&mut self) -> DvbuspW<OtgHsDvbuspulseSpec> {
        DvbuspW::new(self, 0)
    }
}
#[doc = "OTG_HS device VBUS pulsing time register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dvbuspulse::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dvbuspulse::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsDvbuspulseSpec;
impl crate::RegisterSpec for OtgHsDvbuspulseSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`otg_hs_dvbuspulse::R`](R) reader structure"]
impl crate::Readable for OtgHsDvbuspulseSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_dvbuspulse::W`](W) writer structure"]
impl crate::Writable for OtgHsDvbuspulseSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_DVBUSPULSE to value 0x05b8"]
impl crate::Resettable for OtgHsDvbuspulseSpec {
    const RESET_VALUE: u32 = 0x05b8;
}
