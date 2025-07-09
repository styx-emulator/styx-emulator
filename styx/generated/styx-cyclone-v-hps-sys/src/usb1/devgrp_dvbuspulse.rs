// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_dvbuspulse` reader"]
pub type R = crate::R<DevgrpDvbuspulseSpec>;
#[doc = "Register `devgrp_dvbuspulse` writer"]
pub type W = crate::W<DevgrpDvbuspulseSpec>;
#[doc = "Field `dvbuspulse` reader - Specifies the VBUS pulsing time during SRP. This value equals: VBUS pulsing time in PHY clocks/1,024 The value you use depends whether the PHY is operating at 30MHz (16-bit data width) or 60 MHz (8-bit data width)."]
pub type DvbuspulseR = crate::FieldReader<u16>;
#[doc = "Field `dvbuspulse` writer - Specifies the VBUS pulsing time during SRP. This value equals: VBUS pulsing time in PHY clocks/1,024 The value you use depends whether the PHY is operating at 30MHz (16-bit data width) or 60 MHz (8-bit data width)."]
pub type DvbuspulseW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:11 - Specifies the VBUS pulsing time during SRP. This value equals: VBUS pulsing time in PHY clocks/1,024 The value you use depends whether the PHY is operating at 30MHz (16-bit data width) or 60 MHz (8-bit data width)."]
    #[inline(always)]
    pub fn dvbuspulse(&self) -> DvbuspulseR {
        DvbuspulseR::new((self.bits & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - Specifies the VBUS pulsing time during SRP. This value equals: VBUS pulsing time in PHY clocks/1,024 The value you use depends whether the PHY is operating at 30MHz (16-bit data width) or 60 MHz (8-bit data width)."]
    #[inline(always)]
    #[must_use]
    pub fn dvbuspulse(&mut self) -> DvbuspulseW<DevgrpDvbuspulseSpec> {
        DvbuspulseW::new(self, 0)
    }
}
#[doc = "This register specifies the VBUS pulsing time during SRP.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dvbuspulse::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dvbuspulse::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDvbuspulseSpec;
impl crate::RegisterSpec for DevgrpDvbuspulseSpec {
    type Ux = u32;
    const OFFSET: u64 = 2092u64;
}
#[doc = "`read()` method returns [`devgrp_dvbuspulse::R`](R) reader structure"]
impl crate::Readable for DevgrpDvbuspulseSpec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_dvbuspulse::W`](W) writer structure"]
impl crate::Writable for DevgrpDvbuspulseSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_dvbuspulse to value 0x05b8"]
impl crate::Resettable for DevgrpDvbuspulseSpec {
    const RESET_VALUE: u32 = 0x05b8;
}
