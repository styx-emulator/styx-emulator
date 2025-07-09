// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_dvbusdis` reader"]
pub type R = crate::R<DevgrpDvbusdisSpec>;
#[doc = "Register `devgrp_dvbusdis` writer"]
pub type W = crate::W<DevgrpDvbusdisSpec>;
#[doc = "Field `dvbusdis` reader - This value equals: VBUS discharge time in PHY clocks/1,024 The value you use depends whether the PHY is operating at 30 MHz (16-bit data width) or 60 MHz (8-bit data width). Depending on your VBUS load, this value can need adjustment."]
pub type DvbusdisR = crate::FieldReader<u16>;
#[doc = "Field `dvbusdis` writer - This value equals: VBUS discharge time in PHY clocks/1,024 The value you use depends whether the PHY is operating at 30 MHz (16-bit data width) or 60 MHz (8-bit data width). Depending on your VBUS load, this value can need adjustment."]
pub type DvbusdisW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - This value equals: VBUS discharge time in PHY clocks/1,024 The value you use depends whether the PHY is operating at 30 MHz (16-bit data width) or 60 MHz (8-bit data width). Depending on your VBUS load, this value can need adjustment."]
    #[inline(always)]
    pub fn dvbusdis(&self) -> DvbusdisR {
        DvbusdisR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - This value equals: VBUS discharge time in PHY clocks/1,024 The value you use depends whether the PHY is operating at 30 MHz (16-bit data width) or 60 MHz (8-bit data width). Depending on your VBUS load, this value can need adjustment."]
    #[inline(always)]
    #[must_use]
    pub fn dvbusdis(&mut self) -> DvbusdisW<DevgrpDvbusdisSpec> {
        DvbusdisW::new(self, 0)
    }
}
#[doc = "This register specifies the VBUS discharge time after VBUS pulsing during SRP.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dvbusdis::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dvbusdis::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDvbusdisSpec;
impl crate::RegisterSpec for DevgrpDvbusdisSpec {
    type Ux = u32;
    const OFFSET: u64 = 2088u64;
}
#[doc = "`read()` method returns [`devgrp_dvbusdis::R`](R) reader structure"]
impl crate::Readable for DevgrpDvbusdisSpec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_dvbusdis::W`](W) writer structure"]
impl crate::Writable for DevgrpDvbusdisSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_dvbusdis to value 0x17d7"]
impl crate::Resettable for DevgrpDvbusdisSpec {
    const RESET_VALUE: u32 = 0x17d7;
}
