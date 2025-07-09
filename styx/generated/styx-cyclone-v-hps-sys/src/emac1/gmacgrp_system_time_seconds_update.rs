// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_System_Time_Seconds_Update` reader"]
pub type R = crate::R<GmacgrpSystemTimeSecondsUpdateSpec>;
#[doc = "Register `gmacgrp_System_Time_Seconds_Update` writer"]
pub type W = crate::W<GmacgrpSystemTimeSecondsUpdateSpec>;
#[doc = "Field `tss` reader - The value in this field indicates the time in seconds to be initialized or added to the system time."]
pub type TssR = crate::FieldReader<u32>;
#[doc = "Field `tss` writer - The value in this field indicates the time in seconds to be initialized or added to the system time."]
pub type TssW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - The value in this field indicates the time in seconds to be initialized or added to the system time."]
    #[inline(always)]
    pub fn tss(&self) -> TssR {
        TssR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - The value in this field indicates the time in seconds to be initialized or added to the system time."]
    #[inline(always)]
    #[must_use]
    pub fn tss(&mut self) -> TssW<GmacgrpSystemTimeSecondsUpdateSpec> {
        TssW::new(self, 0)
    }
}
#[doc = "The System Time - Seconds Update register, along with the System Time - Nanoseconds Update register, initializes or updates the system time maintained by the MAC. You must write both of these registers before setting the TSINIT or TSUPDT bits in the Timestamp Control register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_system_time_seconds_update::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_system_time_seconds_update::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpSystemTimeSecondsUpdateSpec;
impl crate::RegisterSpec for GmacgrpSystemTimeSecondsUpdateSpec {
    type Ux = u32;
    const OFFSET: u64 = 1808u64;
}
#[doc = "`read()` method returns [`gmacgrp_system_time_seconds_update::R`](R) reader structure"]
impl crate::Readable for GmacgrpSystemTimeSecondsUpdateSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_system_time_seconds_update::W`](W) writer structure"]
impl crate::Writable for GmacgrpSystemTimeSecondsUpdateSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_System_Time_Seconds_Update to value 0"]
impl crate::Resettable for GmacgrpSystemTimeSecondsUpdateSpec {
    const RESET_VALUE: u32 = 0;
}
