// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_System_Time_Nanoseconds` reader"]
pub type R = crate::R<GmacgrpSystemTimeNanosecondsSpec>;
#[doc = "Register `gmacgrp_System_Time_Nanoseconds` writer"]
pub type W = crate::W<GmacgrpSystemTimeNanosecondsSpec>;
#[doc = "Field `tsss` reader - The value in this field has the sub second representation of time, with an accuracy of 0.46 ns. When bit 9 (TSCTRLSSR) is set in Register 448 (Timestamp Control Register), each bit represents 1 ns and the maximum value is 0x3B9A_C9FF, after which it rolls-over to zero."]
pub type TsssR = crate::FieldReader<u32>;
#[doc = "Field `tsss` writer - The value in this field has the sub second representation of time, with an accuracy of 0.46 ns. When bit 9 (TSCTRLSSR) is set in Register 448 (Timestamp Control Register), each bit represents 1 ns and the maximum value is 0x3B9A_C9FF, after which it rolls-over to zero."]
pub type TsssW<'a, REG> = crate::FieldWriter<'a, REG, 31, u32>;
impl R {
    #[doc = "Bits 0:30 - The value in this field has the sub second representation of time, with an accuracy of 0.46 ns. When bit 9 (TSCTRLSSR) is set in Register 448 (Timestamp Control Register), each bit represents 1 ns and the maximum value is 0x3B9A_C9FF, after which it rolls-over to zero."]
    #[inline(always)]
    pub fn tsss(&self) -> TsssR {
        TsssR::new(self.bits & 0x7fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:30 - The value in this field has the sub second representation of time, with an accuracy of 0.46 ns. When bit 9 (TSCTRLSSR) is set in Register 448 (Timestamp Control Register), each bit represents 1 ns and the maximum value is 0x3B9A_C9FF, after which it rolls-over to zero."]
    #[inline(always)]
    #[must_use]
    pub fn tsss(&mut self) -> TsssW<GmacgrpSystemTimeNanosecondsSpec> {
        TsssW::new(self, 0)
    }
}
#[doc = "The value in this field has the sub second representation of time, with an accuracy of 0.46 ns. When TSCTRLSSR is set, each bit represents 1 ns and the maximum value is 0x3B9A_C9FF, after which it rolls-over to zero.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_system_time_nanoseconds::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpSystemTimeNanosecondsSpec;
impl crate::RegisterSpec for GmacgrpSystemTimeNanosecondsSpec {
    type Ux = u32;
    const OFFSET: u64 = 1804u64;
}
#[doc = "`read()` method returns [`gmacgrp_system_time_nanoseconds::R`](R) reader structure"]
impl crate::Readable for GmacgrpSystemTimeNanosecondsSpec {}
#[doc = "`reset()` method sets gmacgrp_System_Time_Nanoseconds to value 0"]
impl crate::Resettable for GmacgrpSystemTimeNanosecondsSpec {
    const RESET_VALUE: u32 = 0;
}
