// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Timestamp_Addend` reader"]
pub type R = crate::R<GmacgrpTimestampAddendSpec>;
#[doc = "Register `gmacgrp_Timestamp_Addend` writer"]
pub type W = crate::W<GmacgrpTimestampAddendSpec>;
#[doc = "Field `tsar` reader - This field indicates the 32-bit time value to be added to the Accumulator register to achieve time synchronization."]
pub type TsarR = crate::FieldReader<u32>;
#[doc = "Field `tsar` writer - This field indicates the 32-bit time value to be added to the Accumulator register to achieve time synchronization."]
pub type TsarW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This field indicates the 32-bit time value to be added to the Accumulator register to achieve time synchronization."]
    #[inline(always)]
    pub fn tsar(&self) -> TsarR {
        TsarR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This field indicates the 32-bit time value to be added to the Accumulator register to achieve time synchronization."]
    #[inline(always)]
    #[must_use]
    pub fn tsar(&mut self) -> TsarW<GmacgrpTimestampAddendSpec> {
        TsarW::new(self, 0)
    }
}
#[doc = "This register value is used only when the system time is configured for Fine Update mode (TSCFUPDT bit in Register 448). This register content is added to a 32-bit accumulator in every clock cycle (of clk_ptp_ref_i) and the system time is updated whenever the accumulator overflows.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_timestamp_addend::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_timestamp_addend::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTimestampAddendSpec;
impl crate::RegisterSpec for GmacgrpTimestampAddendSpec {
    type Ux = u32;
    const OFFSET: u64 = 1816u64;
}
#[doc = "`read()` method returns [`gmacgrp_timestamp_addend::R`](R) reader structure"]
impl crate::Readable for GmacgrpTimestampAddendSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_timestamp_addend::W`](W) writer structure"]
impl crate::Writable for GmacgrpTimestampAddendSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Timestamp_Addend to value 0"]
impl crate::Resettable for GmacgrpTimestampAddendSpec {
    const RESET_VALUE: u32 = 0;
}
