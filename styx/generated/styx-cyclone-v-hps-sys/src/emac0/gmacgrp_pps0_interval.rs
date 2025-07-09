// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_PPS0_Interval` reader"]
pub type R = crate::R<GmacgrpPps0IntervalSpec>;
#[doc = "Register `gmacgrp_PPS0_Interval` writer"]
pub type W = crate::W<GmacgrpPps0IntervalSpec>;
#[doc = "Field `ppsint` reader - These bits store the interval between the rising edges of PPS0 signal output in terms of units of sub-second increment value. You need to program one value less than the required interval. For example, if the PTP reference clock is 50 MHz (period of 20ns), and desired interval between rising edges of PPS0 signal output is 100ns (that is, five units of sub-second increment value), then you should program value 4 (5 -1) in this register."]
pub type PpsintR = crate::FieldReader<u32>;
#[doc = "Field `ppsint` writer - These bits store the interval between the rising edges of PPS0 signal output in terms of units of sub-second increment value. You need to program one value less than the required interval. For example, if the PTP reference clock is 50 MHz (period of 20ns), and desired interval between rising edges of PPS0 signal output is 100ns (that is, five units of sub-second increment value), then you should program value 4 (5 -1) in this register."]
pub type PpsintW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - These bits store the interval between the rising edges of PPS0 signal output in terms of units of sub-second increment value. You need to program one value less than the required interval. For example, if the PTP reference clock is 50 MHz (period of 20ns), and desired interval between rising edges of PPS0 signal output is 100ns (that is, five units of sub-second increment value), then you should program value 4 (5 -1) in this register."]
    #[inline(always)]
    pub fn ppsint(&self) -> PpsintR {
        PpsintR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - These bits store the interval between the rising edges of PPS0 signal output in terms of units of sub-second increment value. You need to program one value less than the required interval. For example, if the PTP reference clock is 50 MHz (period of 20ns), and desired interval between rising edges of PPS0 signal output is 100ns (that is, five units of sub-second increment value), then you should program value 4 (5 -1) in this register."]
    #[inline(always)]
    #[must_use]
    pub fn ppsint(&mut self) -> PpsintW<GmacgrpPps0IntervalSpec> {
        PpsintW::new(self, 0)
    }
}
#[doc = "The PPS0 Interval register contains the number of units of sub-second increment value between the rising edges of PPS0 signal output (ptp_pps_o\\[0\\]).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_pps0_interval::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_pps0_interval::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpPps0IntervalSpec;
impl crate::RegisterSpec for GmacgrpPps0IntervalSpec {
    type Ux = u32;
    const OFFSET: u64 = 1888u64;
}
#[doc = "`read()` method returns [`gmacgrp_pps0_interval::R`](R) reader structure"]
impl crate::Readable for GmacgrpPps0IntervalSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_pps0_interval::W`](W) writer structure"]
impl crate::Writable for GmacgrpPps0IntervalSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_PPS0_Interval to value 0"]
impl crate::Resettable for GmacgrpPps0IntervalSpec {
    const RESET_VALUE: u32 = 0;
}
