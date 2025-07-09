// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_PPS0_Width` reader"]
pub type R = crate::R<GmacgrpPps0WidthSpec>;
#[doc = "Register `gmacgrp_PPS0_Width` writer"]
pub type W = crate::W<GmacgrpPps0WidthSpec>;
#[doc = "Field `ppswidth` reader - These bits store the width between the rising edge and corresponding falling edge of the PPS0 signal output in terms of units of sub-second increment value. You need to program one value less than the required interval. For example, if PTP reference clock is 50 MHz (period of 20ns), and desired width between the rising and corresponding falling edges of PPS0 signal output is 80ns (that is, four units of sub-second increment value), then you should program value 3 (4-1) in this register. Note: The value programmed in this register must be lesser than the value programmed in Register 472 (PPS0 Interval Register)."]
pub type PpswidthR = crate::FieldReader<u32>;
#[doc = "Field `ppswidth` writer - These bits store the width between the rising edge and corresponding falling edge of the PPS0 signal output in terms of units of sub-second increment value. You need to program one value less than the required interval. For example, if PTP reference clock is 50 MHz (period of 20ns), and desired width between the rising and corresponding falling edges of PPS0 signal output is 80ns (that is, four units of sub-second increment value), then you should program value 3 (4-1) in this register. Note: The value programmed in this register must be lesser than the value programmed in Register 472 (PPS0 Interval Register)."]
pub type PpswidthW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - These bits store the width between the rising edge and corresponding falling edge of the PPS0 signal output in terms of units of sub-second increment value. You need to program one value less than the required interval. For example, if PTP reference clock is 50 MHz (period of 20ns), and desired width between the rising and corresponding falling edges of PPS0 signal output is 80ns (that is, four units of sub-second increment value), then you should program value 3 (4-1) in this register. Note: The value programmed in this register must be lesser than the value programmed in Register 472 (PPS0 Interval Register)."]
    #[inline(always)]
    pub fn ppswidth(&self) -> PpswidthR {
        PpswidthR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - These bits store the width between the rising edge and corresponding falling edge of the PPS0 signal output in terms of units of sub-second increment value. You need to program one value less than the required interval. For example, if PTP reference clock is 50 MHz (period of 20ns), and desired width between the rising and corresponding falling edges of PPS0 signal output is 80ns (that is, four units of sub-second increment value), then you should program value 3 (4-1) in this register. Note: The value programmed in this register must be lesser than the value programmed in Register 472 (PPS0 Interval Register)."]
    #[inline(always)]
    #[must_use]
    pub fn ppswidth(&mut self) -> PpswidthW<GmacgrpPps0WidthSpec> {
        PpswidthW::new(self, 0)
    }
}
#[doc = "The PPS0 Width register contains the number of units of sub-second increment value between the rising and corresponding falling edges of the PPS0 signal output (ptp_pps_o\\[0\\]).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_pps0_width::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_pps0_width::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpPps0WidthSpec;
impl crate::RegisterSpec for GmacgrpPps0WidthSpec {
    type Ux = u32;
    const OFFSET: u64 = 1892u64;
}
#[doc = "`read()` method returns [`gmacgrp_pps0_width::R`](R) reader structure"]
impl crate::Readable for GmacgrpPps0WidthSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_pps0_width::W`](W) writer structure"]
impl crate::Writable for GmacgrpPps0WidthSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_PPS0_Width to value 0"]
impl crate::Resettable for GmacgrpPps0WidthSpec {
    const RESET_VALUE: u32 = 0;
}
