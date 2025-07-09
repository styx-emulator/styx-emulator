// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Sub_Second_Increment` reader"]
pub type R = crate::R<GmacgrpSubSecondIncrementSpec>;
#[doc = "Register `gmacgrp_Sub_Second_Increment` writer"]
pub type W = crate::W<GmacgrpSubSecondIncrementSpec>;
#[doc = "Field `ssinc` reader - The value programmed in this field is accumulated every clock cycle (of clk_ptp_i) with the contents of the sub-second register. For example, when PTP clock is 50 MHz (period is 20 ns), you should program 20 (0x14) when the System Time-Nanoseconds register has an accuracy of 1 ns (TSCTRLSSR bit is set). When TSCTRLSSR is clear, the Nanoseconds register has a resolution of ~0.465ns. In this case, you should program a value of 43 (0x2B) that is derived by 20ns/0.465."]
pub type SsincR = crate::FieldReader;
#[doc = "Field `ssinc` writer - The value programmed in this field is accumulated every clock cycle (of clk_ptp_i) with the contents of the sub-second register. For example, when PTP clock is 50 MHz (period is 20 ns), you should program 20 (0x14) when the System Time-Nanoseconds register has an accuracy of 1 ns (TSCTRLSSR bit is set). When TSCTRLSSR is clear, the Nanoseconds register has a resolution of ~0.465ns. In this case, you should program a value of 43 (0x2B) that is derived by 20ns/0.465."]
pub type SsincW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - The value programmed in this field is accumulated every clock cycle (of clk_ptp_i) with the contents of the sub-second register. For example, when PTP clock is 50 MHz (period is 20 ns), you should program 20 (0x14) when the System Time-Nanoseconds register has an accuracy of 1 ns (TSCTRLSSR bit is set). When TSCTRLSSR is clear, the Nanoseconds register has a resolution of ~0.465ns. In this case, you should program a value of 43 (0x2B) that is derived by 20ns/0.465."]
    #[inline(always)]
    pub fn ssinc(&self) -> SsincR {
        SsincR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - The value programmed in this field is accumulated every clock cycle (of clk_ptp_i) with the contents of the sub-second register. For example, when PTP clock is 50 MHz (period is 20 ns), you should program 20 (0x14) when the System Time-Nanoseconds register has an accuracy of 1 ns (TSCTRLSSR bit is set). When TSCTRLSSR is clear, the Nanoseconds register has a resolution of ~0.465ns. In this case, you should program a value of 43 (0x2B) that is derived by 20ns/0.465."]
    #[inline(always)]
    #[must_use]
    pub fn ssinc(&mut self) -> SsincW<GmacgrpSubSecondIncrementSpec> {
        SsincW::new(self, 0)
    }
}
#[doc = "In the Coarse Update mode (TSCFUPDT bit in Register 448), the value in this register is added to the system time every clock cycle of clk_ptp_ref_i. In the Fine Update mode, the value in this register is added to the system time whenever the Accumulator gets an overflow.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_sub_second_increment::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_sub_second_increment::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpSubSecondIncrementSpec;
impl crate::RegisterSpec for GmacgrpSubSecondIncrementSpec {
    type Ux = u32;
    const OFFSET: u64 = 1796u64;
}
#[doc = "`read()` method returns [`gmacgrp_sub_second_increment::R`](R) reader structure"]
impl crate::Readable for GmacgrpSubSecondIncrementSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_sub_second_increment::W`](W) writer structure"]
impl crate::Writable for GmacgrpSubSecondIncrementSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Sub_Second_Increment to value 0"]
impl crate::Resettable for GmacgrpSubSecondIncrementSpec {
    const RESET_VALUE: u32 = 0;
}
