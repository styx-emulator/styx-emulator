// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmagrp_Receive_Interrupt_Watchdog_Timer` reader"]
pub type R = crate::R<DmagrpReceiveInterruptWatchdogTimerSpec>;
#[doc = "Register `dmagrp_Receive_Interrupt_Watchdog_Timer` writer"]
pub type W = crate::W<DmagrpReceiveInterruptWatchdogTimerSpec>;
#[doc = "Field `riwt` reader - This bit indicates the number of system clock cycles multiplied by 256 for which the watchdog timer is set. The watchdog timer gets triggered with the programmed value after the Rx DMA completes the transfer of a frame for which the RI status bit is not set because of the setting in the corresponding descriptor RDES1\\[31\\]. When the watchdog timer runs out, the RI bit is set and the timer is stopped. The watchdog timer is reset when the RI bit is set high because of automatic setting of RI as per RDES1\\[31\\]
of any received frame."]
pub type RiwtR = crate::FieldReader;
#[doc = "Field `riwt` writer - This bit indicates the number of system clock cycles multiplied by 256 for which the watchdog timer is set. The watchdog timer gets triggered with the programmed value after the Rx DMA completes the transfer of a frame for which the RI status bit is not set because of the setting in the corresponding descriptor RDES1\\[31\\]. When the watchdog timer runs out, the RI bit is set and the timer is stopped. The watchdog timer is reset when the RI bit is set high because of automatic setting of RI as per RDES1\\[31\\]
of any received frame."]
pub type RiwtW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - This bit indicates the number of system clock cycles multiplied by 256 for which the watchdog timer is set. The watchdog timer gets triggered with the programmed value after the Rx DMA completes the transfer of a frame for which the RI status bit is not set because of the setting in the corresponding descriptor RDES1\\[31\\]. When the watchdog timer runs out, the RI bit is set and the timer is stopped. The watchdog timer is reset when the RI bit is set high because of automatic setting of RI as per RDES1\\[31\\]
of any received frame."]
    #[inline(always)]
    pub fn riwt(&self) -> RiwtR {
        RiwtR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - This bit indicates the number of system clock cycles multiplied by 256 for which the watchdog timer is set. The watchdog timer gets triggered with the programmed value after the Rx DMA completes the transfer of a frame for which the RI status bit is not set because of the setting in the corresponding descriptor RDES1\\[31\\]. When the watchdog timer runs out, the RI bit is set and the timer is stopped. The watchdog timer is reset when the RI bit is set high because of automatic setting of RI as per RDES1\\[31\\]
of any received frame."]
    #[inline(always)]
    #[must_use]
    pub fn riwt(&mut self) -> RiwtW<DmagrpReceiveInterruptWatchdogTimerSpec> {
        RiwtW::new(self, 0)
    }
}
#[doc = "This register, when written with non-zero value, enables the watchdog timer for the Receive Interrupt (Bit 6) of Register 5 (Status Register)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_receive_interrupt_watchdog_timer::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_receive_interrupt_watchdog_timer::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpReceiveInterruptWatchdogTimerSpec;
impl crate::RegisterSpec for DmagrpReceiveInterruptWatchdogTimerSpec {
    type Ux = u32;
    const OFFSET: u64 = 4132u64;
}
#[doc = "`read()` method returns [`dmagrp_receive_interrupt_watchdog_timer::R`](R) reader structure"]
impl crate::Readable for DmagrpReceiveInterruptWatchdogTimerSpec {}
#[doc = "`write(|w| ..)` method takes [`dmagrp_receive_interrupt_watchdog_timer::W`](W) writer structure"]
impl crate::Writable for DmagrpReceiveInterruptWatchdogTimerSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmagrp_Receive_Interrupt_Watchdog_Timer to value 0"]
impl crate::Resettable for DmagrpReceiveInterruptWatchdogTimerSpec {
    const RESET_VALUE: u32 = 0;
}
