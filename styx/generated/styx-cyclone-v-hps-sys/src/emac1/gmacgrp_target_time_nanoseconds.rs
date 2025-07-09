// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Target_Time_Nanoseconds` reader"]
pub type R = crate::R<GmacgrpTargetTimeNanosecondsSpec>;
#[doc = "Register `gmacgrp_Target_Time_Nanoseconds` writer"]
pub type W = crate::W<GmacgrpTargetTimeNanosecondsSpec>;
#[doc = "Field `ttslo` reader - This register stores the time in (signed) nanoseconds. When the value of the timestamp matches the both Target Timestamp registers, then based on the TRGTMODSEL0 field (Bits \\[6:5\\]) in Register 459 (PPS Control Register), the MAC starts or stops the PPS signal output and generates an interrupt (if enabled). This value should not exceed 0x3B9A_C9FF when TSCTRLSSR is set in the Timestamp control register. The actual start or stop time of the PPS signal output may have an error margin up to one unit of sub-second increment value."]
pub type TtsloR = crate::FieldReader<u32>;
#[doc = "Field `ttslo` writer - This register stores the time in (signed) nanoseconds. When the value of the timestamp matches the both Target Timestamp registers, then based on the TRGTMODSEL0 field (Bits \\[6:5\\]) in Register 459 (PPS Control Register), the MAC starts or stops the PPS signal output and generates an interrupt (if enabled). This value should not exceed 0x3B9A_C9FF when TSCTRLSSR is set in the Timestamp control register. The actual start or stop time of the PPS signal output may have an error margin up to one unit of sub-second increment value."]
pub type TtsloW<'a, REG> = crate::FieldWriter<'a, REG, 31, u32>;
#[doc = "Field `trgtbusy` reader - The MAC sets this bit when the PPSCMD field (Bits\\[3:0\\]) in Register 459 (PPS Control Register) is programmed to 010 or 011. Programming the PPSCMD field to 010 or 011, instructs the MAC to synchronize the Target Time Registers to the PTP clock domain. The MAC clears this bit after synchronizing the Target Time Registers to the PTP clock domain The application must not update the Target Time Registers when this bit is read as 1. Otherwise, the synchronization of the previous programmed time gets corrupted. This bit is reserved when the Enable Flexible Pulse-Per-Second Output feature is not selected."]
pub type TrgtbusyR = crate::BitReader;
#[doc = "Field `trgtbusy` writer - The MAC sets this bit when the PPSCMD field (Bits\\[3:0\\]) in Register 459 (PPS Control Register) is programmed to 010 or 011. Programming the PPSCMD field to 010 or 011, instructs the MAC to synchronize the Target Time Registers to the PTP clock domain. The MAC clears this bit after synchronizing the Target Time Registers to the PTP clock domain The application must not update the Target Time Registers when this bit is read as 1. Otherwise, the synchronization of the previous programmed time gets corrupted. This bit is reserved when the Enable Flexible Pulse-Per-Second Output feature is not selected."]
pub type TrgtbusyW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:30 - This register stores the time in (signed) nanoseconds. When the value of the timestamp matches the both Target Timestamp registers, then based on the TRGTMODSEL0 field (Bits \\[6:5\\]) in Register 459 (PPS Control Register), the MAC starts or stops the PPS signal output and generates an interrupt (if enabled). This value should not exceed 0x3B9A_C9FF when TSCTRLSSR is set in the Timestamp control register. The actual start or stop time of the PPS signal output may have an error margin up to one unit of sub-second increment value."]
    #[inline(always)]
    pub fn ttslo(&self) -> TtsloR {
        TtsloR::new(self.bits & 0x7fff_ffff)
    }
    #[doc = "Bit 31 - The MAC sets this bit when the PPSCMD field (Bits\\[3:0\\]) in Register 459 (PPS Control Register) is programmed to 010 or 011. Programming the PPSCMD field to 010 or 011, instructs the MAC to synchronize the Target Time Registers to the PTP clock domain. The MAC clears this bit after synchronizing the Target Time Registers to the PTP clock domain The application must not update the Target Time Registers when this bit is read as 1. Otherwise, the synchronization of the previous programmed time gets corrupted. This bit is reserved when the Enable Flexible Pulse-Per-Second Output feature is not selected."]
    #[inline(always)]
    pub fn trgtbusy(&self) -> TrgtbusyR {
        TrgtbusyR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:30 - This register stores the time in (signed) nanoseconds. When the value of the timestamp matches the both Target Timestamp registers, then based on the TRGTMODSEL0 field (Bits \\[6:5\\]) in Register 459 (PPS Control Register), the MAC starts or stops the PPS signal output and generates an interrupt (if enabled). This value should not exceed 0x3B9A_C9FF when TSCTRLSSR is set in the Timestamp control register. The actual start or stop time of the PPS signal output may have an error margin up to one unit of sub-second increment value."]
    #[inline(always)]
    #[must_use]
    pub fn ttslo(&mut self) -> TtsloW<GmacgrpTargetTimeNanosecondsSpec> {
        TtsloW::new(self, 0)
    }
    #[doc = "Bit 31 - The MAC sets this bit when the PPSCMD field (Bits\\[3:0\\]) in Register 459 (PPS Control Register) is programmed to 010 or 011. Programming the PPSCMD field to 010 or 011, instructs the MAC to synchronize the Target Time Registers to the PTP clock domain. The MAC clears this bit after synchronizing the Target Time Registers to the PTP clock domain The application must not update the Target Time Registers when this bit is read as 1. Otherwise, the synchronization of the previous programmed time gets corrupted. This bit is reserved when the Enable Flexible Pulse-Per-Second Output feature is not selected."]
    #[inline(always)]
    #[must_use]
    pub fn trgtbusy(&mut self) -> TrgtbusyW<GmacgrpTargetTimeNanosecondsSpec> {
        TrgtbusyW::new(self, 31)
    }
}
#[doc = "Target time\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_target_time_nanoseconds::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_target_time_nanoseconds::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTargetTimeNanosecondsSpec;
impl crate::RegisterSpec for GmacgrpTargetTimeNanosecondsSpec {
    type Ux = u32;
    const OFFSET: u64 = 1824u64;
}
#[doc = "`read()` method returns [`gmacgrp_target_time_nanoseconds::R`](R) reader structure"]
impl crate::Readable for GmacgrpTargetTimeNanosecondsSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_target_time_nanoseconds::W`](W) writer structure"]
impl crate::Writable for GmacgrpTargetTimeNanosecondsSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Target_Time_Nanoseconds to value 0"]
impl crate::Resettable for GmacgrpTargetTimeNanosecondsSpec {
    const RESET_VALUE: u32 = 0;
}
