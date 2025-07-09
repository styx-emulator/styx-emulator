// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_PPS_Control` reader"]
pub type R = crate::R<GmacgrpPpsControlSpec>;
#[doc = "Register `gmacgrp_PPS_Control` writer"]
pub type W = crate::W<GmacgrpPpsControlSpec>;
#[doc = "Field `ppsctrl_ppscmd` reader - PPSCTRL0: PPS0 Output Frequency Control This field controls the frequency of the PPS0 output (ptp_pps_o\\[0\\]) signal. The default value of PPSCTRL is 0000, and the PPS output is 1 pulse (of width clk_ptp_i) every second. For other values of PPSCTRL, the PPS output becomes a generated clock of following frequencies: -0001: The binary rollover is 2 Hz, and the digital rollover is 1 Hz. -0010: The binary rollover is 4 Hz, and the digital rollover is 2 Hz. -0011: The binary rollover is 8 Hz, and the digital rollover is 4 Hz. -0100: The binary rollover is 16 Hz, and the digital rollover is 8 Hz. -... -1111: The binary rollover is 32.768 KHz, and the digital rollover is 16.384 KHz. Note: In the binary rollover mode, the PPS output (ptp_pps_o) has a duty cycle of 50 percent with these frequencies. In the digital rollover mode, the PPS output frequency is an average number. The actual clock is of different frequency that gets synchronized every second. For example: * When PPSCTRL = 0001, the PPS (1 Hz) has a low period of 537 ms and a high period of 463 ms * When PPSCTRL = 0010, the PPS (2 Hz) is a sequence of: - One clock of 50 percent duty cycle and 537 ms period - Second clock of 463 ms period (268 ms low and 195 ms high) * When PPSCTRL = 0011, the PPS (4 Hz) is a sequence of: - Three clocks of 50 percent duty cycle and 268 ms period - Fourth clock of 195 ms period (134 ms low and 61 ms high) This behavior is because of the non-linear toggling of bits in the digital rollover mode in Register 451 (System Time - Nanoseconds Register). Flexible PPS0 Output (ptp_pps_o\\[0\\]) Control Programming these bits with a non-zero value instructs the MAC to initiate an event. Once the command is transferred or synchronized to the PTP clock domain, these bits get cleared automatically. The Software should ensure that these bits are programmed only when they are all-zero. The following list describes the values of PPSCMD0: * 0000: No Command * 0001: START Single Pulse This command generates single pulse rising at the start point defined in Target Time Registers (register 455 and 456) and of a duration defined in the PPS0 Width Register. * 0010: START Pulse Train This command generates the train of pulses rising at the start point defined in the Target Time Registers and of a duration defined in the PPS0 Width Register and repeated at interval defined in the PPS Interval Register. By default, the PPS pulse train is free-running unless stopped by 'STOP Pulse train at time' or 'STOP Pulse Train immediately' commands. * 0011: Cancel START This command cancels the START Single Pulse and START Pulse Train commands if the system time has not crossed the programmed start time. * 0100: STOP Pulse train at time This command stops the train of pulses initiated by the START Pulse Train command (PPSCMD = 0010) after the time programmed in the Target Time registers elapses. * 0101: STOP Pulse Train immediately This command immediately stops the train of pulses initiated by the START Pulse Train command (PPSCMD = 0010). * 0110: Cancel STOP Pulse train This command cancels the STOP pulse train at time command if the programmed stop time has not elapsed. The PPS pulse train becomes free-running on the successful execution of this command. * 0111-1111: Reserved"]
pub type PpsctrlPpscmdR = crate::FieldReader;
#[doc = "Field `ppsctrl_ppscmd` writer - PPSCTRL0: PPS0 Output Frequency Control This field controls the frequency of the PPS0 output (ptp_pps_o\\[0\\]) signal. The default value of PPSCTRL is 0000, and the PPS output is 1 pulse (of width clk_ptp_i) every second. For other values of PPSCTRL, the PPS output becomes a generated clock of following frequencies: -0001: The binary rollover is 2 Hz, and the digital rollover is 1 Hz. -0010: The binary rollover is 4 Hz, and the digital rollover is 2 Hz. -0011: The binary rollover is 8 Hz, and the digital rollover is 4 Hz. -0100: The binary rollover is 16 Hz, and the digital rollover is 8 Hz. -... -1111: The binary rollover is 32.768 KHz, and the digital rollover is 16.384 KHz. Note: In the binary rollover mode, the PPS output (ptp_pps_o) has a duty cycle of 50 percent with these frequencies. In the digital rollover mode, the PPS output frequency is an average number. The actual clock is of different frequency that gets synchronized every second. For example: * When PPSCTRL = 0001, the PPS (1 Hz) has a low period of 537 ms and a high period of 463 ms * When PPSCTRL = 0010, the PPS (2 Hz) is a sequence of: - One clock of 50 percent duty cycle and 537 ms period - Second clock of 463 ms period (268 ms low and 195 ms high) * When PPSCTRL = 0011, the PPS (4 Hz) is a sequence of: - Three clocks of 50 percent duty cycle and 268 ms period - Fourth clock of 195 ms period (134 ms low and 61 ms high) This behavior is because of the non-linear toggling of bits in the digital rollover mode in Register 451 (System Time - Nanoseconds Register). Flexible PPS0 Output (ptp_pps_o\\[0\\]) Control Programming these bits with a non-zero value instructs the MAC to initiate an event. Once the command is transferred or synchronized to the PTP clock domain, these bits get cleared automatically. The Software should ensure that these bits are programmed only when they are all-zero. The following list describes the values of PPSCMD0: * 0000: No Command * 0001: START Single Pulse This command generates single pulse rising at the start point defined in Target Time Registers (register 455 and 456) and of a duration defined in the PPS0 Width Register. * 0010: START Pulse Train This command generates the train of pulses rising at the start point defined in the Target Time Registers and of a duration defined in the PPS0 Width Register and repeated at interval defined in the PPS Interval Register. By default, the PPS pulse train is free-running unless stopped by 'STOP Pulse train at time' or 'STOP Pulse Train immediately' commands. * 0011: Cancel START This command cancels the START Single Pulse and START Pulse Train commands if the system time has not crossed the programmed start time. * 0100: STOP Pulse train at time This command stops the train of pulses initiated by the START Pulse Train command (PPSCMD = 0010) after the time programmed in the Target Time registers elapses. * 0101: STOP Pulse Train immediately This command immediately stops the train of pulses initiated by the START Pulse Train command (PPSCMD = 0010). * 0110: Cancel STOP Pulse train This command cancels the STOP pulse train at time command if the programmed stop time has not elapsed. The PPS pulse train becomes free-running on the successful execution of this command. * 0111-1111: Reserved"]
pub type PpsctrlPpscmdW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "When set low, Bits\\[3:0\\]
function as PPSCTRL (backward compatible). When set high, Bits\\[3:0\\]
function as PPSCMD.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ppsen0 {
    #[doc = "0: `0`"]
    Ppsctrl = 0,
    #[doc = "1: `1`"]
    Ppscmd = 1,
}
impl From<Ppsen0> for bool {
    #[inline(always)]
    fn from(variant: Ppsen0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ppsen0` reader - When set low, Bits\\[3:0\\]
function as PPSCTRL (backward compatible). When set high, Bits\\[3:0\\]
function as PPSCMD."]
pub type Ppsen0R = crate::BitReader<Ppsen0>;
impl Ppsen0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ppsen0 {
        match self.bits {
            false => Ppsen0::Ppsctrl,
            true => Ppsen0::Ppscmd,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ppsctrl(&self) -> bool {
        *self == Ppsen0::Ppsctrl
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_ppscmd(&self) -> bool {
        *self == Ppsen0::Ppscmd
    }
}
#[doc = "Field `ppsen0` writer - When set low, Bits\\[3:0\\]
function as PPSCTRL (backward compatible). When set high, Bits\\[3:0\\]
function as PPSCMD."]
pub type Ppsen0W<'a, REG> = crate::BitWriter<'a, REG, Ppsen0>;
impl<'a, REG> Ppsen0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn ppsctrl(self) -> &'a mut crate::W<REG> {
        self.variant(Ppsen0::Ppsctrl)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn ppscmd(self) -> &'a mut crate::W<REG> {
        self.variant(Ppsen0::Ppscmd)
    }
}
#[doc = "This field indicates the Target Time registers (register 455 and 456) mode for PPS0 output signal\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Trgtmodsel0 {
    #[doc = "0: `0`"]
    Trgtinteronly = 0,
    #[doc = "2: `10`"]
    Trgtintpps0 = 2,
    #[doc = "3: `11`"]
    Trgtnointer = 3,
}
impl From<Trgtmodsel0> for u8 {
    #[inline(always)]
    fn from(variant: Trgtmodsel0) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Trgtmodsel0 {
    type Ux = u8;
}
#[doc = "Field `trgtmodsel0` reader - This field indicates the Target Time registers (register 455 and 456) mode for PPS0 output signal"]
pub type Trgtmodsel0R = crate::FieldReader<Trgtmodsel0>;
impl Trgtmodsel0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Trgtmodsel0> {
        match self.bits {
            0 => Some(Trgtmodsel0::Trgtinteronly),
            2 => Some(Trgtmodsel0::Trgtintpps0),
            3 => Some(Trgtmodsel0::Trgtnointer),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_trgtinteronly(&self) -> bool {
        *self == Trgtmodsel0::Trgtinteronly
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_trgtintpps0(&self) -> bool {
        *self == Trgtmodsel0::Trgtintpps0
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_trgtnointer(&self) -> bool {
        *self == Trgtmodsel0::Trgtnointer
    }
}
#[doc = "Field `trgtmodsel0` writer - This field indicates the Target Time registers (register 455 and 456) mode for PPS0 output signal"]
pub type Trgtmodsel0W<'a, REG> = crate::FieldWriter<'a, REG, 2, Trgtmodsel0>;
impl<'a, REG> Trgtmodsel0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn trgtinteronly(self) -> &'a mut crate::W<REG> {
        self.variant(Trgtmodsel0::Trgtinteronly)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn trgtintpps0(self) -> &'a mut crate::W<REG> {
        self.variant(Trgtmodsel0::Trgtintpps0)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn trgtnointer(self) -> &'a mut crate::W<REG> {
        self.variant(Trgtmodsel0::Trgtnointer)
    }
}
impl R {
    #[doc = "Bits 0:3 - PPSCTRL0: PPS0 Output Frequency Control This field controls the frequency of the PPS0 output (ptp_pps_o\\[0\\]) signal. The default value of PPSCTRL is 0000, and the PPS output is 1 pulse (of width clk_ptp_i) every second. For other values of PPSCTRL, the PPS output becomes a generated clock of following frequencies: -0001: The binary rollover is 2 Hz, and the digital rollover is 1 Hz. -0010: The binary rollover is 4 Hz, and the digital rollover is 2 Hz. -0011: The binary rollover is 8 Hz, and the digital rollover is 4 Hz. -0100: The binary rollover is 16 Hz, and the digital rollover is 8 Hz. -... -1111: The binary rollover is 32.768 KHz, and the digital rollover is 16.384 KHz. Note: In the binary rollover mode, the PPS output (ptp_pps_o) has a duty cycle of 50 percent with these frequencies. In the digital rollover mode, the PPS output frequency is an average number. The actual clock is of different frequency that gets synchronized every second. For example: * When PPSCTRL = 0001, the PPS (1 Hz) has a low period of 537 ms and a high period of 463 ms * When PPSCTRL = 0010, the PPS (2 Hz) is a sequence of: - One clock of 50 percent duty cycle and 537 ms period - Second clock of 463 ms period (268 ms low and 195 ms high) * When PPSCTRL = 0011, the PPS (4 Hz) is a sequence of: - Three clocks of 50 percent duty cycle and 268 ms period - Fourth clock of 195 ms period (134 ms low and 61 ms high) This behavior is because of the non-linear toggling of bits in the digital rollover mode in Register 451 (System Time - Nanoseconds Register). Flexible PPS0 Output (ptp_pps_o\\[0\\]) Control Programming these bits with a non-zero value instructs the MAC to initiate an event. Once the command is transferred or synchronized to the PTP clock domain, these bits get cleared automatically. The Software should ensure that these bits are programmed only when they are all-zero. The following list describes the values of PPSCMD0: * 0000: No Command * 0001: START Single Pulse This command generates single pulse rising at the start point defined in Target Time Registers (register 455 and 456) and of a duration defined in the PPS0 Width Register. * 0010: START Pulse Train This command generates the train of pulses rising at the start point defined in the Target Time Registers and of a duration defined in the PPS0 Width Register and repeated at interval defined in the PPS Interval Register. By default, the PPS pulse train is free-running unless stopped by 'STOP Pulse train at time' or 'STOP Pulse Train immediately' commands. * 0011: Cancel START This command cancels the START Single Pulse and START Pulse Train commands if the system time has not crossed the programmed start time. * 0100: STOP Pulse train at time This command stops the train of pulses initiated by the START Pulse Train command (PPSCMD = 0010) after the time programmed in the Target Time registers elapses. * 0101: STOP Pulse Train immediately This command immediately stops the train of pulses initiated by the START Pulse Train command (PPSCMD = 0010). * 0110: Cancel STOP Pulse train This command cancels the STOP pulse train at time command if the programmed stop time has not elapsed. The PPS pulse train becomes free-running on the successful execution of this command. * 0111-1111: Reserved"]
    #[inline(always)]
    pub fn ppsctrl_ppscmd(&self) -> PpsctrlPpscmdR {
        PpsctrlPpscmdR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bit 4 - When set low, Bits\\[3:0\\]
function as PPSCTRL (backward compatible). When set high, Bits\\[3:0\\]
function as PPSCMD."]
    #[inline(always)]
    pub fn ppsen0(&self) -> Ppsen0R {
        Ppsen0R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bits 5:6 - This field indicates the Target Time registers (register 455 and 456) mode for PPS0 output signal"]
    #[inline(always)]
    pub fn trgtmodsel0(&self) -> Trgtmodsel0R {
        Trgtmodsel0R::new(((self.bits >> 5) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - PPSCTRL0: PPS0 Output Frequency Control This field controls the frequency of the PPS0 output (ptp_pps_o\\[0\\]) signal. The default value of PPSCTRL is 0000, and the PPS output is 1 pulse (of width clk_ptp_i) every second. For other values of PPSCTRL, the PPS output becomes a generated clock of following frequencies: -0001: The binary rollover is 2 Hz, and the digital rollover is 1 Hz. -0010: The binary rollover is 4 Hz, and the digital rollover is 2 Hz. -0011: The binary rollover is 8 Hz, and the digital rollover is 4 Hz. -0100: The binary rollover is 16 Hz, and the digital rollover is 8 Hz. -... -1111: The binary rollover is 32.768 KHz, and the digital rollover is 16.384 KHz. Note: In the binary rollover mode, the PPS output (ptp_pps_o) has a duty cycle of 50 percent with these frequencies. In the digital rollover mode, the PPS output frequency is an average number. The actual clock is of different frequency that gets synchronized every second. For example: * When PPSCTRL = 0001, the PPS (1 Hz) has a low period of 537 ms and a high period of 463 ms * When PPSCTRL = 0010, the PPS (2 Hz) is a sequence of: - One clock of 50 percent duty cycle and 537 ms period - Second clock of 463 ms period (268 ms low and 195 ms high) * When PPSCTRL = 0011, the PPS (4 Hz) is a sequence of: - Three clocks of 50 percent duty cycle and 268 ms period - Fourth clock of 195 ms period (134 ms low and 61 ms high) This behavior is because of the non-linear toggling of bits in the digital rollover mode in Register 451 (System Time - Nanoseconds Register). Flexible PPS0 Output (ptp_pps_o\\[0\\]) Control Programming these bits with a non-zero value instructs the MAC to initiate an event. Once the command is transferred or synchronized to the PTP clock domain, these bits get cleared automatically. The Software should ensure that these bits are programmed only when they are all-zero. The following list describes the values of PPSCMD0: * 0000: No Command * 0001: START Single Pulse This command generates single pulse rising at the start point defined in Target Time Registers (register 455 and 456) and of a duration defined in the PPS0 Width Register. * 0010: START Pulse Train This command generates the train of pulses rising at the start point defined in the Target Time Registers and of a duration defined in the PPS0 Width Register and repeated at interval defined in the PPS Interval Register. By default, the PPS pulse train is free-running unless stopped by 'STOP Pulse train at time' or 'STOP Pulse Train immediately' commands. * 0011: Cancel START This command cancels the START Single Pulse and START Pulse Train commands if the system time has not crossed the programmed start time. * 0100: STOP Pulse train at time This command stops the train of pulses initiated by the START Pulse Train command (PPSCMD = 0010) after the time programmed in the Target Time registers elapses. * 0101: STOP Pulse Train immediately This command immediately stops the train of pulses initiated by the START Pulse Train command (PPSCMD = 0010). * 0110: Cancel STOP Pulse train This command cancels the STOP pulse train at time command if the programmed stop time has not elapsed. The PPS pulse train becomes free-running on the successful execution of this command. * 0111-1111: Reserved"]
    #[inline(always)]
    #[must_use]
    pub fn ppsctrl_ppscmd(&mut self) -> PpsctrlPpscmdW<GmacgrpPpsControlSpec> {
        PpsctrlPpscmdW::new(self, 0)
    }
    #[doc = "Bit 4 - When set low, Bits\\[3:0\\]
function as PPSCTRL (backward compatible). When set high, Bits\\[3:0\\]
function as PPSCMD."]
    #[inline(always)]
    #[must_use]
    pub fn ppsen0(&mut self) -> Ppsen0W<GmacgrpPpsControlSpec> {
        Ppsen0W::new(self, 4)
    }
    #[doc = "Bits 5:6 - This field indicates the Target Time registers (register 455 and 456) mode for PPS0 output signal"]
    #[inline(always)]
    #[must_use]
    pub fn trgtmodsel0(&mut self) -> Trgtmodsel0W<GmacgrpPpsControlSpec> {
        Trgtmodsel0W::new(self, 5)
    }
}
#[doc = "Controls timestamp Pulse-Per-Second output\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_pps_control::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_pps_control::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpPpsControlSpec;
impl crate::RegisterSpec for GmacgrpPpsControlSpec {
    type Ux = u32;
    const OFFSET: u64 = 1836u64;
}
#[doc = "`read()` method returns [`gmacgrp_pps_control::R`](R) reader structure"]
impl crate::Readable for GmacgrpPpsControlSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_pps_control::W`](W) writer structure"]
impl crate::Writable for GmacgrpPpsControlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_PPS_Control to value 0"]
impl crate::Resettable for GmacgrpPpsControlSpec {
    const RESET_VALUE: u32 = 0;
}
