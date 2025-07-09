// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Timestamp_Control` reader"]
pub type R = crate::R<GmacgrpTimestampControlSpec>;
#[doc = "Register `gmacgrp_Timestamp_Control` writer"]
pub type W = crate::W<GmacgrpTimestampControlSpec>;
#[doc = "When set, the timestamp is added for the transmit and receive frames. When disabled, timestamp is not added for the transmit and receive frames and the Timestamp Generator is also suspended. You need to initialize the Timestamp (system time) after enabling this mode. On the receive side, the MAC processes the 1588 frames only if this bit is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsena {
    #[doc = "0: `0`"]
    Notimestamp = 0,
    #[doc = "1: `1`"]
    Timestamp = 1,
}
impl From<Tsena> for bool {
    #[inline(always)]
    fn from(variant: Tsena) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsena` reader - When set, the timestamp is added for the transmit and receive frames. When disabled, timestamp is not added for the transmit and receive frames and the Timestamp Generator is also suspended. You need to initialize the Timestamp (system time) after enabling this mode. On the receive side, the MAC processes the 1588 frames only if this bit is set."]
pub type TsenaR = crate::BitReader<Tsena>;
impl TsenaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsena {
        match self.bits {
            false => Tsena::Notimestamp,
            true => Tsena::Timestamp,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notimestamp(&self) -> bool {
        *self == Tsena::Notimestamp
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_timestamp(&self) -> bool {
        *self == Tsena::Timestamp
    }
}
#[doc = "Field `tsena` writer - When set, the timestamp is added for the transmit and receive frames. When disabled, timestamp is not added for the transmit and receive frames and the Timestamp Generator is also suspended. You need to initialize the Timestamp (system time) after enabling this mode. On the receive side, the MAC processes the 1588 frames only if this bit is set."]
pub type TsenaW<'a, REG> = crate::BitWriter<'a, REG, Tsena>;
impl<'a, REG> TsenaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notimestamp(self) -> &'a mut crate::W<REG> {
        self.variant(Tsena::Notimestamp)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn timestamp(self) -> &'a mut crate::W<REG> {
        self.variant(Tsena::Timestamp)
    }
}
#[doc = "When set, this bit indicates that the system times update should be done using the fine update method. When reset, it indicates the system timestamp update should be done using the Coarse method.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tscfupdt {
    #[doc = "0: `0`"]
    TimestampCoarse = 0,
    #[doc = "1: `1`"]
    TimestampFine = 1,
}
impl From<Tscfupdt> for bool {
    #[inline(always)]
    fn from(variant: Tscfupdt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tscfupdt` reader - When set, this bit indicates that the system times update should be done using the fine update method. When reset, it indicates the system timestamp update should be done using the Coarse method."]
pub type TscfupdtR = crate::BitReader<Tscfupdt>;
impl TscfupdtR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tscfupdt {
        match self.bits {
            false => Tscfupdt::TimestampCoarse,
            true => Tscfupdt::TimestampFine,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_timestamp_coarse(&self) -> bool {
        *self == Tscfupdt::TimestampCoarse
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_timestamp_fine(&self) -> bool {
        *self == Tscfupdt::TimestampFine
    }
}
#[doc = "Field `tscfupdt` writer - When set, this bit indicates that the system times update should be done using the fine update method. When reset, it indicates the system timestamp update should be done using the Coarse method."]
pub type TscfupdtW<'a, REG> = crate::BitWriter<'a, REG, Tscfupdt>;
impl<'a, REG> TscfupdtW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn timestamp_coarse(self) -> &'a mut crate::W<REG> {
        self.variant(Tscfupdt::TimestampCoarse)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn timestamp_fine(self) -> &'a mut crate::W<REG> {
        self.variant(Tscfupdt::TimestampFine)
    }
}
#[doc = "When set, the system time is initialized (overwritten) with the value specified in the Register 452 (System Time - Seconds Update Register) and Register 453 (System Time - Nanoseconds Update Register). This bit should be read zero before updating it. This bit is reset when the initialization is complete. The Timestamp Higher Word register can only be initialized.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsinit {
    #[doc = "0: `0`"]
    NotimestampInit = 0,
    #[doc = "1: `1`"]
    TimestampInit = 1,
}
impl From<Tsinit> for bool {
    #[inline(always)]
    fn from(variant: Tsinit) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsinit` reader - When set, the system time is initialized (overwritten) with the value specified in the Register 452 (System Time - Seconds Update Register) and Register 453 (System Time - Nanoseconds Update Register). This bit should be read zero before updating it. This bit is reset when the initialization is complete. The Timestamp Higher Word register can only be initialized."]
pub type TsinitR = crate::BitReader<Tsinit>;
impl TsinitR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsinit {
        match self.bits {
            false => Tsinit::NotimestampInit,
            true => Tsinit::TimestampInit,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notimestamp_init(&self) -> bool {
        *self == Tsinit::NotimestampInit
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_timestamp_init(&self) -> bool {
        *self == Tsinit::TimestampInit
    }
}
#[doc = "Field `tsinit` writer - When set, the system time is initialized (overwritten) with the value specified in the Register 452 (System Time - Seconds Update Register) and Register 453 (System Time - Nanoseconds Update Register). This bit should be read zero before updating it. This bit is reset when the initialization is complete. The Timestamp Higher Word register can only be initialized."]
pub type TsinitW<'a, REG> = crate::BitWriter<'a, REG, Tsinit>;
impl<'a, REG> TsinitW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notimestamp_init(self) -> &'a mut crate::W<REG> {
        self.variant(Tsinit::NotimestampInit)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn timestamp_init(self) -> &'a mut crate::W<REG> {
        self.variant(Tsinit::TimestampInit)
    }
}
#[doc = "When set, the system time is updated (added or subtracted) with the value specified in Register 452 (System Time - Seconds Update Register) and Register 453 (System Time - Nanoseconds Update Register). This bit should be read zero before updating it. This bit is reset when the update is completed in hardware. The Timestamp Higher Word register is not updated.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsupdt {
    #[doc = "0: `0`"]
    NotimestampUpdated = 0,
    #[doc = "1: `1`"]
    TimestampUpdated = 1,
}
impl From<Tsupdt> for bool {
    #[inline(always)]
    fn from(variant: Tsupdt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsupdt` reader - When set, the system time is updated (added or subtracted) with the value specified in Register 452 (System Time - Seconds Update Register) and Register 453 (System Time - Nanoseconds Update Register). This bit should be read zero before updating it. This bit is reset when the update is completed in hardware. The Timestamp Higher Word register is not updated."]
pub type TsupdtR = crate::BitReader<Tsupdt>;
impl TsupdtR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsupdt {
        match self.bits {
            false => Tsupdt::NotimestampUpdated,
            true => Tsupdt::TimestampUpdated,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notimestamp_updated(&self) -> bool {
        *self == Tsupdt::NotimestampUpdated
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_timestamp_updated(&self) -> bool {
        *self == Tsupdt::TimestampUpdated
    }
}
#[doc = "Field `tsupdt` writer - When set, the system time is updated (added or subtracted) with the value specified in Register 452 (System Time - Seconds Update Register) and Register 453 (System Time - Nanoseconds Update Register). This bit should be read zero before updating it. This bit is reset when the update is completed in hardware. The Timestamp Higher Word register is not updated."]
pub type TsupdtW<'a, REG> = crate::BitWriter<'a, REG, Tsupdt>;
impl<'a, REG> TsupdtW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notimestamp_updated(self) -> &'a mut crate::W<REG> {
        self.variant(Tsupdt::NotimestampUpdated)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn timestamp_updated(self) -> &'a mut crate::W<REG> {
        self.variant(Tsupdt::TimestampUpdated)
    }
}
#[doc = "When set, the timestamp interrupt is generated when the System Time becomes greater than the value written in the Target Time register. This bit is reset after the generation of the Timestamp Trigger Interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tstrig {
    #[doc = "0: `0`"]
    NotimestampIntrTrigEn = 0,
    #[doc = "1: `1`"]
    TimestampIntrTrigEn = 1,
}
impl From<Tstrig> for bool {
    #[inline(always)]
    fn from(variant: Tstrig) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tstrig` reader - When set, the timestamp interrupt is generated when the System Time becomes greater than the value written in the Target Time register. This bit is reset after the generation of the Timestamp Trigger Interrupt."]
pub type TstrigR = crate::BitReader<Tstrig>;
impl TstrigR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tstrig {
        match self.bits {
            false => Tstrig::NotimestampIntrTrigEn,
            true => Tstrig::TimestampIntrTrigEn,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notimestamp_intr_trig_en(&self) -> bool {
        *self == Tstrig::NotimestampIntrTrigEn
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_timestamp_intr_trig_en(&self) -> bool {
        *self == Tstrig::TimestampIntrTrigEn
    }
}
#[doc = "Field `tstrig` writer - When set, the timestamp interrupt is generated when the System Time becomes greater than the value written in the Target Time register. This bit is reset after the generation of the Timestamp Trigger Interrupt."]
pub type TstrigW<'a, REG> = crate::BitWriter<'a, REG, Tstrig>;
impl<'a, REG> TstrigW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notimestamp_intr_trig_en(self) -> &'a mut crate::W<REG> {
        self.variant(Tstrig::NotimestampIntrTrigEn)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn timestamp_intr_trig_en(self) -> &'a mut crate::W<REG> {
        self.variant(Tstrig::TimestampIntrTrigEn)
    }
}
#[doc = "When set, the content of the Timestamp Addend register is updated in the PTP block for fine correction. This is cleared when the update is completed. This register bit should be zero before setting it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsaddreg {
    #[doc = "0: `0`"]
    NotimestampAddendUpdated = 0,
    #[doc = "1: `1`"]
    TimestampAddendUpdated = 1,
}
impl From<Tsaddreg> for bool {
    #[inline(always)]
    fn from(variant: Tsaddreg) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsaddreg` reader - When set, the content of the Timestamp Addend register is updated in the PTP block for fine correction. This is cleared when the update is completed. This register bit should be zero before setting it."]
pub type TsaddregR = crate::BitReader<Tsaddreg>;
impl TsaddregR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsaddreg {
        match self.bits {
            false => Tsaddreg::NotimestampAddendUpdated,
            true => Tsaddreg::TimestampAddendUpdated,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notimestamp_addend_updated(&self) -> bool {
        *self == Tsaddreg::NotimestampAddendUpdated
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_timestamp_addend_updated(&self) -> bool {
        *self == Tsaddreg::TimestampAddendUpdated
    }
}
#[doc = "Field `tsaddreg` writer - When set, the content of the Timestamp Addend register is updated in the PTP block for fine correction. This is cleared when the update is completed. This register bit should be zero before setting it."]
pub type TsaddregW<'a, REG> = crate::BitWriter<'a, REG, Tsaddreg>;
impl<'a, REG> TsaddregW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notimestamp_addend_updated(self) -> &'a mut crate::W<REG> {
        self.variant(Tsaddreg::NotimestampAddendUpdated)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn timestamp_addend_updated(self) -> &'a mut crate::W<REG> {
        self.variant(Tsaddreg::TimestampAddendUpdated)
    }
}
#[doc = "When set, the timestamp snapshot is enabled for all frames received by the MAC.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsenall {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tsenall> for bool {
    #[inline(always)]
    fn from(variant: Tsenall) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsenall` reader - When set, the timestamp snapshot is enabled for all frames received by the MAC."]
pub type TsenallR = crate::BitReader<Tsenall>;
impl TsenallR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsenall {
        match self.bits {
            false => Tsenall::Disabled,
            true => Tsenall::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tsenall::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tsenall::Enabled
    }
}
#[doc = "Field `tsenall` writer - When set, the timestamp snapshot is enabled for all frames received by the MAC."]
pub type TsenallW<'a, REG> = crate::BitWriter<'a, REG, Tsenall>;
impl<'a, REG> TsenallW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tsenall::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tsenall::Enabled)
    }
}
#[doc = "When set, the Timestamp Low register rolls over after 0x3B9A_C9FF value (that is, 1 nanosecond accuracy) and increments the timestamp (High) seconds. When reset, the rollover value of sub-second register is 0x7FFF_FFFF. The sub-second increment has to be programmed correctly depending on the PTP reference clock frequency and the value of this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsctrlssr {
    #[doc = "0: `0`"]
    NotimestampLowRollMax = 0,
    #[doc = "1: `1`"]
    TimestampLowRoll1ns = 1,
}
impl From<Tsctrlssr> for bool {
    #[inline(always)]
    fn from(variant: Tsctrlssr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsctrlssr` reader - When set, the Timestamp Low register rolls over after 0x3B9A_C9FF value (that is, 1 nanosecond accuracy) and increments the timestamp (High) seconds. When reset, the rollover value of sub-second register is 0x7FFF_FFFF. The sub-second increment has to be programmed correctly depending on the PTP reference clock frequency and the value of this bit."]
pub type TsctrlssrR = crate::BitReader<Tsctrlssr>;
impl TsctrlssrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsctrlssr {
        match self.bits {
            false => Tsctrlssr::NotimestampLowRollMax,
            true => Tsctrlssr::TimestampLowRoll1ns,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notimestamp_low_roll_max(&self) -> bool {
        *self == Tsctrlssr::NotimestampLowRollMax
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_timestamp_low_roll_1ns(&self) -> bool {
        *self == Tsctrlssr::TimestampLowRoll1ns
    }
}
#[doc = "Field `tsctrlssr` writer - When set, the Timestamp Low register rolls over after 0x3B9A_C9FF value (that is, 1 nanosecond accuracy) and increments the timestamp (High) seconds. When reset, the rollover value of sub-second register is 0x7FFF_FFFF. The sub-second increment has to be programmed correctly depending on the PTP reference clock frequency and the value of this bit."]
pub type TsctrlssrW<'a, REG> = crate::BitWriter<'a, REG, Tsctrlssr>;
impl<'a, REG> TsctrlssrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notimestamp_low_roll_max(self) -> &'a mut crate::W<REG> {
        self.variant(Tsctrlssr::NotimestampLowRollMax)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn timestamp_low_roll_1ns(self) -> &'a mut crate::W<REG> {
        self.variant(Tsctrlssr::TimestampLowRoll1ns)
    }
}
#[doc = "When set, the PTP packets are processed using the 1588 version 2 format. Otherwise, the PTP packets are processed using the version 1 format.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsver2ena {
    #[doc = "0: `0`"]
    Ptp1588Ver1 = 0,
    #[doc = "1: `1`"]
    Ptp1588Ver2 = 1,
}
impl From<Tsver2ena> for bool {
    #[inline(always)]
    fn from(variant: Tsver2ena) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsver2ena` reader - When set, the PTP packets are processed using the 1588 version 2 format. Otherwise, the PTP packets are processed using the version 1 format."]
pub type Tsver2enaR = crate::BitReader<Tsver2ena>;
impl Tsver2enaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsver2ena {
        match self.bits {
            false => Tsver2ena::Ptp1588Ver1,
            true => Tsver2ena::Ptp1588Ver2,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ptp_1588_ver1(&self) -> bool {
        *self == Tsver2ena::Ptp1588Ver1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_ptp_1588_ver2(&self) -> bool {
        *self == Tsver2ena::Ptp1588Ver2
    }
}
#[doc = "Field `tsver2ena` writer - When set, the PTP packets are processed using the 1588 version 2 format. Otherwise, the PTP packets are processed using the version 1 format."]
pub type Tsver2enaW<'a, REG> = crate::BitWriter<'a, REG, Tsver2ena>;
impl<'a, REG> Tsver2enaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn ptp_1588_ver1(self) -> &'a mut crate::W<REG> {
        self.variant(Tsver2ena::Ptp1588Ver1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn ptp_1588_ver2(self) -> &'a mut crate::W<REG> {
        self.variant(Tsver2ena::Ptp1588Ver2)
    }
}
#[doc = "When set, the MAC receiver processes the PTP packets encapsulated directly in the Ethernet frames. When this bit is clear, the MAC ignores the PTP over Ethernet packets.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsipena {
    #[doc = "0: `0`"]
    NoProcessPtp = 0,
    #[doc = "1: `1`"]
    ProcessPtp = 1,
}
impl From<Tsipena> for bool {
    #[inline(always)]
    fn from(variant: Tsipena) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsipena` reader - When set, the MAC receiver processes the PTP packets encapsulated directly in the Ethernet frames. When this bit is clear, the MAC ignores the PTP over Ethernet packets."]
pub type TsipenaR = crate::BitReader<Tsipena>;
impl TsipenaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsipena {
        match self.bits {
            false => Tsipena::NoProcessPtp,
            true => Tsipena::ProcessPtp,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_no_process_ptp(&self) -> bool {
        *self == Tsipena::NoProcessPtp
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_process_ptp(&self) -> bool {
        *self == Tsipena::ProcessPtp
    }
}
#[doc = "Field `tsipena` writer - When set, the MAC receiver processes the PTP packets encapsulated directly in the Ethernet frames. When this bit is clear, the MAC ignores the PTP over Ethernet packets."]
pub type TsipenaW<'a, REG> = crate::BitWriter<'a, REG, Tsipena>;
impl<'a, REG> TsipenaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn no_process_ptp(self) -> &'a mut crate::W<REG> {
        self.variant(Tsipena::NoProcessPtp)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn process_ptp(self) -> &'a mut crate::W<REG> {
        self.variant(Tsipena::ProcessPtp)
    }
}
#[doc = "When set, the MAC receiver processes PTP packets encapsulated in UDP over IPv6 packets. When this bit is clear, the MAC ignores the PTP transported over UDP-IPv6 packets.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsipv6ena {
    #[doc = "0: `0`"]
    NoProcessPtp = 0,
    #[doc = "1: `1`"]
    ProcessPtp = 1,
}
impl From<Tsipv6ena> for bool {
    #[inline(always)]
    fn from(variant: Tsipv6ena) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsipv6ena` reader - When set, the MAC receiver processes PTP packets encapsulated in UDP over IPv6 packets. When this bit is clear, the MAC ignores the PTP transported over UDP-IPv6 packets."]
pub type Tsipv6enaR = crate::BitReader<Tsipv6ena>;
impl Tsipv6enaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsipv6ena {
        match self.bits {
            false => Tsipv6ena::NoProcessPtp,
            true => Tsipv6ena::ProcessPtp,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_no_process_ptp(&self) -> bool {
        *self == Tsipv6ena::NoProcessPtp
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_process_ptp(&self) -> bool {
        *self == Tsipv6ena::ProcessPtp
    }
}
#[doc = "Field `tsipv6ena` writer - When set, the MAC receiver processes PTP packets encapsulated in UDP over IPv6 packets. When this bit is clear, the MAC ignores the PTP transported over UDP-IPv6 packets."]
pub type Tsipv6enaW<'a, REG> = crate::BitWriter<'a, REG, Tsipv6ena>;
impl<'a, REG> Tsipv6enaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn no_process_ptp(self) -> &'a mut crate::W<REG> {
        self.variant(Tsipv6ena::NoProcessPtp)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn process_ptp(self) -> &'a mut crate::W<REG> {
        self.variant(Tsipv6ena::ProcessPtp)
    }
}
#[doc = "When set, the MAC receiver processes the PTP packets encapsulated in UDP over IPv4 packets. When this bit is clear, the MAC ignores the PTP transported over UDP-IPv4 packets. This bit is set by default.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsipv4ena {
    #[doc = "0: `0`"]
    NoProcessPtp = 0,
    #[doc = "1: `1`"]
    ProcessPtp = 1,
}
impl From<Tsipv4ena> for bool {
    #[inline(always)]
    fn from(variant: Tsipv4ena) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsipv4ena` reader - When set, the MAC receiver processes the PTP packets encapsulated in UDP over IPv4 packets. When this bit is clear, the MAC ignores the PTP transported over UDP-IPv4 packets. This bit is set by default."]
pub type Tsipv4enaR = crate::BitReader<Tsipv4ena>;
impl Tsipv4enaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsipv4ena {
        match self.bits {
            false => Tsipv4ena::NoProcessPtp,
            true => Tsipv4ena::ProcessPtp,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_no_process_ptp(&self) -> bool {
        *self == Tsipv4ena::NoProcessPtp
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_process_ptp(&self) -> bool {
        *self == Tsipv4ena::ProcessPtp
    }
}
#[doc = "Field `tsipv4ena` writer - When set, the MAC receiver processes the PTP packets encapsulated in UDP over IPv4 packets. When this bit is clear, the MAC ignores the PTP transported over UDP-IPv4 packets. This bit is set by default."]
pub type Tsipv4enaW<'a, REG> = crate::BitWriter<'a, REG, Tsipv4ena>;
impl<'a, REG> Tsipv4enaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn no_process_ptp(self) -> &'a mut crate::W<REG> {
        self.variant(Tsipv4ena::NoProcessPtp)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn process_ptp(self) -> &'a mut crate::W<REG> {
        self.variant(Tsipv4ena::ProcessPtp)
    }
}
#[doc = "When set, the timestamp snapshot is taken only for event messages (SYNC, Delay_Req, Pdelay_Req, or Pdelay_Resp). When reset, the snapshot is taken for all messages except Announce, Management, and Signaling.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsevntena {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tsevntena> for bool {
    #[inline(always)]
    fn from(variant: Tsevntena) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsevntena` reader - When set, the timestamp snapshot is taken only for event messages (SYNC, Delay_Req, Pdelay_Req, or Pdelay_Resp). When reset, the snapshot is taken for all messages except Announce, Management, and Signaling."]
pub type TsevntenaR = crate::BitReader<Tsevntena>;
impl TsevntenaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsevntena {
        match self.bits {
            false => Tsevntena::Disabled,
            true => Tsevntena::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tsevntena::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tsevntena::Enabled
    }
}
#[doc = "Field `tsevntena` writer - When set, the timestamp snapshot is taken only for event messages (SYNC, Delay_Req, Pdelay_Req, or Pdelay_Resp). When reset, the snapshot is taken for all messages except Announce, Management, and Signaling."]
pub type TsevntenaW<'a, REG> = crate::BitWriter<'a, REG, Tsevntena>;
impl<'a, REG> TsevntenaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tsevntena::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tsevntena::Enabled)
    }
}
#[doc = "When set, the snapshot is taken only for the messages relevant to the master node. Otherwise, the snapshot is taken for the messages relevant to the slave node.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsmstrena {
    #[doc = "0: `0`"]
    Slave = 0,
    #[doc = "1: `1`"]
    Master = 1,
}
impl From<Tsmstrena> for bool {
    #[inline(always)]
    fn from(variant: Tsmstrena) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsmstrena` reader - When set, the snapshot is taken only for the messages relevant to the master node. Otherwise, the snapshot is taken for the messages relevant to the slave node."]
pub type TsmstrenaR = crate::BitReader<Tsmstrena>;
impl TsmstrenaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsmstrena {
        match self.bits {
            false => Tsmstrena::Slave,
            true => Tsmstrena::Master,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_slave(&self) -> bool {
        *self == Tsmstrena::Slave
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_master(&self) -> bool {
        *self == Tsmstrena::Master
    }
}
#[doc = "Field `tsmstrena` writer - When set, the snapshot is taken only for the messages relevant to the master node. Otherwise, the snapshot is taken for the messages relevant to the slave node."]
pub type TsmstrenaW<'a, REG> = crate::BitWriter<'a, REG, Tsmstrena>;
impl<'a, REG> TsmstrenaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn slave(self) -> &'a mut crate::W<REG> {
        self.variant(Tsmstrena::Slave)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn master(self) -> &'a mut crate::W<REG> {
        self.variant(Tsmstrena::Master)
    }
}
#[doc = "Field `snaptypsel` reader - These bits along with Bits 15 and 14 decide the set of PTP packet types for which snapshot needs to be taken."]
pub type SnaptypselR = crate::FieldReader;
#[doc = "Field `snaptypsel` writer - These bits along with Bits 15 and 14 decide the set of PTP packet types for which snapshot needs to be taken."]
pub type SnaptypselW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "When set, the DA MAC address (that matches any MAC Address register) is used to filter the PTP frames when PTP is directly sent over Ethernet.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tsenmacaddr {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tsenmacaddr> for bool {
    #[inline(always)]
    fn from(variant: Tsenmacaddr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tsenmacaddr` reader - When set, the DA MAC address (that matches any MAC Address register) is used to filter the PTP frames when PTP is directly sent over Ethernet."]
pub type TsenmacaddrR = crate::BitReader<Tsenmacaddr>;
impl TsenmacaddrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tsenmacaddr {
        match self.bits {
            false => Tsenmacaddr::Disabled,
            true => Tsenmacaddr::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tsenmacaddr::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tsenmacaddr::Enabled
    }
}
#[doc = "Field `tsenmacaddr` writer - When set, the DA MAC address (that matches any MAC Address register) is used to filter the PTP frames when PTP is directly sent over Ethernet."]
pub type TsenmacaddrW<'a, REG> = crate::BitWriter<'a, REG, Tsenmacaddr>;
impl<'a, REG> TsenmacaddrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tsenmacaddr::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tsenmacaddr::Enabled)
    }
}
#[doc = "When set, it resets the pointers of the Auxiliary Snapshot FIFO. This bit is cleared when the pointers are reset and the FIFO is empty. When this bit is high, auxiliary snapshots get stored in the FIFO.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Atsfc {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Atsfc> for bool {
    #[inline(always)]
    fn from(variant: Atsfc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `atsfc` reader - When set, it resets the pointers of the Auxiliary Snapshot FIFO. This bit is cleared when the pointers are reset and the FIFO is empty. When this bit is high, auxiliary snapshots get stored in the FIFO."]
pub type AtsfcR = crate::BitReader<Atsfc>;
impl AtsfcR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Atsfc {
        match self.bits {
            false => Atsfc::Disabled,
            true => Atsfc::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Atsfc::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Atsfc::Enabled
    }
}
#[doc = "Field `atsfc` writer - When set, it resets the pointers of the Auxiliary Snapshot FIFO. This bit is cleared when the pointers are reset and the FIFO is empty. When this bit is high, auxiliary snapshots get stored in the FIFO."]
pub type AtsfcW<'a, REG> = crate::BitWriter<'a, REG, Atsfc>;
impl<'a, REG> AtsfcW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Atsfc::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Atsfc::Enabled)
    }
}
#[doc = "This field controls capturing the Auxiliary Snapshot Trigger 0. When this bit is set, the Auxiliary snapshot of event on ptp_aux_trig_i\\[0\\]
input is enabled. When this bit is reset, the events on this input are ignored.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Atsen0 {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Atsen0> for bool {
    #[inline(always)]
    fn from(variant: Atsen0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `atsen0` reader - This field controls capturing the Auxiliary Snapshot Trigger 0. When this bit is set, the Auxiliary snapshot of event on ptp_aux_trig_i\\[0\\]
input is enabled. When this bit is reset, the events on this input are ignored."]
pub type Atsen0R = crate::BitReader<Atsen0>;
impl Atsen0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Atsen0 {
        match self.bits {
            false => Atsen0::Disabled,
            true => Atsen0::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Atsen0::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Atsen0::Enabled
    }
}
#[doc = "Field `atsen0` writer - This field controls capturing the Auxiliary Snapshot Trigger 0. When this bit is set, the Auxiliary snapshot of event on ptp_aux_trig_i\\[0\\]
input is enabled. When this bit is reset, the events on this input are ignored."]
pub type Atsen0W<'a, REG> = crate::BitWriter<'a, REG, Atsen0>;
impl<'a, REG> Atsen0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Atsen0::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Atsen0::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - When set, the timestamp is added for the transmit and receive frames. When disabled, timestamp is not added for the transmit and receive frames and the Timestamp Generator is also suspended. You need to initialize the Timestamp (system time) after enabling this mode. On the receive side, the MAC processes the 1588 frames only if this bit is set."]
    #[inline(always)]
    pub fn tsena(&self) -> TsenaR {
        TsenaR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When set, this bit indicates that the system times update should be done using the fine update method. When reset, it indicates the system timestamp update should be done using the Coarse method."]
    #[inline(always)]
    pub fn tscfupdt(&self) -> TscfupdtR {
        TscfupdtR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - When set, the system time is initialized (overwritten) with the value specified in the Register 452 (System Time - Seconds Update Register) and Register 453 (System Time - Nanoseconds Update Register). This bit should be read zero before updating it. This bit is reset when the initialization is complete. The Timestamp Higher Word register can only be initialized."]
    #[inline(always)]
    pub fn tsinit(&self) -> TsinitR {
        TsinitR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - When set, the system time is updated (added or subtracted) with the value specified in Register 452 (System Time - Seconds Update Register) and Register 453 (System Time - Nanoseconds Update Register). This bit should be read zero before updating it. This bit is reset when the update is completed in hardware. The Timestamp Higher Word register is not updated."]
    #[inline(always)]
    pub fn tsupdt(&self) -> TsupdtR {
        TsupdtR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - When set, the timestamp interrupt is generated when the System Time becomes greater than the value written in the Target Time register. This bit is reset after the generation of the Timestamp Trigger Interrupt."]
    #[inline(always)]
    pub fn tstrig(&self) -> TstrigR {
        TstrigR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - When set, the content of the Timestamp Addend register is updated in the PTP block for fine correction. This is cleared when the update is completed. This register bit should be zero before setting it."]
    #[inline(always)]
    pub fn tsaddreg(&self) -> TsaddregR {
        TsaddregR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 8 - When set, the timestamp snapshot is enabled for all frames received by the MAC."]
    #[inline(always)]
    pub fn tsenall(&self) -> TsenallR {
        TsenallR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - When set, the Timestamp Low register rolls over after 0x3B9A_C9FF value (that is, 1 nanosecond accuracy) and increments the timestamp (High) seconds. When reset, the rollover value of sub-second register is 0x7FFF_FFFF. The sub-second increment has to be programmed correctly depending on the PTP reference clock frequency and the value of this bit."]
    #[inline(always)]
    pub fn tsctrlssr(&self) -> TsctrlssrR {
        TsctrlssrR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - When set, the PTP packets are processed using the 1588 version 2 format. Otherwise, the PTP packets are processed using the version 1 format."]
    #[inline(always)]
    pub fn tsver2ena(&self) -> Tsver2enaR {
        Tsver2enaR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - When set, the MAC receiver processes the PTP packets encapsulated directly in the Ethernet frames. When this bit is clear, the MAC ignores the PTP over Ethernet packets."]
    #[inline(always)]
    pub fn tsipena(&self) -> TsipenaR {
        TsipenaR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - When set, the MAC receiver processes PTP packets encapsulated in UDP over IPv6 packets. When this bit is clear, the MAC ignores the PTP transported over UDP-IPv6 packets."]
    #[inline(always)]
    pub fn tsipv6ena(&self) -> Tsipv6enaR {
        Tsipv6enaR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - When set, the MAC receiver processes the PTP packets encapsulated in UDP over IPv4 packets. When this bit is clear, the MAC ignores the PTP transported over UDP-IPv4 packets. This bit is set by default."]
    #[inline(always)]
    pub fn tsipv4ena(&self) -> Tsipv4enaR {
        Tsipv4enaR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - When set, the timestamp snapshot is taken only for event messages (SYNC, Delay_Req, Pdelay_Req, or Pdelay_Resp). When reset, the snapshot is taken for all messages except Announce, Management, and Signaling."]
    #[inline(always)]
    pub fn tsevntena(&self) -> TsevntenaR {
        TsevntenaR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - When set, the snapshot is taken only for the messages relevant to the master node. Otherwise, the snapshot is taken for the messages relevant to the slave node."]
    #[inline(always)]
    pub fn tsmstrena(&self) -> TsmstrenaR {
        TsmstrenaR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bits 16:17 - These bits along with Bits 15 and 14 decide the set of PTP packet types for which snapshot needs to be taken."]
    #[inline(always)]
    pub fn snaptypsel(&self) -> SnaptypselR {
        SnaptypselR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bit 18 - When set, the DA MAC address (that matches any MAC Address register) is used to filter the PTP frames when PTP is directly sent over Ethernet."]
    #[inline(always)]
    pub fn tsenmacaddr(&self) -> TsenmacaddrR {
        TsenmacaddrR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 24 - When set, it resets the pointers of the Auxiliary Snapshot FIFO. This bit is cleared when the pointers are reset and the FIFO is empty. When this bit is high, auxiliary snapshots get stored in the FIFO."]
    #[inline(always)]
    pub fn atsfc(&self) -> AtsfcR {
        AtsfcR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - This field controls capturing the Auxiliary Snapshot Trigger 0. When this bit is set, the Auxiliary snapshot of event on ptp_aux_trig_i\\[0\\]
input is enabled. When this bit is reset, the events on this input are ignored."]
    #[inline(always)]
    pub fn atsen0(&self) -> Atsen0R {
        Atsen0R::new(((self.bits >> 25) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When set, the timestamp is added for the transmit and receive frames. When disabled, timestamp is not added for the transmit and receive frames and the Timestamp Generator is also suspended. You need to initialize the Timestamp (system time) after enabling this mode. On the receive side, the MAC processes the 1588 frames only if this bit is set."]
    #[inline(always)]
    #[must_use]
    pub fn tsena(&mut self) -> TsenaW<GmacgrpTimestampControlSpec> {
        TsenaW::new(self, 0)
    }
    #[doc = "Bit 1 - When set, this bit indicates that the system times update should be done using the fine update method. When reset, it indicates the system timestamp update should be done using the Coarse method."]
    #[inline(always)]
    #[must_use]
    pub fn tscfupdt(&mut self) -> TscfupdtW<GmacgrpTimestampControlSpec> {
        TscfupdtW::new(self, 1)
    }
    #[doc = "Bit 2 - When set, the system time is initialized (overwritten) with the value specified in the Register 452 (System Time - Seconds Update Register) and Register 453 (System Time - Nanoseconds Update Register). This bit should be read zero before updating it. This bit is reset when the initialization is complete. The Timestamp Higher Word register can only be initialized."]
    #[inline(always)]
    #[must_use]
    pub fn tsinit(&mut self) -> TsinitW<GmacgrpTimestampControlSpec> {
        TsinitW::new(self, 2)
    }
    #[doc = "Bit 3 - When set, the system time is updated (added or subtracted) with the value specified in Register 452 (System Time - Seconds Update Register) and Register 453 (System Time - Nanoseconds Update Register). This bit should be read zero before updating it. This bit is reset when the update is completed in hardware. The Timestamp Higher Word register is not updated."]
    #[inline(always)]
    #[must_use]
    pub fn tsupdt(&mut self) -> TsupdtW<GmacgrpTimestampControlSpec> {
        TsupdtW::new(self, 3)
    }
    #[doc = "Bit 4 - When set, the timestamp interrupt is generated when the System Time becomes greater than the value written in the Target Time register. This bit is reset after the generation of the Timestamp Trigger Interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn tstrig(&mut self) -> TstrigW<GmacgrpTimestampControlSpec> {
        TstrigW::new(self, 4)
    }
    #[doc = "Bit 5 - When set, the content of the Timestamp Addend register is updated in the PTP block for fine correction. This is cleared when the update is completed. This register bit should be zero before setting it."]
    #[inline(always)]
    #[must_use]
    pub fn tsaddreg(&mut self) -> TsaddregW<GmacgrpTimestampControlSpec> {
        TsaddregW::new(self, 5)
    }
    #[doc = "Bit 8 - When set, the timestamp snapshot is enabled for all frames received by the MAC."]
    #[inline(always)]
    #[must_use]
    pub fn tsenall(&mut self) -> TsenallW<GmacgrpTimestampControlSpec> {
        TsenallW::new(self, 8)
    }
    #[doc = "Bit 9 - When set, the Timestamp Low register rolls over after 0x3B9A_C9FF value (that is, 1 nanosecond accuracy) and increments the timestamp (High) seconds. When reset, the rollover value of sub-second register is 0x7FFF_FFFF. The sub-second increment has to be programmed correctly depending on the PTP reference clock frequency and the value of this bit."]
    #[inline(always)]
    #[must_use]
    pub fn tsctrlssr(&mut self) -> TsctrlssrW<GmacgrpTimestampControlSpec> {
        TsctrlssrW::new(self, 9)
    }
    #[doc = "Bit 10 - When set, the PTP packets are processed using the 1588 version 2 format. Otherwise, the PTP packets are processed using the version 1 format."]
    #[inline(always)]
    #[must_use]
    pub fn tsver2ena(&mut self) -> Tsver2enaW<GmacgrpTimestampControlSpec> {
        Tsver2enaW::new(self, 10)
    }
    #[doc = "Bit 11 - When set, the MAC receiver processes the PTP packets encapsulated directly in the Ethernet frames. When this bit is clear, the MAC ignores the PTP over Ethernet packets."]
    #[inline(always)]
    #[must_use]
    pub fn tsipena(&mut self) -> TsipenaW<GmacgrpTimestampControlSpec> {
        TsipenaW::new(self, 11)
    }
    #[doc = "Bit 12 - When set, the MAC receiver processes PTP packets encapsulated in UDP over IPv6 packets. When this bit is clear, the MAC ignores the PTP transported over UDP-IPv6 packets."]
    #[inline(always)]
    #[must_use]
    pub fn tsipv6ena(&mut self) -> Tsipv6enaW<GmacgrpTimestampControlSpec> {
        Tsipv6enaW::new(self, 12)
    }
    #[doc = "Bit 13 - When set, the MAC receiver processes the PTP packets encapsulated in UDP over IPv4 packets. When this bit is clear, the MAC ignores the PTP transported over UDP-IPv4 packets. This bit is set by default."]
    #[inline(always)]
    #[must_use]
    pub fn tsipv4ena(&mut self) -> Tsipv4enaW<GmacgrpTimestampControlSpec> {
        Tsipv4enaW::new(self, 13)
    }
    #[doc = "Bit 14 - When set, the timestamp snapshot is taken only for event messages (SYNC, Delay_Req, Pdelay_Req, or Pdelay_Resp). When reset, the snapshot is taken for all messages except Announce, Management, and Signaling."]
    #[inline(always)]
    #[must_use]
    pub fn tsevntena(&mut self) -> TsevntenaW<GmacgrpTimestampControlSpec> {
        TsevntenaW::new(self, 14)
    }
    #[doc = "Bit 15 - When set, the snapshot is taken only for the messages relevant to the master node. Otherwise, the snapshot is taken for the messages relevant to the slave node."]
    #[inline(always)]
    #[must_use]
    pub fn tsmstrena(&mut self) -> TsmstrenaW<GmacgrpTimestampControlSpec> {
        TsmstrenaW::new(self, 15)
    }
    #[doc = "Bits 16:17 - These bits along with Bits 15 and 14 decide the set of PTP packet types for which snapshot needs to be taken."]
    #[inline(always)]
    #[must_use]
    pub fn snaptypsel(&mut self) -> SnaptypselW<GmacgrpTimestampControlSpec> {
        SnaptypselW::new(self, 16)
    }
    #[doc = "Bit 18 - When set, the DA MAC address (that matches any MAC Address register) is used to filter the PTP frames when PTP is directly sent over Ethernet."]
    #[inline(always)]
    #[must_use]
    pub fn tsenmacaddr(&mut self) -> TsenmacaddrW<GmacgrpTimestampControlSpec> {
        TsenmacaddrW::new(self, 18)
    }
    #[doc = "Bit 24 - When set, it resets the pointers of the Auxiliary Snapshot FIFO. This bit is cleared when the pointers are reset and the FIFO is empty. When this bit is high, auxiliary snapshots get stored in the FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn atsfc(&mut self) -> AtsfcW<GmacgrpTimestampControlSpec> {
        AtsfcW::new(self, 24)
    }
    #[doc = "Bit 25 - This field controls capturing the Auxiliary Snapshot Trigger 0. When this bit is set, the Auxiliary snapshot of event on ptp_aux_trig_i\\[0\\]
input is enabled. When this bit is reset, the events on this input are ignored."]
    #[inline(always)]
    #[must_use]
    pub fn atsen0(&mut self) -> Atsen0W<GmacgrpTimestampControlSpec> {
        Atsen0W::new(self, 25)
    }
}
#[doc = "This register controls the operation of the System Time generator and the processing of PTP packets for timestamping in the Receiver.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_timestamp_control::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_timestamp_control::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTimestampControlSpec;
impl crate::RegisterSpec for GmacgrpTimestampControlSpec {
    type Ux = u32;
    const OFFSET: u64 = 1792u64;
}
#[doc = "`read()` method returns [`gmacgrp_timestamp_control::R`](R) reader structure"]
impl crate::Readable for GmacgrpTimestampControlSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_timestamp_control::W`](W) writer structure"]
impl crate::Writable for GmacgrpTimestampControlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Timestamp_Control to value 0x2000"]
impl crate::Resettable for GmacgrpTimestampControlSpec {
    const RESET_VALUE: u32 = 0x2000;
}
