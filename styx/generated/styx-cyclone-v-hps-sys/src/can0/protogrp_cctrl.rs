// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `protogrp_CCTRL` reader"]
pub type R = crate::R<ProtogrpCctrlSpec>;
#[doc = "Register `protogrp_CCTRL` writer"]
pub type W = crate::W<ProtogrpCctrlSpec>;
#[doc = "Initialization Note: Due to the synchronization mechanism between the two clock domains, there may be a delay until the value written to CCTRL.Init can be read back. Therefore the programmer has to assure that the previous value written to CCTRL.Init has been accepted by reading CCTRL.Init before setting CCTRL.Init to a new value.\n Note: The Bus_Off recovery sequence (see CAN Specification Rev. 2.0) cannot be shortened by setting or resetting CCTRL.Init. If the device goes Bus_Off, it will set CCTRL.Init of its own accord, stopping all bus activities. Once CCTRL.Init has been cleared by the CPU, the device will then wait for 129 occurrences of Bus Idle (129 * 11 consecutive recessive bits) before resuming normal operations. At the end of the Bus_Off recovery sequence, the Error Management Counters will be reset. During the waiting time after the resetting of CCTRL.Init, each time a sequence of 11 recessive bits has been monitored, a Bit0Error code is written to the Status Register, enabling the CPU to readily check up whether the CAN bus is stuck at dominant or continuously disturbed and to monitor the proceeding of the us_Off recovery sequence.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Init {
    #[doc = "0: `0`"]
    Normal = 0,
    #[doc = "1: `1`"]
    Start = 1,
}
impl From<Init> for bool {
    #[inline(always)]
    fn from(variant: Init) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `Init` reader - Initialization Note: Due to the synchronization mechanism between the two clock domains, there may be a delay until the value written to CCTRL.Init can be read back. Therefore the programmer has to assure that the previous value written to CCTRL.Init has been accepted by reading CCTRL.Init before setting CCTRL.Init to a new value.\n Note: The Bus_Off recovery sequence (see CAN Specification Rev. 2.0) cannot be shortened by setting or resetting CCTRL.Init. If the device goes Bus_Off, it will set CCTRL.Init of its own accord, stopping all bus activities. Once CCTRL.Init has been cleared by the CPU, the device will then wait for 129 occurrences of Bus Idle (129 * 11 consecutive recessive bits) before resuming normal operations. At the end of the Bus_Off recovery sequence, the Error Management Counters will be reset. During the waiting time after the resetting of CCTRL.Init, each time a sequence of 11 recessive bits has been monitored, a Bit0Error code is written to the Status Register, enabling the CPU to readily check up whether the CAN bus is stuck at dominant or continuously disturbed and to monitor the proceeding of the us_Off recovery sequence."]
pub type InitR = crate::BitReader<Init>;
impl InitR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Init {
        match self.bits {
            false => Init::Normal,
            true => Init::Start,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_normal(&self) -> bool {
        *self == Init::Normal
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_start(&self) -> bool {
        *self == Init::Start
    }
}
#[doc = "Field `Init` writer - Initialization Note: Due to the synchronization mechanism between the two clock domains, there may be a delay until the value written to CCTRL.Init can be read back. Therefore the programmer has to assure that the previous value written to CCTRL.Init has been accepted by reading CCTRL.Init before setting CCTRL.Init to a new value.\n Note: The Bus_Off recovery sequence (see CAN Specification Rev. 2.0) cannot be shortened by setting or resetting CCTRL.Init. If the device goes Bus_Off, it will set CCTRL.Init of its own accord, stopping all bus activities. Once CCTRL.Init has been cleared by the CPU, the device will then wait for 129 occurrences of Bus Idle (129 * 11 consecutive recessive bits) before resuming normal operations. At the end of the Bus_Off recovery sequence, the Error Management Counters will be reset. During the waiting time after the resetting of CCTRL.Init, each time a sequence of 11 recessive bits has been monitored, a Bit0Error code is written to the Status Register, enabling the CPU to readily check up whether the CAN bus is stuck at dominant or continuously disturbed and to monitor the proceeding of the us_Off recovery sequence."]
pub type InitW<'a, REG> = crate::BitWriter<'a, REG, Init>;
impl<'a, REG> InitW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn normal(self) -> &'a mut crate::W<REG> {
        self.variant(Init::Normal)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn start(self) -> &'a mut crate::W<REG> {
        self.variant(Init::Start)
    }
}
#[doc = "Module Interrupt Line Enable\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ile {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Ile> for bool {
    #[inline(always)]
    fn from(variant: Ile) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ILE` reader - Module Interrupt Line Enable"]
pub type IleR = crate::BitReader<Ile>;
impl IleR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ile {
        match self.bits {
            false => Ile::Disabled,
            true => Ile::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ile::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ile::Enabled
    }
}
#[doc = "Field `ILE` writer - Module Interrupt Line Enable"]
pub type IleW<'a, REG> = crate::BitWriter<'a, REG, Ile>;
impl<'a, REG> IleW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ile::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ile::Enabled)
    }
}
#[doc = "Status Interrupt Enable\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sie {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Sie> for bool {
    #[inline(always)]
    fn from(variant: Sie) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `SIE` reader - Status Interrupt Enable"]
pub type SieR = crate::BitReader<Sie>;
impl SieR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sie {
        match self.bits {
            false => Sie::Disabled,
            true => Sie::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Sie::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Sie::Enabled
    }
}
#[doc = "Field `SIE` writer - Status Interrupt Enable"]
pub type SieW<'a, REG> = crate::BitWriter<'a, REG, Sie>;
impl<'a, REG> SieW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sie::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sie::Enabled)
    }
}
#[doc = "Error Interrupt Enable\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eie {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Eie> for bool {
    #[inline(always)]
    fn from(variant: Eie) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `EIE` reader - Error Interrupt Enable"]
pub type EieR = crate::BitReader<Eie>;
impl EieR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Eie {
        match self.bits {
            false => Eie::Disabled,
            true => Eie::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Eie::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Eie::Enabled
    }
}
#[doc = "Field `EIE` writer - Error Interrupt Enable"]
pub type EieW<'a, REG> = crate::BitWriter<'a, REG, Eie>;
impl<'a, REG> EieW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Eie::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Eie::Enabled)
    }
}
#[doc = "Disable Automatic Retransmission\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dar {
    #[doc = "0: `0`"]
    Enabled = 0,
    #[doc = "1: `1`"]
    Disabled = 1,
}
impl From<Dar> for bool {
    #[inline(always)]
    fn from(variant: Dar) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `DAR` reader - Disable Automatic Retransmission"]
pub type DarR = crate::BitReader<Dar>;
impl DarR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dar {
        match self.bits {
            false => Dar::Enabled,
            true => Dar::Disabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Dar::Enabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Dar::Disabled
    }
}
#[doc = "Field `DAR` writer - Disable Automatic Retransmission"]
pub type DarW<'a, REG> = crate::BitWriter<'a, REG, Dar>;
impl<'a, REG> DarW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dar::Enabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Dar::Disabled)
    }
}
#[doc = "Configuration Change Enable\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cce {
    #[doc = "0: `0`"]
    NoWrAcc = 0,
    #[doc = "1: `1`"]
    WrAcc = 1,
}
impl From<Cce> for bool {
    #[inline(always)]
    fn from(variant: Cce) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `CCE` reader - Configuration Change Enable"]
pub type CceR = crate::BitReader<Cce>;
impl CceR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cce {
        match self.bits {
            false => Cce::NoWrAcc,
            true => Cce::WrAcc,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_no_wr_acc(&self) -> bool {
        *self == Cce::NoWrAcc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_wr_acc(&self) -> bool {
        *self == Cce::WrAcc
    }
}
#[doc = "Field `CCE` writer - Configuration Change Enable"]
pub type CceW<'a, REG> = crate::BitWriter<'a, REG, Cce>;
impl<'a, REG> CceW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn no_wr_acc(self) -> &'a mut crate::W<REG> {
        self.variant(Cce::NoWrAcc)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn wr_acc(self) -> &'a mut crate::W<REG> {
        self.variant(Cce::WrAcc)
    }
}
#[doc = "Test Mode Enable\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Test {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    TestMode = 1,
}
impl From<Test> for bool {
    #[inline(always)]
    fn from(variant: Test) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `Test` reader - Test Mode Enable"]
pub type TestR = crate::BitReader<Test>;
impl TestR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Test {
        match self.bits {
            false => Test::Disabled,
            true => Test::TestMode,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Test::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_test_mode(&self) -> bool {
        *self == Test::TestMode
    }
}
#[doc = "Field `Test` writer - Test Mode Enable"]
pub type TestW<'a, REG> = crate::BitWriter<'a, REG, Test>;
impl<'a, REG> TestW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Test::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn test_mode(self) -> &'a mut crate::W<REG> {
        self.variant(Test::TestMode)
    }
}
#[doc = "Message Object Interrupt Line Enable\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mil {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Mil> for bool {
    #[inline(always)]
    fn from(variant: Mil) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MIL` reader - Message Object Interrupt Line Enable"]
pub type MilR = crate::BitReader<Mil>;
impl MilR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mil {
        match self.bits {
            false => Mil::Disabled,
            true => Mil::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Mil::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Mil::Enabled
    }
}
#[doc = "Field `MIL` writer - Message Object Interrupt Line Enable"]
pub type MilW<'a, REG> = crate::BitWriter<'a, REG, Mil>;
impl<'a, REG> MilW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Mil::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Mil::Enabled)
    }
}
#[doc = "DMA Enable for IF1\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum De1 {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<De1> for bool {
    #[inline(always)]
    fn from(variant: De1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `DE1` reader - DMA Enable for IF1"]
pub type De1R = crate::BitReader<De1>;
impl De1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> De1 {
        match self.bits {
            false => De1::Disabled,
            true => De1::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == De1::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == De1::Enabled
    }
}
#[doc = "Field `DE1` writer - DMA Enable for IF1"]
pub type De1W<'a, REG> = crate::BitWriter<'a, REG, De1>;
impl<'a, REG> De1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(De1::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(De1::Enabled)
    }
}
#[doc = "DMA Enable for IF2\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum De2 {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<De2> for bool {
    #[inline(always)]
    fn from(variant: De2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `DE2` reader - DMA Enable for IF2"]
pub type De2R = crate::BitReader<De2>;
impl De2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> De2 {
        match self.bits {
            false => De2::Disabled,
            true => De2::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == De2::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == De2::Enabled
    }
}
#[doc = "Field `DE2` writer - DMA Enable for IF2"]
pub type De2W<'a, REG> = crate::BitWriter<'a, REG, De2>;
impl<'a, REG> De2W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(De2::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(De2::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - Initialization Note: Due to the synchronization mechanism between the two clock domains, there may be a delay until the value written to CCTRL.Init can be read back. Therefore the programmer has to assure that the previous value written to CCTRL.Init has been accepted by reading CCTRL.Init before setting CCTRL.Init to a new value.\n Note: The Bus_Off recovery sequence (see CAN Specification Rev. 2.0) cannot be shortened by setting or resetting CCTRL.Init. If the device goes Bus_Off, it will set CCTRL.Init of its own accord, stopping all bus activities. Once CCTRL.Init has been cleared by the CPU, the device will then wait for 129 occurrences of Bus Idle (129 * 11 consecutive recessive bits) before resuming normal operations. At the end of the Bus_Off recovery sequence, the Error Management Counters will be reset. During the waiting time after the resetting of CCTRL.Init, each time a sequence of 11 recessive bits has been monitored, a Bit0Error code is written to the Status Register, enabling the CPU to readily check up whether the CAN bus is stuck at dominant or continuously disturbed and to monitor the proceeding of the us_Off recovery sequence."]
    #[inline(always)]
    pub fn init(&self) -> InitR {
        InitR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Module Interrupt Line Enable"]
    #[inline(always)]
    pub fn ile(&self) -> IleR {
        IleR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Status Interrupt Enable"]
    #[inline(always)]
    pub fn sie(&self) -> SieR {
        SieR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Error Interrupt Enable"]
    #[inline(always)]
    pub fn eie(&self) -> EieR {
        EieR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 5 - Disable Automatic Retransmission"]
    #[inline(always)]
    pub fn dar(&self) -> DarR {
        DarR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Configuration Change Enable"]
    #[inline(always)]
    pub fn cce(&self) -> CceR {
        CceR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Test Mode Enable"]
    #[inline(always)]
    pub fn test(&self) -> TestR {
        TestR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 17 - Message Object Interrupt Line Enable"]
    #[inline(always)]
    pub fn mil(&self) -> MilR {
        MilR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - DMA Enable for IF1"]
    #[inline(always)]
    pub fn de1(&self) -> De1R {
        De1R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - DMA Enable for IF2"]
    #[inline(always)]
    pub fn de2(&self) -> De2R {
        De2R::new(((self.bits >> 19) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Initialization Note: Due to the synchronization mechanism between the two clock domains, there may be a delay until the value written to CCTRL.Init can be read back. Therefore the programmer has to assure that the previous value written to CCTRL.Init has been accepted by reading CCTRL.Init before setting CCTRL.Init to a new value.\n Note: The Bus_Off recovery sequence (see CAN Specification Rev. 2.0) cannot be shortened by setting or resetting CCTRL.Init. If the device goes Bus_Off, it will set CCTRL.Init of its own accord, stopping all bus activities. Once CCTRL.Init has been cleared by the CPU, the device will then wait for 129 occurrences of Bus Idle (129 * 11 consecutive recessive bits) before resuming normal operations. At the end of the Bus_Off recovery sequence, the Error Management Counters will be reset. During the waiting time after the resetting of CCTRL.Init, each time a sequence of 11 recessive bits has been monitored, a Bit0Error code is written to the Status Register, enabling the CPU to readily check up whether the CAN bus is stuck at dominant or continuously disturbed and to monitor the proceeding of the us_Off recovery sequence."]
    #[inline(always)]
    #[must_use]
    pub fn init(&mut self) -> InitW<ProtogrpCctrlSpec> {
        InitW::new(self, 0)
    }
    #[doc = "Bit 1 - Module Interrupt Line Enable"]
    #[inline(always)]
    #[must_use]
    pub fn ile(&mut self) -> IleW<ProtogrpCctrlSpec> {
        IleW::new(self, 1)
    }
    #[doc = "Bit 2 - Status Interrupt Enable"]
    #[inline(always)]
    #[must_use]
    pub fn sie(&mut self) -> SieW<ProtogrpCctrlSpec> {
        SieW::new(self, 2)
    }
    #[doc = "Bit 3 - Error Interrupt Enable"]
    #[inline(always)]
    #[must_use]
    pub fn eie(&mut self) -> EieW<ProtogrpCctrlSpec> {
        EieW::new(self, 3)
    }
    #[doc = "Bit 5 - Disable Automatic Retransmission"]
    #[inline(always)]
    #[must_use]
    pub fn dar(&mut self) -> DarW<ProtogrpCctrlSpec> {
        DarW::new(self, 5)
    }
    #[doc = "Bit 6 - Configuration Change Enable"]
    #[inline(always)]
    #[must_use]
    pub fn cce(&mut self) -> CceW<ProtogrpCctrlSpec> {
        CceW::new(self, 6)
    }
    #[doc = "Bit 7 - Test Mode Enable"]
    #[inline(always)]
    #[must_use]
    pub fn test(&mut self) -> TestW<ProtogrpCctrlSpec> {
        TestW::new(self, 7)
    }
    #[doc = "Bit 17 - Message Object Interrupt Line Enable"]
    #[inline(always)]
    #[must_use]
    pub fn mil(&mut self) -> MilW<ProtogrpCctrlSpec> {
        MilW::new(self, 17)
    }
    #[doc = "Bit 18 - DMA Enable for IF1"]
    #[inline(always)]
    #[must_use]
    pub fn de1(&mut self) -> De1W<ProtogrpCctrlSpec> {
        De1W::new(self, 18)
    }
    #[doc = "Bit 19 - DMA Enable for IF2"]
    #[inline(always)]
    #[must_use]
    pub fn de2(&mut self) -> De2W<ProtogrpCctrlSpec> {
        De2W::new(self, 19)
    }
}
#[doc = "Control Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_cctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`protogrp_cctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ProtogrpCctrlSpec;
impl crate::RegisterSpec for ProtogrpCctrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`protogrp_cctrl::R`](R) reader structure"]
impl crate::Readable for ProtogrpCctrlSpec {}
#[doc = "`write(|w| ..)` method takes [`protogrp_cctrl::W`](W) writer structure"]
impl crate::Writable for ProtogrpCctrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets protogrp_CCTRL to value 0x01"]
impl crate::Resettable for ProtogrpCctrlSpec {
    const RESET_VALUE: u32 = 0x01;
}
