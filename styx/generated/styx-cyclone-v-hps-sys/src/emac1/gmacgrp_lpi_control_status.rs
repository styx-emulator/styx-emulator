// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_LPI_Control_Status` reader"]
pub type R = crate::R<GmacgrpLpiControlStatusSpec>;
#[doc = "Register `gmacgrp_LPI_Control_Status` writer"]
pub type W = crate::W<GmacgrpLpiControlStatusSpec>;
#[doc = "When set, this bit indicates that the MAC Transmitter has entered the LPI state because of the setting of the LPIEN bit. This bit is cleared by a read into this register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tlpien {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Tlpien> for bool {
    #[inline(always)]
    fn from(variant: Tlpien) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tlpien` reader - When set, this bit indicates that the MAC Transmitter has entered the LPI state because of the setting of the LPIEN bit. This bit is cleared by a read into this register."]
pub type TlpienR = crate::BitReader<Tlpien>;
impl TlpienR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tlpien {
        match self.bits {
            false => Tlpien::Inactive,
            true => Tlpien::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Tlpien::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Tlpien::Active
    }
}
#[doc = "Field `tlpien` writer - When set, this bit indicates that the MAC Transmitter has entered the LPI state because of the setting of the LPIEN bit. This bit is cleared by a read into this register."]
pub type TlpienW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When set, this bit indicates that the MAC transmitter has exited the LPI state after the user has cleared the LPIEN bit and the LPI TW Timer has expired. This bit is cleared by a read into this register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tlpiex {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Tlpiex> for bool {
    #[inline(always)]
    fn from(variant: Tlpiex) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tlpiex` reader - When set, this bit indicates that the MAC transmitter has exited the LPI state after the user has cleared the LPIEN bit and the LPI TW Timer has expired. This bit is cleared by a read into this register."]
pub type TlpiexR = crate::BitReader<Tlpiex>;
impl TlpiexR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tlpiex {
        match self.bits {
            false => Tlpiex::Inactive,
            true => Tlpiex::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Tlpiex::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Tlpiex::Active
    }
}
#[doc = "Field `tlpiex` writer - When set, this bit indicates that the MAC transmitter has exited the LPI state after the user has cleared the LPIEN bit and the LPI TW Timer has expired. This bit is cleared by a read into this register."]
pub type TlpiexW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When set, this bit indicates that the MAC Receiver has received an LPI pattern and entered the LPI state. This bit is cleared by a read into this register. Note: This bit may not get set if the MAC stops receiving the LPI pattern for a very short duration, such as, less than 3 clock cycles of l3_sp_clk.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rlpien {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rlpien> for bool {
    #[inline(always)]
    fn from(variant: Rlpien) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rlpien` reader - When set, this bit indicates that the MAC Receiver has received an LPI pattern and entered the LPI state. This bit is cleared by a read into this register. Note: This bit may not get set if the MAC stops receiving the LPI pattern for a very short duration, such as, less than 3 clock cycles of l3_sp_clk."]
pub type RlpienR = crate::BitReader<Rlpien>;
impl RlpienR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rlpien {
        match self.bits {
            false => Rlpien::Inactive,
            true => Rlpien::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rlpien::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rlpien::Active
    }
}
#[doc = "Field `rlpien` writer - When set, this bit indicates that the MAC Receiver has received an LPI pattern and entered the LPI state. This bit is cleared by a read into this register. Note: This bit may not get set if the MAC stops receiving the LPI pattern for a very short duration, such as, less than 3 clock cycles of l3_sp_clk."]
pub type RlpienW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When set, this bit indicates that the MAC Receiver has stopped receiving the LPI pattern on the GMII or MII interface, exited the LPI state, and resumed the normal reception. This bit is cleared by a read into this register. Note: This bit may not get set if the MAC stops receiving the LPI pattern for a very short duration, such as, less than 3 clock cycles of l3_sp_clk.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rlpiex {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rlpiex> for bool {
    #[inline(always)]
    fn from(variant: Rlpiex) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rlpiex` reader - When set, this bit indicates that the MAC Receiver has stopped receiving the LPI pattern on the GMII or MII interface, exited the LPI state, and resumed the normal reception. This bit is cleared by a read into this register. Note: This bit may not get set if the MAC stops receiving the LPI pattern for a very short duration, such as, less than 3 clock cycles of l3_sp_clk."]
pub type RlpiexR = crate::BitReader<Rlpiex>;
impl RlpiexR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rlpiex {
        match self.bits {
            false => Rlpiex::Inactive,
            true => Rlpiex::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rlpiex::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rlpiex::Active
    }
}
#[doc = "Field `rlpiex` writer - When set, this bit indicates that the MAC Receiver has stopped receiving the LPI pattern on the GMII or MII interface, exited the LPI state, and resumed the normal reception. This bit is cleared by a read into this register. Note: This bit may not get set if the MAC stops receiving the LPI pattern for a very short duration, such as, less than 3 clock cycles of l3_sp_clk."]
pub type RlpiexW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When set, this bit indicates that the MAC is transmitting the LPI pattern on the GMII or MII interface.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tlpist {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Tlpist> for bool {
    #[inline(always)]
    fn from(variant: Tlpist) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tlpist` reader - When set, this bit indicates that the MAC is transmitting the LPI pattern on the GMII or MII interface."]
pub type TlpistR = crate::BitReader<Tlpist>;
impl TlpistR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tlpist {
        match self.bits {
            false => Tlpist::Inactive,
            true => Tlpist::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Tlpist::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Tlpist::Active
    }
}
#[doc = "Field `tlpist` writer - When set, this bit indicates that the MAC is transmitting the LPI pattern on the GMII or MII interface."]
pub type TlpistW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When set, this bit indicates that the MAC is receiving the LPI pattern on the GMII or MII interface.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rlpist {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rlpist> for bool {
    #[inline(always)]
    fn from(variant: Rlpist) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rlpist` reader - When set, this bit indicates that the MAC is receiving the LPI pattern on the GMII or MII interface."]
pub type RlpistR = crate::BitReader<Rlpist>;
impl RlpistR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rlpist {
        match self.bits {
            false => Rlpist::Inactive,
            true => Rlpist::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rlpist::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rlpist::Active
    }
}
#[doc = "Field `rlpist` writer - When set, this bit indicates that the MAC is receiving the LPI pattern on the GMII or MII interface."]
pub type RlpistW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When set, this bit instructs the MAC Transmitter to enter the LPI state. When reset, this bit instructs the MAC to exit the LPI state and resume normal transmission. This bit is cleared when the LPITXA bit is set and the MAC exits the LPI state because of the arrival of a new packet for transmission.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lpien {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Lpien> for bool {
    #[inline(always)]
    fn from(variant: Lpien) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `lpien` reader - When set, this bit instructs the MAC Transmitter to enter the LPI state. When reset, this bit instructs the MAC to exit the LPI state and resume normal transmission. This bit is cleared when the LPITXA bit is set and the MAC exits the LPI state because of the arrival of a new packet for transmission."]
pub type LpienR = crate::BitReader<Lpien>;
impl LpienR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Lpien {
        match self.bits {
            false => Lpien::Disabled,
            true => Lpien::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Lpien::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Lpien::Enabled
    }
}
#[doc = "Field `lpien` writer - When set, this bit instructs the MAC Transmitter to enter the LPI state. When reset, this bit instructs the MAC to exit the LPI state and resume normal transmission. This bit is cleared when the LPITXA bit is set and the MAC exits the LPI state because of the arrival of a new packet for transmission."]
pub type LpienW<'a, REG> = crate::BitWriter<'a, REG, Lpien>;
impl<'a, REG> LpienW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lpien::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lpien::Enabled)
    }
}
#[doc = "This bit indicates the link status of the PHY. The MAC Transmitter asserts the LPI pattern only when the link status is up (okay) at least for the time indicated by the LPI LS TIMER. When set, the link is considered to be okay (up) and when reset, the link is considered to be down.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pls {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Pls> for bool {
    #[inline(always)]
    fn from(variant: Pls) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `pls` reader - This bit indicates the link status of the PHY. The MAC Transmitter asserts the LPI pattern only when the link status is up (okay) at least for the time indicated by the LPI LS TIMER. When set, the link is considered to be okay (up) and when reset, the link is considered to be down."]
pub type PlsR = crate::BitReader<Pls>;
impl PlsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pls {
        match self.bits {
            false => Pls::Disabled,
            true => Pls::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Pls::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Pls::Enabled
    }
}
#[doc = "Field `pls` writer - This bit indicates the link status of the PHY. The MAC Transmitter asserts the LPI pattern only when the link status is up (okay) at least for the time indicated by the LPI LS TIMER. When set, the link is considered to be okay (up) and when reset, the link is considered to be down."]
pub type PlsW<'a, REG> = crate::BitWriter<'a, REG, Pls>;
impl<'a, REG> PlsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Pls::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Pls::Enabled)
    }
}
#[doc = "This bit enables the link status received on the RGMII receive paths to be used for activating the LPI LS TIMER. When set, the MAC uses the link-status bits of Register 54 (SGMII/RGMII/SMII Status Register) and Bit 17 (PLS) for the LPI LS Timer trigger. When cleared, the MAC ignores the link-status bits of Register 54 and takes only the PLS bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plsen {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Plsen> for bool {
    #[inline(always)]
    fn from(variant: Plsen) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `plsen` reader - This bit enables the link status received on the RGMII receive paths to be used for activating the LPI LS TIMER. When set, the MAC uses the link-status bits of Register 54 (SGMII/RGMII/SMII Status Register) and Bit 17 (PLS) for the LPI LS Timer trigger. When cleared, the MAC ignores the link-status bits of Register 54 and takes only the PLS bit."]
pub type PlsenR = crate::BitReader<Plsen>;
impl PlsenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Plsen {
        match self.bits {
            false => Plsen::Disabled,
            true => Plsen::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Plsen::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Plsen::Enabled
    }
}
#[doc = "Field `plsen` writer - This bit enables the link status received on the RGMII receive paths to be used for activating the LPI LS TIMER. When set, the MAC uses the link-status bits of Register 54 (SGMII/RGMII/SMII Status Register) and Bit 17 (PLS) for the LPI LS Timer trigger. When cleared, the MAC ignores the link-status bits of Register 54 and takes only the PLS bit."]
pub type PlsenW<'a, REG> = crate::BitWriter<'a, REG, Plsen>;
impl<'a, REG> PlsenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Plsen::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Plsen::Enabled)
    }
}
#[doc = "This bit controls the behavior of the MAC when it is entering or coming out of the LPI mode on the transmit side. This bit is not functional in the GMAC-CORE configuration in which the Tx clock gating is done during the LPI mode. If the LPITXA and LPIEN bits are set to 1, the MAC enters the LPI mode only after all outstanding frames (in the core) and pending frames (in the application interface) have been transmitted. The MAC comes out of the LPI mode when the application sends any frame for transmission or the application issues a TX FIFO Flush command. In addition, the MAC automatically clears the LPIEN bit when it exits the LPI state. If TX FIFO Flush is set, in Bit 20 of Register 6 (Operation Mode Register), when the MAC is in the LPI mode, the MAC exits the LPI mode. When this bit is 0, the LPIEN bit directly controls behavior of the MAC when it is entering or coming out of the LPI mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lpitxa {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Lpitxa> for bool {
    #[inline(always)]
    fn from(variant: Lpitxa) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `lpitxa` reader - This bit controls the behavior of the MAC when it is entering or coming out of the LPI mode on the transmit side. This bit is not functional in the GMAC-CORE configuration in which the Tx clock gating is done during the LPI mode. If the LPITXA and LPIEN bits are set to 1, the MAC enters the LPI mode only after all outstanding frames (in the core) and pending frames (in the application interface) have been transmitted. The MAC comes out of the LPI mode when the application sends any frame for transmission or the application issues a TX FIFO Flush command. In addition, the MAC automatically clears the LPIEN bit when it exits the LPI state. If TX FIFO Flush is set, in Bit 20 of Register 6 (Operation Mode Register), when the MAC is in the LPI mode, the MAC exits the LPI mode. When this bit is 0, the LPIEN bit directly controls behavior of the MAC when it is entering or coming out of the LPI mode."]
pub type LpitxaR = crate::BitReader<Lpitxa>;
impl LpitxaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Lpitxa {
        match self.bits {
            false => Lpitxa::Disabled,
            true => Lpitxa::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Lpitxa::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Lpitxa::Enabled
    }
}
#[doc = "Field `lpitxa` writer - This bit controls the behavior of the MAC when it is entering or coming out of the LPI mode on the transmit side. This bit is not functional in the GMAC-CORE configuration in which the Tx clock gating is done during the LPI mode. If the LPITXA and LPIEN bits are set to 1, the MAC enters the LPI mode only after all outstanding frames (in the core) and pending frames (in the application interface) have been transmitted. The MAC comes out of the LPI mode when the application sends any frame for transmission or the application issues a TX FIFO Flush command. In addition, the MAC automatically clears the LPIEN bit when it exits the LPI state. If TX FIFO Flush is set, in Bit 20 of Register 6 (Operation Mode Register), when the MAC is in the LPI mode, the MAC exits the LPI mode. When this bit is 0, the LPIEN bit directly controls behavior of the MAC when it is entering or coming out of the LPI mode."]
pub type LpitxaW<'a, REG> = crate::BitWriter<'a, REG, Lpitxa>;
impl<'a, REG> LpitxaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lpitxa::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lpitxa::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - When set, this bit indicates that the MAC Transmitter has entered the LPI state because of the setting of the LPIEN bit. This bit is cleared by a read into this register."]
    #[inline(always)]
    pub fn tlpien(&self) -> TlpienR {
        TlpienR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When set, this bit indicates that the MAC transmitter has exited the LPI state after the user has cleared the LPIEN bit and the LPI TW Timer has expired. This bit is cleared by a read into this register."]
    #[inline(always)]
    pub fn tlpiex(&self) -> TlpiexR {
        TlpiexR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - When set, this bit indicates that the MAC Receiver has received an LPI pattern and entered the LPI state. This bit is cleared by a read into this register. Note: This bit may not get set if the MAC stops receiving the LPI pattern for a very short duration, such as, less than 3 clock cycles of l3_sp_clk."]
    #[inline(always)]
    pub fn rlpien(&self) -> RlpienR {
        RlpienR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - When set, this bit indicates that the MAC Receiver has stopped receiving the LPI pattern on the GMII or MII interface, exited the LPI state, and resumed the normal reception. This bit is cleared by a read into this register. Note: This bit may not get set if the MAC stops receiving the LPI pattern for a very short duration, such as, less than 3 clock cycles of l3_sp_clk."]
    #[inline(always)]
    pub fn rlpiex(&self) -> RlpiexR {
        RlpiexR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 8 - When set, this bit indicates that the MAC is transmitting the LPI pattern on the GMII or MII interface."]
    #[inline(always)]
    pub fn tlpist(&self) -> TlpistR {
        TlpistR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - When set, this bit indicates that the MAC is receiving the LPI pattern on the GMII or MII interface."]
    #[inline(always)]
    pub fn rlpist(&self) -> RlpistR {
        RlpistR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 16 - When set, this bit instructs the MAC Transmitter to enter the LPI state. When reset, this bit instructs the MAC to exit the LPI state and resume normal transmission. This bit is cleared when the LPITXA bit is set and the MAC exits the LPI state because of the arrival of a new packet for transmission."]
    #[inline(always)]
    pub fn lpien(&self) -> LpienR {
        LpienR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - This bit indicates the link status of the PHY. The MAC Transmitter asserts the LPI pattern only when the link status is up (okay) at least for the time indicated by the LPI LS TIMER. When set, the link is considered to be okay (up) and when reset, the link is considered to be down."]
    #[inline(always)]
    pub fn pls(&self) -> PlsR {
        PlsR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - This bit enables the link status received on the RGMII receive paths to be used for activating the LPI LS TIMER. When set, the MAC uses the link-status bits of Register 54 (SGMII/RGMII/SMII Status Register) and Bit 17 (PLS) for the LPI LS Timer trigger. When cleared, the MAC ignores the link-status bits of Register 54 and takes only the PLS bit."]
    #[inline(always)]
    pub fn plsen(&self) -> PlsenR {
        PlsenR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - This bit controls the behavior of the MAC when it is entering or coming out of the LPI mode on the transmit side. This bit is not functional in the GMAC-CORE configuration in which the Tx clock gating is done during the LPI mode. If the LPITXA and LPIEN bits are set to 1, the MAC enters the LPI mode only after all outstanding frames (in the core) and pending frames (in the application interface) have been transmitted. The MAC comes out of the LPI mode when the application sends any frame for transmission or the application issues a TX FIFO Flush command. In addition, the MAC automatically clears the LPIEN bit when it exits the LPI state. If TX FIFO Flush is set, in Bit 20 of Register 6 (Operation Mode Register), when the MAC is in the LPI mode, the MAC exits the LPI mode. When this bit is 0, the LPIEN bit directly controls behavior of the MAC when it is entering or coming out of the LPI mode."]
    #[inline(always)]
    pub fn lpitxa(&self) -> LpitxaR {
        LpitxaR::new(((self.bits >> 19) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When set, this bit indicates that the MAC Transmitter has entered the LPI state because of the setting of the LPIEN bit. This bit is cleared by a read into this register."]
    #[inline(always)]
    #[must_use]
    pub fn tlpien(&mut self) -> TlpienW<GmacgrpLpiControlStatusSpec> {
        TlpienW::new(self, 0)
    }
    #[doc = "Bit 1 - When set, this bit indicates that the MAC transmitter has exited the LPI state after the user has cleared the LPIEN bit and the LPI TW Timer has expired. This bit is cleared by a read into this register."]
    #[inline(always)]
    #[must_use]
    pub fn tlpiex(&mut self) -> TlpiexW<GmacgrpLpiControlStatusSpec> {
        TlpiexW::new(self, 1)
    }
    #[doc = "Bit 2 - When set, this bit indicates that the MAC Receiver has received an LPI pattern and entered the LPI state. This bit is cleared by a read into this register. Note: This bit may not get set if the MAC stops receiving the LPI pattern for a very short duration, such as, less than 3 clock cycles of l3_sp_clk."]
    #[inline(always)]
    #[must_use]
    pub fn rlpien(&mut self) -> RlpienW<GmacgrpLpiControlStatusSpec> {
        RlpienW::new(self, 2)
    }
    #[doc = "Bit 3 - When set, this bit indicates that the MAC Receiver has stopped receiving the LPI pattern on the GMII or MII interface, exited the LPI state, and resumed the normal reception. This bit is cleared by a read into this register. Note: This bit may not get set if the MAC stops receiving the LPI pattern for a very short duration, such as, less than 3 clock cycles of l3_sp_clk."]
    #[inline(always)]
    #[must_use]
    pub fn rlpiex(&mut self) -> RlpiexW<GmacgrpLpiControlStatusSpec> {
        RlpiexW::new(self, 3)
    }
    #[doc = "Bit 8 - When set, this bit indicates that the MAC is transmitting the LPI pattern on the GMII or MII interface."]
    #[inline(always)]
    #[must_use]
    pub fn tlpist(&mut self) -> TlpistW<GmacgrpLpiControlStatusSpec> {
        TlpistW::new(self, 8)
    }
    #[doc = "Bit 9 - When set, this bit indicates that the MAC is receiving the LPI pattern on the GMII or MII interface."]
    #[inline(always)]
    #[must_use]
    pub fn rlpist(&mut self) -> RlpistW<GmacgrpLpiControlStatusSpec> {
        RlpistW::new(self, 9)
    }
    #[doc = "Bit 16 - When set, this bit instructs the MAC Transmitter to enter the LPI state. When reset, this bit instructs the MAC to exit the LPI state and resume normal transmission. This bit is cleared when the LPITXA bit is set and the MAC exits the LPI state because of the arrival of a new packet for transmission."]
    #[inline(always)]
    #[must_use]
    pub fn lpien(&mut self) -> LpienW<GmacgrpLpiControlStatusSpec> {
        LpienW::new(self, 16)
    }
    #[doc = "Bit 17 - This bit indicates the link status of the PHY. The MAC Transmitter asserts the LPI pattern only when the link status is up (okay) at least for the time indicated by the LPI LS TIMER. When set, the link is considered to be okay (up) and when reset, the link is considered to be down."]
    #[inline(always)]
    #[must_use]
    pub fn pls(&mut self) -> PlsW<GmacgrpLpiControlStatusSpec> {
        PlsW::new(self, 17)
    }
    #[doc = "Bit 18 - This bit enables the link status received on the RGMII receive paths to be used for activating the LPI LS TIMER. When set, the MAC uses the link-status bits of Register 54 (SGMII/RGMII/SMII Status Register) and Bit 17 (PLS) for the LPI LS Timer trigger. When cleared, the MAC ignores the link-status bits of Register 54 and takes only the PLS bit."]
    #[inline(always)]
    #[must_use]
    pub fn plsen(&mut self) -> PlsenW<GmacgrpLpiControlStatusSpec> {
        PlsenW::new(self, 18)
    }
    #[doc = "Bit 19 - This bit controls the behavior of the MAC when it is entering or coming out of the LPI mode on the transmit side. This bit is not functional in the GMAC-CORE configuration in which the Tx clock gating is done during the LPI mode. If the LPITXA and LPIEN bits are set to 1, the MAC enters the LPI mode only after all outstanding frames (in the core) and pending frames (in the application interface) have been transmitted. The MAC comes out of the LPI mode when the application sends any frame for transmission or the application issues a TX FIFO Flush command. In addition, the MAC automatically clears the LPIEN bit when it exits the LPI state. If TX FIFO Flush is set, in Bit 20 of Register 6 (Operation Mode Register), when the MAC is in the LPI mode, the MAC exits the LPI mode. When this bit is 0, the LPIEN bit directly controls behavior of the MAC when it is entering or coming out of the LPI mode."]
    #[inline(always)]
    #[must_use]
    pub fn lpitxa(&mut self) -> LpitxaW<GmacgrpLpiControlStatusSpec> {
        LpitxaW::new(self, 19)
    }
}
#[doc = "The LPI Control and Status Register controls the LPI functions and provides the LPI interrupt status. The status bits are cleared when this register is read.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_lpi_control_status::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_lpi_control_status::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpLpiControlStatusSpec;
impl crate::RegisterSpec for GmacgrpLpiControlStatusSpec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`gmacgrp_lpi_control_status::R`](R) reader structure"]
impl crate::Readable for GmacgrpLpiControlStatusSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_lpi_control_status::W`](W) writer structure"]
impl crate::Writable for GmacgrpLpiControlStatusSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_LPI_Control_Status to value 0"]
impl crate::Resettable for GmacgrpLpiControlStatusSpec {
    const RESET_VALUE: u32 = 0;
}
