// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlr0` reader"]
pub type R = crate::R<Ctrlr0Spec>;
#[doc = "Register `ctrlr0` writer"]
pub type W = crate::W<Ctrlr0Spec>;
#[doc = "Selects the data frame length. When the data frame size is programmed to be less than 16 bits, the receive data are automatically right-justified by the receive logic, with the upper bits of the receiver FIFO zero-padded. You must right-justify transmit data before writing into the transmit FIFO. The transmit logic ignores the upper unused bits when transmitting the data.\n\nValue on reset: 7"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Dfs {
    #[doc = "3: `11`"]
    Width4bit = 3,
    #[doc = "4: `100`"]
    Width5bit = 4,
    #[doc = "5: `101`"]
    Width6bit = 5,
    #[doc = "6: `110`"]
    Width7bit = 6,
    #[doc = "7: `111`"]
    Width8bit = 7,
    #[doc = "8: `1000`"]
    Width9bit = 8,
    #[doc = "9: `1001`"]
    Width10bit = 9,
}
impl From<Dfs> for u8 {
    #[inline(always)]
    fn from(variant: Dfs) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Dfs {
    type Ux = u8;
}
#[doc = "Field `dfs` reader - Selects the data frame length. When the data frame size is programmed to be less than 16 bits, the receive data are automatically right-justified by the receive logic, with the upper bits of the receiver FIFO zero-padded. You must right-justify transmit data before writing into the transmit FIFO. The transmit logic ignores the upper unused bits when transmitting the data."]
pub type DfsR = crate::FieldReader<Dfs>;
impl DfsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Dfs> {
        match self.bits {
            3 => Some(Dfs::Width4bit),
            4 => Some(Dfs::Width5bit),
            5 => Some(Dfs::Width6bit),
            6 => Some(Dfs::Width7bit),
            7 => Some(Dfs::Width8bit),
            8 => Some(Dfs::Width9bit),
            9 => Some(Dfs::Width10bit),
            _ => None,
        }
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_width4bit(&self) -> bool {
        *self == Dfs::Width4bit
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_width5bit(&self) -> bool {
        *self == Dfs::Width5bit
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_width6bit(&self) -> bool {
        *self == Dfs::Width6bit
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_width7bit(&self) -> bool {
        *self == Dfs::Width7bit
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_width8bit(&self) -> bool {
        *self == Dfs::Width8bit
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_width9bit(&self) -> bool {
        *self == Dfs::Width9bit
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_width10bit(&self) -> bool {
        *self == Dfs::Width10bit
    }
}
#[doc = "Field `dfs` writer - Selects the data frame length. When the data frame size is programmed to be less than 16 bits, the receive data are automatically right-justified by the receive logic, with the upper bits of the receiver FIFO zero-padded. You must right-justify transmit data before writing into the transmit FIFO. The transmit logic ignores the upper unused bits when transmitting the data."]
pub type DfsW<'a, REG> = crate::FieldWriter<'a, REG, 4, Dfs>;
impl<'a, REG> DfsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`11`"]
    #[inline(always)]
    pub fn width4bit(self) -> &'a mut crate::W<REG> {
        self.variant(Dfs::Width4bit)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn width5bit(self) -> &'a mut crate::W<REG> {
        self.variant(Dfs::Width5bit)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn width6bit(self) -> &'a mut crate::W<REG> {
        self.variant(Dfs::Width6bit)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn width7bit(self) -> &'a mut crate::W<REG> {
        self.variant(Dfs::Width7bit)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn width8bit(self) -> &'a mut crate::W<REG> {
        self.variant(Dfs::Width8bit)
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn width9bit(self) -> &'a mut crate::W<REG> {
        self.variant(Dfs::Width9bit)
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn width10bit(self) -> &'a mut crate::W<REG> {
        self.variant(Dfs::Width10bit)
    }
}
#[doc = "Selects which serial protocol transfers the data.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Frf {
    #[doc = "0: `0`"]
    Motspi = 0,
    #[doc = "1: `1`"]
    Tissp = 1,
    #[doc = "2: `10`"]
    Natmw = 2,
}
impl From<Frf> for u8 {
    #[inline(always)]
    fn from(variant: Frf) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Frf {
    type Ux = u8;
}
#[doc = "Field `frf` reader - Selects which serial protocol transfers the data."]
pub type FrfR = crate::FieldReader<Frf>;
impl FrfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Frf> {
        match self.bits {
            0 => Some(Frf::Motspi),
            1 => Some(Frf::Tissp),
            2 => Some(Frf::Natmw),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_motspi(&self) -> bool {
        *self == Frf::Motspi
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_tissp(&self) -> bool {
        *self == Frf::Tissp
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_natmw(&self) -> bool {
        *self == Frf::Natmw
    }
}
#[doc = "Field `frf` writer - Selects which serial protocol transfers the data."]
pub type FrfW<'a, REG> = crate::FieldWriter<'a, REG, 2, Frf>;
impl<'a, REG> FrfW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn motspi(self) -> &'a mut crate::W<REG> {
        self.variant(Frf::Motspi)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn tissp(self) -> &'a mut crate::W<REG> {
        self.variant(Frf::Tissp)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn natmw(self) -> &'a mut crate::W<REG> {
        self.variant(Frf::Natmw)
    }
}
#[doc = "Valid when the frame format (FRF) is set to Motorola SPI. The serial clock phase selects the relationship of the serial clock with the slave select signal. When SCPH = 0, data are captured on the first edge of the serial clock. When SCPH = 1, the serial clock starts toggling one cycle after the slave select line is activated, and data are captured on the second edge of the serial clock.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scph {
    #[doc = "0: `0`"]
    Inactivelow = 0,
    #[doc = "1: `1`"]
    Inactivehigh = 1,
}
impl From<Scph> for bool {
    #[inline(always)]
    fn from(variant: Scph) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `scph` reader - Valid when the frame format (FRF) is set to Motorola SPI. The serial clock phase selects the relationship of the serial clock with the slave select signal. When SCPH = 0, data are captured on the first edge of the serial clock. When SCPH = 1, the serial clock starts toggling one cycle after the slave select line is activated, and data are captured on the second edge of the serial clock."]
pub type ScphR = crate::BitReader<Scph>;
impl ScphR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Scph {
        match self.bits {
            false => Scph::Inactivelow,
            true => Scph::Inactivehigh,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactivelow(&self) -> bool {
        *self == Scph::Inactivelow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_inactivehigh(&self) -> bool {
        *self == Scph::Inactivehigh
    }
}
#[doc = "Field `scph` writer - Valid when the frame format (FRF) is set to Motorola SPI. The serial clock phase selects the relationship of the serial clock with the slave select signal. When SCPH = 0, data are captured on the first edge of the serial clock. When SCPH = 1, the serial clock starts toggling one cycle after the slave select line is activated, and data are captured on the second edge of the serial clock."]
pub type ScphW<'a, REG> = crate::BitWriter<'a, REG, Scph>;
impl<'a, REG> ScphW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn inactivelow(self) -> &'a mut crate::W<REG> {
        self.variant(Scph::Inactivelow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn inactivehigh(self) -> &'a mut crate::W<REG> {
        self.variant(Scph::Inactivehigh)
    }
}
#[doc = "Valid when the frame format (FRF) is set to Motorola SPI. Used to select the polarity of the inactive serial clock, which is held inactive when the spi master is not actively transferring data on the serial bus.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scpol {
    #[doc = "0: `0`"]
    Midbit = 0,
    #[doc = "1: `1`"]
    Startbit = 1,
}
impl From<Scpol> for bool {
    #[inline(always)]
    fn from(variant: Scpol) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `scpol` reader - Valid when the frame format (FRF) is set to Motorola SPI. Used to select the polarity of the inactive serial clock, which is held inactive when the spi master is not actively transferring data on the serial bus."]
pub type ScpolR = crate::BitReader<Scpol>;
impl ScpolR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Scpol {
        match self.bits {
            false => Scpol::Midbit,
            true => Scpol::Startbit,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_midbit(&self) -> bool {
        *self == Scpol::Midbit
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_startbit(&self) -> bool {
        *self == Scpol::Startbit
    }
}
#[doc = "Field `scpol` writer - Valid when the frame format (FRF) is set to Motorola SPI. Used to select the polarity of the inactive serial clock, which is held inactive when the spi master is not actively transferring data on the serial bus."]
pub type ScpolW<'a, REG> = crate::BitWriter<'a, REG, Scpol>;
impl<'a, REG> ScpolW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn midbit(self) -> &'a mut crate::W<REG> {
        self.variant(Scpol::Midbit)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn startbit(self) -> &'a mut crate::W<REG> {
        self.variant(Scpol::Startbit)
    }
}
#[doc = "Selects the mode of transfer for serial communication. This field does not affect the transfer duplicity. Only indicates whether the receive or transmit data are valid. In transmit-only mode, data received from the external device is not valid and is not stored in the receive FIFO memory; it is overwritten on the next transfer. In receive-only mode, transmitted data are not valid. After the first write to the transmit FIFO, the same word is retransmitted for the duration of the transfer. In transmit-and-receive mode, both transmit and receive data are valid. The transfer continues until the transmit FIFO is empty. Data received from the external device are stored into the receive FIFO memory\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tmod {
    #[doc = "0: `0`"]
    Txrx = 0,
    #[doc = "1: `1`"]
    Txonly = 1,
    #[doc = "2: `10`"]
    Rxonly = 2,
}
impl From<Tmod> for u8 {
    #[inline(always)]
    fn from(variant: Tmod) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Tmod {
    type Ux = u8;
}
#[doc = "Field `tmod` reader - Selects the mode of transfer for serial communication. This field does not affect the transfer duplicity. Only indicates whether the receive or transmit data are valid. In transmit-only mode, data received from the external device is not valid and is not stored in the receive FIFO memory; it is overwritten on the next transfer. In receive-only mode, transmitted data are not valid. After the first write to the transmit FIFO, the same word is retransmitted for the duration of the transfer. In transmit-and-receive mode, both transmit and receive data are valid. The transfer continues until the transmit FIFO is empty. Data received from the external device are stored into the receive FIFO memory"]
pub type TmodR = crate::FieldReader<Tmod>;
impl TmodR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Tmod> {
        match self.bits {
            0 => Some(Tmod::Txrx),
            1 => Some(Tmod::Txonly),
            2 => Some(Tmod::Rxonly),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_txrx(&self) -> bool {
        *self == Tmod::Txrx
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_txonly(&self) -> bool {
        *self == Tmod::Txonly
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_rxonly(&self) -> bool {
        *self == Tmod::Rxonly
    }
}
#[doc = "Field `tmod` writer - Selects the mode of transfer for serial communication. This field does not affect the transfer duplicity. Only indicates whether the receive or transmit data are valid. In transmit-only mode, data received from the external device is not valid and is not stored in the receive FIFO memory; it is overwritten on the next transfer. In receive-only mode, transmitted data are not valid. After the first write to the transmit FIFO, the same word is retransmitted for the duration of the transfer. In transmit-and-receive mode, both transmit and receive data are valid. The transfer continues until the transmit FIFO is empty. Data received from the external device are stored into the receive FIFO memory"]
pub type TmodW<'a, REG> = crate::FieldWriter<'a, REG, 2, Tmod>;
impl<'a, REG> TmodW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn txrx(self) -> &'a mut crate::W<REG> {
        self.variant(Tmod::Txrx)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn txonly(self) -> &'a mut crate::W<REG> {
        self.variant(Tmod::Txonly)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn rxonly(self) -> &'a mut crate::W<REG> {
        self.variant(Tmod::Rxonly)
    }
}
#[doc = "This bit enables or disables the setting of the spis0_ssi_oe_n output from the SPI Slave. When SLV_OE = 1, the spis0_ssi_oe_n output can never be active. When the spis0_ssi_oe_n output controls the tri-state buffer on the txd output from the slave, a high impedance state is always present on the slave spis0_txd output when SLV_OE = 1. This is useful when the master transmits in broadcast mode (master transmits data to all slave devices). Only one slave may respond with data on the master spis0_rxd line. This bit is enabled after reset and must be disabled by software (when broadcast mode is used), if you do not want this device to respond with data.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlvOe {
    #[doc = "0: `0`"]
    Enabled = 0,
    #[doc = "1: `1`"]
    Disabled = 1,
}
impl From<SlvOe> for bool {
    #[inline(always)]
    fn from(variant: SlvOe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `slv_oe` reader - This bit enables or disables the setting of the spis0_ssi_oe_n output from the SPI Slave. When SLV_OE = 1, the spis0_ssi_oe_n output can never be active. When the spis0_ssi_oe_n output controls the tri-state buffer on the txd output from the slave, a high impedance state is always present on the slave spis0_txd output when SLV_OE = 1. This is useful when the master transmits in broadcast mode (master transmits data to all slave devices). Only one slave may respond with data on the master spis0_rxd line. This bit is enabled after reset and must be disabled by software (when broadcast mode is used), if you do not want this device to respond with data."]
pub type SlvOeR = crate::BitReader<SlvOe>;
impl SlvOeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> SlvOe {
        match self.bits {
            false => SlvOe::Enabled,
            true => SlvOe::Disabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == SlvOe::Enabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == SlvOe::Disabled
    }
}
#[doc = "Field `slv_oe` writer - This bit enables or disables the setting of the spis0_ssi_oe_n output from the SPI Slave. When SLV_OE = 1, the spis0_ssi_oe_n output can never be active. When the spis0_ssi_oe_n output controls the tri-state buffer on the txd output from the slave, a high impedance state is always present on the slave spis0_txd output when SLV_OE = 1. This is useful when the master transmits in broadcast mode (master transmits data to all slave devices). Only one slave may respond with data on the master spis0_rxd line. This bit is enabled after reset and must be disabled by software (when broadcast mode is used), if you do not want this device to respond with data."]
pub type SlvOeW<'a, REG> = crate::BitWriter<'a, REG, SlvOe>;
impl<'a, REG> SlvOeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(SlvOe::Enabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(SlvOe::Disabled)
    }
}
#[doc = "Used for testing purposes only. When internally active, connects the transmit shift register output to the receive shift register input.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Srl {
    #[doc = "0: `0`"]
    Normmode = 0,
    #[doc = "1: `1`"]
    Testmode = 1,
}
impl From<Srl> for bool {
    #[inline(always)]
    fn from(variant: Srl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `srl` reader - Used for testing purposes only. When internally active, connects the transmit shift register output to the receive shift register input."]
pub type SrlR = crate::BitReader<Srl>;
impl SrlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Srl {
        match self.bits {
            false => Srl::Normmode,
            true => Srl::Testmode,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_normmode(&self) -> bool {
        *self == Srl::Normmode
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_testmode(&self) -> bool {
        *self == Srl::Testmode
    }
}
#[doc = "Field `srl` writer - Used for testing purposes only. When internally active, connects the transmit shift register output to the receive shift register input."]
pub type SrlW<'a, REG> = crate::BitWriter<'a, REG, Srl>;
impl<'a, REG> SrlW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn normmode(self) -> &'a mut crate::W<REG> {
        self.variant(Srl::Normmode)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn testmode(self) -> &'a mut crate::W<REG> {
        self.variant(Srl::Testmode)
    }
}
#[doc = "Field `cfs` reader - Selects the length of the control word for the Microwire frame format. The length (in bits) is the value of this field plus 1."]
pub type CfsR = crate::FieldReader;
#[doc = "Field `cfs` writer - Selects the length of the control word for the Microwire frame format. The length (in bits) is the value of this field plus 1."]
pub type CfsW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - Selects the data frame length. When the data frame size is programmed to be less than 16 bits, the receive data are automatically right-justified by the receive logic, with the upper bits of the receiver FIFO zero-padded. You must right-justify transmit data before writing into the transmit FIFO. The transmit logic ignores the upper unused bits when transmitting the data."]
    #[inline(always)]
    pub fn dfs(&self) -> DfsR {
        DfsR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:5 - Selects which serial protocol transfers the data."]
    #[inline(always)]
    pub fn frf(&self) -> FrfR {
        FrfR::new(((self.bits >> 4) & 3) as u8)
    }
    #[doc = "Bit 6 - Valid when the frame format (FRF) is set to Motorola SPI. The serial clock phase selects the relationship of the serial clock with the slave select signal. When SCPH = 0, data are captured on the first edge of the serial clock. When SCPH = 1, the serial clock starts toggling one cycle after the slave select line is activated, and data are captured on the second edge of the serial clock."]
    #[inline(always)]
    pub fn scph(&self) -> ScphR {
        ScphR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Valid when the frame format (FRF) is set to Motorola SPI. Used to select the polarity of the inactive serial clock, which is held inactive when the spi master is not actively transferring data on the serial bus."]
    #[inline(always)]
    pub fn scpol(&self) -> ScpolR {
        ScpolR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:9 - Selects the mode of transfer for serial communication. This field does not affect the transfer duplicity. Only indicates whether the receive or transmit data are valid. In transmit-only mode, data received from the external device is not valid and is not stored in the receive FIFO memory; it is overwritten on the next transfer. In receive-only mode, transmitted data are not valid. After the first write to the transmit FIFO, the same word is retransmitted for the duration of the transfer. In transmit-and-receive mode, both transmit and receive data are valid. The transfer continues until the transmit FIFO is empty. Data received from the external device are stored into the receive FIFO memory"]
    #[inline(always)]
    pub fn tmod(&self) -> TmodR {
        TmodR::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bit 10 - This bit enables or disables the setting of the spis0_ssi_oe_n output from the SPI Slave. When SLV_OE = 1, the spis0_ssi_oe_n output can never be active. When the spis0_ssi_oe_n output controls the tri-state buffer on the txd output from the slave, a high impedance state is always present on the slave spis0_txd output when SLV_OE = 1. This is useful when the master transmits in broadcast mode (master transmits data to all slave devices). Only one slave may respond with data on the master spis0_rxd line. This bit is enabled after reset and must be disabled by software (when broadcast mode is used), if you do not want this device to respond with data."]
    #[inline(always)]
    pub fn slv_oe(&self) -> SlvOeR {
        SlvOeR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Used for testing purposes only. When internally active, connects the transmit shift register output to the receive shift register input."]
    #[inline(always)]
    pub fn srl(&self) -> SrlR {
        SrlR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bits 12:15 - Selects the length of the control word for the Microwire frame format. The length (in bits) is the value of this field plus 1."]
    #[inline(always)]
    pub fn cfs(&self) -> CfsR {
        CfsR::new(((self.bits >> 12) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Selects the data frame length. When the data frame size is programmed to be less than 16 bits, the receive data are automatically right-justified by the receive logic, with the upper bits of the receiver FIFO zero-padded. You must right-justify transmit data before writing into the transmit FIFO. The transmit logic ignores the upper unused bits when transmitting the data."]
    #[inline(always)]
    #[must_use]
    pub fn dfs(&mut self) -> DfsW<Ctrlr0Spec> {
        DfsW::new(self, 0)
    }
    #[doc = "Bits 4:5 - Selects which serial protocol transfers the data."]
    #[inline(always)]
    #[must_use]
    pub fn frf(&mut self) -> FrfW<Ctrlr0Spec> {
        FrfW::new(self, 4)
    }
    #[doc = "Bit 6 - Valid when the frame format (FRF) is set to Motorola SPI. The serial clock phase selects the relationship of the serial clock with the slave select signal. When SCPH = 0, data are captured on the first edge of the serial clock. When SCPH = 1, the serial clock starts toggling one cycle after the slave select line is activated, and data are captured on the second edge of the serial clock."]
    #[inline(always)]
    #[must_use]
    pub fn scph(&mut self) -> ScphW<Ctrlr0Spec> {
        ScphW::new(self, 6)
    }
    #[doc = "Bit 7 - Valid when the frame format (FRF) is set to Motorola SPI. Used to select the polarity of the inactive serial clock, which is held inactive when the spi master is not actively transferring data on the serial bus."]
    #[inline(always)]
    #[must_use]
    pub fn scpol(&mut self) -> ScpolW<Ctrlr0Spec> {
        ScpolW::new(self, 7)
    }
    #[doc = "Bits 8:9 - Selects the mode of transfer for serial communication. This field does not affect the transfer duplicity. Only indicates whether the receive or transmit data are valid. In transmit-only mode, data received from the external device is not valid and is not stored in the receive FIFO memory; it is overwritten on the next transfer. In receive-only mode, transmitted data are not valid. After the first write to the transmit FIFO, the same word is retransmitted for the duration of the transfer. In transmit-and-receive mode, both transmit and receive data are valid. The transfer continues until the transmit FIFO is empty. Data received from the external device are stored into the receive FIFO memory"]
    #[inline(always)]
    #[must_use]
    pub fn tmod(&mut self) -> TmodW<Ctrlr0Spec> {
        TmodW::new(self, 8)
    }
    #[doc = "Bit 10 - This bit enables or disables the setting of the spis0_ssi_oe_n output from the SPI Slave. When SLV_OE = 1, the spis0_ssi_oe_n output can never be active. When the spis0_ssi_oe_n output controls the tri-state buffer on the txd output from the slave, a high impedance state is always present on the slave spis0_txd output when SLV_OE = 1. This is useful when the master transmits in broadcast mode (master transmits data to all slave devices). Only one slave may respond with data on the master spis0_rxd line. This bit is enabled after reset and must be disabled by software (when broadcast mode is used), if you do not want this device to respond with data."]
    #[inline(always)]
    #[must_use]
    pub fn slv_oe(&mut self) -> SlvOeW<Ctrlr0Spec> {
        SlvOeW::new(self, 10)
    }
    #[doc = "Bit 11 - Used for testing purposes only. When internally active, connects the transmit shift register output to the receive shift register input."]
    #[inline(always)]
    #[must_use]
    pub fn srl(&mut self) -> SrlW<Ctrlr0Spec> {
        SrlW::new(self, 11)
    }
    #[doc = "Bits 12:15 - Selects the length of the control word for the Microwire frame format. The length (in bits) is the value of this field plus 1."]
    #[inline(always)]
    #[must_use]
    pub fn cfs(&mut self) -> CfsW<Ctrlr0Spec> {
        CfsW::new(self, 12)
    }
}
#[doc = "This register controls the serial data transfer. It is impossible to write to this register when the SPI Slave is enabled. The SPI Slave is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlr0::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlr0::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ctrlr0Spec;
impl crate::RegisterSpec for Ctrlr0Spec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`ctrlr0::R`](R) reader structure"]
impl crate::Readable for Ctrlr0Spec {}
#[doc = "`write(|w| ..)` method takes [`ctrlr0::W`](W) writer structure"]
impl crate::Writable for Ctrlr0Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlr0 to value 0x07"]
impl crate::Resettable for Ctrlr0Spec {
    const RESET_VALUE: u32 = 0x07;
}
