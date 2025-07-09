// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `lsr` reader"]
pub type R = crate::R<LsrSpec>;
#[doc = "Register `lsr` writer"]
pub type W = crate::W<LsrSpec>;
#[doc = "This is used to indicate that the receiver contains at least one character in the RBR or the receiver FIFO. This bit is cleared when the RBR is read in the non-FIFO mode, or when the receiver FIFO is empty, in the FIFO mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dr {
    #[doc = "0: `0`"]
    Nodatardy = 0,
    #[doc = "1: `1`"]
    Datardy = 1,
}
impl From<Dr> for bool {
    #[inline(always)]
    fn from(variant: Dr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dr` reader - This is used to indicate that the receiver contains at least one character in the RBR or the receiver FIFO. This bit is cleared when the RBR is read in the non-FIFO mode, or when the receiver FIFO is empty, in the FIFO mode."]
pub type DrR = crate::BitReader<Dr>;
impl DrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dr {
        match self.bits {
            false => Dr::Nodatardy,
            true => Dr::Datardy,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nodatardy(&self) -> bool {
        *self == Dr::Nodatardy
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_datardy(&self) -> bool {
        *self == Dr::Datardy
    }
}
#[doc = "Field `dr` writer - This is used to indicate that the receiver contains at least one character in the RBR or the receiver FIFO. This bit is cleared when the RBR is read in the non-FIFO mode, or when the receiver FIFO is empty, in the FIFO mode."]
pub type DrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This is used to indicate the occurrence of an overrun error. This occurs if a new data character was received before the previous data was read. In the non-FIFO mode, the OE bit is set when a new character arrives in the receiver before the previous character was read from the RBR. When this happens, the data in the RBR is overwritten. In the FIFO mode, an overrun error occurs when the FIFO is full and new character arrives at the receiver. The data in the FIFO is retained and the data in the receive shift register is lost.Reading the LSR clears the OE bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Oe {
    #[doc = "0: `0`"]
    Nooverrun = 0,
    #[doc = "1: `1`"]
    Overrun = 1,
}
impl From<Oe> for bool {
    #[inline(always)]
    fn from(variant: Oe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `oe` reader - This is used to indicate the occurrence of an overrun error. This occurs if a new data character was received before the previous data was read. In the non-FIFO mode, the OE bit is set when a new character arrives in the receiver before the previous character was read from the RBR. When this happens, the data in the RBR is overwritten. In the FIFO mode, an overrun error occurs when the FIFO is full and new character arrives at the receiver. The data in the FIFO is retained and the data in the receive shift register is lost.Reading the LSR clears the OE bit."]
pub type OeR = crate::BitReader<Oe>;
impl OeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Oe {
        match self.bits {
            false => Oe::Nooverrun,
            true => Oe::Overrun,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nooverrun(&self) -> bool {
        *self == Oe::Nooverrun
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_overrun(&self) -> bool {
        *self == Oe::Overrun
    }
}
#[doc = "Field `oe` writer - This is used to indicate the occurrence of an overrun error. This occurs if a new data character was received before the previous data was read. In the non-FIFO mode, the OE bit is set when a new character arrives in the receiver before the previous character was read from the RBR. When this happens, the data in the RBR is overwritten. In the FIFO mode, an overrun error occurs when the FIFO is full and new character arrives at the receiver. The data in the FIFO is retained and the data in the receive shift register is lost.Reading the LSR clears the OE bit."]
pub type OeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This is used to indicate the occurrence of a parity error in the receiver if the Parity Enable (PEN) bit (LCR\\[3\\]) is set. Since the parity error is associated with a character received, it is revealed when the character with the parity error arrives at the top of the FIFO. It should be noted that the Parity Error (PE) bit (LSR\\[2\\]) will be set if a break interrupt has occurred, as indicated by Break Interrupt (BI) bit (LSR\\[4\\]). Reading the LSR clears the PE bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pe {
    #[doc = "0: `0`"]
    Noparityerr = 0,
    #[doc = "1: `1`"]
    Parityerr = 1,
}
impl From<Pe> for bool {
    #[inline(always)]
    fn from(variant: Pe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `pe` reader - This is used to indicate the occurrence of a parity error in the receiver if the Parity Enable (PEN) bit (LCR\\[3\\]) is set. Since the parity error is associated with a character received, it is revealed when the character with the parity error arrives at the top of the FIFO. It should be noted that the Parity Error (PE) bit (LSR\\[2\\]) will be set if a break interrupt has occurred, as indicated by Break Interrupt (BI) bit (LSR\\[4\\]). Reading the LSR clears the PE bit."]
pub type PeR = crate::BitReader<Pe>;
impl PeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pe {
        match self.bits {
            false => Pe::Noparityerr,
            true => Pe::Parityerr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noparityerr(&self) -> bool {
        *self == Pe::Noparityerr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_parityerr(&self) -> bool {
        *self == Pe::Parityerr
    }
}
#[doc = "Field `pe` writer - This is used to indicate the occurrence of a parity error in the receiver if the Parity Enable (PEN) bit (LCR\\[3\\]) is set. Since the parity error is associated with a character received, it is revealed when the character with the parity error arrives at the top of the FIFO. It should be noted that the Parity Error (PE) bit (LSR\\[2\\]) will be set if a break interrupt has occurred, as indicated by Break Interrupt (BI) bit (LSR\\[4\\]). Reading the LSR clears the PE bit."]
pub type PeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This is used to indicate the occurrence of a framing error in the receiver. A framing error occurs when the receiver does not detect a valid STOP bit in the received data. In the FIFO mode, since the framing error is associated with a character received, it is revealed when the character with the framing error is at the top of the FIFO. When a framing error occurs the UART will try to resynchronize. It does this by assuming that the error was due to the start bit of the next character and then continues receiving the other bit i.e. data, and/or parity and stop. It should be noted that the Framing Error (FE) bit(LSR\\[3\\]) will be set if a break interrupt has occurred, as indicated by a Break Interrupt BIT bit (LSR\\[4\\]). Reading the LSR clears the FE bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fe {
    #[doc = "0: `0`"]
    Noframeerr = 0,
    #[doc = "1: `1`"]
    Frameerr = 1,
}
impl From<Fe> for bool {
    #[inline(always)]
    fn from(variant: Fe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fe` reader - This is used to indicate the occurrence of a framing error in the receiver. A framing error occurs when the receiver does not detect a valid STOP bit in the received data. In the FIFO mode, since the framing error is associated with a character received, it is revealed when the character with the framing error is at the top of the FIFO. When a framing error occurs the UART will try to resynchronize. It does this by assuming that the error was due to the start bit of the next character and then continues receiving the other bit i.e. data, and/or parity and stop. It should be noted that the Framing Error (FE) bit(LSR\\[3\\]) will be set if a break interrupt has occurred, as indicated by a Break Interrupt BIT bit (LSR\\[4\\]). Reading the LSR clears the FE bit."]
pub type FeR = crate::BitReader<Fe>;
impl FeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fe {
        match self.bits {
            false => Fe::Noframeerr,
            true => Fe::Frameerr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noframeerr(&self) -> bool {
        *self == Fe::Noframeerr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_frameerr(&self) -> bool {
        *self == Fe::Frameerr
    }
}
#[doc = "Field `fe` writer - This is used to indicate the occurrence of a framing error in the receiver. A framing error occurs when the receiver does not detect a valid STOP bit in the received data. In the FIFO mode, since the framing error is associated with a character received, it is revealed when the character with the framing error is at the top of the FIFO. When a framing error occurs the UART will try to resynchronize. It does this by assuming that the error was due to the start bit of the next character and then continues receiving the other bit i.e. data, and/or parity and stop. It should be noted that the Framing Error (FE) bit(LSR\\[3\\]) will be set if a break interrupt has occurred, as indicated by a Break Interrupt BIT bit (LSR\\[4\\]). Reading the LSR clears the FE bit."]
pub type FeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `bi` reader - This is used to indicate the detection of a break sequence on the serial input data. Set whenever the serial input, sin, is held in a logic 0 state for longer than the sum of start time + data bits + parity + stop bits. A break condition on serial input causes one and only one character, consisting of all zeros, to be received by the UART. The character associated with the break condition is carried through the FIFO and is revealed when the character is at the top of the FIFO. Reading the LSR clears the BI bit."]
pub type BiR = crate::BitReader;
#[doc = "Field `bi` writer - This is used to indicate the detection of a break sequence on the serial input data. Set whenever the serial input, sin, is held in a logic 0 state for longer than the sum of start time + data bits + parity + stop bits. A break condition on serial input causes one and only one character, consisting of all zeros, to be received by the UART. The character associated with the break condition is carried through the FIFO and is revealed when the character is at the top of the FIFO. Reading the LSR clears the BI bit."]
pub type BiW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `thre` reader - If THRE mode is disabled (IER\\[7\\]
set to zero) this bit indicates that the THR or Tx FIFO is empty. This bit is set whenever data is transferred from the THR or Tx FIFO to the transmitter shift register and no new data has been written to the THR or Tx FIFO. This also causes a THRE Interrupt to occur, if the THRE Interrupt is enabled. If both THRE and FIFOs are enabled, both (IER\\[7\\]
set to one and FCR\\[0\\]
set to one respectively), the functionality will indicate the transmitter FIFO is full, and no longer controls THRE interrupts, which are then controlled by the FCR\\[5:4\\]
thresholdsetting."]
pub type ThreR = crate::BitReader;
#[doc = "Field `thre` writer - If THRE mode is disabled (IER\\[7\\]
set to zero) this bit indicates that the THR or Tx FIFO is empty. This bit is set whenever data is transferred from the THR or Tx FIFO to the transmitter shift register and no new data has been written to the THR or Tx FIFO. This also causes a THRE Interrupt to occur, if the THRE Interrupt is enabled. If both THRE and FIFOs are enabled, both (IER\\[7\\]
set to one and FCR\\[0\\]
set to one respectively), the functionality will indicate the transmitter FIFO is full, and no longer controls THRE interrupts, which are then controlled by the FCR\\[5:4\\]
thresholdsetting."]
pub type ThreW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "If in FIFO mode and FIFO's enabled (FCR\\[0\\]
set to one), this bit is set whenever the Transmitter Shift Register and the FIFO are both empty. If FIFO's are disabled, this bit is set whenever the Transmitter Holding Register and the Transmitter Shift Register are both empty.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Temt {
    #[doc = "0: `0`"]
    Notempty = 0,
    #[doc = "1: `1`"]
    Empty = 1,
}
impl From<Temt> for bool {
    #[inline(always)]
    fn from(variant: Temt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `temt` reader - If in FIFO mode and FIFO's enabled (FCR\\[0\\]
set to one), this bit is set whenever the Transmitter Shift Register and the FIFO are both empty. If FIFO's are disabled, this bit is set whenever the Transmitter Holding Register and the Transmitter Shift Register are both empty."]
pub type TemtR = crate::BitReader<Temt>;
impl TemtR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Temt {
        match self.bits {
            false => Temt::Notempty,
            true => Temt::Empty,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notempty(&self) -> bool {
        *self == Temt::Notempty
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        *self == Temt::Empty
    }
}
#[doc = "Field `temt` writer - If in FIFO mode and FIFO's enabled (FCR\\[0\\]
set to one), this bit is set whenever the Transmitter Shift Register and the FIFO are both empty. If FIFO's are disabled, this bit is set whenever the Transmitter Holding Register and the Transmitter Shift Register are both empty."]
pub type TemtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is only relevant when FIFO's are enabled (FCR\\[0\\]
set to one). This is used to indicate if there is at least one parity error, framing error, or break indication in the FIFO. This bit is cleared when the LSR is read and the character with the error is at the top of the receiver FIFO and there are no subsequent errors in the FIFO.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rfe {
    #[doc = "0: `0`"]
    Noerr = 0,
    #[doc = "1: `1`"]
    Err = 1,
}
impl From<Rfe> for bool {
    #[inline(always)]
    fn from(variant: Rfe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rfe` reader - This bit is only relevant when FIFO's are enabled (FCR\\[0\\]
set to one). This is used to indicate if there is at least one parity error, framing error, or break indication in the FIFO. This bit is cleared when the LSR is read and the character with the error is at the top of the receiver FIFO and there are no subsequent errors in the FIFO."]
pub type RfeR = crate::BitReader<Rfe>;
impl RfeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rfe {
        match self.bits {
            false => Rfe::Noerr,
            true => Rfe::Err,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noerr(&self) -> bool {
        *self == Rfe::Noerr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_err(&self) -> bool {
        *self == Rfe::Err
    }
}
#[doc = "Field `rfe` writer - This bit is only relevant when FIFO's are enabled (FCR\\[0\\]
set to one). This is used to indicate if there is at least one parity error, framing error, or break indication in the FIFO. This bit is cleared when the LSR is read and the character with the error is at the top of the receiver FIFO and there are no subsequent errors in the FIFO."]
pub type RfeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This is used to indicate that the receiver contains at least one character in the RBR or the receiver FIFO. This bit is cleared when the RBR is read in the non-FIFO mode, or when the receiver FIFO is empty, in the FIFO mode."]
    #[inline(always)]
    pub fn dr(&self) -> DrR {
        DrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This is used to indicate the occurrence of an overrun error. This occurs if a new data character was received before the previous data was read. In the non-FIFO mode, the OE bit is set when a new character arrives in the receiver before the previous character was read from the RBR. When this happens, the data in the RBR is overwritten. In the FIFO mode, an overrun error occurs when the FIFO is full and new character arrives at the receiver. The data in the FIFO is retained and the data in the receive shift register is lost.Reading the LSR clears the OE bit."]
    #[inline(always)]
    pub fn oe(&self) -> OeR {
        OeR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This is used to indicate the occurrence of a parity error in the receiver if the Parity Enable (PEN) bit (LCR\\[3\\]) is set. Since the parity error is associated with a character received, it is revealed when the character with the parity error arrives at the top of the FIFO. It should be noted that the Parity Error (PE) bit (LSR\\[2\\]) will be set if a break interrupt has occurred, as indicated by Break Interrupt (BI) bit (LSR\\[4\\]). Reading the LSR clears the PE bit."]
    #[inline(always)]
    pub fn pe(&self) -> PeR {
        PeR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This is used to indicate the occurrence of a framing error in the receiver. A framing error occurs when the receiver does not detect a valid STOP bit in the received data. In the FIFO mode, since the framing error is associated with a character received, it is revealed when the character with the framing error is at the top of the FIFO. When a framing error occurs the UART will try to resynchronize. It does this by assuming that the error was due to the start bit of the next character and then continues receiving the other bit i.e. data, and/or parity and stop. It should be noted that the Framing Error (FE) bit(LSR\\[3\\]) will be set if a break interrupt has occurred, as indicated by a Break Interrupt BIT bit (LSR\\[4\\]). Reading the LSR clears the FE bit."]
    #[inline(always)]
    pub fn fe(&self) -> FeR {
        FeR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This is used to indicate the detection of a break sequence on the serial input data. Set whenever the serial input, sin, is held in a logic 0 state for longer than the sum of start time + data bits + parity + stop bits. A break condition on serial input causes one and only one character, consisting of all zeros, to be received by the UART. The character associated with the break condition is carried through the FIFO and is revealed when the character is at the top of the FIFO. Reading the LSR clears the BI bit."]
    #[inline(always)]
    pub fn bi(&self) -> BiR {
        BiR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - If THRE mode is disabled (IER\\[7\\]
set to zero) this bit indicates that the THR or Tx FIFO is empty. This bit is set whenever data is transferred from the THR or Tx FIFO to the transmitter shift register and no new data has been written to the THR or Tx FIFO. This also causes a THRE Interrupt to occur, if the THRE Interrupt is enabled. If both THRE and FIFOs are enabled, both (IER\\[7\\]
set to one and FCR\\[0\\]
set to one respectively), the functionality will indicate the transmitter FIFO is full, and no longer controls THRE interrupts, which are then controlled by the FCR\\[5:4\\]
thresholdsetting."]
    #[inline(always)]
    pub fn thre(&self) -> ThreR {
        ThreR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - If in FIFO mode and FIFO's enabled (FCR\\[0\\]
set to one), this bit is set whenever the Transmitter Shift Register and the FIFO are both empty. If FIFO's are disabled, this bit is set whenever the Transmitter Holding Register and the Transmitter Shift Register are both empty."]
    #[inline(always)]
    pub fn temt(&self) -> TemtR {
        TemtR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This bit is only relevant when FIFO's are enabled (FCR\\[0\\]
set to one). This is used to indicate if there is at least one parity error, framing error, or break indication in the FIFO. This bit is cleared when the LSR is read and the character with the error is at the top of the receiver FIFO and there are no subsequent errors in the FIFO."]
    #[inline(always)]
    pub fn rfe(&self) -> RfeR {
        RfeR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This is used to indicate that the receiver contains at least one character in the RBR or the receiver FIFO. This bit is cleared when the RBR is read in the non-FIFO mode, or when the receiver FIFO is empty, in the FIFO mode."]
    #[inline(always)]
    #[must_use]
    pub fn dr(&mut self) -> DrW<LsrSpec> {
        DrW::new(self, 0)
    }
    #[doc = "Bit 1 - This is used to indicate the occurrence of an overrun error. This occurs if a new data character was received before the previous data was read. In the non-FIFO mode, the OE bit is set when a new character arrives in the receiver before the previous character was read from the RBR. When this happens, the data in the RBR is overwritten. In the FIFO mode, an overrun error occurs when the FIFO is full and new character arrives at the receiver. The data in the FIFO is retained and the data in the receive shift register is lost.Reading the LSR clears the OE bit."]
    #[inline(always)]
    #[must_use]
    pub fn oe(&mut self) -> OeW<LsrSpec> {
        OeW::new(self, 1)
    }
    #[doc = "Bit 2 - This is used to indicate the occurrence of a parity error in the receiver if the Parity Enable (PEN) bit (LCR\\[3\\]) is set. Since the parity error is associated with a character received, it is revealed when the character with the parity error arrives at the top of the FIFO. It should be noted that the Parity Error (PE) bit (LSR\\[2\\]) will be set if a break interrupt has occurred, as indicated by Break Interrupt (BI) bit (LSR\\[4\\]). Reading the LSR clears the PE bit."]
    #[inline(always)]
    #[must_use]
    pub fn pe(&mut self) -> PeW<LsrSpec> {
        PeW::new(self, 2)
    }
    #[doc = "Bit 3 - This is used to indicate the occurrence of a framing error in the receiver. A framing error occurs when the receiver does not detect a valid STOP bit in the received data. In the FIFO mode, since the framing error is associated with a character received, it is revealed when the character with the framing error is at the top of the FIFO. When a framing error occurs the UART will try to resynchronize. It does this by assuming that the error was due to the start bit of the next character and then continues receiving the other bit i.e. data, and/or parity and stop. It should be noted that the Framing Error (FE) bit(LSR\\[3\\]) will be set if a break interrupt has occurred, as indicated by a Break Interrupt BIT bit (LSR\\[4\\]). Reading the LSR clears the FE bit."]
    #[inline(always)]
    #[must_use]
    pub fn fe(&mut self) -> FeW<LsrSpec> {
        FeW::new(self, 3)
    }
    #[doc = "Bit 4 - This is used to indicate the detection of a break sequence on the serial input data. Set whenever the serial input, sin, is held in a logic 0 state for longer than the sum of start time + data bits + parity + stop bits. A break condition on serial input causes one and only one character, consisting of all zeros, to be received by the UART. The character associated with the break condition is carried through the FIFO and is revealed when the character is at the top of the FIFO. Reading the LSR clears the BI bit."]
    #[inline(always)]
    #[must_use]
    pub fn bi(&mut self) -> BiW<LsrSpec> {
        BiW::new(self, 4)
    }
    #[doc = "Bit 5 - If THRE mode is disabled (IER\\[7\\]
set to zero) this bit indicates that the THR or Tx FIFO is empty. This bit is set whenever data is transferred from the THR or Tx FIFO to the transmitter shift register and no new data has been written to the THR or Tx FIFO. This also causes a THRE Interrupt to occur, if the THRE Interrupt is enabled. If both THRE and FIFOs are enabled, both (IER\\[7\\]
set to one and FCR\\[0\\]
set to one respectively), the functionality will indicate the transmitter FIFO is full, and no longer controls THRE interrupts, which are then controlled by the FCR\\[5:4\\]
thresholdsetting."]
    #[inline(always)]
    #[must_use]
    pub fn thre(&mut self) -> ThreW<LsrSpec> {
        ThreW::new(self, 5)
    }
    #[doc = "Bit 6 - If in FIFO mode and FIFO's enabled (FCR\\[0\\]
set to one), this bit is set whenever the Transmitter Shift Register and the FIFO are both empty. If FIFO's are disabled, this bit is set whenever the Transmitter Holding Register and the Transmitter Shift Register are both empty."]
    #[inline(always)]
    #[must_use]
    pub fn temt(&mut self) -> TemtW<LsrSpec> {
        TemtW::new(self, 6)
    }
    #[doc = "Bit 7 - This bit is only relevant when FIFO's are enabled (FCR\\[0\\]
set to one). This is used to indicate if there is at least one parity error, framing error, or break indication in the FIFO. This bit is cleared when the LSR is read and the character with the error is at the top of the receiver FIFO and there are no subsequent errors in the FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn rfe(&mut self) -> RfeW<LsrSpec> {
        RfeW::new(self, 7)
    }
}
#[doc = "Reports status of transmit and receive.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lsr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct LsrSpec;
impl crate::RegisterSpec for LsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`lsr::R`](R) reader structure"]
impl crate::Readable for LsrSpec {}
#[doc = "`reset()` method sets lsr to value 0x60"]
impl crate::Resettable for LsrSpec {
    const RESET_VALUE: u32 = 0x60;
}
