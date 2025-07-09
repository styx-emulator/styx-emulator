// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `lcr` reader"]
pub type R = crate::R<LcrSpec>;
#[doc = "Register `lcr` writer"]
pub type W = crate::W<LcrSpec>;
#[doc = "Data Length Select.Selects the number of data bits per character that the peripheral will transmit and receive.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Dls {
    #[doc = "0: `0`"]
    Length5 = 0,
    #[doc = "1: `1`"]
    Length6 = 1,
    #[doc = "2: `10`"]
    Length7 = 2,
    #[doc = "3: `11`"]
    Length8 = 3,
}
impl From<Dls> for u8 {
    #[inline(always)]
    fn from(variant: Dls) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Dls {
    type Ux = u8;
}
#[doc = "Field `dls` reader - Data Length Select.Selects the number of data bits per character that the peripheral will transmit and receive."]
pub type DlsR = crate::FieldReader<Dls>;
impl DlsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dls {
        match self.bits {
            0 => Dls::Length5,
            1 => Dls::Length6,
            2 => Dls::Length7,
            3 => Dls::Length8,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_length5(&self) -> bool {
        *self == Dls::Length5
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_length6(&self) -> bool {
        *self == Dls::Length6
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_length7(&self) -> bool {
        *self == Dls::Length7
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_length8(&self) -> bool {
        *self == Dls::Length8
    }
}
#[doc = "Field `dls` writer - Data Length Select.Selects the number of data bits per character that the peripheral will transmit and receive."]
pub type DlsW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Dls>;
impl<'a, REG> DlsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn length5(self) -> &'a mut crate::W<REG> {
        self.variant(Dls::Length5)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn length6(self) -> &'a mut crate::W<REG> {
        self.variant(Dls::Length6)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn length7(self) -> &'a mut crate::W<REG> {
        self.variant(Dls::Length7)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn length8(self) -> &'a mut crate::W<REG> {
        self.variant(Dls::Length8)
    }
}
#[doc = "Number of stop bits. Used to select the number of stop bits per character that the peripheral will transmit and receive.Note that regardless of the number of stop bits selected the receiver will only check the first stop bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    #[doc = "0: `0`"]
    Onestop = 0,
    #[doc = "1: `1`"]
    Onepoint5stop = 1,
}
impl From<Stop> for bool {
    #[inline(always)]
    fn from(variant: Stop) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `stop` reader - Number of stop bits. Used to select the number of stop bits per character that the peripheral will transmit and receive.Note that regardless of the number of stop bits selected the receiver will only check the first stop bit."]
pub type StopR = crate::BitReader<Stop>;
impl StopR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Stop {
        match self.bits {
            false => Stop::Onestop,
            true => Stop::Onepoint5stop,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_onestop(&self) -> bool {
        *self == Stop::Onestop
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_onepoint5stop(&self) -> bool {
        *self == Stop::Onepoint5stop
    }
}
#[doc = "Field `stop` writer - Number of stop bits. Used to select the number of stop bits per character that the peripheral will transmit and receive.Note that regardless of the number of stop bits selected the receiver will only check the first stop bit."]
pub type StopW<'a, REG> = crate::BitWriter<'a, REG, Stop>;
impl<'a, REG> StopW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn onestop(self) -> &'a mut crate::W<REG> {
        self.variant(Stop::Onestop)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn onepoint5stop(self) -> &'a mut crate::W<REG> {
        self.variant(Stop::Onepoint5stop)
    }
}
#[doc = "This bit is used to enable and disable parity generation and detection in a transmitted and received data character.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pen {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Pen> for bool {
    #[inline(always)]
    fn from(variant: Pen) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `pen` reader - This bit is used to enable and disable parity generation and detection in a transmitted and received data character."]
pub type PenR = crate::BitReader<Pen>;
impl PenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pen {
        match self.bits {
            false => Pen::Disabled,
            true => Pen::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Pen::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Pen::Enabled
    }
}
#[doc = "Field `pen` writer - This bit is used to enable and disable parity generation and detection in a transmitted and received data character."]
pub type PenW<'a, REG> = crate::BitWriter<'a, REG, Pen>;
impl<'a, REG> PenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Pen::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Pen::Enabled)
    }
}
#[doc = "This is used to select between even and odd parity, when parity is enabled (PEN set to one). If set to one, an even number of logic '1's is transmitted or checked. If set to zero, an odd number of logic '1's is transmitted or checked.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eps {
    #[doc = "0: `0`"]
    Oddpar = 0,
    #[doc = "1: `1`"]
    Evenpar = 1,
}
impl From<Eps> for bool {
    #[inline(always)]
    fn from(variant: Eps) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `eps` reader - This is used to select between even and odd parity, when parity is enabled (PEN set to one). If set to one, an even number of logic '1's is transmitted or checked. If set to zero, an odd number of logic '1's is transmitted or checked."]
pub type EpsR = crate::BitReader<Eps>;
impl EpsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Eps {
        match self.bits {
            false => Eps::Oddpar,
            true => Eps::Evenpar,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_oddpar(&self) -> bool {
        *self == Eps::Oddpar
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_evenpar(&self) -> bool {
        *self == Eps::Evenpar
    }
}
#[doc = "Field `eps` writer - This is used to select between even and odd parity, when parity is enabled (PEN set to one). If set to one, an even number of logic '1's is transmitted or checked. If set to zero, an odd number of logic '1's is transmitted or checked."]
pub type EpsW<'a, REG> = crate::BitWriter<'a, REG, Eps>;
impl<'a, REG> EpsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn oddpar(self) -> &'a mut crate::W<REG> {
        self.variant(Eps::Oddpar)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn evenpar(self) -> &'a mut crate::W<REG> {
        self.variant(Eps::Evenpar)
    }
}
#[doc = "Field `break` reader - This is used to cause a break condition to be transmitted to the receiving device. If set to one the serial output is forced to the spacing (logic 0) state. When not in Loopback Mode, as determined by MCR\\[4\\], the sout line is forced low until the Break bit is cleared. When in Loopback Mode, the break condition is internally looped back to the receiver and the sir_out_n line is forced low."]
pub type BreakR = crate::BitReader;
#[doc = "Field `break` writer - This is used to cause a break condition to be transmitted to the receiving device. If set to one the serial output is forced to the spacing (logic 0) state. When not in Loopback Mode, as determined by MCR\\[4\\], the sout line is forced low until the Break bit is cleared. When in Loopback Mode, the break condition is internally looped back to the receiver and the sir_out_n line is forced low."]
pub type BreakW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `dlab` reader - Used to enable reading and writing of the Divisor Latch register (DLL and DLH) to set the baud rate of the UART. This bit must be cleared after initial baud rate setup in order to access other registers."]
pub type DlabR = crate::BitReader;
#[doc = "Field `dlab` writer - Used to enable reading and writing of the Divisor Latch register (DLL and DLH) to set the baud rate of the UART. This bit must be cleared after initial baud rate setup in order to access other registers."]
pub type DlabW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - Data Length Select.Selects the number of data bits per character that the peripheral will transmit and receive."]
    #[inline(always)]
    pub fn dls(&self) -> DlsR {
        DlsR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 2 - Number of stop bits. Used to select the number of stop bits per character that the peripheral will transmit and receive.Note that regardless of the number of stop bits selected the receiver will only check the first stop bit."]
    #[inline(always)]
    pub fn stop(&self) -> StopR {
        StopR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This bit is used to enable and disable parity generation and detection in a transmitted and received data character."]
    #[inline(always)]
    pub fn pen(&self) -> PenR {
        PenR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This is used to select between even and odd parity, when parity is enabled (PEN set to one). If set to one, an even number of logic '1's is transmitted or checked. If set to zero, an odd number of logic '1's is transmitted or checked."]
    #[inline(always)]
    pub fn eps(&self) -> EpsR {
        EpsR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 6 - This is used to cause a break condition to be transmitted to the receiving device. If set to one the serial output is forced to the spacing (logic 0) state. When not in Loopback Mode, as determined by MCR\\[4\\], the sout line is forced low until the Break bit is cleared. When in Loopback Mode, the break condition is internally looped back to the receiver and the sir_out_n line is forced low."]
    #[inline(always)]
    pub fn break_(&self) -> BreakR {
        BreakR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Used to enable reading and writing of the Divisor Latch register (DLL and DLH) to set the baud rate of the UART. This bit must be cleared after initial baud rate setup in order to access other registers."]
    #[inline(always)]
    pub fn dlab(&self) -> DlabR {
        DlabR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - Data Length Select.Selects the number of data bits per character that the peripheral will transmit and receive."]
    #[inline(always)]
    #[must_use]
    pub fn dls(&mut self) -> DlsW<LcrSpec> {
        DlsW::new(self, 0)
    }
    #[doc = "Bit 2 - Number of stop bits. Used to select the number of stop bits per character that the peripheral will transmit and receive.Note that regardless of the number of stop bits selected the receiver will only check the first stop bit."]
    #[inline(always)]
    #[must_use]
    pub fn stop(&mut self) -> StopW<LcrSpec> {
        StopW::new(self, 2)
    }
    #[doc = "Bit 3 - This bit is used to enable and disable parity generation and detection in a transmitted and received data character."]
    #[inline(always)]
    #[must_use]
    pub fn pen(&mut self) -> PenW<LcrSpec> {
        PenW::new(self, 3)
    }
    #[doc = "Bit 4 - This is used to select between even and odd parity, when parity is enabled (PEN set to one). If set to one, an even number of logic '1's is transmitted or checked. If set to zero, an odd number of logic '1's is transmitted or checked."]
    #[inline(always)]
    #[must_use]
    pub fn eps(&mut self) -> EpsW<LcrSpec> {
        EpsW::new(self, 4)
    }
    #[doc = "Bit 6 - This is used to cause a break condition to be transmitted to the receiving device. If set to one the serial output is forced to the spacing (logic 0) state. When not in Loopback Mode, as determined by MCR\\[4\\], the sout line is forced low until the Break bit is cleared. When in Loopback Mode, the break condition is internally looped back to the receiver and the sir_out_n line is forced low."]
    #[inline(always)]
    #[must_use]
    pub fn break_(&mut self) -> BreakW<LcrSpec> {
        BreakW::new(self, 6)
    }
    #[doc = "Bit 7 - Used to enable reading and writing of the Divisor Latch register (DLL and DLH) to set the baud rate of the UART. This bit must be cleared after initial baud rate setup in order to access other registers."]
    #[inline(always)]
    #[must_use]
    pub fn dlab(&mut self) -> DlabW<LcrSpec> {
        DlabW::new(self, 7)
    }
}
#[doc = "Formats serial data.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`lcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct LcrSpec;
impl crate::RegisterSpec for LcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`lcr::R`](R) reader structure"]
impl crate::Readable for LcrSpec {}
#[doc = "`write(|w| ..)` method takes [`lcr::W`](W) writer structure"]
impl crate::Writable for LcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets lcr to value 0"]
impl crate::Resettable for LcrSpec {
    const RESET_VALUE: u32 = 0;
}
