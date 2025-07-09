// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `msr` reader"]
pub type R = crate::R<MsrSpec>;
#[doc = "Register `msr` writer"]
pub type W = crate::W<MsrSpec>;
#[doc = "This is used to indicate that the modem control line uart_cts_n has changed since the last time the MSR was read. That is: Reading the MSR clears the DCTS bit. In Loopback Mode bit \\[4\\]
of MCR set to one, DCTS reflects changes on bit \\[1\\]
RTS of register MCR. Note: If the DCTS bit is not set and the uart_cts_n signal is asserted (low) and a reset occurs (software or otherwise), then the DCTS bit will get set when the reset is removed if the uart_cts_n signal remains asserted.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dcts {
    #[doc = "0: `0`"]
    Nochg = 0,
    #[doc = "1: `1`"]
    Chg = 1,
}
impl From<Dcts> for bool {
    #[inline(always)]
    fn from(variant: Dcts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dcts` reader - This is used to indicate that the modem control line uart_cts_n has changed since the last time the MSR was read. That is: Reading the MSR clears the DCTS bit. In Loopback Mode bit \\[4\\]
of MCR set to one, DCTS reflects changes on bit \\[1\\]
RTS of register MCR. Note: If the DCTS bit is not set and the uart_cts_n signal is asserted (low) and a reset occurs (software or otherwise), then the DCTS bit will get set when the reset is removed if the uart_cts_n signal remains asserted."]
pub type DctsR = crate::BitReader<Dcts>;
impl DctsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dcts {
        match self.bits {
            false => Dcts::Nochg,
            true => Dcts::Chg,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nochg(&self) -> bool {
        *self == Dcts::Nochg
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_chg(&self) -> bool {
        *self == Dcts::Chg
    }
}
#[doc = "Field `dcts` writer - This is used to indicate that the modem control line uart_cts_n has changed since the last time the MSR was read. That is: Reading the MSR clears the DCTS bit. In Loopback Mode bit \\[4\\]
of MCR set to one, DCTS reflects changes on bit \\[1\\]
RTS of register MCR. Note: If the DCTS bit is not set and the uart_cts_n signal is asserted (low) and a reset occurs (software or otherwise), then the DCTS bit will get set when the reset is removed if the uart_cts_n signal remains asserted."]
pub type DctsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This is used to indicate that the modem control line uart_dsr_n has changed since the last time the MSR was read. Reading the MSR clears the DDSR bit.In Loopback Mode (MCR\\[4\\]
set to one), DDSR reflects changes on bit \\[0\\]
DTR of register MCR . Note, if the DDSR bit is not set and the uart_dsr_n signal is asserted (low) and a reset occurs (software or otherwise), then the DDSR bit will get set when the reset is removed if the uart_dsr_n signal remains asserted.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ddsr {
    #[doc = "0: `0`"]
    Nochg = 0,
    #[doc = "1: `1`"]
    Chg = 1,
}
impl From<Ddsr> for bool {
    #[inline(always)]
    fn from(variant: Ddsr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ddsr` reader - This is used to indicate that the modem control line uart_dsr_n has changed since the last time the MSR was read. Reading the MSR clears the DDSR bit.In Loopback Mode (MCR\\[4\\]
set to one), DDSR reflects changes on bit \\[0\\]
DTR of register MCR . Note, if the DDSR bit is not set and the uart_dsr_n signal is asserted (low) and a reset occurs (software or otherwise), then the DDSR bit will get set when the reset is removed if the uart_dsr_n signal remains asserted."]
pub type DdsrR = crate::BitReader<Ddsr>;
impl DdsrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ddsr {
        match self.bits {
            false => Ddsr::Nochg,
            true => Ddsr::Chg,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nochg(&self) -> bool {
        *self == Ddsr::Nochg
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_chg(&self) -> bool {
        *self == Ddsr::Chg
    }
}
#[doc = "Field `ddsr` writer - This is used to indicate that the modem control line uart_dsr_n has changed since the last time the MSR was read. Reading the MSR clears the DDSR bit.In Loopback Mode (MCR\\[4\\]
set to one), DDSR reflects changes on bit \\[0\\]
DTR of register MCR . Note, if the DDSR bit is not set and the uart_dsr_n signal is asserted (low) and a reset occurs (software or otherwise), then the DDSR bit will get set when the reset is removed if the uart_dsr_n signal remains asserted."]
pub type DdsrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This is used to indicate that a change on the input uart_ri_n (from an active low, to an inactive high state) has occurred since the last time the MSR was read. Reading the MSR clears the TERI bit. In Loopback Mode bit \\[4\\]
of register MCR is set to one, TERI reflects when bit \\[2\\]
of register MCR has changed state from a high to a low.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Teri {
    #[doc = "0: `0`"]
    Nochg = 0,
    #[doc = "1: `1`"]
    Chg = 1,
}
impl From<Teri> for bool {
    #[inline(always)]
    fn from(variant: Teri) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `teri` reader - This is used to indicate that a change on the input uart_ri_n (from an active low, to an inactive high state) has occurred since the last time the MSR was read. Reading the MSR clears the TERI bit. In Loopback Mode bit \\[4\\]
of register MCR is set to one, TERI reflects when bit \\[2\\]
of register MCR has changed state from a high to a low."]
pub type TeriR = crate::BitReader<Teri>;
impl TeriR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Teri {
        match self.bits {
            false => Teri::Nochg,
            true => Teri::Chg,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nochg(&self) -> bool {
        *self == Teri::Nochg
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_chg(&self) -> bool {
        *self == Teri::Chg
    }
}
#[doc = "Field `teri` writer - This is used to indicate that a change on the input uart_ri_n (from an active low, to an inactive high state) has occurred since the last time the MSR was read. Reading the MSR clears the TERI bit. In Loopback Mode bit \\[4\\]
of register MCR is set to one, TERI reflects when bit \\[2\\]
of register MCR has changed state from a high to a low."]
pub type TeriW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This is used to indicate that the modem control line dcd_n has changed since the last time the MSR was read. Reading the MSR clears the DDCD bit. In Loopback Mode bit \\[4\\]
of register MCR is set to one, DDCD reflects changes bit \\[3\\]
uart_out2 of register MCR. Note: If the DDCD bit is not set and the uart_dcd_n signal is asserted (low) and a reset occurs (software or otherwise), then the DDCD bit will get set when the reset is removed if the uart_dcd_n signal remains asserted.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ddcd {
    #[doc = "0: `0`"]
    Nochg = 0,
    #[doc = "1: `1`"]
    Chg = 1,
}
impl From<Ddcd> for bool {
    #[inline(always)]
    fn from(variant: Ddcd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ddcd` reader - This is used to indicate that the modem control line dcd_n has changed since the last time the MSR was read. Reading the MSR clears the DDCD bit. In Loopback Mode bit \\[4\\]
of register MCR is set to one, DDCD reflects changes bit \\[3\\]
uart_out2 of register MCR. Note: If the DDCD bit is not set and the uart_dcd_n signal is asserted (low) and a reset occurs (software or otherwise), then the DDCD bit will get set when the reset is removed if the uart_dcd_n signal remains asserted."]
pub type DdcdR = crate::BitReader<Ddcd>;
impl DdcdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ddcd {
        match self.bits {
            false => Ddcd::Nochg,
            true => Ddcd::Chg,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nochg(&self) -> bool {
        *self == Ddcd::Nochg
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_chg(&self) -> bool {
        *self == Ddcd::Chg
    }
}
#[doc = "Field `ddcd` writer - This is used to indicate that the modem control line dcd_n has changed since the last time the MSR was read. Reading the MSR clears the DDCD bit. In Loopback Mode bit \\[4\\]
of register MCR is set to one, DDCD reflects changes bit \\[3\\]
uart_out2 of register MCR. Note: If the DDCD bit is not set and the uart_dcd_n signal is asserted (low) and a reset occurs (software or otherwise), then the DDCD bit will get set when the reset is removed if the uart_dcd_n signal remains asserted."]
pub type DdcdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This is used to indicate the current state of the modem control line uart_cts_n. That is, this bit is the complement uart_cts_n. When the Clear to Send input (uart_cts_n) is asserted it is an indication that the modem or data set is ready to exchange data with the uart. In Loopback Mode bit \\[4\\]
of register MCR is set to one, CTS is the same as bit \\[1\\]
RTS of register MCR.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cts {
    #[doc = "0: `0`"]
    Logic1 = 0,
    #[doc = "1: `1`"]
    Logic0 = 1,
}
impl From<Cts> for bool {
    #[inline(always)]
    fn from(variant: Cts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cts` reader - This is used to indicate the current state of the modem control line uart_cts_n. That is, this bit is the complement uart_cts_n. When the Clear to Send input (uart_cts_n) is asserted it is an indication that the modem or data set is ready to exchange data with the uart. In Loopback Mode bit \\[4\\]
of register MCR is set to one, CTS is the same as bit \\[1\\]
RTS of register MCR."]
pub type CtsR = crate::BitReader<Cts>;
impl CtsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cts {
        match self.bits {
            false => Cts::Logic1,
            true => Cts::Logic0,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_logic1(&self) -> bool {
        *self == Cts::Logic1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_logic0(&self) -> bool {
        *self == Cts::Logic0
    }
}
#[doc = "Field `cts` writer - This is used to indicate the current state of the modem control line uart_cts_n. That is, this bit is the complement uart_cts_n. When the Clear to Send input (uart_cts_n) is asserted it is an indication that the modem or data set is ready to exchange data with the uart. In Loopback Mode bit \\[4\\]
of register MCR is set to one, CTS is the same as bit \\[1\\]
RTS of register MCR."]
pub type CtsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This is used to indicate the current state of the modem control line uart_dsr_n. That is this bit is the complement f uart_dsr_n. When the Data Set Ready input (uart_dsr_n) is asserted it is an indication that the modem or data set is ready to establish communications with the uart. In Loopback Mode bit \\[4\\]
of register MCR is set to one, DSR is the same as bit \\[0\\]
(DTR) of register MCR.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dsr {
    #[doc = "0: `0`"]
    Logic1 = 0,
    #[doc = "1: `1`"]
    Logic0 = 1,
}
impl From<Dsr> for bool {
    #[inline(always)]
    fn from(variant: Dsr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dsr` reader - This is used to indicate the current state of the modem control line uart_dsr_n. That is this bit is the complement f uart_dsr_n. When the Data Set Ready input (uart_dsr_n) is asserted it is an indication that the modem or data set is ready to establish communications with the uart. In Loopback Mode bit \\[4\\]
of register MCR is set to one, DSR is the same as bit \\[0\\]
(DTR) of register MCR."]
pub type DsrR = crate::BitReader<Dsr>;
impl DsrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dsr {
        match self.bits {
            false => Dsr::Logic1,
            true => Dsr::Logic0,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_logic1(&self) -> bool {
        *self == Dsr::Logic1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_logic0(&self) -> bool {
        *self == Dsr::Logic0
    }
}
#[doc = "Field `dsr` writer - This is used to indicate the current state of the modem control line uart_dsr_n. That is this bit is the complement f uart_dsr_n. When the Data Set Ready input (uart_dsr_n) is asserted it is an indication that the modem or data set is ready to establish communications with the uart. In Loopback Mode bit \\[4\\]
of register MCR is set to one, DSR is the same as bit \\[0\\]
(DTR) of register MCR."]
pub type DsrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is used to indicate the current state of the modem control line uart_ri_n. That is this bit is the complement uart_ri_n. When the Ring Indicator input (uart_ri_n) is asserted it is an indication that a telephone ringing signal has been received by the modem or data set. In Loopback Mode bit \\[4\\]
of register MCR set to one, RI is the same as bit \\[2\\]
uart_out1_n of register MCR.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ri {
    #[doc = "0: `0`"]
    Logic1 = 0,
    #[doc = "1: `1`"]
    Logic0 = 1,
}
impl From<Ri> for bool {
    #[inline(always)]
    fn from(variant: Ri) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ri` reader - This bit is used to indicate the current state of the modem control line uart_ri_n. That is this bit is the complement uart_ri_n. When the Ring Indicator input (uart_ri_n) is asserted it is an indication that a telephone ringing signal has been received by the modem or data set. In Loopback Mode bit \\[4\\]
of register MCR set to one, RI is the same as bit \\[2\\]
uart_out1_n of register MCR."]
pub type RiR = crate::BitReader<Ri>;
impl RiR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ri {
        match self.bits {
            false => Ri::Logic1,
            true => Ri::Logic0,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_logic1(&self) -> bool {
        *self == Ri::Logic1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_logic0(&self) -> bool {
        *self == Ri::Logic0
    }
}
#[doc = "Field `ri` writer - This bit is used to indicate the current state of the modem control line uart_ri_n. That is this bit is the complement uart_ri_n. When the Ring Indicator input (uart_ri_n) is asserted it is an indication that a telephone ringing signal has been received by the modem or data set. In Loopback Mode bit \\[4\\]
of register MCR set to one, RI is the same as bit \\[2\\]
uart_out1_n of register MCR."]
pub type RiW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This is used to indicate the current state of the modem control line uart_dcd_n. That is this bit is the complement uart_dcd_n. When the Data Carrier Detect input (uart_dcd_n) is asserted it is an indication that the carrier has been detected by the modem or data set. In Loopback Mode (MCR\\[4\\]
set to one), DCD is the same as MCR\\[3\\]
(uart_out2).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dcd {
    #[doc = "0: `0`"]
    Logic1 = 0,
    #[doc = "1: `1`"]
    Logic0 = 1,
}
impl From<Dcd> for bool {
    #[inline(always)]
    fn from(variant: Dcd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dcd` reader - This is used to indicate the current state of the modem control line uart_dcd_n. That is this bit is the complement uart_dcd_n. When the Data Carrier Detect input (uart_dcd_n) is asserted it is an indication that the carrier has been detected by the modem or data set. In Loopback Mode (MCR\\[4\\]
set to one), DCD is the same as MCR\\[3\\]
(uart_out2)."]
pub type DcdR = crate::BitReader<Dcd>;
impl DcdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dcd {
        match self.bits {
            false => Dcd::Logic1,
            true => Dcd::Logic0,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_logic1(&self) -> bool {
        *self == Dcd::Logic1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_logic0(&self) -> bool {
        *self == Dcd::Logic0
    }
}
#[doc = "Field `dcd` writer - This is used to indicate the current state of the modem control line uart_dcd_n. That is this bit is the complement uart_dcd_n. When the Data Carrier Detect input (uart_dcd_n) is asserted it is an indication that the carrier has been detected by the modem or data set. In Loopback Mode (MCR\\[4\\]
set to one), DCD is the same as MCR\\[3\\]
(uart_out2)."]
pub type DcdW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This is used to indicate that the modem control line uart_cts_n has changed since the last time the MSR was read. That is: Reading the MSR clears the DCTS bit. In Loopback Mode bit \\[4\\]
of MCR set to one, DCTS reflects changes on bit \\[1\\]
RTS of register MCR. Note: If the DCTS bit is not set and the uart_cts_n signal is asserted (low) and a reset occurs (software or otherwise), then the DCTS bit will get set when the reset is removed if the uart_cts_n signal remains asserted."]
    #[inline(always)]
    pub fn dcts(&self) -> DctsR {
        DctsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This is used to indicate that the modem control line uart_dsr_n has changed since the last time the MSR was read. Reading the MSR clears the DDSR bit.In Loopback Mode (MCR\\[4\\]
set to one), DDSR reflects changes on bit \\[0\\]
DTR of register MCR . Note, if the DDSR bit is not set and the uart_dsr_n signal is asserted (low) and a reset occurs (software or otherwise), then the DDSR bit will get set when the reset is removed if the uart_dsr_n signal remains asserted."]
    #[inline(always)]
    pub fn ddsr(&self) -> DdsrR {
        DdsrR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This is used to indicate that a change on the input uart_ri_n (from an active low, to an inactive high state) has occurred since the last time the MSR was read. Reading the MSR clears the TERI bit. In Loopback Mode bit \\[4\\]
of register MCR is set to one, TERI reflects when bit \\[2\\]
of register MCR has changed state from a high to a low."]
    #[inline(always)]
    pub fn teri(&self) -> TeriR {
        TeriR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This is used to indicate that the modem control line dcd_n has changed since the last time the MSR was read. Reading the MSR clears the DDCD bit. In Loopback Mode bit \\[4\\]
of register MCR is set to one, DDCD reflects changes bit \\[3\\]
uart_out2 of register MCR. Note: If the DDCD bit is not set and the uart_dcd_n signal is asserted (low) and a reset occurs (software or otherwise), then the DDCD bit will get set when the reset is removed if the uart_dcd_n signal remains asserted."]
    #[inline(always)]
    pub fn ddcd(&self) -> DdcdR {
        DdcdR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This is used to indicate the current state of the modem control line uart_cts_n. That is, this bit is the complement uart_cts_n. When the Clear to Send input (uart_cts_n) is asserted it is an indication that the modem or data set is ready to exchange data with the uart. In Loopback Mode bit \\[4\\]
of register MCR is set to one, CTS is the same as bit \\[1\\]
RTS of register MCR."]
    #[inline(always)]
    pub fn cts(&self) -> CtsR {
        CtsR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This is used to indicate the current state of the modem control line uart_dsr_n. That is this bit is the complement f uart_dsr_n. When the Data Set Ready input (uart_dsr_n) is asserted it is an indication that the modem or data set is ready to establish communications with the uart. In Loopback Mode bit \\[4\\]
of register MCR is set to one, DSR is the same as bit \\[0\\]
(DTR) of register MCR."]
    #[inline(always)]
    pub fn dsr(&self) -> DsrR {
        DsrR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit is used to indicate the current state of the modem control line uart_ri_n. That is this bit is the complement uart_ri_n. When the Ring Indicator input (uart_ri_n) is asserted it is an indication that a telephone ringing signal has been received by the modem or data set. In Loopback Mode bit \\[4\\]
of register MCR set to one, RI is the same as bit \\[2\\]
uart_out1_n of register MCR."]
    #[inline(always)]
    pub fn ri(&self) -> RiR {
        RiR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This is used to indicate the current state of the modem control line uart_dcd_n. That is this bit is the complement uart_dcd_n. When the Data Carrier Detect input (uart_dcd_n) is asserted it is an indication that the carrier has been detected by the modem or data set. In Loopback Mode (MCR\\[4\\]
set to one), DCD is the same as MCR\\[3\\]
(uart_out2)."]
    #[inline(always)]
    pub fn dcd(&self) -> DcdR {
        DcdR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This is used to indicate that the modem control line uart_cts_n has changed since the last time the MSR was read. That is: Reading the MSR clears the DCTS bit. In Loopback Mode bit \\[4\\]
of MCR set to one, DCTS reflects changes on bit \\[1\\]
RTS of register MCR. Note: If the DCTS bit is not set and the uart_cts_n signal is asserted (low) and a reset occurs (software or otherwise), then the DCTS bit will get set when the reset is removed if the uart_cts_n signal remains asserted."]
    #[inline(always)]
    #[must_use]
    pub fn dcts(&mut self) -> DctsW<MsrSpec> {
        DctsW::new(self, 0)
    }
    #[doc = "Bit 1 - This is used to indicate that the modem control line uart_dsr_n has changed since the last time the MSR was read. Reading the MSR clears the DDSR bit.In Loopback Mode (MCR\\[4\\]
set to one), DDSR reflects changes on bit \\[0\\]
DTR of register MCR . Note, if the DDSR bit is not set and the uart_dsr_n signal is asserted (low) and a reset occurs (software or otherwise), then the DDSR bit will get set when the reset is removed if the uart_dsr_n signal remains asserted."]
    #[inline(always)]
    #[must_use]
    pub fn ddsr(&mut self) -> DdsrW<MsrSpec> {
        DdsrW::new(self, 1)
    }
    #[doc = "Bit 2 - This is used to indicate that a change on the input uart_ri_n (from an active low, to an inactive high state) has occurred since the last time the MSR was read. Reading the MSR clears the TERI bit. In Loopback Mode bit \\[4\\]
of register MCR is set to one, TERI reflects when bit \\[2\\]
of register MCR has changed state from a high to a low."]
    #[inline(always)]
    #[must_use]
    pub fn teri(&mut self) -> TeriW<MsrSpec> {
        TeriW::new(self, 2)
    }
    #[doc = "Bit 3 - This is used to indicate that the modem control line dcd_n has changed since the last time the MSR was read. Reading the MSR clears the DDCD bit. In Loopback Mode bit \\[4\\]
of register MCR is set to one, DDCD reflects changes bit \\[3\\]
uart_out2 of register MCR. Note: If the DDCD bit is not set and the uart_dcd_n signal is asserted (low) and a reset occurs (software or otherwise), then the DDCD bit will get set when the reset is removed if the uart_dcd_n signal remains asserted."]
    #[inline(always)]
    #[must_use]
    pub fn ddcd(&mut self) -> DdcdW<MsrSpec> {
        DdcdW::new(self, 3)
    }
    #[doc = "Bit 4 - This is used to indicate the current state of the modem control line uart_cts_n. That is, this bit is the complement uart_cts_n. When the Clear to Send input (uart_cts_n) is asserted it is an indication that the modem or data set is ready to exchange data with the uart. In Loopback Mode bit \\[4\\]
of register MCR is set to one, CTS is the same as bit \\[1\\]
RTS of register MCR."]
    #[inline(always)]
    #[must_use]
    pub fn cts(&mut self) -> CtsW<MsrSpec> {
        CtsW::new(self, 4)
    }
    #[doc = "Bit 5 - This is used to indicate the current state of the modem control line uart_dsr_n. That is this bit is the complement f uart_dsr_n. When the Data Set Ready input (uart_dsr_n) is asserted it is an indication that the modem or data set is ready to establish communications with the uart. In Loopback Mode bit \\[4\\]
of register MCR is set to one, DSR is the same as bit \\[0\\]
(DTR) of register MCR."]
    #[inline(always)]
    #[must_use]
    pub fn dsr(&mut self) -> DsrW<MsrSpec> {
        DsrW::new(self, 5)
    }
    #[doc = "Bit 6 - This bit is used to indicate the current state of the modem control line uart_ri_n. That is this bit is the complement uart_ri_n. When the Ring Indicator input (uart_ri_n) is asserted it is an indication that a telephone ringing signal has been received by the modem or data set. In Loopback Mode bit \\[4\\]
of register MCR set to one, RI is the same as bit \\[2\\]
uart_out1_n of register MCR."]
    #[inline(always)]
    #[must_use]
    pub fn ri(&mut self) -> RiW<MsrSpec> {
        RiW::new(self, 6)
    }
    #[doc = "Bit 7 - This is used to indicate the current state of the modem control line uart_dcd_n. That is this bit is the complement uart_dcd_n. When the Data Carrier Detect input (uart_dcd_n) is asserted it is an indication that the carrier has been detected by the modem or data set. In Loopback Mode (MCR\\[4\\]
set to one), DCD is the same as MCR\\[3\\]
(uart_out2)."]
    #[inline(always)]
    #[must_use]
    pub fn dcd(&mut self) -> DcdW<MsrSpec> {
        DcdW::new(self, 7)
    }
}
#[doc = "It should be noted that whenever bits 0, 1, 2 or 3 are set to logic one, to indicate a change on the modem control inputs, a modem status interrupt will be generated if enabled via the IER regardless of when the change occurred. Since the delta bits (bits 0, 1, 3) can get set after a reset if their respective modem signals are active (see individual bits for details), a read of the MSR after reset can be performed to prevent unwanted interrupts.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsrSpec;
impl crate::RegisterSpec for MsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`msr::R`](R) reader structure"]
impl crate::Readable for MsrSpec {}
#[doc = "`reset()` method sets msr to value 0"]
impl crate::Resettable for MsrSpec {
    const RESET_VALUE: u32 = 0;
}
