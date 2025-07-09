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
#[doc = "Register `mcr` reader"]
pub type R = crate::R<McrSpec>;
#[doc = "Register `mcr` writer"]
pub type W = crate::W<McrSpec>;
#[doc = "This is used to directly control the Data Terminal Ready output. The value written to this location is inverted and driven out on uart_dtr_n, that is: The Data Terminal Ready output is used to inform the modem or data set that the UART is ready to establish communications. Note that Loopback mode bit \\[4\\]
of MCR is set to one, the uart_dtr_n output is held inactive high while the value of this location is internally looped back to an input.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dtr {
    #[doc = "0: `0`"]
    Logic1 = 0,
    #[doc = "1: `1`"]
    Logic0 = 1,
}
impl From<Dtr> for bool {
    #[inline(always)]
    fn from(variant: Dtr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dtr` reader - This is used to directly control the Data Terminal Ready output. The value written to this location is inverted and driven out on uart_dtr_n, that is: The Data Terminal Ready output is used to inform the modem or data set that the UART is ready to establish communications. Note that Loopback mode bit \\[4\\]
of MCR is set to one, the uart_dtr_n output is held inactive high while the value of this location is internally looped back to an input."]
pub type DtrR = crate::BitReader<Dtr>;
impl DtrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dtr {
        match self.bits {
            false => Dtr::Logic1,
            true => Dtr::Logic0,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_logic1(&self) -> bool {
        *self == Dtr::Logic1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_logic0(&self) -> bool {
        *self == Dtr::Logic0
    }
}
#[doc = "Field `dtr` writer - This is used to directly control the Data Terminal Ready output. The value written to this location is inverted and driven out on uart_dtr_n, that is: The Data Terminal Ready output is used to inform the modem or data set that the UART is ready to establish communications. Note that Loopback mode bit \\[4\\]
of MCR is set to one, the uart_dtr_n output is held inactive high while the value of this location is internally looped back to an input."]
pub type DtrW<'a, REG> = crate::BitWriter<'a, REG, Dtr>;
impl<'a, REG> DtrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn logic1(self) -> &'a mut crate::W<REG> {
        self.variant(Dtr::Logic1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn logic0(self) -> &'a mut crate::W<REG> {
        self.variant(Dtr::Logic0)
    }
}
#[doc = "This is used to directly control the Request to Send (uart_rts_n) output. The Request to Send (uart_rts_n) output is used to inform the modem or data set that the UART is ready to exchange data. When Auto RTS Flow Control is not enabled (MCR\\[5\\]
set to zero), the uart_rts_n signal is set low by programming MCR\\[1\\]
(RTS) to a high. If Auto Flow Control is active (MCR\\[5\\]
set to one) and FIFO's enable (FCR\\[0\\]
set to one), the uart_rts_n output is controlled in the same way, but is also gated with the receiver FIFO threshold trigger (uart_rts_n is inactive high when above the threshold). The uart_rts_n signal will be de-asserted when MCR\\[1\\]
is set low. Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_rts_n output is held inactive high while the value of this location is internally looped back to an input.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rts {
    #[doc = "0: `0`"]
    Logic1 = 0,
    #[doc = "1: `1`"]
    Logic0 = 1,
}
impl From<Rts> for bool {
    #[inline(always)]
    fn from(variant: Rts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rts` reader - This is used to directly control the Request to Send (uart_rts_n) output. The Request to Send (uart_rts_n) output is used to inform the modem or data set that the UART is ready to exchange data. When Auto RTS Flow Control is not enabled (MCR\\[5\\]
set to zero), the uart_rts_n signal is set low by programming MCR\\[1\\]
(RTS) to a high. If Auto Flow Control is active (MCR\\[5\\]
set to one) and FIFO's enable (FCR\\[0\\]
set to one), the uart_rts_n output is controlled in the same way, but is also gated with the receiver FIFO threshold trigger (uart_rts_n is inactive high when above the threshold). The uart_rts_n signal will be de-asserted when MCR\\[1\\]
is set low. Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_rts_n output is held inactive high while the value of this location is internally looped back to an input."]
pub type RtsR = crate::BitReader<Rts>;
impl RtsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rts {
        match self.bits {
            false => Rts::Logic1,
            true => Rts::Logic0,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_logic1(&self) -> bool {
        *self == Rts::Logic1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_logic0(&self) -> bool {
        *self == Rts::Logic0
    }
}
#[doc = "Field `rts` writer - This is used to directly control the Request to Send (uart_rts_n) output. The Request to Send (uart_rts_n) output is used to inform the modem or data set that the UART is ready to exchange data. When Auto RTS Flow Control is not enabled (MCR\\[5\\]
set to zero), the uart_rts_n signal is set low by programming MCR\\[1\\]
(RTS) to a high. If Auto Flow Control is active (MCR\\[5\\]
set to one) and FIFO's enable (FCR\\[0\\]
set to one), the uart_rts_n output is controlled in the same way, but is also gated with the receiver FIFO threshold trigger (uart_rts_n is inactive high when above the threshold). The uart_rts_n signal will be de-asserted when MCR\\[1\\]
is set low. Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_rts_n output is held inactive high while the value of this location is internally looped back to an input."]
pub type RtsW<'a, REG> = crate::BitWriter<'a, REG, Rts>;
impl<'a, REG> RtsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn logic1(self) -> &'a mut crate::W<REG> {
        self.variant(Rts::Logic1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn logic0(self) -> &'a mut crate::W<REG> {
        self.variant(Rts::Logic0)
    }
}
#[doc = "The value written to this location is inverted and driven out on uart_out1_n pin. Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_out1_n output is held inactive high while the value of this location is internally looped back to an input.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Out1 {
    #[doc = "0: `0`"]
    Logic1 = 0,
    #[doc = "1: `1`"]
    Logic0 = 1,
}
impl From<Out1> for bool {
    #[inline(always)]
    fn from(variant: Out1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `out1` reader - The value written to this location is inverted and driven out on uart_out1_n pin. Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_out1_n output is held inactive high while the value of this location is internally looped back to an input."]
pub type Out1R = crate::BitReader<Out1>;
impl Out1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Out1 {
        match self.bits {
            false => Out1::Logic1,
            true => Out1::Logic0,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_logic1(&self) -> bool {
        *self == Out1::Logic1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_logic0(&self) -> bool {
        *self == Out1::Logic0
    }
}
#[doc = "Field `out1` writer - The value written to this location is inverted and driven out on uart_out1_n pin. Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_out1_n output is held inactive high while the value of this location is internally looped back to an input."]
pub type Out1W<'a, REG> = crate::BitWriter<'a, REG, Out1>;
impl<'a, REG> Out1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn logic1(self) -> &'a mut crate::W<REG> {
        self.variant(Out1::Logic1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn logic0(self) -> &'a mut crate::W<REG> {
        self.variant(Out1::Logic0)
    }
}
#[doc = "This is used to directly control the user-designated uart_out2_n output. The value written to this location is inverted and driven out on uart_out2_n Note: In Loopback mode bit 4 of the modem control register (MCR) is set to one, the uart_out2_n output is held inactive high while the value of this location is internally looped back to an input.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Out2 {
    #[doc = "0: `0`"]
    Logic1 = 0,
    #[doc = "1: `1`"]
    Logic0 = 1,
}
impl From<Out2> for bool {
    #[inline(always)]
    fn from(variant: Out2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `out2` reader - This is used to directly control the user-designated uart_out2_n output. The value written to this location is inverted and driven out on uart_out2_n Note: In Loopback mode bit 4 of the modem control register (MCR) is set to one, the uart_out2_n output is held inactive high while the value of this location is internally looped back to an input."]
pub type Out2R = crate::BitReader<Out2>;
impl Out2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Out2 {
        match self.bits {
            false => Out2::Logic1,
            true => Out2::Logic0,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_logic1(&self) -> bool {
        *self == Out2::Logic1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_logic0(&self) -> bool {
        *self == Out2::Logic0
    }
}
#[doc = "Field `out2` writer - This is used to directly control the user-designated uart_out2_n output. The value written to this location is inverted and driven out on uart_out2_n Note: In Loopback mode bit 4 of the modem control register (MCR) is set to one, the uart_out2_n output is held inactive high while the value of this location is internally looped back to an input."]
pub type Out2W<'a, REG> = crate::BitWriter<'a, REG, Out2>;
impl<'a, REG> Out2W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn logic1(self) -> &'a mut crate::W<REG> {
        self.variant(Out2::Logic1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn logic0(self) -> &'a mut crate::W<REG> {
        self.variant(Out2::Logic0)
    }
}
#[doc = "Field `loopback` reader - This is used to put the UART into a diagnostic mode for test purposes. If UART mode is NOT active, bit \\[6\\]
of the modem control register MCR is set to zero, data on the sout line is held high, while serial data output is looped back to the sin line, internally. In this mode all the interrupts are fully functional. Also, in loopback mode, the modem control inputs (uart_dsr_n, uart_cts_n, uart_ri_n, uart_dcd_n) are disconnected and the modem control outputs (uart_dtr_n, uart_rts_n, uart_out1_n, uart_out2_n) are loopedback to the inputs, internally."]
pub type LoopbackR = crate::BitReader;
#[doc = "Field `loopback` writer - This is used to put the UART into a diagnostic mode for test purposes. If UART mode is NOT active, bit \\[6\\]
of the modem control register MCR is set to zero, data on the sout line is held high, while serial data output is looped back to the sin line, internally. In this mode all the interrupts are fully functional. Also, in loopback mode, the modem control inputs (uart_dsr_n, uart_cts_n, uart_ri_n, uart_dcd_n) are disconnected and the modem control outputs (uart_dtr_n, uart_rts_n, uart_out1_n, uart_out2_n) are loopedback to the inputs, internally."]
pub type LoopbackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When FIFOs are enabled, the Auto Flow Control enable bits are active.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Afce {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Afce> for bool {
    #[inline(always)]
    fn from(variant: Afce) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `afce` reader - When FIFOs are enabled, the Auto Flow Control enable bits are active."]
pub type AfceR = crate::BitReader<Afce>;
impl AfceR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Afce {
        match self.bits {
            false => Afce::Disabled,
            true => Afce::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Afce::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Afce::Enabled
    }
}
#[doc = "Field `afce` writer - When FIFOs are enabled, the Auto Flow Control enable bits are active."]
pub type AfceW<'a, REG> = crate::BitWriter<'a, REG, Afce>;
impl<'a, REG> AfceW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Afce::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Afce::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - This is used to directly control the Data Terminal Ready output. The value written to this location is inverted and driven out on uart_dtr_n, that is: The Data Terminal Ready output is used to inform the modem or data set that the UART is ready to establish communications. Note that Loopback mode bit \\[4\\]
of MCR is set to one, the uart_dtr_n output is held inactive high while the value of this location is internally looped back to an input."]
    #[inline(always)]
    pub fn dtr(&self) -> DtrR {
        DtrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This is used to directly control the Request to Send (uart_rts_n) output. The Request to Send (uart_rts_n) output is used to inform the modem or data set that the UART is ready to exchange data. When Auto RTS Flow Control is not enabled (MCR\\[5\\]
set to zero), the uart_rts_n signal is set low by programming MCR\\[1\\]
(RTS) to a high. If Auto Flow Control is active (MCR\\[5\\]
set to one) and FIFO's enable (FCR\\[0\\]
set to one), the uart_rts_n output is controlled in the same way, but is also gated with the receiver FIFO threshold trigger (uart_rts_n is inactive high when above the threshold). The uart_rts_n signal will be de-asserted when MCR\\[1\\]
is set low. Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_rts_n output is held inactive high while the value of this location is internally looped back to an input."]
    #[inline(always)]
    pub fn rts(&self) -> RtsR {
        RtsR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - The value written to this location is inverted and driven out on uart_out1_n pin. Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_out1_n output is held inactive high while the value of this location is internally looped back to an input."]
    #[inline(always)]
    pub fn out1(&self) -> Out1R {
        Out1R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This is used to directly control the user-designated uart_out2_n output. The value written to this location is inverted and driven out on uart_out2_n Note: In Loopback mode bit 4 of the modem control register (MCR) is set to one, the uart_out2_n output is held inactive high while the value of this location is internally looped back to an input."]
    #[inline(always)]
    pub fn out2(&self) -> Out2R {
        Out2R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This is used to put the UART into a diagnostic mode for test purposes. If UART mode is NOT active, bit \\[6\\]
of the modem control register MCR is set to zero, data on the sout line is held high, while serial data output is looped back to the sin line, internally. In this mode all the interrupts are fully functional. Also, in loopback mode, the modem control inputs (uart_dsr_n, uart_cts_n, uart_ri_n, uart_dcd_n) are disconnected and the modem control outputs (uart_dtr_n, uart_rts_n, uart_out1_n, uart_out2_n) are loopedback to the inputs, internally."]
    #[inline(always)]
    pub fn loopback(&self) -> LoopbackR {
        LoopbackR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - When FIFOs are enabled, the Auto Flow Control enable bits are active."]
    #[inline(always)]
    pub fn afce(&self) -> AfceR {
        AfceR::new(((self.bits >> 5) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This is used to directly control the Data Terminal Ready output. The value written to this location is inverted and driven out on uart_dtr_n, that is: The Data Terminal Ready output is used to inform the modem or data set that the UART is ready to establish communications. Note that Loopback mode bit \\[4\\]
of MCR is set to one, the uart_dtr_n output is held inactive high while the value of this location is internally looped back to an input."]
    #[inline(always)]
    #[must_use]
    pub fn dtr(&mut self) -> DtrW<McrSpec> {
        DtrW::new(self, 0)
    }
    #[doc = "Bit 1 - This is used to directly control the Request to Send (uart_rts_n) output. The Request to Send (uart_rts_n) output is used to inform the modem or data set that the UART is ready to exchange data. When Auto RTS Flow Control is not enabled (MCR\\[5\\]
set to zero), the uart_rts_n signal is set low by programming MCR\\[1\\]
(RTS) to a high. If Auto Flow Control is active (MCR\\[5\\]
set to one) and FIFO's enable (FCR\\[0\\]
set to one), the uart_rts_n output is controlled in the same way, but is also gated with the receiver FIFO threshold trigger (uart_rts_n is inactive high when above the threshold). The uart_rts_n signal will be de-asserted when MCR\\[1\\]
is set low. Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_rts_n output is held inactive high while the value of this location is internally looped back to an input."]
    #[inline(always)]
    #[must_use]
    pub fn rts(&mut self) -> RtsW<McrSpec> {
        RtsW::new(self, 1)
    }
    #[doc = "Bit 2 - The value written to this location is inverted and driven out on uart_out1_n pin. Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_out1_n output is held inactive high while the value of this location is internally looped back to an input."]
    #[inline(always)]
    #[must_use]
    pub fn out1(&mut self) -> Out1W<McrSpec> {
        Out1W::new(self, 2)
    }
    #[doc = "Bit 3 - This is used to directly control the user-designated uart_out2_n output. The value written to this location is inverted and driven out on uart_out2_n Note: In Loopback mode bit 4 of the modem control register (MCR) is set to one, the uart_out2_n output is held inactive high while the value of this location is internally looped back to an input."]
    #[inline(always)]
    #[must_use]
    pub fn out2(&mut self) -> Out2W<McrSpec> {
        Out2W::new(self, 3)
    }
    #[doc = "Bit 4 - This is used to put the UART into a diagnostic mode for test purposes. If UART mode is NOT active, bit \\[6\\]
of the modem control register MCR is set to zero, data on the sout line is held high, while serial data output is looped back to the sin line, internally. In this mode all the interrupts are fully functional. Also, in loopback mode, the modem control inputs (uart_dsr_n, uart_cts_n, uart_ri_n, uart_dcd_n) are disconnected and the modem control outputs (uart_dtr_n, uart_rts_n, uart_out1_n, uart_out2_n) are loopedback to the inputs, internally."]
    #[inline(always)]
    #[must_use]
    pub fn loopback(&mut self) -> LoopbackW<McrSpec> {
        LoopbackW::new(self, 4)
    }
    #[doc = "Bit 5 - When FIFOs are enabled, the Auto Flow Control enable bits are active."]
    #[inline(always)]
    #[must_use]
    pub fn afce(&mut self) -> AfceW<McrSpec> {
        AfceW::new(self, 5)
    }
}
#[doc = "Reports various operations of the modem signals\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct McrSpec;
impl crate::RegisterSpec for McrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`mcr::R`](R) reader structure"]
impl crate::Readable for McrSpec {}
#[doc = "`write(|w| ..)` method takes [`mcr::W`](W) writer structure"]
impl crate::Writable for McrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mcr to value 0"]
impl crate::Resettable for McrSpec {
    const RESET_VALUE: u32 = 0;
}
