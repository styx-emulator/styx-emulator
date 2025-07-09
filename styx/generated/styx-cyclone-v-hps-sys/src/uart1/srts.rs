// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `srts` reader"]
pub type R = crate::R<SrtsSpec>;
#[doc = "Register `srts` writer"]
pub type W = crate::W<SrtsSpec>;
#[doc = "This is used to directly control the Request to Send (uart_rts_n) output. The Request to Send (uart_rts_n) output is used to inform the modem or data set that the UART is read to exchange data. The uart_rts_n signal is set low by programming MCR\\[1\\]
(RTS) to a high. In Auto Flow Control, (MCR\\[5\\]
set to one) and FIFO's are enabled (FCR\\[0\\]
set to one), the uart_rts_n output is controlled in the same way, but is also gated with the receiver FIFO threshold trigger (uart_rts_n is inactive high when above the threshold). Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_rts_n output is held inactive high while the value of this location is internally looped back to an input.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Srts {
    #[doc = "1: `1`"]
    Logic0 = 1,
    #[doc = "0: `0`"]
    Logic1 = 0,
}
impl From<Srts> for bool {
    #[inline(always)]
    fn from(variant: Srts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `srts` reader - This is used to directly control the Request to Send (uart_rts_n) output. The Request to Send (uart_rts_n) output is used to inform the modem or data set that the UART is read to exchange data. The uart_rts_n signal is set low by programming MCR\\[1\\]
(RTS) to a high. In Auto Flow Control, (MCR\\[5\\]
set to one) and FIFO's are enabled (FCR\\[0\\]
set to one), the uart_rts_n output is controlled in the same way, but is also gated with the receiver FIFO threshold trigger (uart_rts_n is inactive high when above the threshold). Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_rts_n output is held inactive high while the value of this location is internally looped back to an input."]
pub type SrtsR = crate::BitReader<Srts>;
impl SrtsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Srts {
        match self.bits {
            true => Srts::Logic0,
            false => Srts::Logic1,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_logic0(&self) -> bool {
        *self == Srts::Logic0
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_logic1(&self) -> bool {
        *self == Srts::Logic1
    }
}
#[doc = "Field `srts` writer - This is used to directly control the Request to Send (uart_rts_n) output. The Request to Send (uart_rts_n) output is used to inform the modem or data set that the UART is read to exchange data. The uart_rts_n signal is set low by programming MCR\\[1\\]
(RTS) to a high. In Auto Flow Control, (MCR\\[5\\]
set to one) and FIFO's are enabled (FCR\\[0\\]
set to one), the uart_rts_n output is controlled in the same way, but is also gated with the receiver FIFO threshold trigger (uart_rts_n is inactive high when above the threshold). Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_rts_n output is held inactive high while the value of this location is internally looped back to an input."]
pub type SrtsW<'a, REG> = crate::BitWriter<'a, REG, Srts>;
impl<'a, REG> SrtsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn logic0(self) -> &'a mut crate::W<REG> {
        self.variant(Srts::Logic0)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn logic1(self) -> &'a mut crate::W<REG> {
        self.variant(Srts::Logic1)
    }
}
impl R {
    #[doc = "Bit 0 - This is used to directly control the Request to Send (uart_rts_n) output. The Request to Send (uart_rts_n) output is used to inform the modem or data set that the UART is read to exchange data. The uart_rts_n signal is set low by programming MCR\\[1\\]
(RTS) to a high. In Auto Flow Control, (MCR\\[5\\]
set to one) and FIFO's are enabled (FCR\\[0\\]
set to one), the uart_rts_n output is controlled in the same way, but is also gated with the receiver FIFO threshold trigger (uart_rts_n is inactive high when above the threshold). Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_rts_n output is held inactive high while the value of this location is internally looped back to an input."]
    #[inline(always)]
    pub fn srts(&self) -> SrtsR {
        SrtsR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This is used to directly control the Request to Send (uart_rts_n) output. The Request to Send (uart_rts_n) output is used to inform the modem or data set that the UART is read to exchange data. The uart_rts_n signal is set low by programming MCR\\[1\\]
(RTS) to a high. In Auto Flow Control, (MCR\\[5\\]
set to one) and FIFO's are enabled (FCR\\[0\\]
set to one), the uart_rts_n output is controlled in the same way, but is also gated with the receiver FIFO threshold trigger (uart_rts_n is inactive high when above the threshold). Note that in Loopback mode (MCR\\[4\\]
set to one), the uart_rts_n output is held inactive high while the value of this location is internally looped back to an input."]
    #[inline(always)]
    #[must_use]
    pub fn srts(&mut self) -> SrtsW<SrtsSpec> {
        SrtsW::new(self, 0)
    }
}
#[doc = "This is a shadow register for the RTS status (MCR\\[1\\]), this can be used to remove the burden of having to performing a read modify write on the MCR.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`srts::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`srts::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrtsSpec;
impl crate::RegisterSpec for SrtsSpec {
    type Ux = u32;
    const OFFSET: u64 = 140u64;
}
#[doc = "`read()` method returns [`srts::R`](R) reader structure"]
impl crate::Readable for SrtsSpec {}
#[doc = "`write(|w| ..)` method takes [`srts::W`](W) writer structure"]
impl crate::Writable for SrtsSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets srts to value 0"]
impl crate::Resettable for SrtsSpec {
    const RESET_VALUE: u32 = 0;
}
