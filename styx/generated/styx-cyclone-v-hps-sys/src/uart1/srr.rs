// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `srr` reader"]
pub type R = crate::R<SrrSpec>;
#[doc = "Register `srr` writer"]
pub type W = crate::W<SrrSpec>;
#[doc = "Field `ur` reader - This asynchronously resets the UART and synchronously removes the reset assertion."]
pub type UrR = crate::BitReader;
#[doc = "This asynchronously resets the UART and synchronously removes the reset assertion.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ur {
    #[doc = "0: `0`"]
    Noreset = 0,
    #[doc = "1: `1`"]
    Reset = 1,
}
impl From<Ur> for bool {
    #[inline(always)]
    fn from(variant: Ur) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ur` writer - This asynchronously resets the UART and synchronously removes the reset assertion."]
pub type UrW<'a, REG> = crate::BitWriter<'a, REG, Ur>;
impl<'a, REG> UrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noreset(self) -> &'a mut crate::W<REG> {
        self.variant(Ur::Noreset)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn reset(self) -> &'a mut crate::W<REG> {
        self.variant(Ur::Reset)
    }
}
#[doc = "Field `rfr` reader - This is a shadow register for the Rx FIFO Reset bit (FCR\\[1\\]). This can be used to remove the burden on software having to store previously written FCR values (which are pretty static) just to reset the receive FIFO. This resets the control portion of the receive FIFO and treats the FIFO as empty. This will also de-assert the DMA Rx request and single signals. Note that this bit is 'self-clearing' and it is not necessary to clear this bit."]
pub type RfrR = crate::BitReader;
#[doc = "This is a shadow register for the Rx FIFO Reset bit (FCR\\[1\\]). This can be used to remove the burden on software having to store previously written FCR values (which are pretty static) just to reset the receive FIFO. This resets the control portion of the receive FIFO and treats the FIFO as empty. This will also de-assert the DMA Rx request and single signals. Note that this bit is 'self-clearing' and it is not necessary to clear this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rfr {
    #[doc = "0: `0`"]
    Noreset = 0,
    #[doc = "1: `1`"]
    Reset = 1,
}
impl From<Rfr> for bool {
    #[inline(always)]
    fn from(variant: Rfr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rfr` writer - This is a shadow register for the Rx FIFO Reset bit (FCR\\[1\\]). This can be used to remove the burden on software having to store previously written FCR values (which are pretty static) just to reset the receive FIFO. This resets the control portion of the receive FIFO and treats the FIFO as empty. This will also de-assert the DMA Rx request and single signals. Note that this bit is 'self-clearing' and it is not necessary to clear this bit."]
pub type RfrW<'a, REG> = crate::BitWriter<'a, REG, Rfr>;
impl<'a, REG> RfrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noreset(self) -> &'a mut crate::W<REG> {
        self.variant(Rfr::Noreset)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn reset(self) -> &'a mut crate::W<REG> {
        self.variant(Rfr::Reset)
    }
}
#[doc = "Field `xfr` reader - This is a shadow register forthe Tx FIFO Reset bit (FCR\\[2\\]). This can be used to remove the burden on software having to store previously written FCR values (which are pretty static) just to reset the transmit FIFO.This resets the control portion of the transmit FIFO and treats the FIFO as empty. This will also de-assert the DMA Tx request and single signals."]
pub type XfrR = crate::BitReader;
#[doc = "This is a shadow register forthe Tx FIFO Reset bit (FCR\\[2\\]). This can be used to remove the burden on software having to store previously written FCR values (which are pretty static) just to reset the transmit FIFO.This resets the control portion of the transmit FIFO and treats the FIFO as empty. This will also de-assert the DMA Tx request and single signals.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Xfr {
    #[doc = "0: `0`"]
    Noreset = 0,
    #[doc = "1: `1`"]
    Reset = 1,
}
impl From<Xfr> for bool {
    #[inline(always)]
    fn from(variant: Xfr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `xfr` writer - This is a shadow register forthe Tx FIFO Reset bit (FCR\\[2\\]). This can be used to remove the burden on software having to store previously written FCR values (which are pretty static) just to reset the transmit FIFO.This resets the control portion of the transmit FIFO and treats the FIFO as empty. This will also de-assert the DMA Tx request and single signals."]
pub type XfrW<'a, REG> = crate::BitWriter<'a, REG, Xfr>;
impl<'a, REG> XfrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noreset(self) -> &'a mut crate::W<REG> {
        self.variant(Xfr::Noreset)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn reset(self) -> &'a mut crate::W<REG> {
        self.variant(Xfr::Reset)
    }
}
impl R {
    #[doc = "Bit 0 - This asynchronously resets the UART and synchronously removes the reset assertion."]
    #[inline(always)]
    pub fn ur(&self) -> UrR {
        UrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This is a shadow register for the Rx FIFO Reset bit (FCR\\[1\\]). This can be used to remove the burden on software having to store previously written FCR values (which are pretty static) just to reset the receive FIFO. This resets the control portion of the receive FIFO and treats the FIFO as empty. This will also de-assert the DMA Rx request and single signals. Note that this bit is 'self-clearing' and it is not necessary to clear this bit."]
    #[inline(always)]
    pub fn rfr(&self) -> RfrR {
        RfrR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This is a shadow register forthe Tx FIFO Reset bit (FCR\\[2\\]). This can be used to remove the burden on software having to store previously written FCR values (which are pretty static) just to reset the transmit FIFO.This resets the control portion of the transmit FIFO and treats the FIFO as empty. This will also de-assert the DMA Tx request and single signals."]
    #[inline(always)]
    pub fn xfr(&self) -> XfrR {
        XfrR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This asynchronously resets the UART and synchronously removes the reset assertion."]
    #[inline(always)]
    #[must_use]
    pub fn ur(&mut self) -> UrW<SrrSpec> {
        UrW::new(self, 0)
    }
    #[doc = "Bit 1 - This is a shadow register for the Rx FIFO Reset bit (FCR\\[1\\]). This can be used to remove the burden on software having to store previously written FCR values (which are pretty static) just to reset the receive FIFO. This resets the control portion of the receive FIFO and treats the FIFO as empty. This will also de-assert the DMA Rx request and single signals. Note that this bit is 'self-clearing' and it is not necessary to clear this bit."]
    #[inline(always)]
    #[must_use]
    pub fn rfr(&mut self) -> RfrW<SrrSpec> {
        RfrW::new(self, 1)
    }
    #[doc = "Bit 2 - This is a shadow register forthe Tx FIFO Reset bit (FCR\\[2\\]). This can be used to remove the burden on software having to store previously written FCR values (which are pretty static) just to reset the transmit FIFO.This resets the control portion of the transmit FIFO and treats the FIFO as empty. This will also de-assert the DMA Tx request and single signals."]
    #[inline(always)]
    #[must_use]
    pub fn xfr(&mut self) -> XfrW<SrrSpec> {
        XfrW::new(self, 2)
    }
}
#[doc = "Provides Software Resets for Tx/Rx FIFO's and the uart.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`srr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrrSpec;
impl crate::RegisterSpec for SrrSpec {
    type Ux = u32;
    const OFFSET: u64 = 136u64;
}
#[doc = "`write(|w| ..)` method takes [`srr::W`](W) writer structure"]
impl crate::Writable for SrrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets srr to value 0"]
impl crate::Resettable for SrrSpec {
    const RESET_VALUE: u32 = 0;
}
