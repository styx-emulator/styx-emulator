// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `sbcr` reader"]
pub type R = crate::R<SbcrSpec>;
#[doc = "Register `sbcr` writer"]
pub type W = crate::W<SbcrSpec>;
#[doc = "This is used to cause a break condition to be transmitted to the receiving device. If set to one the serial output is forced to the spacing (logic 0) state. When not in Loopback Mode, as determined by MCR\\[4\\], the uart_txd line is forced low until the Break bit is cleared. When in Loopback Mode, the break condition is internally looped back to the receiver.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sbcr {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Sbcr> for bool {
    #[inline(always)]
    fn from(variant: Sbcr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sbcr` reader - This is used to cause a break condition to be transmitted to the receiving device. If set to one the serial output is forced to the spacing (logic 0) state. When not in Loopback Mode, as determined by MCR\\[4\\], the uart_txd line is forced low until the Break bit is cleared. When in Loopback Mode, the break condition is internally looped back to the receiver."]
pub type SbcrR = crate::BitReader<Sbcr>;
impl SbcrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sbcr {
        match self.bits {
            false => Sbcr::Disabled,
            true => Sbcr::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Sbcr::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Sbcr::Enabled
    }
}
#[doc = "Field `sbcr` writer - This is used to cause a break condition to be transmitted to the receiving device. If set to one the serial output is forced to the spacing (logic 0) state. When not in Loopback Mode, as determined by MCR\\[4\\], the uart_txd line is forced low until the Break bit is cleared. When in Loopback Mode, the break condition is internally looped back to the receiver."]
pub type SbcrW<'a, REG> = crate::BitWriter<'a, REG, Sbcr>;
impl<'a, REG> SbcrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sbcr::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sbcr::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - This is used to cause a break condition to be transmitted to the receiving device. If set to one the serial output is forced to the spacing (logic 0) state. When not in Loopback Mode, as determined by MCR\\[4\\], the uart_txd line is forced low until the Break bit is cleared. When in Loopback Mode, the break condition is internally looped back to the receiver."]
    #[inline(always)]
    pub fn sbcr(&self) -> SbcrR {
        SbcrR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This is used to cause a break condition to be transmitted to the receiving device. If set to one the serial output is forced to the spacing (logic 0) state. When not in Loopback Mode, as determined by MCR\\[4\\], the uart_txd line is forced low until the Break bit is cleared. When in Loopback Mode, the break condition is internally looped back to the receiver."]
    #[inline(always)]
    #[must_use]
    pub fn sbcr(&mut self) -> SbcrW<SbcrSpec> {
        SbcrW::new(self, 0)
    }
}
#[doc = "This is a shadow register for the Break bit \\[6\\]
of the register LCR. This can be used to remove the burden of having to performing a read modify write on the LCR.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sbcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sbcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SbcrSpec;
impl crate::RegisterSpec for SbcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 144u64;
}
#[doc = "`read()` method returns [`sbcr::R`](R) reader structure"]
impl crate::Readable for SbcrSpec {}
#[doc = "`write(|w| ..)` method takes [`sbcr::W`](W) writer structure"]
impl crate::Writable for SbcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets sbcr to value 0"]
impl crate::Resettable for SbcrSpec {
    const RESET_VALUE: u32 = 0;
}
