// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `sfe` reader"]
pub type R = crate::R<SfeSpec>;
#[doc = "Register `sfe` writer"]
pub type W = crate::W<SfeSpec>;
#[doc = "This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the FIFO enable bit gets updated. This enables/disables the transmit (Tx) and receive (Rx ) FIFO's. If this bit is set to zero (disabled) after being enabled then both the Tx and Rx controller portion of FIFO's will be reset.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sfe {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Sfe> for bool {
    #[inline(always)]
    fn from(variant: Sfe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sfe` reader - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the FIFO enable bit gets updated. This enables/disables the transmit (Tx) and receive (Rx ) FIFO's. If this bit is set to zero (disabled) after being enabled then both the Tx and Rx controller portion of FIFO's will be reset."]
pub type SfeR = crate::BitReader<Sfe>;
impl SfeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sfe {
        match self.bits {
            false => Sfe::Disabled,
            true => Sfe::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Sfe::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Sfe::Enabled
    }
}
#[doc = "Field `sfe` writer - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the FIFO enable bit gets updated. This enables/disables the transmit (Tx) and receive (Rx ) FIFO's. If this bit is set to zero (disabled) after being enabled then both the Tx and Rx controller portion of FIFO's will be reset."]
pub type SfeW<'a, REG> = crate::BitWriter<'a, REG, Sfe>;
impl<'a, REG> SfeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sfe::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Sfe::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the FIFO enable bit gets updated. This enables/disables the transmit (Tx) and receive (Rx ) FIFO's. If this bit is set to zero (disabled) after being enabled then both the Tx and Rx controller portion of FIFO's will be reset."]
    #[inline(always)]
    pub fn sfe(&self) -> SfeR {
        SfeR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the FIFO enable bit gets updated. This enables/disables the transmit (Tx) and receive (Rx ) FIFO's. If this bit is set to zero (disabled) after being enabled then both the Tx and Rx controller portion of FIFO's will be reset."]
    #[inline(always)]
    #[must_use]
    pub fn sfe(&mut self) -> SfeW<SfeSpec> {
        SfeW::new(self, 0)
    }
}
#[doc = "This is a shadow register for the FIFO enable bit \\[0\\]
of register FCR.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sfe::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sfe::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SfeSpec;
impl crate::RegisterSpec for SfeSpec {
    type Ux = u32;
    const OFFSET: u64 = 152u64;
}
#[doc = "`read()` method returns [`sfe::R`](R) reader structure"]
impl crate::Readable for SfeSpec {}
#[doc = "`write(|w| ..)` method takes [`sfe::W`](W) writer structure"]
impl crate::Writable for SfeSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets sfe to value 0"]
impl crate::Resettable for SfeSpec {
    const RESET_VALUE: u32 = 0;
}
