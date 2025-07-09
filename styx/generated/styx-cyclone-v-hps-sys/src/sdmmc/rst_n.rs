// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `rst_n` reader"]
pub type R = crate::R<RstNSpec>;
#[doc = "Register `rst_n` writer"]
pub type W = crate::W<RstNSpec>;
#[doc = "This bit causes the cards to enter pre-idle state, which requires it to be re-initialized.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardReset {
    #[doc = "1: `1`"]
    Assert = 1,
    #[doc = "0: `0`"]
    Deassert = 0,
}
impl From<CardReset> for bool {
    #[inline(always)]
    fn from(variant: CardReset) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `card_reset` reader - This bit causes the cards to enter pre-idle state, which requires it to be re-initialized."]
pub type CardResetR = crate::BitReader<CardReset>;
impl CardResetR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> CardReset {
        match self.bits {
            true => CardReset::Assert,
            false => CardReset::Deassert,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_assert(&self) -> bool {
        *self == CardReset::Assert
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_deassert(&self) -> bool {
        *self == CardReset::Deassert
    }
}
#[doc = "Field `card_reset` writer - This bit causes the cards to enter pre-idle state, which requires it to be re-initialized."]
pub type CardResetW<'a, REG> = crate::BitWriter<'a, REG, CardReset>;
impl<'a, REG> CardResetW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn assert(self) -> &'a mut crate::W<REG> {
        self.variant(CardReset::Assert)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn deassert(self) -> &'a mut crate::W<REG> {
        self.variant(CardReset::Deassert)
    }
}
impl R {
    #[doc = "Bit 0 - This bit causes the cards to enter pre-idle state, which requires it to be re-initialized."]
    #[inline(always)]
    pub fn card_reset(&self) -> CardResetR {
        CardResetR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit causes the cards to enter pre-idle state, which requires it to be re-initialized."]
    #[inline(always)]
    #[must_use]
    pub fn card_reset(&mut self) -> CardResetW<RstNSpec> {
        CardResetW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rst_n::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rst_n::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RstNSpec;
impl crate::RegisterSpec for RstNSpec {
    type Ux = u32;
    const OFFSET: u64 = 120u64;
}
#[doc = "`read()` method returns [`rst_n::R`](R) reader structure"]
impl crate::Readable for RstNSpec {}
#[doc = "`write(|w| ..)` method takes [`rst_n::W`](W) writer structure"]
impl crate::Writable for RstNSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets rst_n to value 0x01"]
impl crate::Resettable for RstNSpec {
    const RESET_VALUE: u32 = 0x01;
}
