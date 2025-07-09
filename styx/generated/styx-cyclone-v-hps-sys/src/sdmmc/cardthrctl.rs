// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `cardthrctl` reader"]
pub type R = crate::R<CardthrctlSpec>;
#[doc = "Register `cardthrctl` writer"]
pub type W = crate::W<CardthrctlSpec>;
#[doc = "Host Controller initiates Read Transfer only if CardRdThreshold amount of space is available in receive FIFO.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cardrdthren {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Cardrdthren> for bool {
    #[inline(always)]
    fn from(variant: Cardrdthren) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cardrdthren` reader - Host Controller initiates Read Transfer only if CardRdThreshold amount of space is available in receive FIFO."]
pub type CardrdthrenR = crate::BitReader<Cardrdthren>;
impl CardrdthrenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cardrdthren {
        match self.bits {
            true => Cardrdthren::Enabled,
            false => Cardrdthren::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Cardrdthren::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Cardrdthren::Disabled
    }
}
#[doc = "Field `cardrdthren` writer - Host Controller initiates Read Transfer only if CardRdThreshold amount of space is available in receive FIFO."]
pub type CardrdthrenW<'a, REG> = crate::BitWriter<'a, REG, Cardrdthren>;
impl<'a, REG> CardrdthrenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cardrdthren::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Cardrdthren::Disabled)
    }
}
#[doc = "Field `cardrdthreshold` reader - Card Read Threshold size"]
pub type CardrdthresholdR = crate::FieldReader<u16>;
#[doc = "Field `cardrdthreshold` writer - Card Read Threshold size"]
pub type CardrdthresholdW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bit 0 - Host Controller initiates Read Transfer only if CardRdThreshold amount of space is available in receive FIFO."]
    #[inline(always)]
    pub fn cardrdthren(&self) -> CardrdthrenR {
        CardrdthrenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 16:27 - Card Read Threshold size"]
    #[inline(always)]
    pub fn cardrdthreshold(&self) -> CardrdthresholdR {
        CardrdthresholdR::new(((self.bits >> 16) & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bit 0 - Host Controller initiates Read Transfer only if CardRdThreshold amount of space is available in receive FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn cardrdthren(&mut self) -> CardrdthrenW<CardthrctlSpec> {
        CardrdthrenW::new(self, 0)
    }
    #[doc = "Bits 16:27 - Card Read Threshold size"]
    #[inline(always)]
    #[must_use]
    pub fn cardrdthreshold(&mut self) -> CardrdthresholdW<CardthrctlSpec> {
        CardrdthresholdW::new(self, 16)
    }
}
#[doc = "See Field descriptions\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cardthrctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cardthrctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CardthrctlSpec;
impl crate::RegisterSpec for CardthrctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 256u64;
}
#[doc = "`read()` method returns [`cardthrctl::R`](R) reader structure"]
impl crate::Readable for CardthrctlSpec {}
#[doc = "`write(|w| ..)` method takes [`cardthrctl::W`](W) writer structure"]
impl crate::Writable for CardthrctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets cardthrctl to value 0"]
impl crate::Resettable for CardthrctlSpec {
    const RESET_VALUE: u32 = 0;
}
