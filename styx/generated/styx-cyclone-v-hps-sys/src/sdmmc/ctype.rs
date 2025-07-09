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
#[doc = "Register `ctype` reader"]
pub type R = crate::R<CtypeSpec>;
#[doc = "Register `ctype` writer"]
pub type W = crate::W<CtypeSpec>;
#[doc = "Ignored if card_width1 is MODE8BIT.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardWidth2 {
    #[doc = "0: `0`"]
    Mode1bit = 0,
    #[doc = "1: `1`"]
    Mode4bit = 1,
}
impl From<CardWidth2> for bool {
    #[inline(always)]
    fn from(variant: CardWidth2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `card_width2` reader - Ignored if card_width1 is MODE8BIT."]
pub type CardWidth2R = crate::BitReader<CardWidth2>;
impl CardWidth2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> CardWidth2 {
        match self.bits {
            false => CardWidth2::Mode1bit,
            true => CardWidth2::Mode4bit,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mode1bit(&self) -> bool {
        *self == CardWidth2::Mode1bit
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_mode4bit(&self) -> bool {
        *self == CardWidth2::Mode4bit
    }
}
#[doc = "Field `card_width2` writer - Ignored if card_width1 is MODE8BIT."]
pub type CardWidth2W<'a, REG> = crate::BitWriter<'a, REG, CardWidth2>;
impl<'a, REG> CardWidth2W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mode1bit(self) -> &'a mut crate::W<REG> {
        self.variant(CardWidth2::Mode1bit)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn mode4bit(self) -> &'a mut crate::W<REG> {
        self.variant(CardWidth2::Mode4bit)
    }
}
#[doc = "Indicates if card is 8 bit or othersize. If not 8-bit, card_width2 specifies the width.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardWidth1 {
    #[doc = "0: `0`"]
    Non8bit = 0,
    #[doc = "1: `1`"]
    Mode8bit = 1,
}
impl From<CardWidth1> for bool {
    #[inline(always)]
    fn from(variant: CardWidth1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `card_width1` reader - Indicates if card is 8 bit or othersize. If not 8-bit, card_width2 specifies the width."]
pub type CardWidth1R = crate::BitReader<CardWidth1>;
impl CardWidth1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> CardWidth1 {
        match self.bits {
            false => CardWidth1::Non8bit,
            true => CardWidth1::Mode8bit,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_non8bit(&self) -> bool {
        *self == CardWidth1::Non8bit
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_mode8bit(&self) -> bool {
        *self == CardWidth1::Mode8bit
    }
}
#[doc = "Field `card_width1` writer - Indicates if card is 8 bit or othersize. If not 8-bit, card_width2 specifies the width."]
pub type CardWidth1W<'a, REG> = crate::BitWriter<'a, REG, CardWidth1>;
impl<'a, REG> CardWidth1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn non8bit(self) -> &'a mut crate::W<REG> {
        self.variant(CardWidth1::Non8bit)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn mode8bit(self) -> &'a mut crate::W<REG> {
        self.variant(CardWidth1::Mode8bit)
    }
}
impl R {
    #[doc = "Bit 0 - Ignored if card_width1 is MODE8BIT."]
    #[inline(always)]
    pub fn card_width2(&self) -> CardWidth2R {
        CardWidth2R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 16 - Indicates if card is 8 bit or othersize. If not 8-bit, card_width2 specifies the width."]
    #[inline(always)]
    pub fn card_width1(&self) -> CardWidth1R {
        CardWidth1R::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Ignored if card_width1 is MODE8BIT."]
    #[inline(always)]
    #[must_use]
    pub fn card_width2(&mut self) -> CardWidth2W<CtypeSpec> {
        CardWidth2W::new(self, 0)
    }
    #[doc = "Bit 16 - Indicates if card is 8 bit or othersize. If not 8-bit, card_width2 specifies the width."]
    #[inline(always)]
    #[must_use]
    pub fn card_width1(&mut self) -> CardWidth1W<CtypeSpec> {
        CardWidth1W::new(self, 16)
    }
}
#[doc = "Describes card formats.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctype::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctype::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtypeSpec;
impl crate::RegisterSpec for CtypeSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`ctype::R`](R) reader structure"]
impl crate::Readable for CtypeSpec {}
#[doc = "`write(|w| ..)` method takes [`ctype::W`](W) writer structure"]
impl crate::Writable for CtypeSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctype to value 0"]
impl crate::Resettable for CtypeSpec {
    const RESET_VALUE: u32 = 0;
}
