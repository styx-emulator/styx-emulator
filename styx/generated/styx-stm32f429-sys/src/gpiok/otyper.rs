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
#[doc = "Register `OTYPER` reader"]
pub type R = crate::R<OtyperSpec>;
#[doc = "Register `OTYPER` writer"]
pub type W = crate::W<OtyperSpec>;
#[doc = "Field `OT0` reader - Port x configuration bits (y = 0..15)"]
pub type Ot0R = crate::BitReader;
#[doc = "Field `OT0` writer - Port x configuration bits (y = 0..15)"]
pub type Ot0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT1` reader - Port x configuration bits (y = 0..15)"]
pub type Ot1R = crate::BitReader;
#[doc = "Field `OT1` writer - Port x configuration bits (y = 0..15)"]
pub type Ot1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT2` reader - Port x configuration bits (y = 0..15)"]
pub type Ot2R = crate::BitReader;
#[doc = "Field `OT2` writer - Port x configuration bits (y = 0..15)"]
pub type Ot2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT3` reader - Port x configuration bits (y = 0..15)"]
pub type Ot3R = crate::BitReader;
#[doc = "Field `OT3` writer - Port x configuration bits (y = 0..15)"]
pub type Ot3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT4` reader - Port x configuration bits (y = 0..15)"]
pub type Ot4R = crate::BitReader;
#[doc = "Field `OT4` writer - Port x configuration bits (y = 0..15)"]
pub type Ot4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT5` reader - Port x configuration bits (y = 0..15)"]
pub type Ot5R = crate::BitReader;
#[doc = "Field `OT5` writer - Port x configuration bits (y = 0..15)"]
pub type Ot5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT6` reader - Port x configuration bits (y = 0..15)"]
pub type Ot6R = crate::BitReader;
#[doc = "Field `OT6` writer - Port x configuration bits (y = 0..15)"]
pub type Ot6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT7` reader - Port x configuration bits (y = 0..15)"]
pub type Ot7R = crate::BitReader;
#[doc = "Field `OT7` writer - Port x configuration bits (y = 0..15)"]
pub type Ot7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT8` reader - Port x configuration bits (y = 0..15)"]
pub type Ot8R = crate::BitReader;
#[doc = "Field `OT8` writer - Port x configuration bits (y = 0..15)"]
pub type Ot8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT9` reader - Port x configuration bits (y = 0..15)"]
pub type Ot9R = crate::BitReader;
#[doc = "Field `OT9` writer - Port x configuration bits (y = 0..15)"]
pub type Ot9W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT10` reader - Port x configuration bits (y = 0..15)"]
pub type Ot10R = crate::BitReader;
#[doc = "Field `OT10` writer - Port x configuration bits (y = 0..15)"]
pub type Ot10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT11` reader - Port x configuration bits (y = 0..15)"]
pub type Ot11R = crate::BitReader;
#[doc = "Field `OT11` writer - Port x configuration bits (y = 0..15)"]
pub type Ot11W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT12` reader - Port x configuration bits (y = 0..15)"]
pub type Ot12R = crate::BitReader;
#[doc = "Field `OT12` writer - Port x configuration bits (y = 0..15)"]
pub type Ot12W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT13` reader - Port x configuration bits (y = 0..15)"]
pub type Ot13R = crate::BitReader;
#[doc = "Field `OT13` writer - Port x configuration bits (y = 0..15)"]
pub type Ot13W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT14` reader - Port x configuration bits (y = 0..15)"]
pub type Ot14R = crate::BitReader;
#[doc = "Field `OT14` writer - Port x configuration bits (y = 0..15)"]
pub type Ot14W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OT15` reader - Port x configuration bits (y = 0..15)"]
pub type Ot15R = crate::BitReader;
#[doc = "Field `OT15` writer - Port x configuration bits (y = 0..15)"]
pub type Ot15W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot0(&self) -> Ot0R {
        Ot0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot1(&self) -> Ot1R {
        Ot1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot2(&self) -> Ot2R {
        Ot2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot3(&self) -> Ot3R {
        Ot3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot4(&self) -> Ot4R {
        Ot4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot5(&self) -> Ot5R {
        Ot5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot6(&self) -> Ot6R {
        Ot6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot7(&self) -> Ot7R {
        Ot7R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot8(&self) -> Ot8R {
        Ot8R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot9(&self) -> Ot9R {
        Ot9R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot10(&self) -> Ot10R {
        Ot10R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot11(&self) -> Ot11R {
        Ot11R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot12(&self) -> Ot12R {
        Ot12R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot13(&self) -> Ot13R {
        Ot13R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot14(&self) -> Ot14R {
        Ot14R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    pub fn ot15(&self) -> Ot15R {
        Ot15R::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot0(&mut self) -> Ot0W<OtyperSpec> {
        Ot0W::new(self, 0)
    }
    #[doc = "Bit 1 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot1(&mut self) -> Ot1W<OtyperSpec> {
        Ot1W::new(self, 1)
    }
    #[doc = "Bit 2 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot2(&mut self) -> Ot2W<OtyperSpec> {
        Ot2W::new(self, 2)
    }
    #[doc = "Bit 3 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot3(&mut self) -> Ot3W<OtyperSpec> {
        Ot3W::new(self, 3)
    }
    #[doc = "Bit 4 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot4(&mut self) -> Ot4W<OtyperSpec> {
        Ot4W::new(self, 4)
    }
    #[doc = "Bit 5 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot5(&mut self) -> Ot5W<OtyperSpec> {
        Ot5W::new(self, 5)
    }
    #[doc = "Bit 6 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot6(&mut self) -> Ot6W<OtyperSpec> {
        Ot6W::new(self, 6)
    }
    #[doc = "Bit 7 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot7(&mut self) -> Ot7W<OtyperSpec> {
        Ot7W::new(self, 7)
    }
    #[doc = "Bit 8 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot8(&mut self) -> Ot8W<OtyperSpec> {
        Ot8W::new(self, 8)
    }
    #[doc = "Bit 9 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot9(&mut self) -> Ot9W<OtyperSpec> {
        Ot9W::new(self, 9)
    }
    #[doc = "Bit 10 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot10(&mut self) -> Ot10W<OtyperSpec> {
        Ot10W::new(self, 10)
    }
    #[doc = "Bit 11 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot11(&mut self) -> Ot11W<OtyperSpec> {
        Ot11W::new(self, 11)
    }
    #[doc = "Bit 12 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot12(&mut self) -> Ot12W<OtyperSpec> {
        Ot12W::new(self, 12)
    }
    #[doc = "Bit 13 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot13(&mut self) -> Ot13W<OtyperSpec> {
        Ot13W::new(self, 13)
    }
    #[doc = "Bit 14 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot14(&mut self) -> Ot14W<OtyperSpec> {
        Ot14W::new(self, 14)
    }
    #[doc = "Bit 15 - Port x configuration bits (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn ot15(&mut self) -> Ot15W<OtyperSpec> {
        Ot15W::new(self, 15)
    }
}
#[doc = "GPIO port output type register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otyper::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otyper::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtyperSpec;
impl crate::RegisterSpec for OtyperSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`otyper::R`](R) reader structure"]
impl crate::Readable for OtyperSpec {}
#[doc = "`write(|w| ..)` method takes [`otyper::W`](W) writer structure"]
impl crate::Writable for OtyperSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTYPER to value 0"]
impl crate::Resettable for OtyperSpec {
    const RESET_VALUE: u32 = 0;
}
