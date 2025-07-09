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
#[doc = "Register `IDR` reader"]
pub type R = crate::R<IdrSpec>;
#[doc = "Register `IDR` writer"]
pub type W = crate::W<IdrSpec>;
#[doc = "Field `IDR0` reader - Port input data (y = 0..15)"]
pub type Idr0R = crate::BitReader;
#[doc = "Field `IDR0` writer - Port input data (y = 0..15)"]
pub type Idr0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR1` reader - Port input data (y = 0..15)"]
pub type Idr1R = crate::BitReader;
#[doc = "Field `IDR1` writer - Port input data (y = 0..15)"]
pub type Idr1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR2` reader - Port input data (y = 0..15)"]
pub type Idr2R = crate::BitReader;
#[doc = "Field `IDR2` writer - Port input data (y = 0..15)"]
pub type Idr2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR3` reader - Port input data (y = 0..15)"]
pub type Idr3R = crate::BitReader;
#[doc = "Field `IDR3` writer - Port input data (y = 0..15)"]
pub type Idr3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR4` reader - Port input data (y = 0..15)"]
pub type Idr4R = crate::BitReader;
#[doc = "Field `IDR4` writer - Port input data (y = 0..15)"]
pub type Idr4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR5` reader - Port input data (y = 0..15)"]
pub type Idr5R = crate::BitReader;
#[doc = "Field `IDR5` writer - Port input data (y = 0..15)"]
pub type Idr5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR6` reader - Port input data (y = 0..15)"]
pub type Idr6R = crate::BitReader;
#[doc = "Field `IDR6` writer - Port input data (y = 0..15)"]
pub type Idr6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR7` reader - Port input data (y = 0..15)"]
pub type Idr7R = crate::BitReader;
#[doc = "Field `IDR7` writer - Port input data (y = 0..15)"]
pub type Idr7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR8` reader - Port input data (y = 0..15)"]
pub type Idr8R = crate::BitReader;
#[doc = "Field `IDR8` writer - Port input data (y = 0..15)"]
pub type Idr8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR9` reader - Port input data (y = 0..15)"]
pub type Idr9R = crate::BitReader;
#[doc = "Field `IDR9` writer - Port input data (y = 0..15)"]
pub type Idr9W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR10` reader - Port input data (y = 0..15)"]
pub type Idr10R = crate::BitReader;
#[doc = "Field `IDR10` writer - Port input data (y = 0..15)"]
pub type Idr10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR11` reader - Port input data (y = 0..15)"]
pub type Idr11R = crate::BitReader;
#[doc = "Field `IDR11` writer - Port input data (y = 0..15)"]
pub type Idr11W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR12` reader - Port input data (y = 0..15)"]
pub type Idr12R = crate::BitReader;
#[doc = "Field `IDR12` writer - Port input data (y = 0..15)"]
pub type Idr12W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR13` reader - Port input data (y = 0..15)"]
pub type Idr13R = crate::BitReader;
#[doc = "Field `IDR13` writer - Port input data (y = 0..15)"]
pub type Idr13W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR14` reader - Port input data (y = 0..15)"]
pub type Idr14R = crate::BitReader;
#[doc = "Field `IDR14` writer - Port input data (y = 0..15)"]
pub type Idr14W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDR15` reader - Port input data (y = 0..15)"]
pub type Idr15R = crate::BitReader;
#[doc = "Field `IDR15` writer - Port input data (y = 0..15)"]
pub type Idr15W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr0(&self) -> Idr0R {
        Idr0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr1(&self) -> Idr1R {
        Idr1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr2(&self) -> Idr2R {
        Idr2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr3(&self) -> Idr3R {
        Idr3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr4(&self) -> Idr4R {
        Idr4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr5(&self) -> Idr5R {
        Idr5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr6(&self) -> Idr6R {
        Idr6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr7(&self) -> Idr7R {
        Idr7R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr8(&self) -> Idr8R {
        Idr8R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr9(&self) -> Idr9R {
        Idr9R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr10(&self) -> Idr10R {
        Idr10R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr11(&self) -> Idr11R {
        Idr11R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr12(&self) -> Idr12R {
        Idr12R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr13(&self) -> Idr13R {
        Idr13R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr14(&self) -> Idr14R {
        Idr14R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Port input data (y = 0..15)"]
    #[inline(always)]
    pub fn idr15(&self) -> Idr15R {
        Idr15R::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr0(&mut self) -> Idr0W<IdrSpec> {
        Idr0W::new(self, 0)
    }
    #[doc = "Bit 1 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr1(&mut self) -> Idr1W<IdrSpec> {
        Idr1W::new(self, 1)
    }
    #[doc = "Bit 2 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr2(&mut self) -> Idr2W<IdrSpec> {
        Idr2W::new(self, 2)
    }
    #[doc = "Bit 3 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr3(&mut self) -> Idr3W<IdrSpec> {
        Idr3W::new(self, 3)
    }
    #[doc = "Bit 4 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr4(&mut self) -> Idr4W<IdrSpec> {
        Idr4W::new(self, 4)
    }
    #[doc = "Bit 5 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr5(&mut self) -> Idr5W<IdrSpec> {
        Idr5W::new(self, 5)
    }
    #[doc = "Bit 6 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr6(&mut self) -> Idr6W<IdrSpec> {
        Idr6W::new(self, 6)
    }
    #[doc = "Bit 7 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr7(&mut self) -> Idr7W<IdrSpec> {
        Idr7W::new(self, 7)
    }
    #[doc = "Bit 8 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr8(&mut self) -> Idr8W<IdrSpec> {
        Idr8W::new(self, 8)
    }
    #[doc = "Bit 9 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr9(&mut self) -> Idr9W<IdrSpec> {
        Idr9W::new(self, 9)
    }
    #[doc = "Bit 10 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr10(&mut self) -> Idr10W<IdrSpec> {
        Idr10W::new(self, 10)
    }
    #[doc = "Bit 11 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr11(&mut self) -> Idr11W<IdrSpec> {
        Idr11W::new(self, 11)
    }
    #[doc = "Bit 12 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr12(&mut self) -> Idr12W<IdrSpec> {
        Idr12W::new(self, 12)
    }
    #[doc = "Bit 13 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr13(&mut self) -> Idr13W<IdrSpec> {
        Idr13W::new(self, 13)
    }
    #[doc = "Bit 14 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr14(&mut self) -> Idr14W<IdrSpec> {
        Idr14W::new(self, 14)
    }
    #[doc = "Bit 15 - Port input data (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn idr15(&mut self) -> Idr15W<IdrSpec> {
        Idr15W::new(self, 15)
    }
}
#[doc = "GPIO port input data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdrSpec;
impl crate::RegisterSpec for IdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`idr::R`](R) reader structure"]
impl crate::Readable for IdrSpec {}
#[doc = "`reset()` method sets IDR to value 0"]
impl crate::Resettable for IdrSpec {
    const RESET_VALUE: u32 = 0;
}
