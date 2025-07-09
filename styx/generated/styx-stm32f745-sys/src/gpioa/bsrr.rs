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
#[doc = "Register `BSRR` reader"]
pub type R = crate::R<BsrrSpec>;
#[doc = "Register `BSRR` writer"]
pub type W = crate::W<BsrrSpec>;
#[doc = "Field `BS0` reader - Port x set bit y (y= 0..15)"]
pub type Bs0R = crate::BitReader;
#[doc = "Field `BS0` writer - Port x set bit y (y= 0..15)"]
pub type Bs0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS1` reader - Port x set bit y (y= 0..15)"]
pub type Bs1R = crate::BitReader;
#[doc = "Field `BS1` writer - Port x set bit y (y= 0..15)"]
pub type Bs1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS2` reader - Port x set bit y (y= 0..15)"]
pub type Bs2R = crate::BitReader;
#[doc = "Field `BS2` writer - Port x set bit y (y= 0..15)"]
pub type Bs2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS3` reader - Port x set bit y (y= 0..15)"]
pub type Bs3R = crate::BitReader;
#[doc = "Field `BS3` writer - Port x set bit y (y= 0..15)"]
pub type Bs3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS4` reader - Port x set bit y (y= 0..15)"]
pub type Bs4R = crate::BitReader;
#[doc = "Field `BS4` writer - Port x set bit y (y= 0..15)"]
pub type Bs4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS5` reader - Port x set bit y (y= 0..15)"]
pub type Bs5R = crate::BitReader;
#[doc = "Field `BS5` writer - Port x set bit y (y= 0..15)"]
pub type Bs5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS6` reader - Port x set bit y (y= 0..15)"]
pub type Bs6R = crate::BitReader;
#[doc = "Field `BS6` writer - Port x set bit y (y= 0..15)"]
pub type Bs6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS7` reader - Port x set bit y (y= 0..15)"]
pub type Bs7R = crate::BitReader;
#[doc = "Field `BS7` writer - Port x set bit y (y= 0..15)"]
pub type Bs7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS8` reader - Port x set bit y (y= 0..15)"]
pub type Bs8R = crate::BitReader;
#[doc = "Field `BS8` writer - Port x set bit y (y= 0..15)"]
pub type Bs8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS9` reader - Port x set bit y (y= 0..15)"]
pub type Bs9R = crate::BitReader;
#[doc = "Field `BS9` writer - Port x set bit y (y= 0..15)"]
pub type Bs9W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS10` reader - Port x set bit y (y= 0..15)"]
pub type Bs10R = crate::BitReader;
#[doc = "Field `BS10` writer - Port x set bit y (y= 0..15)"]
pub type Bs10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS11` reader - Port x set bit y (y= 0..15)"]
pub type Bs11R = crate::BitReader;
#[doc = "Field `BS11` writer - Port x set bit y (y= 0..15)"]
pub type Bs11W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS12` reader - Port x set bit y (y= 0..15)"]
pub type Bs12R = crate::BitReader;
#[doc = "Field `BS12` writer - Port x set bit y (y= 0..15)"]
pub type Bs12W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS13` reader - Port x set bit y (y= 0..15)"]
pub type Bs13R = crate::BitReader;
#[doc = "Field `BS13` writer - Port x set bit y (y= 0..15)"]
pub type Bs13W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS14` reader - Port x set bit y (y= 0..15)"]
pub type Bs14R = crate::BitReader;
#[doc = "Field `BS14` writer - Port x set bit y (y= 0..15)"]
pub type Bs14W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BS15` reader - Port x set bit y (y= 0..15)"]
pub type Bs15R = crate::BitReader;
#[doc = "Field `BS15` writer - Port x set bit y (y= 0..15)"]
pub type Bs15W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR0` reader - Port x set bit y (y= 0..15)"]
pub type Br0R = crate::BitReader;
#[doc = "Field `BR0` writer - Port x set bit y (y= 0..15)"]
pub type Br0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR1` reader - Port x reset bit y (y = 0..15)"]
pub type Br1R = crate::BitReader;
#[doc = "Field `BR1` writer - Port x reset bit y (y = 0..15)"]
pub type Br1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR2` reader - Port x reset bit y (y = 0..15)"]
pub type Br2R = crate::BitReader;
#[doc = "Field `BR2` writer - Port x reset bit y (y = 0..15)"]
pub type Br2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR3` reader - Port x reset bit y (y = 0..15)"]
pub type Br3R = crate::BitReader;
#[doc = "Field `BR3` writer - Port x reset bit y (y = 0..15)"]
pub type Br3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR4` reader - Port x reset bit y (y = 0..15)"]
pub type Br4R = crate::BitReader;
#[doc = "Field `BR4` writer - Port x reset bit y (y = 0..15)"]
pub type Br4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR5` reader - Port x reset bit y (y = 0..15)"]
pub type Br5R = crate::BitReader;
#[doc = "Field `BR5` writer - Port x reset bit y (y = 0..15)"]
pub type Br5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR6` reader - Port x reset bit y (y = 0..15)"]
pub type Br6R = crate::BitReader;
#[doc = "Field `BR6` writer - Port x reset bit y (y = 0..15)"]
pub type Br6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR7` reader - Port x reset bit y (y = 0..15)"]
pub type Br7R = crate::BitReader;
#[doc = "Field `BR7` writer - Port x reset bit y (y = 0..15)"]
pub type Br7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR8` reader - Port x reset bit y (y = 0..15)"]
pub type Br8R = crate::BitReader;
#[doc = "Field `BR8` writer - Port x reset bit y (y = 0..15)"]
pub type Br8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR9` reader - Port x reset bit y (y = 0..15)"]
pub type Br9R = crate::BitReader;
#[doc = "Field `BR9` writer - Port x reset bit y (y = 0..15)"]
pub type Br9W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR10` reader - Port x reset bit y (y = 0..15)"]
pub type Br10R = crate::BitReader;
#[doc = "Field `BR10` writer - Port x reset bit y (y = 0..15)"]
pub type Br10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR11` reader - Port x reset bit y (y = 0..15)"]
pub type Br11R = crate::BitReader;
#[doc = "Field `BR11` writer - Port x reset bit y (y = 0..15)"]
pub type Br11W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR12` reader - Port x reset bit y (y = 0..15)"]
pub type Br12R = crate::BitReader;
#[doc = "Field `BR12` writer - Port x reset bit y (y = 0..15)"]
pub type Br12W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR13` reader - Port x reset bit y (y = 0..15)"]
pub type Br13R = crate::BitReader;
#[doc = "Field `BR13` writer - Port x reset bit y (y = 0..15)"]
pub type Br13W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR14` reader - Port x reset bit y (y = 0..15)"]
pub type Br14R = crate::BitReader;
#[doc = "Field `BR14` writer - Port x reset bit y (y = 0..15)"]
pub type Br14W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BR15` reader - Port x reset bit y (y = 0..15)"]
pub type Br15R = crate::BitReader;
#[doc = "Field `BR15` writer - Port x reset bit y (y = 0..15)"]
pub type Br15W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs0(&self) -> Bs0R {
        Bs0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs1(&self) -> Bs1R {
        Bs1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs2(&self) -> Bs2R {
        Bs2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs3(&self) -> Bs3R {
        Bs3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs4(&self) -> Bs4R {
        Bs4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs5(&self) -> Bs5R {
        Bs5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs6(&self) -> Bs6R {
        Bs6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs7(&self) -> Bs7R {
        Bs7R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs8(&self) -> Bs8R {
        Bs8R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs9(&self) -> Bs9R {
        Bs9R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs10(&self) -> Bs10R {
        Bs10R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs11(&self) -> Bs11R {
        Bs11R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs12(&self) -> Bs12R {
        Bs12R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs13(&self) -> Bs13R {
        Bs13R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs14(&self) -> Bs14R {
        Bs14R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn bs15(&self) -> Bs15R {
        Bs15R::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    pub fn br0(&self) -> Br0R {
        Br0R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br1(&self) -> Br1R {
        Br1R::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br2(&self) -> Br2R {
        Br2R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br3(&self) -> Br3R {
        Br3R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br4(&self) -> Br4R {
        Br4R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br5(&self) -> Br5R {
        Br5R::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br6(&self) -> Br6R {
        Br6R::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br7(&self) -> Br7R {
        Br7R::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br8(&self) -> Br8R {
        Br8R::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br9(&self) -> Br9R {
        Br9R::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br10(&self) -> Br10R {
        Br10R::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br11(&self) -> Br11R {
        Br11R::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br12(&self) -> Br12R {
        Br12R::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br13(&self) -> Br13R {
        Br13R::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br14(&self) -> Br14R {
        Br14R::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    pub fn br15(&self) -> Br15R {
        Br15R::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs0(&mut self) -> Bs0W<BsrrSpec> {
        Bs0W::new(self, 0)
    }
    #[doc = "Bit 1 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs1(&mut self) -> Bs1W<BsrrSpec> {
        Bs1W::new(self, 1)
    }
    #[doc = "Bit 2 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs2(&mut self) -> Bs2W<BsrrSpec> {
        Bs2W::new(self, 2)
    }
    #[doc = "Bit 3 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs3(&mut self) -> Bs3W<BsrrSpec> {
        Bs3W::new(self, 3)
    }
    #[doc = "Bit 4 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs4(&mut self) -> Bs4W<BsrrSpec> {
        Bs4W::new(self, 4)
    }
    #[doc = "Bit 5 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs5(&mut self) -> Bs5W<BsrrSpec> {
        Bs5W::new(self, 5)
    }
    #[doc = "Bit 6 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs6(&mut self) -> Bs6W<BsrrSpec> {
        Bs6W::new(self, 6)
    }
    #[doc = "Bit 7 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs7(&mut self) -> Bs7W<BsrrSpec> {
        Bs7W::new(self, 7)
    }
    #[doc = "Bit 8 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs8(&mut self) -> Bs8W<BsrrSpec> {
        Bs8W::new(self, 8)
    }
    #[doc = "Bit 9 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs9(&mut self) -> Bs9W<BsrrSpec> {
        Bs9W::new(self, 9)
    }
    #[doc = "Bit 10 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs10(&mut self) -> Bs10W<BsrrSpec> {
        Bs10W::new(self, 10)
    }
    #[doc = "Bit 11 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs11(&mut self) -> Bs11W<BsrrSpec> {
        Bs11W::new(self, 11)
    }
    #[doc = "Bit 12 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs12(&mut self) -> Bs12W<BsrrSpec> {
        Bs12W::new(self, 12)
    }
    #[doc = "Bit 13 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs13(&mut self) -> Bs13W<BsrrSpec> {
        Bs13W::new(self, 13)
    }
    #[doc = "Bit 14 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs14(&mut self) -> Bs14W<BsrrSpec> {
        Bs14W::new(self, 14)
    }
    #[doc = "Bit 15 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn bs15(&mut self) -> Bs15W<BsrrSpec> {
        Bs15W::new(self, 15)
    }
    #[doc = "Bit 16 - Port x set bit y (y= 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br0(&mut self) -> Br0W<BsrrSpec> {
        Br0W::new(self, 16)
    }
    #[doc = "Bit 17 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br1(&mut self) -> Br1W<BsrrSpec> {
        Br1W::new(self, 17)
    }
    #[doc = "Bit 18 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br2(&mut self) -> Br2W<BsrrSpec> {
        Br2W::new(self, 18)
    }
    #[doc = "Bit 19 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br3(&mut self) -> Br3W<BsrrSpec> {
        Br3W::new(self, 19)
    }
    #[doc = "Bit 20 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br4(&mut self) -> Br4W<BsrrSpec> {
        Br4W::new(self, 20)
    }
    #[doc = "Bit 21 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br5(&mut self) -> Br5W<BsrrSpec> {
        Br5W::new(self, 21)
    }
    #[doc = "Bit 22 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br6(&mut self) -> Br6W<BsrrSpec> {
        Br6W::new(self, 22)
    }
    #[doc = "Bit 23 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br7(&mut self) -> Br7W<BsrrSpec> {
        Br7W::new(self, 23)
    }
    #[doc = "Bit 24 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br8(&mut self) -> Br8W<BsrrSpec> {
        Br8W::new(self, 24)
    }
    #[doc = "Bit 25 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br9(&mut self) -> Br9W<BsrrSpec> {
        Br9W::new(self, 25)
    }
    #[doc = "Bit 26 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br10(&mut self) -> Br10W<BsrrSpec> {
        Br10W::new(self, 26)
    }
    #[doc = "Bit 27 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br11(&mut self) -> Br11W<BsrrSpec> {
        Br11W::new(self, 27)
    }
    #[doc = "Bit 28 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br12(&mut self) -> Br12W<BsrrSpec> {
        Br12W::new(self, 28)
    }
    #[doc = "Bit 29 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br13(&mut self) -> Br13W<BsrrSpec> {
        Br13W::new(self, 29)
    }
    #[doc = "Bit 30 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br14(&mut self) -> Br14W<BsrrSpec> {
        Br14W::new(self, 30)
    }
    #[doc = "Bit 31 - Port x reset bit y (y = 0..15)"]
    #[inline(always)]
    #[must_use]
    pub fn br15(&mut self) -> Br15W<BsrrSpec> {
        Br15W::new(self, 31)
    }
}
#[doc = "GPIO port bit set/reset register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bsrr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BsrrSpec;
impl crate::RegisterSpec for BsrrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`write(|w| ..)` method takes [`bsrr::W`](W) writer structure"]
impl crate::Writable for BsrrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets BSRR to value 0"]
impl crate::Resettable for BsrrSpec {
    const RESET_VALUE: u32 = 0;
}
