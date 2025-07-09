// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `LISR` reader"]
pub type R = crate::R<LisrSpec>;
#[doc = "Register `LISR` writer"]
pub type W = crate::W<LisrSpec>;
#[doc = "Field `FEIF0` reader - Stream x FIFO error interrupt flag (x=3..0)"]
pub type Feif0R = crate::BitReader;
#[doc = "Field `FEIF0` writer - Stream x FIFO error interrupt flag (x=3..0)"]
pub type Feif0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMEIF0` reader - Stream x direct mode error interrupt flag (x=3..0)"]
pub type Dmeif0R = crate::BitReader;
#[doc = "Field `DMEIF0` writer - Stream x direct mode error interrupt flag (x=3..0)"]
pub type Dmeif0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TEIF0` reader - Stream x transfer error interrupt flag (x=3..0)"]
pub type Teif0R = crate::BitReader;
#[doc = "Field `TEIF0` writer - Stream x transfer error interrupt flag (x=3..0)"]
pub type Teif0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HTIF0` reader - Stream x half transfer interrupt flag (x=3..0)"]
pub type Htif0R = crate::BitReader;
#[doc = "Field `HTIF0` writer - Stream x half transfer interrupt flag (x=3..0)"]
pub type Htif0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCIF0` reader - Stream x transfer complete interrupt flag (x = 3..0)"]
pub type Tcif0R = crate::BitReader;
#[doc = "Field `TCIF0` writer - Stream x transfer complete interrupt flag (x = 3..0)"]
pub type Tcif0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FEIF1` reader - Stream x FIFO error interrupt flag (x=3..0)"]
pub type Feif1R = crate::BitReader;
#[doc = "Field `FEIF1` writer - Stream x FIFO error interrupt flag (x=3..0)"]
pub type Feif1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMEIF1` reader - Stream x direct mode error interrupt flag (x=3..0)"]
pub type Dmeif1R = crate::BitReader;
#[doc = "Field `DMEIF1` writer - Stream x direct mode error interrupt flag (x=3..0)"]
pub type Dmeif1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TEIF1` reader - Stream x transfer error interrupt flag (x=3..0)"]
pub type Teif1R = crate::BitReader;
#[doc = "Field `TEIF1` writer - Stream x transfer error interrupt flag (x=3..0)"]
pub type Teif1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HTIF1` reader - Stream x half transfer interrupt flag (x=3..0)"]
pub type Htif1R = crate::BitReader;
#[doc = "Field `HTIF1` writer - Stream x half transfer interrupt flag (x=3..0)"]
pub type Htif1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCIF1` reader - Stream x transfer complete interrupt flag (x = 3..0)"]
pub type Tcif1R = crate::BitReader;
#[doc = "Field `TCIF1` writer - Stream x transfer complete interrupt flag (x = 3..0)"]
pub type Tcif1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FEIF2` reader - Stream x FIFO error interrupt flag (x=3..0)"]
pub type Feif2R = crate::BitReader;
#[doc = "Field `FEIF2` writer - Stream x FIFO error interrupt flag (x=3..0)"]
pub type Feif2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMEIF2` reader - Stream x direct mode error interrupt flag (x=3..0)"]
pub type Dmeif2R = crate::BitReader;
#[doc = "Field `DMEIF2` writer - Stream x direct mode error interrupt flag (x=3..0)"]
pub type Dmeif2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TEIF2` reader - Stream x transfer error interrupt flag (x=3..0)"]
pub type Teif2R = crate::BitReader;
#[doc = "Field `TEIF2` writer - Stream x transfer error interrupt flag (x=3..0)"]
pub type Teif2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HTIF2` reader - Stream x half transfer interrupt flag (x=3..0)"]
pub type Htif2R = crate::BitReader;
#[doc = "Field `HTIF2` writer - Stream x half transfer interrupt flag (x=3..0)"]
pub type Htif2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCIF2` reader - Stream x transfer complete interrupt flag (x = 3..0)"]
pub type Tcif2R = crate::BitReader;
#[doc = "Field `TCIF2` writer - Stream x transfer complete interrupt flag (x = 3..0)"]
pub type Tcif2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FEIF3` reader - Stream x FIFO error interrupt flag (x=3..0)"]
pub type Feif3R = crate::BitReader;
#[doc = "Field `FEIF3` writer - Stream x FIFO error interrupt flag (x=3..0)"]
pub type Feif3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMEIF3` reader - Stream x direct mode error interrupt flag (x=3..0)"]
pub type Dmeif3R = crate::BitReader;
#[doc = "Field `DMEIF3` writer - Stream x direct mode error interrupt flag (x=3..0)"]
pub type Dmeif3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TEIF3` reader - Stream x transfer error interrupt flag (x=3..0)"]
pub type Teif3R = crate::BitReader;
#[doc = "Field `TEIF3` writer - Stream x transfer error interrupt flag (x=3..0)"]
pub type Teif3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HTIF3` reader - Stream x half transfer interrupt flag (x=3..0)"]
pub type Htif3R = crate::BitReader;
#[doc = "Field `HTIF3` writer - Stream x half transfer interrupt flag (x=3..0)"]
pub type Htif3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCIF3` reader - Stream x transfer complete interrupt flag (x = 3..0)"]
pub type Tcif3R = crate::BitReader;
#[doc = "Field `TCIF3` writer - Stream x transfer complete interrupt flag (x = 3..0)"]
pub type Tcif3W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Stream x FIFO error interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn feif0(&self) -> Feif0R {
        Feif0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 2 - Stream x direct mode error interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn dmeif0(&self) -> Dmeif0R {
        Dmeif0R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Stream x transfer error interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn teif0(&self) -> Teif0R {
        Teif0R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Stream x half transfer interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn htif0(&self) -> Htif0R {
        Htif0R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Stream x transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn tcif0(&self) -> Tcif0R {
        Tcif0R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Stream x FIFO error interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn feif1(&self) -> Feif1R {
        Feif1R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8 - Stream x direct mode error interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn dmeif1(&self) -> Dmeif1R {
        Dmeif1R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Stream x transfer error interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn teif1(&self) -> Teif1R {
        Teif1R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Stream x half transfer interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn htif1(&self) -> Htif1R {
        Htif1R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Stream x transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn tcif1(&self) -> Tcif1R {
        Tcif1R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 16 - Stream x FIFO error interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn feif2(&self) -> Feif2R {
        Feif2R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 18 - Stream x direct mode error interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn dmeif2(&self) -> Dmeif2R {
        Dmeif2R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Stream x transfer error interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn teif2(&self) -> Teif2R {
        Teif2R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Stream x half transfer interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn htif2(&self) -> Htif2R {
        Htif2R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Stream x transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn tcif2(&self) -> Tcif2R {
        Tcif2R::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Stream x FIFO error interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn feif3(&self) -> Feif3R {
        Feif3R::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 24 - Stream x direct mode error interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn dmeif3(&self) -> Dmeif3R {
        Dmeif3R::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Stream x transfer error interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn teif3(&self) -> Teif3R {
        Teif3R::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Stream x half transfer interrupt flag (x=3..0)"]
    #[inline(always)]
    pub fn htif3(&self) -> Htif3R {
        Htif3R::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Stream x transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn tcif3(&self) -> Tcif3R {
        Tcif3R::new(((self.bits >> 27) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Stream x FIFO error interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn feif0(&mut self) -> Feif0W<LisrSpec> {
        Feif0W::new(self, 0)
    }
    #[doc = "Bit 2 - Stream x direct mode error interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn dmeif0(&mut self) -> Dmeif0W<LisrSpec> {
        Dmeif0W::new(self, 2)
    }
    #[doc = "Bit 3 - Stream x transfer error interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn teif0(&mut self) -> Teif0W<LisrSpec> {
        Teif0W::new(self, 3)
    }
    #[doc = "Bit 4 - Stream x half transfer interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn htif0(&mut self) -> Htif0W<LisrSpec> {
        Htif0W::new(self, 4)
    }
    #[doc = "Bit 5 - Stream x transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn tcif0(&mut self) -> Tcif0W<LisrSpec> {
        Tcif0W::new(self, 5)
    }
    #[doc = "Bit 6 - Stream x FIFO error interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn feif1(&mut self) -> Feif1W<LisrSpec> {
        Feif1W::new(self, 6)
    }
    #[doc = "Bit 8 - Stream x direct mode error interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn dmeif1(&mut self) -> Dmeif1W<LisrSpec> {
        Dmeif1W::new(self, 8)
    }
    #[doc = "Bit 9 - Stream x transfer error interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn teif1(&mut self) -> Teif1W<LisrSpec> {
        Teif1W::new(self, 9)
    }
    #[doc = "Bit 10 - Stream x half transfer interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn htif1(&mut self) -> Htif1W<LisrSpec> {
        Htif1W::new(self, 10)
    }
    #[doc = "Bit 11 - Stream x transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn tcif1(&mut self) -> Tcif1W<LisrSpec> {
        Tcif1W::new(self, 11)
    }
    #[doc = "Bit 16 - Stream x FIFO error interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn feif2(&mut self) -> Feif2W<LisrSpec> {
        Feif2W::new(self, 16)
    }
    #[doc = "Bit 18 - Stream x direct mode error interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn dmeif2(&mut self) -> Dmeif2W<LisrSpec> {
        Dmeif2W::new(self, 18)
    }
    #[doc = "Bit 19 - Stream x transfer error interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn teif2(&mut self) -> Teif2W<LisrSpec> {
        Teif2W::new(self, 19)
    }
    #[doc = "Bit 20 - Stream x half transfer interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn htif2(&mut self) -> Htif2W<LisrSpec> {
        Htif2W::new(self, 20)
    }
    #[doc = "Bit 21 - Stream x transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn tcif2(&mut self) -> Tcif2W<LisrSpec> {
        Tcif2W::new(self, 21)
    }
    #[doc = "Bit 22 - Stream x FIFO error interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn feif3(&mut self) -> Feif3W<LisrSpec> {
        Feif3W::new(self, 22)
    }
    #[doc = "Bit 24 - Stream x direct mode error interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn dmeif3(&mut self) -> Dmeif3W<LisrSpec> {
        Dmeif3W::new(self, 24)
    }
    #[doc = "Bit 25 - Stream x transfer error interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn teif3(&mut self) -> Teif3W<LisrSpec> {
        Teif3W::new(self, 25)
    }
    #[doc = "Bit 26 - Stream x half transfer interrupt flag (x=3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn htif3(&mut self) -> Htif3W<LisrSpec> {
        Htif3W::new(self, 26)
    }
    #[doc = "Bit 27 - Stream x transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn tcif3(&mut self) -> Tcif3W<LisrSpec> {
        Tcif3W::new(self, 27)
    }
}
#[doc = "low interrupt status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lisr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct LisrSpec;
impl crate::RegisterSpec for LisrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`lisr::R`](R) reader structure"]
impl crate::Readable for LisrSpec {}
#[doc = "`reset()` method sets LISR to value 0"]
impl crate::Resettable for LisrSpec {
    const RESET_VALUE: u32 = 0;
}
