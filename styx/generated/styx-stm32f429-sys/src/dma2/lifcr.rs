// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `LIFCR` reader"]
pub type R = crate::R<LifcrSpec>;
#[doc = "Register `LIFCR` writer"]
pub type W = crate::W<LifcrSpec>;
#[doc = "Field `CFEIF0` reader - Stream x clear FIFO error interrupt flag (x = 3..0)"]
pub type Cfeif0R = crate::BitReader;
#[doc = "Field `CFEIF0` writer - Stream x clear FIFO error interrupt flag (x = 3..0)"]
pub type Cfeif0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CDMEIF0` reader - Stream x clear direct mode error interrupt flag (x = 3..0)"]
pub type Cdmeif0R = crate::BitReader;
#[doc = "Field `CDMEIF0` writer - Stream x clear direct mode error interrupt flag (x = 3..0)"]
pub type Cdmeif0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTEIF0` reader - Stream x clear transfer error interrupt flag (x = 3..0)"]
pub type Cteif0R = crate::BitReader;
#[doc = "Field `CTEIF0` writer - Stream x clear transfer error interrupt flag (x = 3..0)"]
pub type Cteif0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CHTIF0` reader - Stream x clear half transfer interrupt flag (x = 3..0)"]
pub type Chtif0R = crate::BitReader;
#[doc = "Field `CHTIF0` writer - Stream x clear half transfer interrupt flag (x = 3..0)"]
pub type Chtif0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTCIF0` reader - Stream x clear transfer complete interrupt flag (x = 3..0)"]
pub type Ctcif0R = crate::BitReader;
#[doc = "Field `CTCIF0` writer - Stream x clear transfer complete interrupt flag (x = 3..0)"]
pub type Ctcif0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CFEIF1` reader - Stream x clear FIFO error interrupt flag (x = 3..0)"]
pub type Cfeif1R = crate::BitReader;
#[doc = "Field `CFEIF1` writer - Stream x clear FIFO error interrupt flag (x = 3..0)"]
pub type Cfeif1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CDMEIF1` reader - Stream x clear direct mode error interrupt flag (x = 3..0)"]
pub type Cdmeif1R = crate::BitReader;
#[doc = "Field `CDMEIF1` writer - Stream x clear direct mode error interrupt flag (x = 3..0)"]
pub type Cdmeif1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTEIF1` reader - Stream x clear transfer error interrupt flag (x = 3..0)"]
pub type Cteif1R = crate::BitReader;
#[doc = "Field `CTEIF1` writer - Stream x clear transfer error interrupt flag (x = 3..0)"]
pub type Cteif1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CHTIF1` reader - Stream x clear half transfer interrupt flag (x = 3..0)"]
pub type Chtif1R = crate::BitReader;
#[doc = "Field `CHTIF1` writer - Stream x clear half transfer interrupt flag (x = 3..0)"]
pub type Chtif1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTCIF1` reader - Stream x clear transfer complete interrupt flag (x = 3..0)"]
pub type Ctcif1R = crate::BitReader;
#[doc = "Field `CTCIF1` writer - Stream x clear transfer complete interrupt flag (x = 3..0)"]
pub type Ctcif1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CFEIF2` reader - Stream x clear FIFO error interrupt flag (x = 3..0)"]
pub type Cfeif2R = crate::BitReader;
#[doc = "Field `CFEIF2` writer - Stream x clear FIFO error interrupt flag (x = 3..0)"]
pub type Cfeif2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CDMEIF2` reader - Stream x clear direct mode error interrupt flag (x = 3..0)"]
pub type Cdmeif2R = crate::BitReader;
#[doc = "Field `CDMEIF2` writer - Stream x clear direct mode error interrupt flag (x = 3..0)"]
pub type Cdmeif2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTEIF2` reader - Stream x clear transfer error interrupt flag (x = 3..0)"]
pub type Cteif2R = crate::BitReader;
#[doc = "Field `CTEIF2` writer - Stream x clear transfer error interrupt flag (x = 3..0)"]
pub type Cteif2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CHTIF2` reader - Stream x clear half transfer interrupt flag (x = 3..0)"]
pub type Chtif2R = crate::BitReader;
#[doc = "Field `CHTIF2` writer - Stream x clear half transfer interrupt flag (x = 3..0)"]
pub type Chtif2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTCIF2` reader - Stream x clear transfer complete interrupt flag (x = 3..0)"]
pub type Ctcif2R = crate::BitReader;
#[doc = "Field `CTCIF2` writer - Stream x clear transfer complete interrupt flag (x = 3..0)"]
pub type Ctcif2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CFEIF3` reader - Stream x clear FIFO error interrupt flag (x = 3..0)"]
pub type Cfeif3R = crate::BitReader;
#[doc = "Field `CFEIF3` writer - Stream x clear FIFO error interrupt flag (x = 3..0)"]
pub type Cfeif3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CDMEIF3` reader - Stream x clear direct mode error interrupt flag (x = 3..0)"]
pub type Cdmeif3R = crate::BitReader;
#[doc = "Field `CDMEIF3` writer - Stream x clear direct mode error interrupt flag (x = 3..0)"]
pub type Cdmeif3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTEIF3` reader - Stream x clear transfer error interrupt flag (x = 3..0)"]
pub type Cteif3R = crate::BitReader;
#[doc = "Field `CTEIF3` writer - Stream x clear transfer error interrupt flag (x = 3..0)"]
pub type Cteif3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CHTIF3` reader - Stream x clear half transfer interrupt flag (x = 3..0)"]
pub type Chtif3R = crate::BitReader;
#[doc = "Field `CHTIF3` writer - Stream x clear half transfer interrupt flag (x = 3..0)"]
pub type Chtif3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTCIF3` reader - Stream x clear transfer complete interrupt flag (x = 3..0)"]
pub type Ctcif3R = crate::BitReader;
#[doc = "Field `CTCIF3` writer - Stream x clear transfer complete interrupt flag (x = 3..0)"]
pub type Ctcif3W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Stream x clear FIFO error interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn cfeif0(&self) -> Cfeif0R {
        Cfeif0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 2 - Stream x clear direct mode error interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn cdmeif0(&self) -> Cdmeif0R {
        Cdmeif0R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Stream x clear transfer error interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn cteif0(&self) -> Cteif0R {
        Cteif0R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Stream x clear half transfer interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn chtif0(&self) -> Chtif0R {
        Chtif0R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Stream x clear transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn ctcif0(&self) -> Ctcif0R {
        Ctcif0R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Stream x clear FIFO error interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn cfeif1(&self) -> Cfeif1R {
        Cfeif1R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8 - Stream x clear direct mode error interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn cdmeif1(&self) -> Cdmeif1R {
        Cdmeif1R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Stream x clear transfer error interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn cteif1(&self) -> Cteif1R {
        Cteif1R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Stream x clear half transfer interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn chtif1(&self) -> Chtif1R {
        Chtif1R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Stream x clear transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn ctcif1(&self) -> Ctcif1R {
        Ctcif1R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 16 - Stream x clear FIFO error interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn cfeif2(&self) -> Cfeif2R {
        Cfeif2R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 18 - Stream x clear direct mode error interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn cdmeif2(&self) -> Cdmeif2R {
        Cdmeif2R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Stream x clear transfer error interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn cteif2(&self) -> Cteif2R {
        Cteif2R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Stream x clear half transfer interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn chtif2(&self) -> Chtif2R {
        Chtif2R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Stream x clear transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn ctcif2(&self) -> Ctcif2R {
        Ctcif2R::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Stream x clear FIFO error interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn cfeif3(&self) -> Cfeif3R {
        Cfeif3R::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 24 - Stream x clear direct mode error interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn cdmeif3(&self) -> Cdmeif3R {
        Cdmeif3R::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Stream x clear transfer error interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn cteif3(&self) -> Cteif3R {
        Cteif3R::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Stream x clear half transfer interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn chtif3(&self) -> Chtif3R {
        Chtif3R::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Stream x clear transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    pub fn ctcif3(&self) -> Ctcif3R {
        Ctcif3R::new(((self.bits >> 27) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Stream x clear FIFO error interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn cfeif0(&mut self) -> Cfeif0W<LifcrSpec> {
        Cfeif0W::new(self, 0)
    }
    #[doc = "Bit 2 - Stream x clear direct mode error interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn cdmeif0(&mut self) -> Cdmeif0W<LifcrSpec> {
        Cdmeif0W::new(self, 2)
    }
    #[doc = "Bit 3 - Stream x clear transfer error interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn cteif0(&mut self) -> Cteif0W<LifcrSpec> {
        Cteif0W::new(self, 3)
    }
    #[doc = "Bit 4 - Stream x clear half transfer interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn chtif0(&mut self) -> Chtif0W<LifcrSpec> {
        Chtif0W::new(self, 4)
    }
    #[doc = "Bit 5 - Stream x clear transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn ctcif0(&mut self) -> Ctcif0W<LifcrSpec> {
        Ctcif0W::new(self, 5)
    }
    #[doc = "Bit 6 - Stream x clear FIFO error interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn cfeif1(&mut self) -> Cfeif1W<LifcrSpec> {
        Cfeif1W::new(self, 6)
    }
    #[doc = "Bit 8 - Stream x clear direct mode error interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn cdmeif1(&mut self) -> Cdmeif1W<LifcrSpec> {
        Cdmeif1W::new(self, 8)
    }
    #[doc = "Bit 9 - Stream x clear transfer error interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn cteif1(&mut self) -> Cteif1W<LifcrSpec> {
        Cteif1W::new(self, 9)
    }
    #[doc = "Bit 10 - Stream x clear half transfer interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn chtif1(&mut self) -> Chtif1W<LifcrSpec> {
        Chtif1W::new(self, 10)
    }
    #[doc = "Bit 11 - Stream x clear transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn ctcif1(&mut self) -> Ctcif1W<LifcrSpec> {
        Ctcif1W::new(self, 11)
    }
    #[doc = "Bit 16 - Stream x clear FIFO error interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn cfeif2(&mut self) -> Cfeif2W<LifcrSpec> {
        Cfeif2W::new(self, 16)
    }
    #[doc = "Bit 18 - Stream x clear direct mode error interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn cdmeif2(&mut self) -> Cdmeif2W<LifcrSpec> {
        Cdmeif2W::new(self, 18)
    }
    #[doc = "Bit 19 - Stream x clear transfer error interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn cteif2(&mut self) -> Cteif2W<LifcrSpec> {
        Cteif2W::new(self, 19)
    }
    #[doc = "Bit 20 - Stream x clear half transfer interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn chtif2(&mut self) -> Chtif2W<LifcrSpec> {
        Chtif2W::new(self, 20)
    }
    #[doc = "Bit 21 - Stream x clear transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn ctcif2(&mut self) -> Ctcif2W<LifcrSpec> {
        Ctcif2W::new(self, 21)
    }
    #[doc = "Bit 22 - Stream x clear FIFO error interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn cfeif3(&mut self) -> Cfeif3W<LifcrSpec> {
        Cfeif3W::new(self, 22)
    }
    #[doc = "Bit 24 - Stream x clear direct mode error interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn cdmeif3(&mut self) -> Cdmeif3W<LifcrSpec> {
        Cdmeif3W::new(self, 24)
    }
    #[doc = "Bit 25 - Stream x clear transfer error interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn cteif3(&mut self) -> Cteif3W<LifcrSpec> {
        Cteif3W::new(self, 25)
    }
    #[doc = "Bit 26 - Stream x clear half transfer interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn chtif3(&mut self) -> Chtif3W<LifcrSpec> {
        Chtif3W::new(self, 26)
    }
    #[doc = "Bit 27 - Stream x clear transfer complete interrupt flag (x = 3..0)"]
    #[inline(always)]
    #[must_use]
    pub fn ctcif3(&mut self) -> Ctcif3W<LifcrSpec> {
        Ctcif3W::new(self, 27)
    }
}
#[doc = "low interrupt flag clear register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lifcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`lifcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct LifcrSpec;
impl crate::RegisterSpec for LifcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`lifcr::R`](R) reader structure"]
impl crate::Readable for LifcrSpec {}
#[doc = "`write(|w| ..)` method takes [`lifcr::W`](W) writer structure"]
impl crate::Writable for LifcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets LIFCR to value 0"]
impl crate::Resettable for LifcrSpec {
    const RESET_VALUE: u32 = 0;
}
