// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `HIFCR` reader"]
pub type R = crate::R<HifcrSpec>;
#[doc = "Register `HIFCR` writer"]
pub type W = crate::W<HifcrSpec>;
#[doc = "Field `CFEIF4` reader - Stream x clear FIFO error interrupt flag (x = 7..4)"]
pub type Cfeif4R = crate::BitReader;
#[doc = "Field `CFEIF4` writer - Stream x clear FIFO error interrupt flag (x = 7..4)"]
pub type Cfeif4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CDMEIF4` reader - Stream x clear direct mode error interrupt flag (x = 7..4)"]
pub type Cdmeif4R = crate::BitReader;
#[doc = "Field `CDMEIF4` writer - Stream x clear direct mode error interrupt flag (x = 7..4)"]
pub type Cdmeif4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTEIF4` reader - Stream x clear transfer error interrupt flag (x = 7..4)"]
pub type Cteif4R = crate::BitReader;
#[doc = "Field `CTEIF4` writer - Stream x clear transfer error interrupt flag (x = 7..4)"]
pub type Cteif4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CHTIF4` reader - Stream x clear half transfer interrupt flag (x = 7..4)"]
pub type Chtif4R = crate::BitReader;
#[doc = "Field `CHTIF4` writer - Stream x clear half transfer interrupt flag (x = 7..4)"]
pub type Chtif4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTCIF4` reader - Stream x clear transfer complete interrupt flag (x = 7..4)"]
pub type Ctcif4R = crate::BitReader;
#[doc = "Field `CTCIF4` writer - Stream x clear transfer complete interrupt flag (x = 7..4)"]
pub type Ctcif4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CFEIF5` reader - Stream x clear FIFO error interrupt flag (x = 7..4)"]
pub type Cfeif5R = crate::BitReader;
#[doc = "Field `CFEIF5` writer - Stream x clear FIFO error interrupt flag (x = 7..4)"]
pub type Cfeif5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CDMEIF5` reader - Stream x clear direct mode error interrupt flag (x = 7..4)"]
pub type Cdmeif5R = crate::BitReader;
#[doc = "Field `CDMEIF5` writer - Stream x clear direct mode error interrupt flag (x = 7..4)"]
pub type Cdmeif5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTEIF5` reader - Stream x clear transfer error interrupt flag (x = 7..4)"]
pub type Cteif5R = crate::BitReader;
#[doc = "Field `CTEIF5` writer - Stream x clear transfer error interrupt flag (x = 7..4)"]
pub type Cteif5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CHTIF5` reader - Stream x clear half transfer interrupt flag (x = 7..4)"]
pub type Chtif5R = crate::BitReader;
#[doc = "Field `CHTIF5` writer - Stream x clear half transfer interrupt flag (x = 7..4)"]
pub type Chtif5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTCIF5` reader - Stream x clear transfer complete interrupt flag (x = 7..4)"]
pub type Ctcif5R = crate::BitReader;
#[doc = "Field `CTCIF5` writer - Stream x clear transfer complete interrupt flag (x = 7..4)"]
pub type Ctcif5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CFEIF6` reader - Stream x clear FIFO error interrupt flag (x = 7..4)"]
pub type Cfeif6R = crate::BitReader;
#[doc = "Field `CFEIF6` writer - Stream x clear FIFO error interrupt flag (x = 7..4)"]
pub type Cfeif6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CDMEIF6` reader - Stream x clear direct mode error interrupt flag (x = 7..4)"]
pub type Cdmeif6R = crate::BitReader;
#[doc = "Field `CDMEIF6` writer - Stream x clear direct mode error interrupt flag (x = 7..4)"]
pub type Cdmeif6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTEIF6` reader - Stream x clear transfer error interrupt flag (x = 7..4)"]
pub type Cteif6R = crate::BitReader;
#[doc = "Field `CTEIF6` writer - Stream x clear transfer error interrupt flag (x = 7..4)"]
pub type Cteif6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CHTIF6` reader - Stream x clear half transfer interrupt flag (x = 7..4)"]
pub type Chtif6R = crate::BitReader;
#[doc = "Field `CHTIF6` writer - Stream x clear half transfer interrupt flag (x = 7..4)"]
pub type Chtif6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTCIF6` reader - Stream x clear transfer complete interrupt flag (x = 7..4)"]
pub type Ctcif6R = crate::BitReader;
#[doc = "Field `CTCIF6` writer - Stream x clear transfer complete interrupt flag (x = 7..4)"]
pub type Ctcif6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CFEIF7` reader - Stream x clear FIFO error interrupt flag (x = 7..4)"]
pub type Cfeif7R = crate::BitReader;
#[doc = "Field `CFEIF7` writer - Stream x clear FIFO error interrupt flag (x = 7..4)"]
pub type Cfeif7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CDMEIF7` reader - Stream x clear direct mode error interrupt flag (x = 7..4)"]
pub type Cdmeif7R = crate::BitReader;
#[doc = "Field `CDMEIF7` writer - Stream x clear direct mode error interrupt flag (x = 7..4)"]
pub type Cdmeif7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTEIF7` reader - Stream x clear transfer error interrupt flag (x = 7..4)"]
pub type Cteif7R = crate::BitReader;
#[doc = "Field `CTEIF7` writer - Stream x clear transfer error interrupt flag (x = 7..4)"]
pub type Cteif7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CHTIF7` reader - Stream x clear half transfer interrupt flag (x = 7..4)"]
pub type Chtif7R = crate::BitReader;
#[doc = "Field `CHTIF7` writer - Stream x clear half transfer interrupt flag (x = 7..4)"]
pub type Chtif7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTCIF7` reader - Stream x clear transfer complete interrupt flag (x = 7..4)"]
pub type Ctcif7R = crate::BitReader;
#[doc = "Field `CTCIF7` writer - Stream x clear transfer complete interrupt flag (x = 7..4)"]
pub type Ctcif7W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Stream x clear FIFO error interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn cfeif4(&self) -> Cfeif4R {
        Cfeif4R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 2 - Stream x clear direct mode error interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn cdmeif4(&self) -> Cdmeif4R {
        Cdmeif4R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Stream x clear transfer error interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn cteif4(&self) -> Cteif4R {
        Cteif4R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Stream x clear half transfer interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn chtif4(&self) -> Chtif4R {
        Chtif4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Stream x clear transfer complete interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn ctcif4(&self) -> Ctcif4R {
        Ctcif4R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Stream x clear FIFO error interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn cfeif5(&self) -> Cfeif5R {
        Cfeif5R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8 - Stream x clear direct mode error interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn cdmeif5(&self) -> Cdmeif5R {
        Cdmeif5R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Stream x clear transfer error interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn cteif5(&self) -> Cteif5R {
        Cteif5R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Stream x clear half transfer interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn chtif5(&self) -> Chtif5R {
        Chtif5R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Stream x clear transfer complete interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn ctcif5(&self) -> Ctcif5R {
        Ctcif5R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 16 - Stream x clear FIFO error interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn cfeif6(&self) -> Cfeif6R {
        Cfeif6R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 18 - Stream x clear direct mode error interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn cdmeif6(&self) -> Cdmeif6R {
        Cdmeif6R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Stream x clear transfer error interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn cteif6(&self) -> Cteif6R {
        Cteif6R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Stream x clear half transfer interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn chtif6(&self) -> Chtif6R {
        Chtif6R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Stream x clear transfer complete interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn ctcif6(&self) -> Ctcif6R {
        Ctcif6R::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Stream x clear FIFO error interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn cfeif7(&self) -> Cfeif7R {
        Cfeif7R::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 24 - Stream x clear direct mode error interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn cdmeif7(&self) -> Cdmeif7R {
        Cdmeif7R::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Stream x clear transfer error interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn cteif7(&self) -> Cteif7R {
        Cteif7R::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Stream x clear half transfer interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn chtif7(&self) -> Chtif7R {
        Chtif7R::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Stream x clear transfer complete interrupt flag (x = 7..4)"]
    #[inline(always)]
    pub fn ctcif7(&self) -> Ctcif7R {
        Ctcif7R::new(((self.bits >> 27) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Stream x clear FIFO error interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn cfeif4(&mut self) -> Cfeif4W<HifcrSpec> {
        Cfeif4W::new(self, 0)
    }
    #[doc = "Bit 2 - Stream x clear direct mode error interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn cdmeif4(&mut self) -> Cdmeif4W<HifcrSpec> {
        Cdmeif4W::new(self, 2)
    }
    #[doc = "Bit 3 - Stream x clear transfer error interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn cteif4(&mut self) -> Cteif4W<HifcrSpec> {
        Cteif4W::new(self, 3)
    }
    #[doc = "Bit 4 - Stream x clear half transfer interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn chtif4(&mut self) -> Chtif4W<HifcrSpec> {
        Chtif4W::new(self, 4)
    }
    #[doc = "Bit 5 - Stream x clear transfer complete interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn ctcif4(&mut self) -> Ctcif4W<HifcrSpec> {
        Ctcif4W::new(self, 5)
    }
    #[doc = "Bit 6 - Stream x clear FIFO error interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn cfeif5(&mut self) -> Cfeif5W<HifcrSpec> {
        Cfeif5W::new(self, 6)
    }
    #[doc = "Bit 8 - Stream x clear direct mode error interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn cdmeif5(&mut self) -> Cdmeif5W<HifcrSpec> {
        Cdmeif5W::new(self, 8)
    }
    #[doc = "Bit 9 - Stream x clear transfer error interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn cteif5(&mut self) -> Cteif5W<HifcrSpec> {
        Cteif5W::new(self, 9)
    }
    #[doc = "Bit 10 - Stream x clear half transfer interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn chtif5(&mut self) -> Chtif5W<HifcrSpec> {
        Chtif5W::new(self, 10)
    }
    #[doc = "Bit 11 - Stream x clear transfer complete interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn ctcif5(&mut self) -> Ctcif5W<HifcrSpec> {
        Ctcif5W::new(self, 11)
    }
    #[doc = "Bit 16 - Stream x clear FIFO error interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn cfeif6(&mut self) -> Cfeif6W<HifcrSpec> {
        Cfeif6W::new(self, 16)
    }
    #[doc = "Bit 18 - Stream x clear direct mode error interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn cdmeif6(&mut self) -> Cdmeif6W<HifcrSpec> {
        Cdmeif6W::new(self, 18)
    }
    #[doc = "Bit 19 - Stream x clear transfer error interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn cteif6(&mut self) -> Cteif6W<HifcrSpec> {
        Cteif6W::new(self, 19)
    }
    #[doc = "Bit 20 - Stream x clear half transfer interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn chtif6(&mut self) -> Chtif6W<HifcrSpec> {
        Chtif6W::new(self, 20)
    }
    #[doc = "Bit 21 - Stream x clear transfer complete interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn ctcif6(&mut self) -> Ctcif6W<HifcrSpec> {
        Ctcif6W::new(self, 21)
    }
    #[doc = "Bit 22 - Stream x clear FIFO error interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn cfeif7(&mut self) -> Cfeif7W<HifcrSpec> {
        Cfeif7W::new(self, 22)
    }
    #[doc = "Bit 24 - Stream x clear direct mode error interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn cdmeif7(&mut self) -> Cdmeif7W<HifcrSpec> {
        Cdmeif7W::new(self, 24)
    }
    #[doc = "Bit 25 - Stream x clear transfer error interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn cteif7(&mut self) -> Cteif7W<HifcrSpec> {
        Cteif7W::new(self, 25)
    }
    #[doc = "Bit 26 - Stream x clear half transfer interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn chtif7(&mut self) -> Chtif7W<HifcrSpec> {
        Chtif7W::new(self, 26)
    }
    #[doc = "Bit 27 - Stream x clear transfer complete interrupt flag (x = 7..4)"]
    #[inline(always)]
    #[must_use]
    pub fn ctcif7(&mut self) -> Ctcif7W<HifcrSpec> {
        Ctcif7W::new(self, 27)
    }
}
#[doc = "high interrupt flag clear register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hifcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hifcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HifcrSpec;
impl crate::RegisterSpec for HifcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`hifcr::R`](R) reader structure"]
impl crate::Readable for HifcrSpec {}
#[doc = "`write(|w| ..)` method takes [`hifcr::W`](W) writer structure"]
impl crate::Writable for HifcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets HIFCR to value 0"]
impl crate::Resettable for HifcrSpec {
    const RESET_VALUE: u32 = 0;
}
