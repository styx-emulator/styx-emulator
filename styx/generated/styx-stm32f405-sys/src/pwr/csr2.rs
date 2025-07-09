// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR2` reader"]
pub type R = crate::R<Csr2Spec>;
#[doc = "Register `CSR2` writer"]
pub type W = crate::W<Csr2Spec>;
#[doc = "Field `WUPF1` reader - Wakeup Pin flag for PA0"]
pub type Wupf1R = crate::BitReader;
#[doc = "Field `WUPF1` writer - Wakeup Pin flag for PA0"]
pub type Wupf1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUPF2` reader - Wakeup Pin flag for PA2"]
pub type Wupf2R = crate::BitReader;
#[doc = "Field `WUPF2` writer - Wakeup Pin flag for PA2"]
pub type Wupf2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUPF3` reader - Wakeup Pin flag for PC1"]
pub type Wupf3R = crate::BitReader;
#[doc = "Field `WUPF3` writer - Wakeup Pin flag for PC1"]
pub type Wupf3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUPF4` reader - Wakeup Pin flag for PC13"]
pub type Wupf4R = crate::BitReader;
#[doc = "Field `WUPF4` writer - Wakeup Pin flag for PC13"]
pub type Wupf4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUPF5` reader - Wakeup Pin flag for PI8"]
pub type Wupf5R = crate::BitReader;
#[doc = "Field `WUPF5` writer - Wakeup Pin flag for PI8"]
pub type Wupf5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUPF6` reader - Wakeup Pin flag for PI11"]
pub type Wupf6R = crate::BitReader;
#[doc = "Field `WUPF6` writer - Wakeup Pin flag for PI11"]
pub type Wupf6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EWUP1` reader - Enable Wakeup pin for PA0"]
pub type Ewup1R = crate::BitReader;
#[doc = "Field `EWUP1` writer - Enable Wakeup pin for PA0"]
pub type Ewup1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EWUP2` reader - Enable Wakeup pin for PA2"]
pub type Ewup2R = crate::BitReader;
#[doc = "Field `EWUP2` writer - Enable Wakeup pin for PA2"]
pub type Ewup2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EWUP3` reader - Enable Wakeup pin for PC1"]
pub type Ewup3R = crate::BitReader;
#[doc = "Field `EWUP3` writer - Enable Wakeup pin for PC1"]
pub type Ewup3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EWUP4` reader - Enable Wakeup pin for PC13"]
pub type Ewup4R = crate::BitReader;
#[doc = "Field `EWUP4` writer - Enable Wakeup pin for PC13"]
pub type Ewup4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EWUP5` reader - Enable Wakeup pin for PI8"]
pub type Ewup5R = crate::BitReader;
#[doc = "Field `EWUP5` writer - Enable Wakeup pin for PI8"]
pub type Ewup5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EWUP6` reader - Enable Wakeup pin for PI11"]
pub type Ewup6R = crate::BitReader;
#[doc = "Field `EWUP6` writer - Enable Wakeup pin for PI11"]
pub type Ewup6W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Wakeup Pin flag for PA0"]
    #[inline(always)]
    pub fn wupf1(&self) -> Wupf1R {
        Wupf1R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Wakeup Pin flag for PA2"]
    #[inline(always)]
    pub fn wupf2(&self) -> Wupf2R {
        Wupf2R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Wakeup Pin flag for PC1"]
    #[inline(always)]
    pub fn wupf3(&self) -> Wupf3R {
        Wupf3R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Wakeup Pin flag for PC13"]
    #[inline(always)]
    pub fn wupf4(&self) -> Wupf4R {
        Wupf4R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Wakeup Pin flag for PI8"]
    #[inline(always)]
    pub fn wupf5(&self) -> Wupf5R {
        Wupf5R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Wakeup Pin flag for PI11"]
    #[inline(always)]
    pub fn wupf6(&self) -> Wupf6R {
        Wupf6R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 8 - Enable Wakeup pin for PA0"]
    #[inline(always)]
    pub fn ewup1(&self) -> Ewup1R {
        Ewup1R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Enable Wakeup pin for PA2"]
    #[inline(always)]
    pub fn ewup2(&self) -> Ewup2R {
        Ewup2R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Enable Wakeup pin for PC1"]
    #[inline(always)]
    pub fn ewup3(&self) -> Ewup3R {
        Ewup3R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Enable Wakeup pin for PC13"]
    #[inline(always)]
    pub fn ewup4(&self) -> Ewup4R {
        Ewup4R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Enable Wakeup pin for PI8"]
    #[inline(always)]
    pub fn ewup5(&self) -> Ewup5R {
        Ewup5R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Enable Wakeup pin for PI11"]
    #[inline(always)]
    pub fn ewup6(&self) -> Ewup6R {
        Ewup6R::new(((self.bits >> 13) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Wakeup Pin flag for PA0"]
    #[inline(always)]
    #[must_use]
    pub fn wupf1(&mut self) -> Wupf1W<Csr2Spec> {
        Wupf1W::new(self, 0)
    }
    #[doc = "Bit 1 - Wakeup Pin flag for PA2"]
    #[inline(always)]
    #[must_use]
    pub fn wupf2(&mut self) -> Wupf2W<Csr2Spec> {
        Wupf2W::new(self, 1)
    }
    #[doc = "Bit 2 - Wakeup Pin flag for PC1"]
    #[inline(always)]
    #[must_use]
    pub fn wupf3(&mut self) -> Wupf3W<Csr2Spec> {
        Wupf3W::new(self, 2)
    }
    #[doc = "Bit 3 - Wakeup Pin flag for PC13"]
    #[inline(always)]
    #[must_use]
    pub fn wupf4(&mut self) -> Wupf4W<Csr2Spec> {
        Wupf4W::new(self, 3)
    }
    #[doc = "Bit 4 - Wakeup Pin flag for PI8"]
    #[inline(always)]
    #[must_use]
    pub fn wupf5(&mut self) -> Wupf5W<Csr2Spec> {
        Wupf5W::new(self, 4)
    }
    #[doc = "Bit 5 - Wakeup Pin flag for PI11"]
    #[inline(always)]
    #[must_use]
    pub fn wupf6(&mut self) -> Wupf6W<Csr2Spec> {
        Wupf6W::new(self, 5)
    }
    #[doc = "Bit 8 - Enable Wakeup pin for PA0"]
    #[inline(always)]
    #[must_use]
    pub fn ewup1(&mut self) -> Ewup1W<Csr2Spec> {
        Ewup1W::new(self, 8)
    }
    #[doc = "Bit 9 - Enable Wakeup pin for PA2"]
    #[inline(always)]
    #[must_use]
    pub fn ewup2(&mut self) -> Ewup2W<Csr2Spec> {
        Ewup2W::new(self, 9)
    }
    #[doc = "Bit 10 - Enable Wakeup pin for PC1"]
    #[inline(always)]
    #[must_use]
    pub fn ewup3(&mut self) -> Ewup3W<Csr2Spec> {
        Ewup3W::new(self, 10)
    }
    #[doc = "Bit 11 - Enable Wakeup pin for PC13"]
    #[inline(always)]
    #[must_use]
    pub fn ewup4(&mut self) -> Ewup4W<Csr2Spec> {
        Ewup4W::new(self, 11)
    }
    #[doc = "Bit 12 - Enable Wakeup pin for PI8"]
    #[inline(always)]
    #[must_use]
    pub fn ewup5(&mut self) -> Ewup5W<Csr2Spec> {
        Ewup5W::new(self, 12)
    }
    #[doc = "Bit 13 - Enable Wakeup pin for PI11"]
    #[inline(always)]
    #[must_use]
    pub fn ewup6(&mut self) -> Ewup6W<Csr2Spec> {
        Ewup6W::new(self, 13)
    }
}
#[doc = "power control/status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr2Spec;
impl crate::RegisterSpec for Csr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`csr2::R`](R) reader structure"]
impl crate::Readable for Csr2Spec {}
#[doc = "`write(|w| ..)` method takes [`csr2::W`](W) writer structure"]
impl crate::Writable for Csr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR2 to value 0"]
impl crate::Resettable for Csr2Spec {
    const RESET_VALUE: u32 = 0;
}
