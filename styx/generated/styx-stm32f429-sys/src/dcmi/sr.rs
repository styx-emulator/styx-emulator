// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SR` reader"]
pub type R = crate::R<SrSpec>;
#[doc = "Register `SR` writer"]
pub type W = crate::W<SrSpec>;
#[doc = "Field `HSYNC` reader - HSYNC"]
pub type HsyncR = crate::BitReader;
#[doc = "Field `HSYNC` writer - HSYNC"]
pub type HsyncW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VSYNC` reader - VSYNC"]
pub type VsyncR = crate::BitReader;
#[doc = "Field `VSYNC` writer - VSYNC"]
pub type VsyncW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FNE` reader - FIFO not empty"]
pub type FneR = crate::BitReader;
#[doc = "Field `FNE` writer - FIFO not empty"]
pub type FneW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - HSYNC"]
    #[inline(always)]
    pub fn hsync(&self) -> HsyncR {
        HsyncR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - VSYNC"]
    #[inline(always)]
    pub fn vsync(&self) -> VsyncR {
        VsyncR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - FIFO not empty"]
    #[inline(always)]
    pub fn fne(&self) -> FneR {
        FneR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - HSYNC"]
    #[inline(always)]
    #[must_use]
    pub fn hsync(&mut self) -> HsyncW<SrSpec> {
        HsyncW::new(self, 0)
    }
    #[doc = "Bit 1 - VSYNC"]
    #[inline(always)]
    #[must_use]
    pub fn vsync(&mut self) -> VsyncW<SrSpec> {
        VsyncW::new(self, 1)
    }
    #[doc = "Bit 2 - FIFO not empty"]
    #[inline(always)]
    #[must_use]
    pub fn fne(&mut self) -> FneW<SrSpec> {
        FneW::new(self, 2)
    }
}
#[doc = "status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrSpec;
impl crate::RegisterSpec for SrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`sr::R`](R) reader structure"]
impl crate::Readable for SrSpec {}
#[doc = "`reset()` method sets SR to value 0"]
impl crate::Resettable for SrSpec {
    const RESET_VALUE: u32 = 0;
}
