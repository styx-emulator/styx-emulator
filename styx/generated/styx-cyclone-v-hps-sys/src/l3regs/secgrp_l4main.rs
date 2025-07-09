// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `secgrp_l4main` reader"]
pub type R = crate::R<SecgrpL4mainSpec>;
#[doc = "Register `secgrp_l4main` writer"]
pub type W = crate::W<SecgrpL4mainSpec>;
#[doc = "Field `spis0` reader - Controls whether secure or non-secure masters can access the SPI Slave 0 slave."]
pub type Spis0R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the SPI Slave 0 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spis0 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Spis0> for bool {
    #[inline(always)]
    fn from(variant: Spis0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `spis0` writer - Controls whether secure or non-secure masters can access the SPI Slave 0 slave."]
pub type Spis0W<'a, REG> = crate::BitWriter<'a, REG, Spis0>;
impl<'a, REG> Spis0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Spis0::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Spis0::Nonsecure)
    }
}
#[doc = "Field `spis1` reader - Controls whether secure or non-secure masters can access the SPI Slave 1 slave."]
pub type Spis1R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the SPI Slave 1 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spis1 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Spis1> for bool {
    #[inline(always)]
    fn from(variant: Spis1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `spis1` writer - Controls whether secure or non-secure masters can access the SPI Slave 1 slave."]
pub type Spis1W<'a, REG> = crate::BitWriter<'a, REG, Spis1>;
impl<'a, REG> Spis1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Spis1::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Spis1::Nonsecure)
    }
}
#[doc = "Field `dmasecure` reader - Controls whether secure or non-secure masters can access the DMA Secure slave."]
pub type DmasecureR = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the DMA Secure slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dmasecure {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Dmasecure> for bool {
    #[inline(always)]
    fn from(variant: Dmasecure) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dmasecure` writer - Controls whether secure or non-secure masters can access the DMA Secure slave."]
pub type DmasecureW<'a, REG> = crate::BitWriter<'a, REG, Dmasecure>;
impl<'a, REG> DmasecureW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Dmasecure::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Dmasecure::Nonsecure)
    }
}
#[doc = "Field `dmanonsecure` reader - Controls whether secure or non-secure masters can access the DMA Non-secure slave."]
pub type DmanonsecureR = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the DMA Non-secure slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dmanonsecure {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Dmanonsecure> for bool {
    #[inline(always)]
    fn from(variant: Dmanonsecure) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dmanonsecure` writer - Controls whether secure or non-secure masters can access the DMA Non-secure slave."]
pub type DmanonsecureW<'a, REG> = crate::BitWriter<'a, REG, Dmanonsecure>;
impl<'a, REG> DmanonsecureW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Dmanonsecure::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Dmanonsecure::Nonsecure)
    }
}
impl R {
    #[doc = "Bit 0 - Controls whether secure or non-secure masters can access the SPI Slave 0 slave."]
    #[inline(always)]
    pub fn spis0(&self) -> Spis0R {
        Spis0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls whether secure or non-secure masters can access the SPI Slave 1 slave."]
    #[inline(always)]
    pub fn spis1(&self) -> Spis1R {
        Spis1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Controls whether secure or non-secure masters can access the DMA Secure slave."]
    #[inline(always)]
    pub fn dmasecure(&self) -> DmasecureR {
        DmasecureR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Controls whether secure or non-secure masters can access the DMA Non-secure slave."]
    #[inline(always)]
    pub fn dmanonsecure(&self) -> DmanonsecureR {
        DmanonsecureR::new(((self.bits >> 3) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls whether secure or non-secure masters can access the SPI Slave 0 slave."]
    #[inline(always)]
    #[must_use]
    pub fn spis0(&mut self) -> Spis0W<SecgrpL4mainSpec> {
        Spis0W::new(self, 0)
    }
    #[doc = "Bit 1 - Controls whether secure or non-secure masters can access the SPI Slave 1 slave."]
    #[inline(always)]
    #[must_use]
    pub fn spis1(&mut self) -> Spis1W<SecgrpL4mainSpec> {
        Spis1W::new(self, 1)
    }
    #[doc = "Bit 2 - Controls whether secure or non-secure masters can access the DMA Secure slave."]
    #[inline(always)]
    #[must_use]
    pub fn dmasecure(&mut self) -> DmasecureW<SecgrpL4mainSpec> {
        DmasecureW::new(self, 2)
    }
    #[doc = "Bit 3 - Controls whether secure or non-secure masters can access the DMA Non-secure slave."]
    #[inline(always)]
    #[must_use]
    pub fn dmanonsecure(&mut self) -> DmanonsecureW<SecgrpL4mainSpec> {
        DmanonsecureW::new(self, 3)
    }
}
#[doc = "Controls security settings for L4 Main peripherals.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_l4main::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SecgrpL4mainSpec;
impl crate::RegisterSpec for SecgrpL4mainSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`write(|w| ..)` method takes [`secgrp_l4main::W`](W) writer structure"]
impl crate::Writable for SecgrpL4mainSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets secgrp_l4main to value 0"]
impl crate::Resettable for SecgrpL4mainSpec {
    const RESET_VALUE: u32 = 0;
}
