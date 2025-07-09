// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `secgrp_l4spim` reader"]
pub type R = crate::R<SecgrpL4spimSpec>;
#[doc = "Register `secgrp_l4spim` writer"]
pub type W = crate::W<SecgrpL4spimSpec>;
#[doc = "Field `spim0` reader - Controls whether secure or non-secure masters can access the SPI Master 0 slave."]
pub type Spim0R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the SPI Master 0 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spim0 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Spim0> for bool {
    #[inline(always)]
    fn from(variant: Spim0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `spim0` writer - Controls whether secure or non-secure masters can access the SPI Master 0 slave."]
pub type Spim0W<'a, REG> = crate::BitWriter<'a, REG, Spim0>;
impl<'a, REG> Spim0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Spim0::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Spim0::Nonsecure)
    }
}
#[doc = "Field `spim1` reader - Controls whether secure or non-secure masters can access the SPI Master 1 slave."]
pub type Spim1R = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the SPI Master 1 slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spim1 {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Spim1> for bool {
    #[inline(always)]
    fn from(variant: Spim1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `spim1` writer - Controls whether secure or non-secure masters can access the SPI Master 1 slave."]
pub type Spim1W<'a, REG> = crate::BitWriter<'a, REG, Spim1>;
impl<'a, REG> Spim1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Spim1::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Spim1::Nonsecure)
    }
}
#[doc = "Field `scanmgr` reader - Controls whether secure or non-secure masters can access the Scan Manager slave."]
pub type ScanmgrR = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the Scan Manager slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scanmgr {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<Scanmgr> for bool {
    #[inline(always)]
    fn from(variant: Scanmgr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `scanmgr` writer - Controls whether secure or non-secure masters can access the Scan Manager slave."]
pub type ScanmgrW<'a, REG> = crate::BitWriter<'a, REG, Scanmgr>;
impl<'a, REG> ScanmgrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(Scanmgr::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(Scanmgr::Nonsecure)
    }
}
impl R {
    #[doc = "Bit 0 - Controls whether secure or non-secure masters can access the SPI Master 0 slave."]
    #[inline(always)]
    pub fn spim0(&self) -> Spim0R {
        Spim0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls whether secure or non-secure masters can access the SPI Master 1 slave."]
    #[inline(always)]
    pub fn spim1(&self) -> Spim1R {
        Spim1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Controls whether secure or non-secure masters can access the Scan Manager slave."]
    #[inline(always)]
    pub fn scanmgr(&self) -> ScanmgrR {
        ScanmgrR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls whether secure or non-secure masters can access the SPI Master 0 slave."]
    #[inline(always)]
    #[must_use]
    pub fn spim0(&mut self) -> Spim0W<SecgrpL4spimSpec> {
        Spim0W::new(self, 0)
    }
    #[doc = "Bit 1 - Controls whether secure or non-secure masters can access the SPI Master 1 slave."]
    #[inline(always)]
    #[must_use]
    pub fn spim1(&mut self) -> Spim1W<SecgrpL4spimSpec> {
        Spim1W::new(self, 1)
    }
    #[doc = "Bit 2 - Controls whether secure or non-secure masters can access the Scan Manager slave."]
    #[inline(always)]
    #[must_use]
    pub fn scanmgr(&mut self) -> ScanmgrW<SecgrpL4spimSpec> {
        ScanmgrW::new(self, 2)
    }
}
#[doc = "Controls security settings for L4 SPIM peripherals.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_l4spim::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SecgrpL4spimSpec;
impl crate::RegisterSpec for SecgrpL4spimSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`write(|w| ..)` method takes [`secgrp_l4spim::W`](W) writer structure"]
impl crate::Writable for SecgrpL4spimSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets secgrp_l4spim to value 0"]
impl crate::Resettable for SecgrpL4spimSpec {
    const RESET_VALUE: u32 = 0;
}
