// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CTR` reader"]
pub type R = crate::R<CtrSpec>;
#[doc = "Register `CTR` writer"]
pub type W = crate::W<CtrSpec>;
#[doc = "Field `_IminLine` reader - IminLine"]
pub type _IminLineR = crate::FieldReader;
#[doc = "Field `_IminLine` writer - IminLine"]
pub type _IminLineW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `DMinLine` reader - DMinLine"]
pub type DminLineR = crate::FieldReader;
#[doc = "Field `DMinLine` writer - DMinLine"]
pub type DminLineW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `ERG` reader - ERG"]
pub type ErgR = crate::FieldReader;
#[doc = "Field `ERG` writer - ERG"]
pub type ErgW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `CWG` reader - CWG"]
pub type CwgR = crate::FieldReader;
#[doc = "Field `CWG` writer - CWG"]
pub type CwgW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `Format` reader - Format"]
pub type FormatR = crate::FieldReader;
#[doc = "Field `Format` writer - Format"]
pub type FormatW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 0:3 - IminLine"]
    #[inline(always)]
    pub fn _imin_line(&self) -> _IminLineR {
        _IminLineR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 16:19 - DMinLine"]
    #[inline(always)]
    pub fn dmin_line(&self) -> DminLineR {
        DminLineR::new(((self.bits >> 16) & 0x0f) as u8)
    }
    #[doc = "Bits 20:23 - ERG"]
    #[inline(always)]
    pub fn erg(&self) -> ErgR {
        ErgR::new(((self.bits >> 20) & 0x0f) as u8)
    }
    #[doc = "Bits 24:27 - CWG"]
    #[inline(always)]
    pub fn cwg(&self) -> CwgR {
        CwgR::new(((self.bits >> 24) & 0x0f) as u8)
    }
    #[doc = "Bits 29:31 - Format"]
    #[inline(always)]
    pub fn format(&self) -> FormatR {
        FormatR::new(((self.bits >> 29) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - IminLine"]
    #[inline(always)]
    #[must_use]
    pub fn _imin_line(&mut self) -> _IminLineW<CtrSpec> {
        _IminLineW::new(self, 0)
    }
    #[doc = "Bits 16:19 - DMinLine"]
    #[inline(always)]
    #[must_use]
    pub fn dmin_line(&mut self) -> DminLineW<CtrSpec> {
        DminLineW::new(self, 16)
    }
    #[doc = "Bits 20:23 - ERG"]
    #[inline(always)]
    #[must_use]
    pub fn erg(&mut self) -> ErgW<CtrSpec> {
        ErgW::new(self, 20)
    }
    #[doc = "Bits 24:27 - CWG"]
    #[inline(always)]
    #[must_use]
    pub fn cwg(&mut self) -> CwgW<CtrSpec> {
        CwgW::new(self, 24)
    }
    #[doc = "Bits 29:31 - Format"]
    #[inline(always)]
    #[must_use]
    pub fn format(&mut self) -> FormatW<CtrSpec> {
        FormatW::new(self, 29)
    }
}
#[doc = "Cache Type register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrSpec;
impl crate::RegisterSpec for CtrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`ctr::R`](R) reader structure"]
impl crate::Readable for CtrSpec {}
#[doc = "`reset()` method sets CTR to value 0x8303_c003"]
impl crate::Resettable for CtrSpec {
    const RESET_VALUE: u32 = 0x8303_c003;
}
