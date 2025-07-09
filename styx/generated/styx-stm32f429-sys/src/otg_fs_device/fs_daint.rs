// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FS_DAINT` reader"]
pub type R = crate::R<FsDaintSpec>;
#[doc = "Register `FS_DAINT` writer"]
pub type W = crate::W<FsDaintSpec>;
#[doc = "Field `IEPINT` reader - IN endpoint interrupt bits"]
pub type IepintR = crate::FieldReader<u16>;
#[doc = "Field `IEPINT` writer - IN endpoint interrupt bits"]
pub type IepintW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `OEPINT` reader - OUT endpoint interrupt bits"]
pub type OepintR = crate::FieldReader<u16>;
#[doc = "Field `OEPINT` writer - OUT endpoint interrupt bits"]
pub type OepintW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - IN endpoint interrupt bits"]
    #[inline(always)]
    pub fn iepint(&self) -> IepintR {
        IepintR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - OUT endpoint interrupt bits"]
    #[inline(always)]
    pub fn oepint(&self) -> OepintR {
        OepintR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - IN endpoint interrupt bits"]
    #[inline(always)]
    #[must_use]
    pub fn iepint(&mut self) -> IepintW<FsDaintSpec> {
        IepintW::new(self, 0)
    }
    #[doc = "Bits 16:31 - OUT endpoint interrupt bits"]
    #[inline(always)]
    #[must_use]
    pub fn oepint(&mut self) -> OepintW<FsDaintSpec> {
        OepintW::new(self, 16)
    }
}
#[doc = "OTG_FS device all endpoints interrupt register (OTG_FS_DAINT)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_daint::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FsDaintSpec;
impl crate::RegisterSpec for FsDaintSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`fs_daint::R`](R) reader structure"]
impl crate::Readable for FsDaintSpec {}
#[doc = "`reset()` method sets FS_DAINT to value 0"]
impl crate::Resettable for FsDaintSpec {
    const RESET_VALUE: u32 = 0;
}
