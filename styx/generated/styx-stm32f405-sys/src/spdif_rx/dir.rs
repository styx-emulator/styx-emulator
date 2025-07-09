// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DIR` reader"]
pub type R = crate::R<DirSpec>;
#[doc = "Register `DIR` writer"]
pub type W = crate::W<DirSpec>;
#[doc = "Field `THI` reader - Threshold HIGH"]
pub type ThiR = crate::FieldReader<u16>;
#[doc = "Field `THI` writer - Threshold HIGH"]
pub type ThiW<'a, REG> = crate::FieldWriter<'a, REG, 13, u16>;
#[doc = "Field `TLO` reader - Threshold LOW"]
pub type TloR = crate::FieldReader<u16>;
#[doc = "Field `TLO` writer - Threshold LOW"]
pub type TloW<'a, REG> = crate::FieldWriter<'a, REG, 13, u16>;
impl R {
    #[doc = "Bits 0:12 - Threshold HIGH"]
    #[inline(always)]
    pub fn thi(&self) -> ThiR {
        ThiR::new((self.bits & 0x1fff) as u16)
    }
    #[doc = "Bits 16:28 - Threshold LOW"]
    #[inline(always)]
    pub fn tlo(&self) -> TloR {
        TloR::new(((self.bits >> 16) & 0x1fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:12 - Threshold HIGH"]
    #[inline(always)]
    #[must_use]
    pub fn thi(&mut self) -> ThiW<DirSpec> {
        ThiW::new(self, 0)
    }
    #[doc = "Bits 16:28 - Threshold LOW"]
    #[inline(always)]
    #[must_use]
    pub fn tlo(&mut self) -> TloW<DirSpec> {
        TloW::new(self, 16)
    }
}
#[doc = "Debug Information register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dir::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DirSpec;
impl crate::RegisterSpec for DirSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`dir::R`](R) reader structure"]
impl crate::Readable for DirSpec {}
#[doc = "`reset()` method sets DIR to value 0"]
impl crate::Resettable for DirSpec {
    const RESET_VALUE: u32 = 0;
}
