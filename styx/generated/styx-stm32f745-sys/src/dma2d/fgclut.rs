// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FGCLUT` reader"]
pub type R = crate::R<FgclutSpec>;
#[doc = "Register `FGCLUT` writer"]
pub type W = crate::W<FgclutSpec>;
#[doc = "Field `BLUE` reader - BLUE"]
pub type BlueR = crate::FieldReader;
#[doc = "Field `BLUE` writer - BLUE"]
pub type BlueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `GREEN` reader - GREEN"]
pub type GreenR = crate::FieldReader;
#[doc = "Field `GREEN` writer - GREEN"]
pub type GreenW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `RED` reader - RED"]
pub type RedR = crate::FieldReader;
#[doc = "Field `RED` writer - RED"]
pub type RedW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `APLHA` reader - APLHA"]
pub type AplhaR = crate::FieldReader;
#[doc = "Field `APLHA` writer - APLHA"]
pub type AplhaW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - BLUE"]
    #[inline(always)]
    pub fn blue(&self) -> BlueR {
        BlueR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - GREEN"]
    #[inline(always)]
    pub fn green(&self) -> GreenR {
        GreenR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - RED"]
    #[inline(always)]
    pub fn red(&self) -> RedR {
        RedR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - APLHA"]
    #[inline(always)]
    pub fn aplha(&self) -> AplhaR {
        AplhaR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - BLUE"]
    #[inline(always)]
    #[must_use]
    pub fn blue(&mut self) -> BlueW<FgclutSpec> {
        BlueW::new(self, 0)
    }
    #[doc = "Bits 8:15 - GREEN"]
    #[inline(always)]
    #[must_use]
    pub fn green(&mut self) -> GreenW<FgclutSpec> {
        GreenW::new(self, 8)
    }
    #[doc = "Bits 16:23 - RED"]
    #[inline(always)]
    #[must_use]
    pub fn red(&mut self) -> RedW<FgclutSpec> {
        RedW::new(self, 16)
    }
    #[doc = "Bits 24:31 - APLHA"]
    #[inline(always)]
    #[must_use]
    pub fn aplha(&mut self) -> AplhaW<FgclutSpec> {
        AplhaW::new(self, 24)
    }
}
#[doc = "FGCLUT\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fgclut::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fgclut::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FgclutSpec;
impl crate::RegisterSpec for FgclutSpec {
    type Ux = u32;
    const OFFSET: u64 = 1024u64;
}
#[doc = "`read()` method returns [`fgclut::R`](R) reader structure"]
impl crate::Readable for FgclutSpec {}
#[doc = "`write(|w| ..)` method takes [`fgclut::W`](W) writer structure"]
impl crate::Writable for FgclutSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FGCLUT to value 0"]
impl crate::Resettable for FgclutSpec {
    const RESET_VALUE: u32 = 0;
}
