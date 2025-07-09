// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CACR` reader"]
pub type R = crate::R<CacrSpec>;
#[doc = "Register `CACR` writer"]
pub type W = crate::W<CacrSpec>;
#[doc = "Field `SIWT` reader - SIWT"]
pub type SiwtR = crate::BitReader;
#[doc = "Field `SIWT` writer - SIWT"]
pub type SiwtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ECCEN` reader - ECCEN"]
pub type EccenR = crate::BitReader;
#[doc = "Field `ECCEN` writer - ECCEN"]
pub type EccenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FORCEWT` reader - FORCEWT"]
pub type ForcewtR = crate::BitReader;
#[doc = "Field `FORCEWT` writer - FORCEWT"]
pub type ForcewtW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - SIWT"]
    #[inline(always)]
    pub fn siwt(&self) -> SiwtR {
        SiwtR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - ECCEN"]
    #[inline(always)]
    pub fn eccen(&self) -> EccenR {
        EccenR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - FORCEWT"]
    #[inline(always)]
    pub fn forcewt(&self) -> ForcewtR {
        ForcewtR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - SIWT"]
    #[inline(always)]
    #[must_use]
    pub fn siwt(&mut self) -> SiwtW<CacrSpec> {
        SiwtW::new(self, 0)
    }
    #[doc = "Bit 1 - ECCEN"]
    #[inline(always)]
    #[must_use]
    pub fn eccen(&mut self) -> EccenW<CacrSpec> {
        EccenW::new(self, 1)
    }
    #[doc = "Bit 2 - FORCEWT"]
    #[inline(always)]
    #[must_use]
    pub fn forcewt(&mut self) -> ForcewtW<CacrSpec> {
        ForcewtW::new(self, 2)
    }
}
#[doc = "Auxiliary Cache Control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cacr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cacr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CacrSpec;
impl crate::RegisterSpec for CacrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`cacr::R`](R) reader structure"]
impl crate::Readable for CacrSpec {}
#[doc = "`write(|w| ..)` method takes [`cacr::W`](W) writer structure"]
impl crate::Writable for CacrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CACR to value 0"]
impl crate::Resettable for CacrSpec {
    const RESET_VALUE: u32 = 0;
}
