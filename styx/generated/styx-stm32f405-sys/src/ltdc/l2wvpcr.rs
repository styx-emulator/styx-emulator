// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `L2WVPCR` reader"]
pub type R = crate::R<L2wvpcrSpec>;
#[doc = "Register `L2WVPCR` writer"]
pub type W = crate::W<L2wvpcrSpec>;
#[doc = "Field `WVSTPOS` reader - Window Vertical Start Position"]
pub type WvstposR = crate::FieldReader<u16>;
#[doc = "Field `WVSTPOS` writer - Window Vertical Start Position"]
pub type WvstposW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
#[doc = "Field `WVSPPOS` reader - Window Vertical Stop Position"]
pub type WvspposR = crate::FieldReader<u16>;
#[doc = "Field `WVSPPOS` writer - Window Vertical Stop Position"]
pub type WvspposW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
impl R {
    #[doc = "Bits 0:10 - Window Vertical Start Position"]
    #[inline(always)]
    pub fn wvstpos(&self) -> WvstposR {
        WvstposR::new((self.bits & 0x07ff) as u16)
    }
    #[doc = "Bits 16:26 - Window Vertical Stop Position"]
    #[inline(always)]
    pub fn wvsppos(&self) -> WvspposR {
        WvspposR::new(((self.bits >> 16) & 0x07ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:10 - Window Vertical Start Position"]
    #[inline(always)]
    #[must_use]
    pub fn wvstpos(&mut self) -> WvstposW<L2wvpcrSpec> {
        WvstposW::new(self, 0)
    }
    #[doc = "Bits 16:26 - Window Vertical Stop Position"]
    #[inline(always)]
    #[must_use]
    pub fn wvsppos(&mut self) -> WvspposW<L2wvpcrSpec> {
        WvspposW::new(self, 16)
    }
}
#[doc = "Layerx Window Vertical Position Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l2wvpcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l2wvpcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct L2wvpcrSpec;
impl crate::RegisterSpec for L2wvpcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 268u64;
}
#[doc = "`read()` method returns [`l2wvpcr::R`](R) reader structure"]
impl crate::Readable for L2wvpcrSpec {}
#[doc = "`write(|w| ..)` method takes [`l2wvpcr::W`](W) writer structure"]
impl crate::Writable for L2wvpcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets L2WVPCR to value 0"]
impl crate::Resettable for L2wvpcrSpec {
    const RESET_VALUE: u32 = 0;
}
