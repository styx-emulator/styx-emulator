// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SAI_AFRCR` reader"]
pub type R = crate::R<SaiAfrcrSpec>;
#[doc = "Register `SAI_AFRCR` writer"]
pub type W = crate::W<SaiAfrcrSpec>;
#[doc = "Field `FRL` reader - Frame length"]
pub type FrlR = crate::FieldReader;
#[doc = "Field `FRL` writer - Frame length"]
pub type FrlW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `FSALL` reader - Frame synchronization active level length"]
pub type FsallR = crate::FieldReader;
#[doc = "Field `FSALL` writer - Frame synchronization active level length"]
pub type FsallW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `FSDEF` reader - Frame synchronization definition"]
pub type FsdefR = crate::BitReader;
#[doc = "Field `FSDEF` writer - Frame synchronization definition"]
pub type FsdefW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FSPOL` reader - Frame synchronization polarity"]
pub type FspolR = crate::BitReader;
#[doc = "Field `FSPOL` writer - Frame synchronization polarity"]
pub type FspolW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FSOFF` reader - Frame synchronization offset"]
pub type FsoffR = crate::BitReader;
#[doc = "Field `FSOFF` writer - Frame synchronization offset"]
pub type FsoffW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:7 - Frame length"]
    #[inline(always)]
    pub fn frl(&self) -> FrlR {
        FrlR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:14 - Frame synchronization active level length"]
    #[inline(always)]
    pub fn fsall(&self) -> FsallR {
        FsallR::new(((self.bits >> 8) & 0x7f) as u8)
    }
    #[doc = "Bit 16 - Frame synchronization definition"]
    #[inline(always)]
    pub fn fsdef(&self) -> FsdefR {
        FsdefR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Frame synchronization polarity"]
    #[inline(always)]
    pub fn fspol(&self) -> FspolR {
        FspolR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Frame synchronization offset"]
    #[inline(always)]
    pub fn fsoff(&self) -> FsoffR {
        FsoffR::new(((self.bits >> 18) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:7 - Frame length"]
    #[inline(always)]
    #[must_use]
    pub fn frl(&mut self) -> FrlW<SaiAfrcrSpec> {
        FrlW::new(self, 0)
    }
    #[doc = "Bits 8:14 - Frame synchronization active level length"]
    #[inline(always)]
    #[must_use]
    pub fn fsall(&mut self) -> FsallW<SaiAfrcrSpec> {
        FsallW::new(self, 8)
    }
    #[doc = "Bit 16 - Frame synchronization definition"]
    #[inline(always)]
    #[must_use]
    pub fn fsdef(&mut self) -> FsdefW<SaiAfrcrSpec> {
        FsdefW::new(self, 16)
    }
    #[doc = "Bit 17 - Frame synchronization polarity"]
    #[inline(always)]
    #[must_use]
    pub fn fspol(&mut self) -> FspolW<SaiAfrcrSpec> {
        FspolW::new(self, 17)
    }
    #[doc = "Bit 18 - Frame synchronization offset"]
    #[inline(always)]
    #[must_use]
    pub fn fsoff(&mut self) -> FsoffW<SaiAfrcrSpec> {
        FsoffW::new(self, 18)
    }
}
#[doc = "SAI AFrame configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_afrcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_afrcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SaiAfrcrSpec;
impl crate::RegisterSpec for SaiAfrcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`sai_afrcr::R`](R) reader structure"]
impl crate::Readable for SaiAfrcrSpec {}
#[doc = "`write(|w| ..)` method takes [`sai_afrcr::W`](W) writer structure"]
impl crate::Writable for SaiAfrcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SAI_AFRCR to value 0x07"]
impl crate::Resettable for SaiAfrcrSpec {
    const RESET_VALUE: u32 = 0x07;
}
