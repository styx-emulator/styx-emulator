// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MMCRIR` reader"]
pub type R = crate::R<MmcrirSpec>;
#[doc = "Register `MMCRIR` writer"]
pub type W = crate::W<MmcrirSpec>;
#[doc = "Field `RFCES` reader - RFCES"]
pub type RfcesR = crate::BitReader;
#[doc = "Field `RFCES` writer - RFCES"]
pub type RfcesW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RFAES` reader - RFAES"]
pub type RfaesR = crate::BitReader;
#[doc = "Field `RFAES` writer - RFAES"]
pub type RfaesW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RGUFS` reader - RGUFS"]
pub type RgufsR = crate::BitReader;
#[doc = "Field `RGUFS` writer - RGUFS"]
pub type RgufsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 5 - RFCES"]
    #[inline(always)]
    pub fn rfces(&self) -> RfcesR {
        RfcesR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - RFAES"]
    #[inline(always)]
    pub fn rfaes(&self) -> RfaesR {
        RfaesR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 17 - RGUFS"]
    #[inline(always)]
    pub fn rgufs(&self) -> RgufsR {
        RgufsR::new(((self.bits >> 17) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 5 - RFCES"]
    #[inline(always)]
    #[must_use]
    pub fn rfces(&mut self) -> RfcesW<MmcrirSpec> {
        RfcesW::new(self, 5)
    }
    #[doc = "Bit 6 - RFAES"]
    #[inline(always)]
    #[must_use]
    pub fn rfaes(&mut self) -> RfaesW<MmcrirSpec> {
        RfaesW::new(self, 6)
    }
    #[doc = "Bit 17 - RGUFS"]
    #[inline(always)]
    #[must_use]
    pub fn rgufs(&mut self) -> RgufsW<MmcrirSpec> {
        RgufsW::new(self, 17)
    }
}
#[doc = "Ethernet MMC receive interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmcrir::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mmcrir::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmcrirSpec;
impl crate::RegisterSpec for MmcrirSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`mmcrir::R`](R) reader structure"]
impl crate::Readable for MmcrirSpec {}
#[doc = "`write(|w| ..)` method takes [`mmcrir::W`](W) writer structure"]
impl crate::Writable for MmcrirSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MMCRIR to value 0"]
impl crate::Resettable for MmcrirSpec {
    const RESET_VALUE: u32 = 0;
}
