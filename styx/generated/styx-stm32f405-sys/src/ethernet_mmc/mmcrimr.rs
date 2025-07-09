// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MMCRIMR` reader"]
pub type R = crate::R<MmcrimrSpec>;
#[doc = "Register `MMCRIMR` writer"]
pub type W = crate::W<MmcrimrSpec>;
#[doc = "Field `RFCEM` reader - RFCEM"]
pub type RfcemR = crate::BitReader;
#[doc = "Field `RFCEM` writer - RFCEM"]
pub type RfcemW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RFAEM` reader - RFAEM"]
pub type RfaemR = crate::BitReader;
#[doc = "Field `RFAEM` writer - RFAEM"]
pub type RfaemW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RGUFM` reader - RGUFM"]
pub type RgufmR = crate::BitReader;
#[doc = "Field `RGUFM` writer - RGUFM"]
pub type RgufmW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 5 - RFCEM"]
    #[inline(always)]
    pub fn rfcem(&self) -> RfcemR {
        RfcemR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - RFAEM"]
    #[inline(always)]
    pub fn rfaem(&self) -> RfaemR {
        RfaemR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 17 - RGUFM"]
    #[inline(always)]
    pub fn rgufm(&self) -> RgufmR {
        RgufmR::new(((self.bits >> 17) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 5 - RFCEM"]
    #[inline(always)]
    #[must_use]
    pub fn rfcem(&mut self) -> RfcemW<MmcrimrSpec> {
        RfcemW::new(self, 5)
    }
    #[doc = "Bit 6 - RFAEM"]
    #[inline(always)]
    #[must_use]
    pub fn rfaem(&mut self) -> RfaemW<MmcrimrSpec> {
        RfaemW::new(self, 6)
    }
    #[doc = "Bit 17 - RGUFM"]
    #[inline(always)]
    #[must_use]
    pub fn rgufm(&mut self) -> RgufmW<MmcrimrSpec> {
        RgufmW::new(self, 17)
    }
}
#[doc = "Ethernet MMC receive interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmcrimr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mmcrimr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmcrimrSpec;
impl crate::RegisterSpec for MmcrimrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`mmcrimr::R`](R) reader structure"]
impl crate::Readable for MmcrimrSpec {}
#[doc = "`write(|w| ..)` method takes [`mmcrimr::W`](W) writer structure"]
impl crate::Writable for MmcrimrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MMCRIMR to value 0"]
impl crate::Resettable for MmcrimrSpec {
    const RESET_VALUE: u32 = 0;
}
