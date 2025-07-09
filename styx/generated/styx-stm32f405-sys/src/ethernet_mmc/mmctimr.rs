// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MMCTIMR` reader"]
pub type R = crate::R<MmctimrSpec>;
#[doc = "Register `MMCTIMR` writer"]
pub type W = crate::W<MmctimrSpec>;
#[doc = "Field `TGFSCM` reader - TGFSCM"]
pub type TgfscmR = crate::BitReader;
#[doc = "Field `TGFSCM` writer - TGFSCM"]
pub type TgfscmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TGFMSCM` reader - TGFMSCM"]
pub type TgfmscmR = crate::BitReader;
#[doc = "Field `TGFMSCM` writer - TGFMSCM"]
pub type TgfmscmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TGFM` reader - TGFM"]
pub type TgfmR = crate::BitReader;
#[doc = "Field `TGFM` writer - TGFM"]
pub type TgfmW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 14 - TGFSCM"]
    #[inline(always)]
    pub fn tgfscm(&self) -> TgfscmR {
        TgfscmR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - TGFMSCM"]
    #[inline(always)]
    pub fn tgfmscm(&self) -> TgfmscmR {
        TgfmscmR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - TGFM"]
    #[inline(always)]
    pub fn tgfm(&self) -> TgfmR {
        TgfmR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 14 - TGFSCM"]
    #[inline(always)]
    #[must_use]
    pub fn tgfscm(&mut self) -> TgfscmW<MmctimrSpec> {
        TgfscmW::new(self, 14)
    }
    #[doc = "Bit 15 - TGFMSCM"]
    #[inline(always)]
    #[must_use]
    pub fn tgfmscm(&mut self) -> TgfmscmW<MmctimrSpec> {
        TgfmscmW::new(self, 15)
    }
    #[doc = "Bit 16 - TGFM"]
    #[inline(always)]
    #[must_use]
    pub fn tgfm(&mut self) -> TgfmW<MmctimrSpec> {
        TgfmW::new(self, 16)
    }
}
#[doc = "Ethernet MMC transmit interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmctimr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mmctimr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmctimrSpec;
impl crate::RegisterSpec for MmctimrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`mmctimr::R`](R) reader structure"]
impl crate::Readable for MmctimrSpec {}
#[doc = "`write(|w| ..)` method takes [`mmctimr::W`](W) writer structure"]
impl crate::Writable for MmctimrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MMCTIMR to value 0"]
impl crate::Resettable for MmctimrSpec {
    const RESET_VALUE: u32 = 0;
}
