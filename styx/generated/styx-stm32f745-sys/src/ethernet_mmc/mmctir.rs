// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MMCTIR` reader"]
pub type R = crate::R<MmctirSpec>;
#[doc = "Register `MMCTIR` writer"]
pub type W = crate::W<MmctirSpec>;
#[doc = "Field `TGFSCS` reader - TGFSCS"]
pub type TgfscsR = crate::BitReader;
#[doc = "Field `TGFSCS` writer - TGFSCS"]
pub type TgfscsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TGFMSCS` reader - TGFMSCS"]
pub type TgfmscsR = crate::BitReader;
#[doc = "Field `TGFMSCS` writer - TGFMSCS"]
pub type TgfmscsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TGFS` reader - TGFS"]
pub type TgfsR = crate::BitReader;
#[doc = "Field `TGFS` writer - TGFS"]
pub type TgfsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 14 - TGFSCS"]
    #[inline(always)]
    pub fn tgfscs(&self) -> TgfscsR {
        TgfscsR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - TGFMSCS"]
    #[inline(always)]
    pub fn tgfmscs(&self) -> TgfmscsR {
        TgfmscsR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 21 - TGFS"]
    #[inline(always)]
    pub fn tgfs(&self) -> TgfsR {
        TgfsR::new(((self.bits >> 21) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 14 - TGFSCS"]
    #[inline(always)]
    #[must_use]
    pub fn tgfscs(&mut self) -> TgfscsW<MmctirSpec> {
        TgfscsW::new(self, 14)
    }
    #[doc = "Bit 15 - TGFMSCS"]
    #[inline(always)]
    #[must_use]
    pub fn tgfmscs(&mut self) -> TgfmscsW<MmctirSpec> {
        TgfmscsW::new(self, 15)
    }
    #[doc = "Bit 21 - TGFS"]
    #[inline(always)]
    #[must_use]
    pub fn tgfs(&mut self) -> TgfsW<MmctirSpec> {
        TgfsW::new(self, 21)
    }
}
#[doc = "Ethernet MMC transmit interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmctir::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmctirSpec;
impl crate::RegisterSpec for MmctirSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`mmctir::R`](R) reader structure"]
impl crate::Readable for MmctirSpec {}
#[doc = "`reset()` method sets MMCTIR to value 0"]
impl crate::Resettable for MmctirSpec {
    const RESET_VALUE: u32 = 0;
}
