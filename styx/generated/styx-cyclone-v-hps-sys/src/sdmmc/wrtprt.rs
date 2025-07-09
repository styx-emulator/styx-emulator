// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `wrtprt` reader"]
pub type R = crate::R<WrtprtSpec>;
#[doc = "Register `wrtprt` writer"]
pub type W = crate::W<WrtprtSpec>;
#[doc = "Value on sdmmc_wp_i input port.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteProtect {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<WriteProtect> for bool {
    #[inline(always)]
    fn from(variant: WriteProtect) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `write_protect` reader - Value on sdmmc_wp_i input port."]
pub type WriteProtectR = crate::BitReader<WriteProtect>;
impl WriteProtectR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> WriteProtect {
        match self.bits {
            true => WriteProtect::Enabled,
            false => WriteProtect::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == WriteProtect::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == WriteProtect::Disabled
    }
}
#[doc = "Field `write_protect` writer - Value on sdmmc_wp_i input port."]
pub type WriteProtectW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Value on sdmmc_wp_i input port."]
    #[inline(always)]
    pub fn write_protect(&self) -> WriteProtectR {
        WriteProtectR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Value on sdmmc_wp_i input port."]
    #[inline(always)]
    #[must_use]
    pub fn write_protect(&mut self) -> WriteProtectW<WrtprtSpec> {
        WriteProtectW::new(self, 0)
    }
}
#[doc = "See Field Description.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wrtprt::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WrtprtSpec;
impl crate::RegisterSpec for WrtprtSpec {
    type Ux = u32;
    const OFFSET: u64 = 84u64;
}
#[doc = "`read()` method returns [`wrtprt::R`](R) reader structure"]
impl crate::Readable for WrtprtSpec {}
#[doc = "`reset()` method sets wrtprt to value 0x01"]
impl crate::Resettable for WrtprtSpec {
    const RESET_VALUE: u32 = 0x01;
}
