// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DBGMCU_IDCODE` reader"]
pub type R = crate::R<DbgmcuIdcodeSpec>;
#[doc = "Register `DBGMCU_IDCODE` writer"]
pub type W = crate::W<DbgmcuIdcodeSpec>;
#[doc = "Field `DEV_ID` reader - DEV_ID"]
pub type DevIdR = crate::FieldReader<u16>;
#[doc = "Field `DEV_ID` writer - DEV_ID"]
pub type DevIdW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
#[doc = "Field `REV_ID` reader - REV_ID"]
pub type RevIdR = crate::FieldReader<u16>;
#[doc = "Field `REV_ID` writer - REV_ID"]
pub type RevIdW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:11 - DEV_ID"]
    #[inline(always)]
    pub fn dev_id(&self) -> DevIdR {
        DevIdR::new((self.bits & 0x0fff) as u16)
    }
    #[doc = "Bits 16:31 - REV_ID"]
    #[inline(always)]
    pub fn rev_id(&self) -> RevIdR {
        RevIdR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - DEV_ID"]
    #[inline(always)]
    #[must_use]
    pub fn dev_id(&mut self) -> DevIdW<DbgmcuIdcodeSpec> {
        DevIdW::new(self, 0)
    }
    #[doc = "Bits 16:31 - REV_ID"]
    #[inline(always)]
    #[must_use]
    pub fn rev_id(&mut self) -> RevIdW<DbgmcuIdcodeSpec> {
        RevIdW::new(self, 16)
    }
}
#[doc = "IDCODE\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dbgmcu_idcode::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DbgmcuIdcodeSpec;
impl crate::RegisterSpec for DbgmcuIdcodeSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`dbgmcu_idcode::R`](R) reader structure"]
impl crate::Readable for DbgmcuIdcodeSpec {}
#[doc = "`reset()` method sets DBGMCU_IDCODE to value 0x1000_6411"]
impl crate::Resettable for DbgmcuIdcodeSpec {
    const RESET_VALUE: u32 = 0x1000_6411;
}
