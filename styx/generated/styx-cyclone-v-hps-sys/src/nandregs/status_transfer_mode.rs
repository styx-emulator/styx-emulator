// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `status_transfer_mode` reader"]
pub type R = crate::R<StatusTransferModeSpec>;
#[doc = "Register `status_transfer_mode` writer"]
pub type W = crate::W<StatusTransferModeSpec>;
#[doc = "Field `value0` reader - list\\]\\[*\\]00 - Bank 0 is in Main mode \\[*\\]01 - Bank 0 is in Spare mode \\[*\\]10 - Bank 0 is in Main+Spare mode\\[/list\\]"]
pub type Value0R = crate::FieldReader;
#[doc = "Field `value0` writer - list\\]\\[*\\]00 - Bank 0 is in Main mode \\[*\\]01 - Bank 0 is in Spare mode \\[*\\]10 - Bank 0 is in Main+Spare mode\\[/list\\]"]
pub type Value0W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `value1` reader - list\\]\\[*\\]00 - Bank 1 is in Main mode \\[*\\]01 - Bank 1 is in Spare mode \\[*\\]10 - Bank 1 is in Main+Spare mode\\[/list\\]"]
pub type Value1R = crate::FieldReader;
#[doc = "Field `value1` writer - list\\]\\[*\\]00 - Bank 1 is in Main mode \\[*\\]01 - Bank 1 is in Spare mode \\[*\\]10 - Bank 1 is in Main+Spare mode\\[/list\\]"]
pub type Value1W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `value2` reader - list\\]\\[*\\]00 - Bank 2 is in Main mode \\[*\\]01 - Bank 2 is in Spare mode \\[*\\]10 - Bank 2 is in Main+Spare mode\\[/list\\]"]
pub type Value2R = crate::FieldReader;
#[doc = "Field `value2` writer - list\\]\\[*\\]00 - Bank 2 is in Main mode \\[*\\]01 - Bank 2 is in Spare mode \\[*\\]10 - Bank 2 is in Main+Spare mode\\[/list\\]"]
pub type Value2W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `value3` reader - list\\]\\[*\\]00 - Bank 3 is in Main mode \\[*\\]01 - Bank 3 is in Spare mode \\[*\\]10 - Bank 3 is in Main+Spare mode\\[/list\\]"]
pub type Value3R = crate::FieldReader;
#[doc = "Field `value3` writer - list\\]\\[*\\]00 - Bank 3 is in Main mode \\[*\\]01 - Bank 3 is in Spare mode \\[*\\]10 - Bank 3 is in Main+Spare mode\\[/list\\]"]
pub type Value3W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - list\\]\\[*\\]00 - Bank 0 is in Main mode \\[*\\]01 - Bank 0 is in Spare mode \\[*\\]10 - Bank 0 is in Main+Spare mode\\[/list\\]"]
    #[inline(always)]
    pub fn value0(&self) -> Value0R {
        Value0R::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - list\\]\\[*\\]00 - Bank 1 is in Main mode \\[*\\]01 - Bank 1 is in Spare mode \\[*\\]10 - Bank 1 is in Main+Spare mode\\[/list\\]"]
    #[inline(always)]
    pub fn value1(&self) -> Value1R {
        Value1R::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bits 4:5 - list\\]\\[*\\]00 - Bank 2 is in Main mode \\[*\\]01 - Bank 2 is in Spare mode \\[*\\]10 - Bank 2 is in Main+Spare mode\\[/list\\]"]
    #[inline(always)]
    pub fn value2(&self) -> Value2R {
        Value2R::new(((self.bits >> 4) & 3) as u8)
    }
    #[doc = "Bits 6:7 - list\\]\\[*\\]00 - Bank 3 is in Main mode \\[*\\]01 - Bank 3 is in Spare mode \\[*\\]10 - Bank 3 is in Main+Spare mode\\[/list\\]"]
    #[inline(always)]
    pub fn value3(&self) -> Value3R {
        Value3R::new(((self.bits >> 6) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - list\\]\\[*\\]00 - Bank 0 is in Main mode \\[*\\]01 - Bank 0 is in Spare mode \\[*\\]10 - Bank 0 is in Main+Spare mode\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn value0(&mut self) -> Value0W<StatusTransferModeSpec> {
        Value0W::new(self, 0)
    }
    #[doc = "Bits 2:3 - list\\]\\[*\\]00 - Bank 1 is in Main mode \\[*\\]01 - Bank 1 is in Spare mode \\[*\\]10 - Bank 1 is in Main+Spare mode\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn value1(&mut self) -> Value1W<StatusTransferModeSpec> {
        Value1W::new(self, 2)
    }
    #[doc = "Bits 4:5 - list\\]\\[*\\]00 - Bank 2 is in Main mode \\[*\\]01 - Bank 2 is in Spare mode \\[*\\]10 - Bank 2 is in Main+Spare mode\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn value2(&mut self) -> Value2W<StatusTransferModeSpec> {
        Value2W::new(self, 4)
    }
    #[doc = "Bits 6:7 - list\\]\\[*\\]00 - Bank 3 is in Main mode \\[*\\]01 - Bank 3 is in Spare mode \\[*\\]10 - Bank 3 is in Main+Spare mode\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn value3(&mut self) -> Value3W<StatusTransferModeSpec> {
        Value3W::new(self, 6)
    }
}
#[doc = "Current data transfer mode is Main only, Spare only or Main+Spare. This information is per bank.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_transfer_mode::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StatusTransferModeSpec;
impl crate::RegisterSpec for StatusTransferModeSpec {
    type Ux = u32;
    const OFFSET: u64 = 1024u64;
}
#[doc = "`read()` method returns [`status_transfer_mode::R`](R) reader structure"]
impl crate::Readable for StatusTransferModeSpec {}
#[doc = "`reset()` method sets status_transfer_mode to value 0"]
impl crate::Resettable for StatusTransferModeSpec {
    const RESET_VALUE: u32 = 0;
}
