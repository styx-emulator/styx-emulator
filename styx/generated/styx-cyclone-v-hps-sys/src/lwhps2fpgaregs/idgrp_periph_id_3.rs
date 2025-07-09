// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `idgrp_periph_id_3` reader"]
pub type R = crate::R<IdgrpPeriphId3Spec>;
#[doc = "Register `idgrp_periph_id_3` writer"]
pub type W = crate::W<IdgrpPeriphId3Spec>;
#[doc = "Field `cust_mod_num` reader - Customer Model Number"]
pub type CustModNumR = crate::FieldReader;
#[doc = "Field `cust_mod_num` writer - Customer Model Number"]
pub type CustModNumW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `rev_and` reader - Revision"]
pub type RevAndR = crate::FieldReader;
#[doc = "Field `rev_and` writer - Revision"]
pub type RevAndW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - Customer Model Number"]
    #[inline(always)]
    pub fn cust_mod_num(&self) -> CustModNumR {
        CustModNumR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:7 - Revision"]
    #[inline(always)]
    pub fn rev_and(&self) -> RevAndR {
        RevAndR::new(((self.bits >> 4) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Customer Model Number"]
    #[inline(always)]
    #[must_use]
    pub fn cust_mod_num(&mut self) -> CustModNumW<IdgrpPeriphId3Spec> {
        CustModNumW::new(self, 0)
    }
    #[doc = "Bits 4:7 - Revision"]
    #[inline(always)]
    #[must_use]
    pub fn rev_and(&mut self) -> RevAndW<IdgrpPeriphId3Spec> {
        RevAndW::new(self, 4)
    }
}
#[doc = "Peripheral ID3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_3::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdgrpPeriphId3Spec;
impl crate::RegisterSpec for IdgrpPeriphId3Spec {
    type Ux = u32;
    const OFFSET: u64 = 8172u64;
}
#[doc = "`read()` method returns [`idgrp_periph_id_3::R`](R) reader structure"]
impl crate::Readable for IdgrpPeriphId3Spec {}
#[doc = "`reset()` method sets idgrp_periph_id_3 to value 0"]
impl crate::Resettable for IdgrpPeriphId3Spec {
    const RESET_VALUE: u32 = 0;
}
