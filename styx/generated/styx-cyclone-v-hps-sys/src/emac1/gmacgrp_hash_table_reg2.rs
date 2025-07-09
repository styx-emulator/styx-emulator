// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Hash_Table_Reg2` reader"]
pub type R = crate::R<GmacgrpHashTableReg2Spec>;
#[doc = "Register `gmacgrp_Hash_Table_Reg2` writer"]
pub type W = crate::W<GmacgrpHashTableReg2Spec>;
#[doc = "Field `ht95t64` reader - This field contains the third 32 Bits (95:64) of the Hash table."]
pub type Ht95t64R = crate::FieldReader<u32>;
#[doc = "Field `ht95t64` writer - This field contains the third 32 Bits (95:64) of the Hash table."]
pub type Ht95t64W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This field contains the third 32 Bits (95:64) of the Hash table."]
    #[inline(always)]
    pub fn ht95t64(&self) -> Ht95t64R {
        Ht95t64R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This field contains the third 32 Bits (95:64) of the Hash table."]
    #[inline(always)]
    #[must_use]
    pub fn ht95t64(&mut self) -> Ht95t64W<GmacgrpHashTableReg2Spec> {
        Ht95t64W::new(self, 0)
    }
}
#[doc = "This register contains the third 32 bits of the hash table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpHashTableReg2Spec;
impl crate::RegisterSpec for GmacgrpHashTableReg2Spec {
    type Ux = u32;
    const OFFSET: u64 = 1288u64;
}
#[doc = "`read()` method returns [`gmacgrp_hash_table_reg2::R`](R) reader structure"]
impl crate::Readable for GmacgrpHashTableReg2Spec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_hash_table_reg2::W`](W) writer structure"]
impl crate::Writable for GmacgrpHashTableReg2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Hash_Table_Reg2 to value 0"]
impl crate::Resettable for GmacgrpHashTableReg2Spec {
    const RESET_VALUE: u32 = 0;
}
