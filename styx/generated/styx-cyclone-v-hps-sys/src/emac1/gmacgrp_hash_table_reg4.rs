// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Hash_Table_Reg4` reader"]
pub type R = crate::R<GmacgrpHashTableReg4Spec>;
#[doc = "Register `gmacgrp_Hash_Table_Reg4` writer"]
pub type W = crate::W<GmacgrpHashTableReg4Spec>;
#[doc = "Field `ht159t128` reader - This field contains the fifth 32 Bits (159:128) of the Hash table."]
pub type Ht159t128R = crate::FieldReader<u32>;
#[doc = "Field `ht159t128` writer - This field contains the fifth 32 Bits (159:128) of the Hash table."]
pub type Ht159t128W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This field contains the fifth 32 Bits (159:128) of the Hash table."]
    #[inline(always)]
    pub fn ht159t128(&self) -> Ht159t128R {
        Ht159t128R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This field contains the fifth 32 Bits (159:128) of the Hash table."]
    #[inline(always)]
    #[must_use]
    pub fn ht159t128(&mut self) -> Ht159t128W<GmacgrpHashTableReg4Spec> {
        Ht159t128W::new(self, 0)
    }
}
#[doc = "This register contains the fifth 32 bits of the hash table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpHashTableReg4Spec;
impl crate::RegisterSpec for GmacgrpHashTableReg4Spec {
    type Ux = u32;
    const OFFSET: u64 = 1296u64;
}
#[doc = "`read()` method returns [`gmacgrp_hash_table_reg4::R`](R) reader structure"]
impl crate::Readable for GmacgrpHashTableReg4Spec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_hash_table_reg4::W`](W) writer structure"]
impl crate::Writable for GmacgrpHashTableReg4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Hash_Table_Reg4 to value 0"]
impl crate::Resettable for GmacgrpHashTableReg4Spec {
    const RESET_VALUE: u32 = 0;
}
