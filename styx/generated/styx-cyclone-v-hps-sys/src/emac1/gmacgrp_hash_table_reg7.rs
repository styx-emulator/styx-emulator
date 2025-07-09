// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Hash_Table_Reg7` reader"]
pub type R = crate::R<GmacgrpHashTableReg7Spec>;
#[doc = "Register `gmacgrp_Hash_Table_Reg7` writer"]
pub type W = crate::W<GmacgrpHashTableReg7Spec>;
#[doc = "Field `ht255t224` reader - This field contains the eighth 32 Bits (255:224) of the Hash table."]
pub type Ht255t224R = crate::FieldReader<u32>;
#[doc = "Field `ht255t224` writer - This field contains the eighth 32 Bits (255:224) of the Hash table."]
pub type Ht255t224W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This field contains the eighth 32 Bits (255:224) of the Hash table."]
    #[inline(always)]
    pub fn ht255t224(&self) -> Ht255t224R {
        Ht255t224R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This field contains the eighth 32 Bits (255:224) of the Hash table."]
    #[inline(always)]
    #[must_use]
    pub fn ht255t224(&mut self) -> Ht255t224W<GmacgrpHashTableReg7Spec> {
        Ht255t224W::new(self, 0)
    }
}
#[doc = "This register contains the eighth 32 bits of the hash table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg7::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg7::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpHashTableReg7Spec;
impl crate::RegisterSpec for GmacgrpHashTableReg7Spec {
    type Ux = u32;
    const OFFSET: u64 = 1308u64;
}
#[doc = "`read()` method returns [`gmacgrp_hash_table_reg7::R`](R) reader structure"]
impl crate::Readable for GmacgrpHashTableReg7Spec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_hash_table_reg7::W`](W) writer structure"]
impl crate::Writable for GmacgrpHashTableReg7Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Hash_Table_Reg7 to value 0"]
impl crate::Resettable for GmacgrpHashTableReg7Spec {
    const RESET_VALUE: u32 = 0;
}
