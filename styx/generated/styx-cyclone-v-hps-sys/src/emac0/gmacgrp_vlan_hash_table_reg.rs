// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_VLAN_Hash_Table_Reg` reader"]
pub type R = crate::R<GmacgrpVlanHashTableRegSpec>;
#[doc = "Register `gmacgrp_VLAN_Hash_Table_Reg` writer"]
pub type W = crate::W<GmacgrpVlanHashTableRegSpec>;
#[doc = "Field `vlht` reader - This field contains the 16-bit VLAN Hash Table."]
pub type VlhtR = crate::FieldReader<u16>;
#[doc = "Field `vlht` writer - This field contains the 16-bit VLAN Hash Table."]
pub type VlhtW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - This field contains the 16-bit VLAN Hash Table."]
    #[inline(always)]
    pub fn vlht(&self) -> VlhtR {
        VlhtR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - This field contains the 16-bit VLAN Hash Table."]
    #[inline(always)]
    #[must_use]
    pub fn vlht(&mut self) -> VlhtW<GmacgrpVlanHashTableRegSpec> {
        VlhtW::new(self, 0)
    }
}
#[doc = "The 16-bit Hash table is used for group address filtering based on VLAN tag when Bit 18 (VTHM) of Register 7 (VLAN Tag Register) is set. For hash filtering, the content of the 16-bit VLAN tag or 12-bit VLAN ID (based on Bit 16 (ETV) of VLAN Tag Register) in the incoming frame is passed through the CRC logic and the upper four bits of the calculated CRC are used to index the contents of the VLAN Hash table. For example, a hash value of 4b'1000 selects Bit 8 of the VLAN Hash table. The hash value of the destination address is calculated in the following way: 1. Calculate the 32-bit CRC for the VLAN tag or ID (See IEEE 802.3, Section 3.2.8 for the steps to calculate CRC32). 2. Perform bitwise reversal for the value obtained in Step 1. 3. Take the upper four bits from the value obtained in Step 2. If the corresponding bit value of the register is 1'b1, the frame is accepted. Otherwise, it is rejected. Because the Hash Table register is double-synchronized to the (G)MII clock domain, the synchronization is triggered only when Bits\\[15:8\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of this register are written. Notes: * Because of double-synchronization, consecutive writes to this register should be performed after at least four clock cycles in the destination clock domain.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_vlan_hash_table_reg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_vlan_hash_table_reg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpVlanHashTableRegSpec;
impl crate::RegisterSpec for GmacgrpVlanHashTableRegSpec {
    type Ux = u32;
    const OFFSET: u64 = 1416u64;
}
#[doc = "`read()` method returns [`gmacgrp_vlan_hash_table_reg::R`](R) reader structure"]
impl crate::Readable for GmacgrpVlanHashTableRegSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_vlan_hash_table_reg::W`](W) writer structure"]
impl crate::Writable for GmacgrpVlanHashTableRegSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_VLAN_Hash_Table_Reg to value 0"]
impl crate::Resettable for GmacgrpVlanHashTableRegSpec {
    const RESET_VALUE: u32 = 0;
}
