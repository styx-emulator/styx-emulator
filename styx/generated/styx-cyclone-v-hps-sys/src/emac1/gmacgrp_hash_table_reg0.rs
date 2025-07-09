// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `gmacgrp_Hash_Table_Reg0` reader"]
pub type R = crate::R<GmacgrpHashTableReg0Spec>;
#[doc = "Register `gmacgrp_Hash_Table_Reg0` writer"]
pub type W = crate::W<GmacgrpHashTableReg0Spec>;
#[doc = "Field `ht31t0` reader - This field contains the first 32 Bits (31:0) of the Hash table."]
pub type Ht31t0R = crate::FieldReader<u32>;
#[doc = "Field `ht31t0` writer - This field contains the first 32 Bits (31:0) of the Hash table."]
pub type Ht31t0W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This field contains the first 32 Bits (31:0) of the Hash table."]
    #[inline(always)]
    pub fn ht31t0(&self) -> Ht31t0R {
        Ht31t0R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This field contains the first 32 Bits (31:0) of the Hash table."]
    #[inline(always)]
    #[must_use]
    pub fn ht31t0(&mut self) -> Ht31t0W<GmacgrpHashTableReg0Spec> {
        Ht31t0W::new(self, 0)
    }
}
#[doc = "This register contains the first 32 bits of the hash table. The 256-bit Hash table is used for group address filtering. For hash filtering, the content of the destination address in the incoming frame is passed through the CRC logic and the upper eight bits of the CRC register are used to index the content of the Hash table. The most significant bits determines the register to be used (Hash Table Register X), and the least significant five bits determine the bit within the register. For example, a hash value of 8b'10111111 selects Bit 31 of the Hash Table Register 5. The hash value of the destination address is calculated in the following way: 1. Calculate the 32-bit CRC for the DA (See IEEE 802.3, Section 3.2.8 for the steps to calculate CRC32). 2. Perform bitwise reversal for the value obtained in Step 1. 3. Take the upper 8 bits from the value obtained in Step 2. If the corresponding bit value of the register is 1'b1, the frame is accepted. Otherwise, it is rejected. If the Bit 1 (Pass All Multicast) is set in Register 1 (MAC Frame Filter), then all multicast frames are accepted regardless of the multicast hash values. Because the Hash Table register is double-synchronized to the (G)MII clock domain, the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Hash Table Register X registers are written. Note: Because of double-synchronization, consecutive writes to this register should be performed after at least four clock cycles in the destination clock domain.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg0::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg0::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpHashTableReg0Spec;
impl crate::RegisterSpec for GmacgrpHashTableReg0Spec {
    type Ux = u32;
    const OFFSET: u64 = 1280u64;
}
#[doc = "`read()` method returns [`gmacgrp_hash_table_reg0::R`](R) reader structure"]
impl crate::Readable for GmacgrpHashTableReg0Spec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_hash_table_reg0::W`](W) writer structure"]
impl crate::Writable for GmacgrpHashTableReg0Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Hash_Table_Reg0 to value 0"]
impl crate::Resettable for GmacgrpHashTableReg0Spec {
    const RESET_VALUE: u32 = 0;
}
