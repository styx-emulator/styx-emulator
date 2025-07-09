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
#[doc = "Register `gmacgrp_MAC_Address113_Low` reader"]
pub type R = crate::R<GmacgrpMacAddress113LowSpec>;
#[doc = "Register `gmacgrp_MAC_Address113_Low` writer"]
pub type W = crate::W<GmacgrpMacAddress113LowSpec>;
#[doc = "Field `addrlo` reader - This field contains the lower 32 bits of the 114th 6-byte MAC address. The content of this field is undefined until loaded by software after the initialization process."]
pub type AddrloR = crate::FieldReader<u32>;
#[doc = "Field `addrlo` writer - This field contains the lower 32 bits of the 114th 6-byte MAC address. The content of this field is undefined until loaded by software after the initialization process."]
pub type AddrloW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This field contains the lower 32 bits of the 114th 6-byte MAC address. The content of this field is undefined until loaded by software after the initialization process."]
    #[inline(always)]
    pub fn addrlo(&self) -> AddrloR {
        AddrloR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This field contains the lower 32 bits of the 114th 6-byte MAC address. The content of this field is undefined until loaded by software after the initialization process."]
    #[inline(always)]
    #[must_use]
    pub fn addrlo(&mut self) -> AddrloW<GmacgrpMacAddress113LowSpec> {
        AddrloW::new(self, 0)
    }
}
#[doc = "The MAC Address113 Low register holds the lower 32 bits of the 114th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address113_low::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address113_low::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpMacAddress113LowSpec;
impl crate::RegisterSpec for GmacgrpMacAddress113LowSpec {
    type Ux = u32;
    const OFFSET: u64 = 2828u64;
}
#[doc = "`read()` method returns [`gmacgrp_mac_address113_low::R`](R) reader structure"]
impl crate::Readable for GmacgrpMacAddress113LowSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_mac_address113_low::W`](W) writer structure"]
impl crate::Writable for GmacgrpMacAddress113LowSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_MAC_Address113_Low to value 0xffff_ffff"]
impl crate::Resettable for GmacgrpMacAddress113LowSpec {
    const RESET_VALUE: u32 = 0xffff_ffff;
}
