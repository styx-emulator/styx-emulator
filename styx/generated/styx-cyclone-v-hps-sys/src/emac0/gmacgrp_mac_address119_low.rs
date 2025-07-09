// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_MAC_Address119_Low` reader"]
pub type R = crate::R<GmacgrpMacAddress119LowSpec>;
#[doc = "Register `gmacgrp_MAC_Address119_Low` writer"]
pub type W = crate::W<GmacgrpMacAddress119LowSpec>;
#[doc = "Field `addrlo` reader - This field contains the lower 32 bits of the 120th 6-byte MAC address. The content of this field is undefined until loaded by software after the initialization process."]
pub type AddrloR = crate::FieldReader<u32>;
#[doc = "Field `addrlo` writer - This field contains the lower 32 bits of the 120th 6-byte MAC address. The content of this field is undefined until loaded by software after the initialization process."]
pub type AddrloW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This field contains the lower 32 bits of the 120th 6-byte MAC address. The content of this field is undefined until loaded by software after the initialization process."]
    #[inline(always)]
    pub fn addrlo(&self) -> AddrloR {
        AddrloR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This field contains the lower 32 bits of the 120th 6-byte MAC address. The content of this field is undefined until loaded by software after the initialization process."]
    #[inline(always)]
    #[must_use]
    pub fn addrlo(&mut self) -> AddrloW<GmacgrpMacAddress119LowSpec> {
        AddrloW::new(self, 0)
    }
}
#[doc = "The MAC Address119 Low register holds the lower 32 bits of the 120th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address119_low::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address119_low::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpMacAddress119LowSpec;
impl crate::RegisterSpec for GmacgrpMacAddress119LowSpec {
    type Ux = u32;
    const OFFSET: u64 = 2876u64;
}
#[doc = "`read()` method returns [`gmacgrp_mac_address119_low::R`](R) reader structure"]
impl crate::Readable for GmacgrpMacAddress119LowSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_mac_address119_low::W`](W) writer structure"]
impl crate::Writable for GmacgrpMacAddress119LowSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_MAC_Address119_Low to value 0xffff_ffff"]
impl crate::Resettable for GmacgrpMacAddress119LowSpec {
    const RESET_VALUE: u32 = 0xffff_ffff;
}
