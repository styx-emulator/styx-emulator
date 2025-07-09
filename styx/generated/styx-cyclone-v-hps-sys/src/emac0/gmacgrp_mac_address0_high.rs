// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_MAC_Address0_High` reader"]
pub type R = crate::R<GmacgrpMacAddress0HighSpec>;
#[doc = "Register `gmacgrp_MAC_Address0_High` writer"]
pub type W = crate::W<GmacgrpMacAddress0HighSpec>;
#[doc = "Field `addrhi` reader - This field contains the upper 16 bits (47:32) of the first 6-byte MAC address. The MAC uses this field for filtering the received frames and inserting the MAC address in the Transmit Flow Control (PAUSE) Frames."]
pub type AddrhiR = crate::FieldReader<u16>;
#[doc = "Field `addrhi` writer - This field contains the upper 16 bits (47:32) of the first 6-byte MAC address. The MAC uses this field for filtering the received frames and inserting the MAC address in the Transmit Flow Control (PAUSE) Frames."]
pub type AddrhiW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `ae` reader - This bit is always set to 1."]
pub type AeR = crate::BitReader;
#[doc = "Field `ae` writer - This bit is always set to 1."]
pub type AeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:15 - This field contains the upper 16 bits (47:32) of the first 6-byte MAC address. The MAC uses this field for filtering the received frames and inserting the MAC address in the Transmit Flow Control (PAUSE) Frames."]
    #[inline(always)]
    pub fn addrhi(&self) -> AddrhiR {
        AddrhiR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bit 31 - This bit is always set to 1."]
    #[inline(always)]
    pub fn ae(&self) -> AeR {
        AeR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:15 - This field contains the upper 16 bits (47:32) of the first 6-byte MAC address. The MAC uses this field for filtering the received frames and inserting the MAC address in the Transmit Flow Control (PAUSE) Frames."]
    #[inline(always)]
    #[must_use]
    pub fn addrhi(&mut self) -> AddrhiW<GmacgrpMacAddress0HighSpec> {
        AddrhiW::new(self, 0)
    }
    #[doc = "Bit 31 - This bit is always set to 1."]
    #[inline(always)]
    #[must_use]
    pub fn ae(&mut self) -> AeW<GmacgrpMacAddress0HighSpec> {
        AeW::new(self, 31)
    }
}
#[doc = "The MAC Address0 High register holds the upper 16 bits of the first 6-byte MAC address of the station. The first DA byte that is received on the (G)MII interface corresponds to the LS byte (Bits \\[7:0\\]) of the MAC Address Low register. For example, if 0x112233445566 is received (0x11 in lane 0 of the first column) on the (G)MII as the destination address, then the MacAddress0 Register \\[47:0\\]
is compared with 0x665544332211. Because the MAC address registers are double-synchronized to the (G)MII clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address0 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address0_high::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address0_high::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpMacAddress0HighSpec;
impl crate::RegisterSpec for GmacgrpMacAddress0HighSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`gmacgrp_mac_address0_high::R`](R) reader structure"]
impl crate::Readable for GmacgrpMacAddress0HighSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_mac_address0_high::W`](W) writer structure"]
impl crate::Writable for GmacgrpMacAddress0HighSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_MAC_Address0_High to value 0x8000_ffff"]
impl crate::Resettable for GmacgrpMacAddress0HighSpec {
    const RESET_VALUE: u32 = 0x8000_ffff;
}
