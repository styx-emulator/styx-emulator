// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Layer4_Address0` reader"]
pub type R = crate::R<GmacgrpLayer4Address0Spec>;
#[doc = "Register `gmacgrp_Layer4_Address0` writer"]
pub type W = crate::W<GmacgrpLayer4Address0Spec>;
#[doc = "Field `l4sp0` reader - Layer 4 Source Port Number Field When Bit 16 (L4PEN0) is reset and Bit 20 (L4DPM0) is set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the TCP Source Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN0) and Bit 20 (L4DPM0) are set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the UDP Source Port Number field in the IPv4 or IPv6 frames."]
pub type L4sp0R = crate::FieldReader<u16>;
#[doc = "Field `l4sp0` writer - Layer 4 Source Port Number Field When Bit 16 (L4PEN0) is reset and Bit 20 (L4DPM0) is set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the TCP Source Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN0) and Bit 20 (L4DPM0) are set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the UDP Source Port Number field in the IPv4 or IPv6 frames."]
pub type L4sp0W<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `l4dp0` reader - When Bit 16 (L4PEN0) is reset and Bit 20 (L4DPM0) is set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the TCP Destination Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN0) and Bit 20 (L4DPM0) are set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the UDP Destination Port Number field in the IPv4 or IPv6 frames."]
pub type L4dp0R = crate::FieldReader<u16>;
#[doc = "Field `l4dp0` writer - When Bit 16 (L4PEN0) is reset and Bit 20 (L4DPM0) is set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the TCP Destination Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN0) and Bit 20 (L4DPM0) are set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the UDP Destination Port Number field in the IPv4 or IPv6 frames."]
pub type L4dp0W<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Layer 4 Source Port Number Field When Bit 16 (L4PEN0) is reset and Bit 20 (L4DPM0) is set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the TCP Source Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN0) and Bit 20 (L4DPM0) are set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the UDP Source Port Number field in the IPv4 or IPv6 frames."]
    #[inline(always)]
    pub fn l4sp0(&self) -> L4sp0R {
        L4sp0R::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - When Bit 16 (L4PEN0) is reset and Bit 20 (L4DPM0) is set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the TCP Destination Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN0) and Bit 20 (L4DPM0) are set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the UDP Destination Port Number field in the IPv4 or IPv6 frames."]
    #[inline(always)]
    pub fn l4dp0(&self) -> L4dp0R {
        L4dp0R::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Layer 4 Source Port Number Field When Bit 16 (L4PEN0) is reset and Bit 20 (L4DPM0) is set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the TCP Source Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN0) and Bit 20 (L4DPM0) are set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the UDP Source Port Number field in the IPv4 or IPv6 frames."]
    #[inline(always)]
    #[must_use]
    pub fn l4sp0(&mut self) -> L4sp0W<GmacgrpLayer4Address0Spec> {
        L4sp0W::new(self, 0)
    }
    #[doc = "Bits 16:31 - When Bit 16 (L4PEN0) is reset and Bit 20 (L4DPM0) is set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the TCP Destination Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN0) and Bit 20 (L4DPM0) are set in Register 256 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the UDP Destination Port Number field in the IPv4 or IPv6 frames."]
    #[inline(always)]
    #[must_use]
    pub fn l4dp0(&mut self) -> L4dp0W<GmacgrpLayer4Address0Spec> {
        L4dp0W::new(self, 16)
    }
}
#[doc = "Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer4_address0::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer4_address0::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpLayer4Address0Spec;
impl crate::RegisterSpec for GmacgrpLayer4Address0Spec {
    type Ux = u32;
    const OFFSET: u64 = 1028u64;
}
#[doc = "`read()` method returns [`gmacgrp_layer4_address0::R`](R) reader structure"]
impl crate::Readable for GmacgrpLayer4Address0Spec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_layer4_address0::W`](W) writer structure"]
impl crate::Writable for GmacgrpLayer4Address0Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Layer4_Address0 to value 0"]
impl crate::Resettable for GmacgrpLayer4Address0Spec {
    const RESET_VALUE: u32 = 0;
}
