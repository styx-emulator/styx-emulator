// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Layer3_Addr2_Reg2` reader"]
pub type R = crate::R<GmacgrpLayer3Addr2Reg2Spec>;
#[doc = "Register `gmacgrp_Layer3_Addr2_Reg2` writer"]
pub type W = crate::W<GmacgrpLayer3Addr2Reg2Spec>;
#[doc = "Field `l3a22` reader - When Bit 0 (L3PEN2) and Bit 2 (L3SAM2) are set in Register 280 (Layer 3 and Layer 4 Control Register 2), this field contains the value to be matched with Bits \\[95:64\\]
of the IP Source Address field in the IPv6 frames. When Bit 0 (L3PEN2) and Bit 4 (L3DAM2) are set in Register 256 (Layer 3 and Layer 4 Control Register 2), this field contains value to be matched with Bits \\[95:64\\]
of the IP Destination Address field in the IPv6 frames. When Bit 0 (L3PEN2) is reset in Register 280 (Layer 3 and Layer 4 Control Register 2), this register is not used."]
pub type L3a22R = crate::FieldReader<u32>;
#[doc = "Field `l3a22` writer - When Bit 0 (L3PEN2) and Bit 2 (L3SAM2) are set in Register 280 (Layer 3 and Layer 4 Control Register 2), this field contains the value to be matched with Bits \\[95:64\\]
of the IP Source Address field in the IPv6 frames. When Bit 0 (L3PEN2) and Bit 4 (L3DAM2) are set in Register 256 (Layer 3 and Layer 4 Control Register 2), this field contains value to be matched with Bits \\[95:64\\]
of the IP Destination Address field in the IPv6 frames. When Bit 0 (L3PEN2) is reset in Register 280 (Layer 3 and Layer 4 Control Register 2), this register is not used."]
pub type L3a22W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - When Bit 0 (L3PEN2) and Bit 2 (L3SAM2) are set in Register 280 (Layer 3 and Layer 4 Control Register 2), this field contains the value to be matched with Bits \\[95:64\\]
of the IP Source Address field in the IPv6 frames. When Bit 0 (L3PEN2) and Bit 4 (L3DAM2) are set in Register 256 (Layer 3 and Layer 4 Control Register 2), this field contains value to be matched with Bits \\[95:64\\]
of the IP Destination Address field in the IPv6 frames. When Bit 0 (L3PEN2) is reset in Register 280 (Layer 3 and Layer 4 Control Register 2), this register is not used."]
    #[inline(always)]
    pub fn l3a22(&self) -> L3a22R {
        L3a22R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - When Bit 0 (L3PEN2) and Bit 2 (L3SAM2) are set in Register 280 (Layer 3 and Layer 4 Control Register 2), this field contains the value to be matched with Bits \\[95:64\\]
of the IP Source Address field in the IPv6 frames. When Bit 0 (L3PEN2) and Bit 4 (L3DAM2) are set in Register 256 (Layer 3 and Layer 4 Control Register 2), this field contains value to be matched with Bits \\[95:64\\]
of the IP Destination Address field in the IPv6 frames. When Bit 0 (L3PEN2) is reset in Register 280 (Layer 3 and Layer 4 Control Register 2), this register is not used."]
    #[inline(always)]
    #[must_use]
    pub fn l3a22(&mut self) -> L3a22W<GmacgrpLayer3Addr2Reg2Spec> {
        L3a22W::new(self, 0)
    }
}
#[doc = "For IPv4 frames, the Layer 3 Address 2 Register 2 is reserved. For IPv6 frames, it contains Bits \\[95:64\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr2_reg2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr2_reg2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpLayer3Addr2Reg2Spec;
impl crate::RegisterSpec for GmacgrpLayer3Addr2Reg2Spec {
    type Ux = u32;
    const OFFSET: u64 = 1144u64;
}
#[doc = "`read()` method returns [`gmacgrp_layer3_addr2_reg2::R`](R) reader structure"]
impl crate::Readable for GmacgrpLayer3Addr2Reg2Spec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_layer3_addr2_reg2::W`](W) writer structure"]
impl crate::Writable for GmacgrpLayer3Addr2Reg2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Layer3_Addr2_Reg2 to value 0"]
impl crate::Resettable for GmacgrpLayer3Addr2Reg2Spec {
    const RESET_VALUE: u32 = 0;
}
