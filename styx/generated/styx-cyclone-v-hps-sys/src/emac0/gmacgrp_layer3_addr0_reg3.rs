// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Layer3_Addr0_Reg3` reader"]
pub type R = crate::R<GmacgrpLayer3Addr0Reg3Spec>;
#[doc = "Register `gmacgrp_Layer3_Addr0_Reg3` writer"]
pub type W = crate::W<GmacgrpLayer3Addr0Reg3Spec>;
#[doc = "Field `l3a03` reader - When Bit 0 (L3PEN3) and Bit 2 (L3SAM3) are set in Register 292 (Layer 3 and Layer 4 Control Register 3), this field contains the value to be matched with Bits \\[31:0\\]
of the IP Source Address field in the IPv6 frames. When Bit 0 (L3PEN3) and Bit 4 (L3DAM3) are set in Register 292 (Layer 3 and Layer 4 Control Register 3), this field contains the value to be matched with Bits \\[31:0\\]
of the IP Destination Address field in the IPv6 frames. When Bit 0 (L3PEN3) is reset and Bit 2 (L3SAM3) is set in Register 292 (Layer 3 and Layer 4 Control Register 3), this field contains the value to be matched with the IP Source Address field in the IPv4 frames."]
pub type L3a03R = crate::FieldReader<u32>;
#[doc = "Field `l3a03` writer - When Bit 0 (L3PEN3) and Bit 2 (L3SAM3) are set in Register 292 (Layer 3 and Layer 4 Control Register 3), this field contains the value to be matched with Bits \\[31:0\\]
of the IP Source Address field in the IPv6 frames. When Bit 0 (L3PEN3) and Bit 4 (L3DAM3) are set in Register 292 (Layer 3 and Layer 4 Control Register 3), this field contains the value to be matched with Bits \\[31:0\\]
of the IP Destination Address field in the IPv6 frames. When Bit 0 (L3PEN3) is reset and Bit 2 (L3SAM3) is set in Register 292 (Layer 3 and Layer 4 Control Register 3), this field contains the value to be matched with the IP Source Address field in the IPv4 frames."]
pub type L3a03W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - When Bit 0 (L3PEN3) and Bit 2 (L3SAM3) are set in Register 292 (Layer 3 and Layer 4 Control Register 3), this field contains the value to be matched with Bits \\[31:0\\]
of the IP Source Address field in the IPv6 frames. When Bit 0 (L3PEN3) and Bit 4 (L3DAM3) are set in Register 292 (Layer 3 and Layer 4 Control Register 3), this field contains the value to be matched with Bits \\[31:0\\]
of the IP Destination Address field in the IPv6 frames. When Bit 0 (L3PEN3) is reset and Bit 2 (L3SAM3) is set in Register 292 (Layer 3 and Layer 4 Control Register 3), this field contains the value to be matched with the IP Source Address field in the IPv4 frames."]
    #[inline(always)]
    pub fn l3a03(&self) -> L3a03R {
        L3a03R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - When Bit 0 (L3PEN3) and Bit 2 (L3SAM3) are set in Register 292 (Layer 3 and Layer 4 Control Register 3), this field contains the value to be matched with Bits \\[31:0\\]
of the IP Source Address field in the IPv6 frames. When Bit 0 (L3PEN3) and Bit 4 (L3DAM3) are set in Register 292 (Layer 3 and Layer 4 Control Register 3), this field contains the value to be matched with Bits \\[31:0\\]
of the IP Destination Address field in the IPv6 frames. When Bit 0 (L3PEN3) is reset and Bit 2 (L3SAM3) is set in Register 292 (Layer 3 and Layer 4 Control Register 3), this field contains the value to be matched with the IP Source Address field in the IPv4 frames."]
    #[inline(always)]
    #[must_use]
    pub fn l3a03(&mut self) -> L3a03W<GmacgrpLayer3Addr0Reg3Spec> {
        L3a03W::new(self, 0)
    }
}
#[doc = "For IPv4 frames, the Layer 3 Address 0 Register 3 contains the 32-bit IP Source Address field. For IPv6 frames, it contains Bits \\[31:0\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr0_reg3::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr0_reg3::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpLayer3Addr0Reg3Spec;
impl crate::RegisterSpec for GmacgrpLayer3Addr0Reg3Spec {
    type Ux = u32;
    const OFFSET: u64 = 1184u64;
}
#[doc = "`read()` method returns [`gmacgrp_layer3_addr0_reg3::R`](R) reader structure"]
impl crate::Readable for GmacgrpLayer3Addr0Reg3Spec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_layer3_addr0_reg3::W`](W) writer structure"]
impl crate::Writable for GmacgrpLayer3Addr0Reg3Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Layer3_Addr0_Reg3 to value 0"]
impl crate::Resettable for GmacgrpLayer3Addr0Reg3Spec {
    const RESET_VALUE: u32 = 0;
}
