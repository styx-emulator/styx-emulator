// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Layer3_Addr3_Reg1` reader"]
pub type R = crate::R<GmacgrpLayer3Addr3Reg1Spec>;
#[doc = "Register `gmacgrp_Layer3_Addr3_Reg1` writer"]
pub type W = crate::W<GmacgrpLayer3Addr3Reg1Spec>;
#[doc = "Field `l3a31` reader - When Bit 1 (L3PEN1) and Bit 2 (L3SAM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with Bits \\[127:96\\]
of the IP Source Address field in the IPv6 frames. When Bit 0 (L3PEN1) and Bit 4 (L3DAM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with Bits \\[127:96\\]
of the IP Destination Address field in the IPv6 frames. When Bit 0 (L3PEN1) is reset in Register 268 (Layer 3 and Layer 4 Control Register 1), this register is not used."]
pub type L3a31R = crate::FieldReader<u32>;
#[doc = "Field `l3a31` writer - When Bit 1 (L3PEN1) and Bit 2 (L3SAM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with Bits \\[127:96\\]
of the IP Source Address field in the IPv6 frames. When Bit 0 (L3PEN1) and Bit 4 (L3DAM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with Bits \\[127:96\\]
of the IP Destination Address field in the IPv6 frames. When Bit 0 (L3PEN1) is reset in Register 268 (Layer 3 and Layer 4 Control Register 1), this register is not used."]
pub type L3a31W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - When Bit 1 (L3PEN1) and Bit 2 (L3SAM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with Bits \\[127:96\\]
of the IP Source Address field in the IPv6 frames. When Bit 0 (L3PEN1) and Bit 4 (L3DAM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with Bits \\[127:96\\]
of the IP Destination Address field in the IPv6 frames. When Bit 0 (L3PEN1) is reset in Register 268 (Layer 3 and Layer 4 Control Register 1), this register is not used."]
    #[inline(always)]
    pub fn l3a31(&self) -> L3a31R {
        L3a31R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - When Bit 1 (L3PEN1) and Bit 2 (L3SAM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with Bits \\[127:96\\]
of the IP Source Address field in the IPv6 frames. When Bit 0 (L3PEN1) and Bit 4 (L3DAM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with Bits \\[127:96\\]
of the IP Destination Address field in the IPv6 frames. When Bit 0 (L3PEN1) is reset in Register 268 (Layer 3 and Layer 4 Control Register 1), this register is not used."]
    #[inline(always)]
    #[must_use]
    pub fn l3a31(&mut self) -> L3a31W<GmacgrpLayer3Addr3Reg1Spec> {
        L3a31W::new(self, 0)
    }
}
#[doc = "For IPv4 frames, the Layer 3 Address 3 Register 1 is reserved. For IPv6 frames, it contains Bits \\[127:96\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr3_reg1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr3_reg1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpLayer3Addr3Reg1Spec;
impl crate::RegisterSpec for GmacgrpLayer3Addr3Reg1Spec {
    type Ux = u32;
    const OFFSET: u64 = 1100u64;
}
#[doc = "`read()` method returns [`gmacgrp_layer3_addr3_reg1::R`](R) reader structure"]
impl crate::Readable for GmacgrpLayer3Addr3Reg1Spec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_layer3_addr3_reg1::W`](W) writer structure"]
impl crate::Writable for GmacgrpLayer3Addr3Reg1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Layer3_Addr3_Reg1 to value 0"]
impl crate::Resettable for GmacgrpLayer3Addr3Reg1Spec {
    const RESET_VALUE: u32 = 0;
}
