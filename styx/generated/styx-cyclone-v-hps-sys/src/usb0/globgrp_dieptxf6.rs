// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `globgrp_dieptxf6` reader"]
pub type R = crate::R<GlobgrpDieptxf6Spec>;
#[doc = "Register `globgrp_dieptxf6` writer"]
pub type W = crate::W<GlobgrpDieptxf6Spec>;
#[doc = "Field `inepntxfstaddr` reader - This field contains the memory start address for IN endpoint Transmit FIFO 6."]
pub type InepntxfstaddrR = crate::FieldReader<u16>;
#[doc = "Field `inepntxfstaddr` writer - This field contains the memory start address for IN endpoint Transmit FIFO 6."]
pub type InepntxfstaddrW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `inepntxfdep` reader - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 8192."]
pub type InepntxfdepR = crate::FieldReader<u16>;
#[doc = "Field `inepntxfdep` writer - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 8192."]
pub type InepntxfdepW<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
impl R {
    #[doc = "Bits 0:15 - This field contains the memory start address for IN endpoint Transmit FIFO 6."]
    #[inline(always)]
    pub fn inepntxfstaddr(&self) -> InepntxfstaddrR {
        InepntxfstaddrR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:29 - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 8192."]
    #[inline(always)]
    pub fn inepntxfdep(&self) -> InepntxfdepR {
        InepntxfdepR::new(((self.bits >> 16) & 0x3fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - This field contains the memory start address for IN endpoint Transmit FIFO 6."]
    #[inline(always)]
    #[must_use]
    pub fn inepntxfstaddr(&mut self) -> InepntxfstaddrW<GlobgrpDieptxf6Spec> {
        InepntxfstaddrW::new(self, 0)
    }
    #[doc = "Bits 16:29 - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 8192."]
    #[inline(always)]
    #[must_use]
    pub fn inepntxfdep(&mut self) -> InepntxfdepW<GlobgrpDieptxf6Spec> {
        InepntxfdepW::new(self, 16)
    }
}
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf6::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf6::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpDieptxf6Spec;
impl crate::RegisterSpec for GlobgrpDieptxf6Spec {
    type Ux = u32;
    const OFFSET: u64 = 280u64;
}
#[doc = "`read()` method returns [`globgrp_dieptxf6::R`](R) reader structure"]
impl crate::Readable for GlobgrpDieptxf6Spec {}
#[doc = "`write(|w| ..)` method takes [`globgrp_dieptxf6::W`](W) writer structure"]
impl crate::Writable for GlobgrpDieptxf6Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets globgrp_dieptxf6 to value 0x2000_e000"]
impl crate::Resettable for GlobgrpDieptxf6Spec {
    const RESET_VALUE: u32 = 0x2000_e000;
}
