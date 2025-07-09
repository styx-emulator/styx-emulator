// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `globgrp_dieptxf9` reader"]
pub type R = crate::R<GlobgrpDieptxf9Spec>;
#[doc = "Register `globgrp_dieptxf9` writer"]
pub type W = crate::W<GlobgrpDieptxf9Spec>;
#[doc = "Field `inepntxfstaddr` reader - This field contains the memory start address for IN endpoint Transmit FIFO 9."]
pub type InepntxfstaddrR = crate::FieldReader<u16>;
#[doc = "Field `inepntxfstaddr` writer - This field contains the memory start address for IN endpoint Transmit FIFO 9."]
pub type InepntxfstaddrW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `inepntxfdep` reader - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 8192."]
pub type InepntxfdepR = crate::FieldReader<u16>;
#[doc = "Field `inepntxfdep` writer - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 8192."]
pub type InepntxfdepW<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
impl R {
    #[doc = "Bits 0:15 - This field contains the memory start address for IN endpoint Transmit FIFO 9."]
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
    #[doc = "Bits 0:15 - This field contains the memory start address for IN endpoint Transmit FIFO 9."]
    #[inline(always)]
    #[must_use]
    pub fn inepntxfstaddr(&mut self) -> InepntxfstaddrW<GlobgrpDieptxf9Spec> {
        InepntxfstaddrW::new(self, 0)
    }
    #[doc = "Bits 16:29 - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 8192."]
    #[inline(always)]
    #[must_use]
    pub fn inepntxfdep(&mut self) -> InepntxfdepW<GlobgrpDieptxf9Spec> {
        InepntxfdepW::new(self, 16)
    }
}
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf9::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf9::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpDieptxf9Spec;
impl crate::RegisterSpec for GlobgrpDieptxf9Spec {
    type Ux = u32;
    const OFFSET: u64 = 292u64;
}
#[doc = "`read()` method returns [`globgrp_dieptxf9::R`](R) reader structure"]
impl crate::Readable for GlobgrpDieptxf9Spec {}
#[doc = "`write(|w| ..)` method takes [`globgrp_dieptxf9::W`](W) writer structure"]
impl crate::Writable for GlobgrpDieptxf9Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets globgrp_dieptxf9 to value 0x2000_4000"]
impl crate::Resettable for GlobgrpDieptxf9Spec {
    const RESET_VALUE: u32 = 0x2000_4000;
}
