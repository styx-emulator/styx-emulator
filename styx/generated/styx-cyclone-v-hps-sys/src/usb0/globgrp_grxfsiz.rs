// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `globgrp_grxfsiz` reader"]
pub type R = crate::R<GlobgrpGrxfsizSpec>;
#[doc = "Register `globgrp_grxfsiz` writer"]
pub type W = crate::W<GlobgrpGrxfsizSpec>;
#[doc = "Field `rxfdep` reader - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 32,768 The power-on reset value of this register is specified as the Largest Rx Data FIFO Dept 8192. Using the Dynamic FIFO Sizing, you can write a new value in this field. Programmed values must not exceed 8192."]
pub type RxfdepR = crate::FieldReader<u16>;
#[doc = "Field `rxfdep` writer - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 32,768 The power-on reset value of this register is specified as the Largest Rx Data FIFO Dept 8192. Using the Dynamic FIFO Sizing, you can write a new value in this field. Programmed values must not exceed 8192."]
pub type RxfdepW<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
impl R {
    #[doc = "Bits 0:13 - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 32,768 The power-on reset value of this register is specified as the Largest Rx Data FIFO Dept 8192. Using the Dynamic FIFO Sizing, you can write a new value in this field. Programmed values must not exceed 8192."]
    #[inline(always)]
    pub fn rxfdep(&self) -> RxfdepR {
        RxfdepR::new((self.bits & 0x3fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:13 - This value is in terms of 32-bit words. Minimum value is 16 Maximum value is 32,768 The power-on reset value of this register is specified as the Largest Rx Data FIFO Dept 8192. Using the Dynamic FIFO Sizing, you can write a new value in this field. Programmed values must not exceed 8192."]
    #[inline(always)]
    #[must_use]
    pub fn rxfdep(&mut self) -> RxfdepW<GlobgrpGrxfsizSpec> {
        RxfdepW::new(self, 0)
    }
}
#[doc = "The application can program the RAM size that must be allocated to the RxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_grxfsiz::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_grxfsiz::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGrxfsizSpec;
impl crate::RegisterSpec for GlobgrpGrxfsizSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`globgrp_grxfsiz::R`](R) reader structure"]
impl crate::Readable for GlobgrpGrxfsizSpec {}
#[doc = "`write(|w| ..)` method takes [`globgrp_grxfsiz::W`](W) writer structure"]
impl crate::Writable for GlobgrpGrxfsizSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets globgrp_grxfsiz to value 0x2000"]
impl crate::Resettable for GlobgrpGrxfsizSpec {
    const RESET_VALUE: u32 = 0x2000;
}
