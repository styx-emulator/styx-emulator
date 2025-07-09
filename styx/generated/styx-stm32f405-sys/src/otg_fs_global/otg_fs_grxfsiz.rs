// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_GRXFSIZ` reader"]
pub type R = crate::R<OtgFsGrxfsizSpec>;
#[doc = "Register `OTG_FS_GRXFSIZ` writer"]
pub type W = crate::W<OtgFsGrxfsizSpec>;
#[doc = "Field `RXFD` reader - RxFIFO depth"]
pub type RxfdR = crate::FieldReader<u16>;
#[doc = "Field `RXFD` writer - RxFIFO depth"]
pub type RxfdW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - RxFIFO depth"]
    #[inline(always)]
    pub fn rxfd(&self) -> RxfdR {
        RxfdR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - RxFIFO depth"]
    #[inline(always)]
    #[must_use]
    pub fn rxfd(&mut self) -> RxfdW<OtgFsGrxfsizSpec> {
        RxfdW::new(self, 0)
    }
}
#[doc = "OTG_FS Receive FIFO size register (OTG_FS_GRXFSIZ)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_grxfsiz::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_grxfsiz::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsGrxfsizSpec;
impl crate::RegisterSpec for OtgFsGrxfsizSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`otg_fs_grxfsiz::R`](R) reader structure"]
impl crate::Readable for OtgFsGrxfsizSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_grxfsiz::W`](W) writer structure"]
impl crate::Writable for OtgFsGrxfsizSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_GRXFSIZ to value 0x0200"]
impl crate::Resettable for OtgFsGrxfsizSpec {
    const RESET_VALUE: u32 = 0x0200;
}
