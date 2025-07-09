// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FS_DIEPTXF2` reader"]
pub type R = crate::R<FsDieptxf2Spec>;
#[doc = "Register `FS_DIEPTXF2` writer"]
pub type W = crate::W<FsDieptxf2Spec>;
#[doc = "Field `INEPTXSA` reader - IN endpoint FIFO3 transmit RAM start address"]
pub type IneptxsaR = crate::FieldReader<u16>;
#[doc = "Field `INEPTXSA` writer - IN endpoint FIFO3 transmit RAM start address"]
pub type IneptxsaW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `INEPTXFD` reader - IN endpoint TxFIFO depth"]
pub type IneptxfdR = crate::FieldReader<u16>;
#[doc = "Field `INEPTXFD` writer - IN endpoint TxFIFO depth"]
pub type IneptxfdW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - IN endpoint FIFO3 transmit RAM start address"]
    #[inline(always)]
    pub fn ineptxsa(&self) -> IneptxsaR {
        IneptxsaR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - IN endpoint TxFIFO depth"]
    #[inline(always)]
    pub fn ineptxfd(&self) -> IneptxfdR {
        IneptxfdR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - IN endpoint FIFO3 transmit RAM start address"]
    #[inline(always)]
    #[must_use]
    pub fn ineptxsa(&mut self) -> IneptxsaW<FsDieptxf2Spec> {
        IneptxsaW::new(self, 0)
    }
    #[doc = "Bits 16:31 - IN endpoint TxFIFO depth"]
    #[inline(always)]
    #[must_use]
    pub fn ineptxfd(&mut self) -> IneptxfdW<FsDieptxf2Spec> {
        IneptxfdW::new(self, 16)
    }
}
#[doc = "OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF3)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_dieptxf2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_dieptxf2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FsDieptxf2Spec;
impl crate::RegisterSpec for FsDieptxf2Spec {
    type Ux = u32;
    const OFFSET: u64 = 264u64;
}
#[doc = "`read()` method returns [`fs_dieptxf2::R`](R) reader structure"]
impl crate::Readable for FsDieptxf2Spec {}
#[doc = "`write(|w| ..)` method takes [`fs_dieptxf2::W`](W) writer structure"]
impl crate::Writable for FsDieptxf2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FS_DIEPTXF2 to value 0x0200_0400"]
impl crate::Resettable for FsDieptxf2Spec {
    const RESET_VALUE: u32 = 0x0200_0400;
}
