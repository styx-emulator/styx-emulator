// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FS_DAINTMSK` reader"]
pub type R = crate::R<FsDaintmskSpec>;
#[doc = "Register `FS_DAINTMSK` writer"]
pub type W = crate::W<FsDaintmskSpec>;
#[doc = "Field `IEPM` reader - IN EP interrupt mask bits"]
pub type IepmR = crate::FieldReader<u16>;
#[doc = "Field `IEPM` writer - IN EP interrupt mask bits"]
pub type IepmW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `OEPINT` reader - OUT endpoint interrupt bits"]
pub type OepintR = crate::FieldReader<u16>;
#[doc = "Field `OEPINT` writer - OUT endpoint interrupt bits"]
pub type OepintW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - IN EP interrupt mask bits"]
    #[inline(always)]
    pub fn iepm(&self) -> IepmR {
        IepmR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - OUT endpoint interrupt bits"]
    #[inline(always)]
    pub fn oepint(&self) -> OepintR {
        OepintR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - IN EP interrupt mask bits"]
    #[inline(always)]
    #[must_use]
    pub fn iepm(&mut self) -> IepmW<FsDaintmskSpec> {
        IepmW::new(self, 0)
    }
    #[doc = "Bits 16:31 - OUT endpoint interrupt bits"]
    #[inline(always)]
    #[must_use]
    pub fn oepint(&mut self) -> OepintW<FsDaintmskSpec> {
        OepintW::new(self, 16)
    }
}
#[doc = "OTG_FS all endpoints interrupt mask register (OTG_FS_DAINTMSK)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_daintmsk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_daintmsk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FsDaintmskSpec;
impl crate::RegisterSpec for FsDaintmskSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`fs_daintmsk::R`](R) reader structure"]
impl crate::Readable for FsDaintmskSpec {}
#[doc = "`write(|w| ..)` method takes [`fs_daintmsk::W`](W) writer structure"]
impl crate::Writable for FsDaintmskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FS_DAINTMSK to value 0"]
impl crate::Resettable for FsDaintmskSpec {
    const RESET_VALUE: u32 = 0;
}
