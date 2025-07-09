// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `VTOR` reader"]
pub type R = crate::R<VtorSpec>;
#[doc = "Register `VTOR` writer"]
pub type W = crate::W<VtorSpec>;
#[doc = "Field `TBLOFF` reader - Vector table base offset field"]
pub type TbloffR = crate::FieldReader<u32>;
#[doc = "Field `TBLOFF` writer - Vector table base offset field"]
pub type TbloffW<'a, REG> = crate::FieldWriter<'a, REG, 21, u32>;
impl R {
    #[doc = "Bits 9:29 - Vector table base offset field"]
    #[inline(always)]
    pub fn tbloff(&self) -> TbloffR {
        TbloffR::new((self.bits >> 9) & 0x001f_ffff)
    }
}
impl W {
    #[doc = "Bits 9:29 - Vector table base offset field"]
    #[inline(always)]
    #[must_use]
    pub fn tbloff(&mut self) -> TbloffW<VtorSpec> {
        TbloffW::new(self, 9)
    }
}
#[doc = "Vector table offset register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vtor::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vtor::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct VtorSpec;
impl crate::RegisterSpec for VtorSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`vtor::R`](R) reader structure"]
impl crate::Readable for VtorSpec {}
#[doc = "`write(|w| ..)` method takes [`vtor::W`](W) writer structure"]
impl crate::Writable for VtorSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets VTOR to value 0"]
impl crate::Resettable for VtorSpec {
    const RESET_VALUE: u32 = 0;
}
