// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OAR2` reader"]
pub type R = crate::R<Oar2Spec>;
#[doc = "Register `OAR2` writer"]
pub type W = crate::W<Oar2Spec>;
#[doc = "Field `ENDUAL` reader - Dual addressing mode enable"]
pub type EndualR = crate::BitReader;
#[doc = "Field `ENDUAL` writer - Dual addressing mode enable"]
pub type EndualW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADD2` reader - Interface address"]
pub type Add2R = crate::FieldReader;
#[doc = "Field `ADD2` writer - Interface address"]
pub type Add2W<'a, REG> = crate::FieldWriter<'a, REG, 7>;
impl R {
    #[doc = "Bit 0 - Dual addressing mode enable"]
    #[inline(always)]
    pub fn endual(&self) -> EndualR {
        EndualR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:7 - Interface address"]
    #[inline(always)]
    pub fn add2(&self) -> Add2R {
        Add2R::new(((self.bits >> 1) & 0x7f) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Dual addressing mode enable"]
    #[inline(always)]
    #[must_use]
    pub fn endual(&mut self) -> EndualW<Oar2Spec> {
        EndualW::new(self, 0)
    }
    #[doc = "Bits 1:7 - Interface address"]
    #[inline(always)]
    #[must_use]
    pub fn add2(&mut self) -> Add2W<Oar2Spec> {
        Add2W::new(self, 1)
    }
}
#[doc = "Own address register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`oar2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`oar2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Oar2Spec;
impl crate::RegisterSpec for Oar2Spec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`oar2::R`](R) reader structure"]
impl crate::Readable for Oar2Spec {}
#[doc = "`write(|w| ..)` method takes [`oar2::W`](W) writer structure"]
impl crate::Writable for Oar2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OAR2 to value 0"]
impl crate::Resettable for Oar2Spec {
    const RESET_VALUE: u32 = 0;
}
