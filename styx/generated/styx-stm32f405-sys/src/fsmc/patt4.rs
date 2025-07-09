// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PATT4` reader"]
pub type R = crate::R<Patt4Spec>;
#[doc = "Register `PATT4` writer"]
pub type W = crate::W<Patt4Spec>;
#[doc = "Field `ATTSETx` reader - ATTSETx"]
pub type AttsetxR = crate::FieldReader;
#[doc = "Field `ATTSETx` writer - ATTSETx"]
pub type AttsetxW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `ATTWAITx` reader - ATTWAITx"]
pub type AttwaitxR = crate::FieldReader;
#[doc = "Field `ATTWAITx` writer - ATTWAITx"]
pub type AttwaitxW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `ATTHOLDx` reader - ATTHOLDx"]
pub type AttholdxR = crate::FieldReader;
#[doc = "Field `ATTHOLDx` writer - ATTHOLDx"]
pub type AttholdxW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `ATTHIZx` reader - ATTHIZx"]
pub type AtthizxR = crate::FieldReader;
#[doc = "Field `ATTHIZx` writer - ATTHIZx"]
pub type AtthizxW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - ATTSETx"]
    #[inline(always)]
    pub fn attsetx(&self) -> AttsetxR {
        AttsetxR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - ATTWAITx"]
    #[inline(always)]
    pub fn attwaitx(&self) -> AttwaitxR {
        AttwaitxR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - ATTHOLDx"]
    #[inline(always)]
    pub fn attholdx(&self) -> AttholdxR {
        AttholdxR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - ATTHIZx"]
    #[inline(always)]
    pub fn atthizx(&self) -> AtthizxR {
        AtthizxR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - ATTSETx"]
    #[inline(always)]
    #[must_use]
    pub fn attsetx(&mut self) -> AttsetxW<Patt4Spec> {
        AttsetxW::new(self, 0)
    }
    #[doc = "Bits 8:15 - ATTWAITx"]
    #[inline(always)]
    #[must_use]
    pub fn attwaitx(&mut self) -> AttwaitxW<Patt4Spec> {
        AttwaitxW::new(self, 8)
    }
    #[doc = "Bits 16:23 - ATTHOLDx"]
    #[inline(always)]
    #[must_use]
    pub fn attholdx(&mut self) -> AttholdxW<Patt4Spec> {
        AttholdxW::new(self, 16)
    }
    #[doc = "Bits 24:31 - ATTHIZx"]
    #[inline(always)]
    #[must_use]
    pub fn atthizx(&mut self) -> AtthizxW<Patt4Spec> {
        AtthizxW::new(self, 24)
    }
}
#[doc = "Attribute memory space timing register 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`patt4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`patt4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Patt4Spec;
impl crate::RegisterSpec for Patt4Spec {
    type Ux = u32;
    const OFFSET: u64 = 172u64;
}
#[doc = "`read()` method returns [`patt4::R`](R) reader structure"]
impl crate::Readable for Patt4Spec {}
#[doc = "`write(|w| ..)` method takes [`patt4::W`](W) writer structure"]
impl crate::Writable for Patt4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PATT4 to value 0xfcfc_fcfc"]
impl crate::Resettable for Patt4Spec {
    const RESET_VALUE: u32 = 0xfcfc_fcfc;
}
