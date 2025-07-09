// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ARG` reader"]
pub type R = crate::R<ArgSpec>;
#[doc = "Register `ARG` writer"]
pub type W = crate::W<ArgSpec>;
#[doc = "Field `CMDARG` reader - Command argument"]
pub type CmdargR = crate::FieldReader<u32>;
#[doc = "Field `CMDARG` writer - Command argument"]
pub type CmdargW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Command argument"]
    #[inline(always)]
    pub fn cmdarg(&self) -> CmdargR {
        CmdargR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Command argument"]
    #[inline(always)]
    #[must_use]
    pub fn cmdarg(&mut self) -> CmdargW<ArgSpec> {
        CmdargW::new(self, 0)
    }
}
#[doc = "argument register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`arg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`arg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ArgSpec;
impl crate::RegisterSpec for ArgSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`arg::R`](R) reader structure"]
impl crate::Readable for ArgSpec {}
#[doc = "`write(|w| ..)` method takes [`arg::W`](W) writer structure"]
impl crate::Writable for ArgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ARG to value 0"]
impl crate::Resettable for ArgSpec {
    const RESET_VALUE: u32 = 0;
}
