// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `secgrp_stm` reader"]
pub type R = crate::R<SecgrpStmSpec>;
#[doc = "Register `secgrp_stm` writer"]
pub type W = crate::W<SecgrpStmSpec>;
#[doc = "Field `s` reader - Controls whether secure or non-secure masters can access the STM slave."]
pub type SR = crate::BitReader;
#[doc = "Controls whether secure or non-secure masters can access the STM slave.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S {
    #[doc = "0: `0`"]
    Secure = 0,
    #[doc = "1: `1`"]
    Nonsecure = 1,
}
impl From<S> for bool {
    #[inline(always)]
    fn from(variant: S) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `s` writer - Controls whether secure or non-secure masters can access the STM slave."]
pub type SW<'a, REG> = crate::BitWriter<'a, REG, S>;
impl<'a, REG> SW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn secure(self) -> &'a mut crate::W<REG> {
        self.variant(S::Secure)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonsecure(self) -> &'a mut crate::W<REG> {
        self.variant(S::Nonsecure)
    }
}
impl R {
    #[doc = "Bit 0 - Controls whether secure or non-secure masters can access the STM slave."]
    #[inline(always)]
    pub fn s(&self) -> SR {
        SR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls whether secure or non-secure masters can access the STM slave."]
    #[inline(always)]
    #[must_use]
    pub fn s(&mut self) -> SW<SecgrpStmSpec> {
        SW::new(self, 0)
    }
}
#[doc = "Controls security settings for STM peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_stm::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SecgrpStmSpec;
impl crate::RegisterSpec for SecgrpStmSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`write(|w| ..)` method takes [`secgrp_stm::W`](W) writer structure"]
impl crate::Writable for SecgrpStmSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets secgrp_stm to value 0"]
impl crate::Resettable for SecgrpStmSpec {
    const RESET_VALUE: u32 = 0;
}
