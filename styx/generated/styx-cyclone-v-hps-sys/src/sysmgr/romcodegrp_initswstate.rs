// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `romcodegrp_initswstate` reader"]
pub type R = crate::R<RomcodegrpInitswstateSpec>;
#[doc = "Register `romcodegrp_initswstate` writer"]
pub type W = crate::W<RomcodegrpInitswstateSpec>;
#[doc = "Written with magic value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Value {
    #[doc = "0: `0`"]
    Invalid = 0,
    #[doc = "1230198614: `1001001010100110101011101010110`"]
    Valid = 1230198614,
}
impl From<Value> for u32 {
    #[inline(always)]
    fn from(variant: Value) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Value {
    type Ux = u32;
}
#[doc = "Field `value` reader - Written with magic value."]
pub type ValueR = crate::FieldReader<Value>;
impl ValueR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Value> {
        match self.bits {
            0 => Some(Value::Invalid),
            1230198614 => Some(Value::Valid),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_invalid(&self) -> bool {
        *self == Value::Invalid
    }
    #[doc = "`1001001010100110101011101010110`"]
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        *self == Value::Valid
    }
}
#[doc = "Field `value` writer - Written with magic value."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 32, Value>;
impl<'a, REG> ValueW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u32>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn invalid(self) -> &'a mut crate::W<REG> {
        self.variant(Value::Invalid)
    }
    #[doc = "`1001001010100110101011101010110`"]
    #[inline(always)]
    pub fn valid(self) -> &'a mut crate::W<REG> {
        self.variant(Value::Valid)
    }
}
impl R {
    #[doc = "Bits 0:31 - Written with magic value."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Written with magic value."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<RomcodegrpInitswstateSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "The preloader software (loaded by the Boot ROM) writes the magic value 0x49535756 (ISWV in ASCII) to this register when it has reached a valid state.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_initswstate::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_initswstate::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RomcodegrpInitswstateSpec;
impl crate::RegisterSpec for RomcodegrpInitswstateSpec {
    type Ux = u32;
    const OFFSET: u64 = 200u64;
}
#[doc = "`read()` method returns [`romcodegrp_initswstate::R`](R) reader structure"]
impl crate::Readable for RomcodegrpInitswstateSpec {}
#[doc = "`write(|w| ..)` method takes [`romcodegrp_initswstate::W`](W) writer structure"]
impl crate::Writable for RomcodegrpInitswstateSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets romcodegrp_initswstate to value 0"]
impl crate::Resettable for RomcodegrpInitswstateSpec {
    const RESET_VALUE: u32 = 0;
}
