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
#[doc = "Register `ic_comp_version` reader"]
pub type R = crate::R<IcCompVersionSpec>;
#[doc = "Register `ic_comp_version` writer"]
pub type W = crate::W<IcCompVersionSpec>;
#[doc = "Specifies I2C release number (encoded as 4 ASCII characters)\n\nValue on reset: 825372714"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum IcCompVersion {
    #[doc = "825372714: `110001001100100011000000101010`"]
    Ver1_20a = 825372714,
}
impl From<IcCompVersion> for u32 {
    #[inline(always)]
    fn from(variant: IcCompVersion) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for IcCompVersion {
    type Ux = u32;
}
#[doc = "Field `ic_comp_version` reader - Specifies I2C release number (encoded as 4 ASCII characters)"]
pub type IcCompVersionR = crate::FieldReader<IcCompVersion>;
impl IcCompVersionR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<IcCompVersion> {
        match self.bits {
            825372714 => Some(IcCompVersion::Ver1_20a),
            _ => None,
        }
    }
    #[doc = "`110001001100100011000000101010`"]
    #[inline(always)]
    pub fn is_ver_1_20a(&self) -> bool {
        *self == IcCompVersion::Ver1_20a
    }
}
#[doc = "Field `ic_comp_version` writer - Specifies I2C release number (encoded as 4 ASCII characters)"]
pub type IcCompVersionW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Specifies I2C release number (encoded as 4 ASCII characters)"]
    #[inline(always)]
    pub fn ic_comp_version(&self) -> IcCompVersionR {
        IcCompVersionR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Specifies I2C release number (encoded as 4 ASCII characters)"]
    #[inline(always)]
    #[must_use]
    pub fn ic_comp_version(&mut self) -> IcCompVersionW<IcCompVersionSpec> {
        IcCompVersionW::new(self, 0)
    }
}
#[doc = "Describes the version of the I2C\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_comp_version::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcCompVersionSpec;
impl crate::RegisterSpec for IcCompVersionSpec {
    type Ux = u32;
    const OFFSET: u64 = 248u64;
}
#[doc = "`read()` method returns [`ic_comp_version::R`](R) reader structure"]
impl crate::Readable for IcCompVersionSpec {}
#[doc = "`reset()` method sets ic_comp_version to value 0x3132_302a"]
impl crate::Resettable for IcCompVersionSpec {
    const RESET_VALUE: u32 = 0x3132_302a;
}
