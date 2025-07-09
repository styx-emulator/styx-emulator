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
#[doc = "Register `config_spare_area_skip_bytes` reader"]
pub type R = crate::R<ConfigSpareAreaSkipBytesSpec>;
#[doc = "Register `config_spare_area_skip_bytes` writer"]
pub type W = crate::W<ConfigSpareAreaSkipBytesSpec>;
#[doc = "Field `value` reader - Number of bytes to skip from start of spare area before last ECC sector data starts. The bytes will be written with the value programmed in the spare_area_marker register. This register could be potentially used to preserve the bad block marker in the spare area by marking it good. The default value is zero which means no bytes will be skipped and last ECC sector will start from the beginning of spare area."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Number of bytes to skip from start of spare area before last ECC sector data starts. The bytes will be written with the value programmed in the spare_area_marker register. This register could be potentially used to preserve the bad block marker in the spare area by marking it good. The default value is zero which means no bytes will be skipped and last ECC sector will start from the beginning of spare area."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
impl R {
    #[doc = "Bits 0:5 - Number of bytes to skip from start of spare area before last ECC sector data starts. The bytes will be written with the value programmed in the spare_area_marker register. This register could be potentially used to preserve the bad block marker in the spare area by marking it good. The default value is zero which means no bytes will be skipped and last ECC sector will start from the beginning of spare area."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0x3f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:5 - Number of bytes to skip from start of spare area before last ECC sector data starts. The bytes will be written with the value programmed in the spare_area_marker register. This register could be potentially used to preserve the bad block marker in the spare area by marking it good. The default value is zero which means no bytes will be skipped and last ECC sector will start from the beginning of spare area."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigSpareAreaSkipBytesSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Spare area skip bytes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_spare_area_skip_bytes::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_spare_area_skip_bytes::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigSpareAreaSkipBytesSpec;
impl crate::RegisterSpec for ConfigSpareAreaSkipBytesSpec {
    type Ux = u32;
    const OFFSET: u64 = 560u64;
}
#[doc = "`read()` method returns [`config_spare_area_skip_bytes::R`](R) reader structure"]
impl crate::Readable for ConfigSpareAreaSkipBytesSpec {}
#[doc = "`write(|w| ..)` method takes [`config_spare_area_skip_bytes::W`](W) writer structure"]
impl crate::Writable for ConfigSpareAreaSkipBytesSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_spare_area_skip_bytes to value 0"]
impl crate::Resettable for ConfigSpareAreaSkipBytesSpec {
    const RESET_VALUE: u32 = 0;
}
