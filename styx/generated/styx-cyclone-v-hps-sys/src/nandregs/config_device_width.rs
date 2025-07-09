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
#[doc = "Register `config_device_width` reader"]
pub type R = crate::R<ConfigDeviceWidthSpec>;
#[doc = "Register `config_device_width` writer"]
pub type W = crate::W<ConfigDeviceWidthSpec>;
#[doc = "Field `value` reader - Controller will read Electronic Signature of devices and populate this field. Software could also choose to override the populated value although only one value is supported. The values in this field should be as follows\\[list\\]\\[*\\]2'h00 - 8bit device\\[*\\]All other values - Reserved\\[/list\\]"]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Controller will read Electronic Signature of devices and populate this field. Software could also choose to override the populated value although only one value is supported. The values in this field should be as follows\\[list\\]\\[*\\]2'h00 - 8bit device\\[*\\]All other values - Reserved\\[/list\\]"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Controller will read Electronic Signature of devices and populate this field. Software could also choose to override the populated value although only one value is supported. The values in this field should be as follows\\[list\\]\\[*\\]2'h00 - 8bit device\\[*\\]All other values - Reserved\\[/list\\]"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Controller will read Electronic Signature of devices and populate this field. Software could also choose to override the populated value although only one value is supported. The values in this field should be as follows\\[list\\]\\[*\\]2'h00 - 8bit device\\[*\\]All other values - Reserved\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigDeviceWidthSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "I/O width of attached devices\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_device_width::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_device_width::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigDeviceWidthSpec;
impl crate::RegisterSpec for ConfigDeviceWidthSpec {
    type Ux = u32;
    const OFFSET: u64 = 352u64;
}
#[doc = "`read()` method returns [`config_device_width::R`](R) reader structure"]
impl crate::Readable for ConfigDeviceWidthSpec {}
#[doc = "`write(|w| ..)` method takes [`config_device_width::W`](W) writer structure"]
impl crate::Writable for ConfigDeviceWidthSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_device_width to value 0x03"]
impl crate::Resettable for ConfigDeviceWidthSpec {
    const RESET_VALUE: u32 = 0x03;
}
