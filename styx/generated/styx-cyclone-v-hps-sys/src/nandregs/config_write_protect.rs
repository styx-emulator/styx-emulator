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
#[doc = "Register `config_write_protect` reader"]
pub type R = crate::R<ConfigWriteProtectSpec>;
#[doc = "Register `config_write_protect` writer"]
pub type W = crate::W<ConfigWriteProtectSpec>;
#[doc = "Field `flag` reader - When the controller is in reset, the WP# pin is always asserted to the device. Once the reset is removed, the WP# is de-asserted. The software will then have to come and program this bit to assert/de-assert the same. \\[list\\]\\[*\\]1 - Write protect de-assert \\[*\\]0 - Write protect assert\\[/list\\]"]
pub type FlagR = crate::BitReader;
#[doc = "Field `flag` writer - When the controller is in reset, the WP# pin is always asserted to the device. Once the reset is removed, the WP# is de-asserted. The software will then have to come and program this bit to assert/de-assert the same. \\[list\\]\\[*\\]1 - Write protect de-assert \\[*\\]0 - Write protect assert\\[/list\\]"]
pub type FlagW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - When the controller is in reset, the WP# pin is always asserted to the device. Once the reset is removed, the WP# is de-asserted. The software will then have to come and program this bit to assert/de-assert the same. \\[list\\]\\[*\\]1 - Write protect de-assert \\[*\\]0 - Write protect assert\\[/list\\]"]
    #[inline(always)]
    pub fn flag(&self) -> FlagR {
        FlagR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When the controller is in reset, the WP# pin is always asserted to the device. Once the reset is removed, the WP# is de-asserted. The software will then have to come and program this bit to assert/de-assert the same. \\[list\\]\\[*\\]1 - Write protect de-assert \\[*\\]0 - Write protect assert\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn flag(&mut self) -> FlagW<ConfigWriteProtectSpec> {
        FlagW::new(self, 0)
    }
}
#[doc = "This register is used to control the assertion/de-assertion of the WP# pin to the device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_write_protect::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_write_protect::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigWriteProtectSpec;
impl crate::RegisterSpec for ConfigWriteProtectSpec {
    type Ux = u32;
    const OFFSET: u64 = 640u64;
}
#[doc = "`read()` method returns [`config_write_protect::R`](R) reader structure"]
impl crate::Readable for ConfigWriteProtectSpec {}
#[doc = "`write(|w| ..)` method takes [`config_write_protect::W`](W) writer structure"]
impl crate::Writable for ConfigWriteProtectSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_write_protect to value 0x01"]
impl crate::Resettable for ConfigWriteProtectSpec {
    const RESET_VALUE: u32 = 0x01;
}
