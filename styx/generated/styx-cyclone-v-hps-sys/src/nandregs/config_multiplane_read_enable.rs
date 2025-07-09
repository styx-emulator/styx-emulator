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
#[doc = "Register `config_multiplane_read_enable` reader"]
pub type R = crate::R<ConfigMultiplaneReadEnableSpec>;
#[doc = "Register `config_multiplane_read_enable` writer"]
pub type W = crate::W<ConfigMultiplaneReadEnableSpec>;
#[doc = "Field `flag` reader - Certain devices support dedicated multiplane read command sequences to read data in the same fashion as is written with multiplane program commands. This bit set should be set for the above devices. When not set, pipeline reads in multiplane mode will still happen in the order of multiplane writes, though normal read command sequences will be issued to the device. \\[list\\]\\[*\\]1 - Device supports multiplane read sequence \\[*\\]0 - Device does not support multiplane read sequence\\[/list\\]"]
pub type FlagR = crate::BitReader;
#[doc = "Field `flag` writer - Certain devices support dedicated multiplane read command sequences to read data in the same fashion as is written with multiplane program commands. This bit set should be set for the above devices. When not set, pipeline reads in multiplane mode will still happen in the order of multiplane writes, though normal read command sequences will be issued to the device. \\[list\\]\\[*\\]1 - Device supports multiplane read sequence \\[*\\]0 - Device does not support multiplane read sequence\\[/list\\]"]
pub type FlagW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Certain devices support dedicated multiplane read command sequences to read data in the same fashion as is written with multiplane program commands. This bit set should be set for the above devices. When not set, pipeline reads in multiplane mode will still happen in the order of multiplane writes, though normal read command sequences will be issued to the device. \\[list\\]\\[*\\]1 - Device supports multiplane read sequence \\[*\\]0 - Device does not support multiplane read sequence\\[/list\\]"]
    #[inline(always)]
    pub fn flag(&self) -> FlagR {
        FlagR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Certain devices support dedicated multiplane read command sequences to read data in the same fashion as is written with multiplane program commands. This bit set should be set for the above devices. When not set, pipeline reads in multiplane mode will still happen in the order of multiplane writes, though normal read command sequences will be issued to the device. \\[list\\]\\[*\\]1 - Device supports multiplane read sequence \\[*\\]0 - Device does not support multiplane read sequence\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn flag(&mut self) -> FlagW<ConfigMultiplaneReadEnableSpec> {
        FlagW::new(self, 0)
    }
}
#[doc = "Device supports multiplane read command sequence\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_multiplane_read_enable::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_multiplane_read_enable::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigMultiplaneReadEnableSpec;
impl crate::RegisterSpec for ConfigMultiplaneReadEnableSpec {
    type Ux = u32;
    const OFFSET: u64 = 128u64;
}
#[doc = "`read()` method returns [`config_multiplane_read_enable::R`](R) reader structure"]
impl crate::Readable for ConfigMultiplaneReadEnableSpec {}
#[doc = "`write(|w| ..)` method takes [`config_multiplane_read_enable::W`](W) writer structure"]
impl crate::Writable for ConfigMultiplaneReadEnableSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_multiplane_read_enable to value 0"]
impl crate::Resettable for ConfigMultiplaneReadEnableSpec {
    const RESET_VALUE: u32 = 0;
}
