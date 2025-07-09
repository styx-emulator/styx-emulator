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
#[doc = "Register `spi_version_id` reader"]
pub type R = crate::R<SpiVersionIdSpec>;
#[doc = "Register `spi_version_id` writer"]
pub type W = crate::W<SpiVersionIdSpec>;
#[doc = "Field `spi_version_id` reader - Contains the hex representation of the Synopsys component version. Consists of ASCII value for each number in the version."]
pub type SpiVersionIdR = crate::FieldReader<u32>;
#[doc = "Field `spi_version_id` writer - Contains the hex representation of the Synopsys component version. Consists of ASCII value for each number in the version."]
pub type SpiVersionIdW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Contains the hex representation of the Synopsys component version. Consists of ASCII value for each number in the version."]
    #[inline(always)]
    pub fn spi_version_id(&self) -> SpiVersionIdR {
        SpiVersionIdR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Contains the hex representation of the Synopsys component version. Consists of ASCII value for each number in the version."]
    #[inline(always)]
    #[must_use]
    pub fn spi_version_id(&mut self) -> SpiVersionIdW<SpiVersionIdSpec> {
        SpiVersionIdW::new(self, 0)
    }
}
#[doc = "Version ID Register value\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`spi_version_id::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`spi_version_id::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SpiVersionIdSpec;
impl crate::RegisterSpec for SpiVersionIdSpec {
    type Ux = u32;
    const OFFSET: u64 = 92u64;
}
#[doc = "`read()` method returns [`spi_version_id::R`](R) reader structure"]
impl crate::Readable for SpiVersionIdSpec {}
#[doc = "`write(|w| ..)` method takes [`spi_version_id::W`](W) writer structure"]
impl crate::Writable for SpiVersionIdSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets spi_version_id to value 0x3332_302a"]
impl crate::Resettable for SpiVersionIdSpec {
    const RESET_VALUE: u32 = 0x3332_302a;
}
