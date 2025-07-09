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
#[doc = "Register `config_first_block_of_next_plane` reader"]
pub type R = crate::R<ConfigFirstBlockOfNextPlaneSpec>;
#[doc = "Register `config_first_block_of_next_plane` writer"]
pub type W = crate::W<ConfigFirstBlockOfNextPlaneSpec>;
#[doc = "Field `value` reader - This values informs the controller of the plane structure of the device. In case the device is a multi plane device and the value here is 1, the controller understands that the next plane starts from Block number 1 and in conjunction with the number of planes parameter can decide upon the distribution of blocks in a plane in the device."]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - This values informs the controller of the plane structure of the device. In case the device is a multi plane device and the value here is 1, the controller understands that the next plane starts from Block number 1 and in conjunction with the number of planes parameter can decide upon the distribution of blocks in a plane in the device."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - This values informs the controller of the plane structure of the device. In case the device is a multi plane device and the value here is 1, the controller understands that the next plane starts from Block number 1 and in conjunction with the number of planes parameter can decide upon the distribution of blocks in a plane in the device."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - This values informs the controller of the plane structure of the device. In case the device is a multi plane device and the value here is 1, the controller understands that the next plane starts from Block number 1 and in conjunction with the number of planes parameter can decide upon the distribution of blocks in a plane in the device."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigFirstBlockOfNextPlaneSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "The starting block address of the next plane in a multi plane device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_first_block_of_next_plane::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_first_block_of_next_plane::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigFirstBlockOfNextPlaneSpec;
impl crate::RegisterSpec for ConfigFirstBlockOfNextPlaneSpec {
    type Ux = u32;
    const OFFSET: u64 = 624u64;
}
#[doc = "`read()` method returns [`config_first_block_of_next_plane::R`](R) reader structure"]
impl crate::Readable for ConfigFirstBlockOfNextPlaneSpec {}
#[doc = "`write(|w| ..)` method takes [`config_first_block_of_next_plane::W`](W) writer structure"]
impl crate::Writable for ConfigFirstBlockOfNextPlaneSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_first_block_of_next_plane to value 0x01"]
impl crate::Resettable for ConfigFirstBlockOfNextPlaneSpec {
    const RESET_VALUE: u32 = 0x01;
}
