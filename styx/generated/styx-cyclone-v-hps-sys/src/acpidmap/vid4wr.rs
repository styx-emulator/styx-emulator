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
#[doc = "Register `vid4wr` reader"]
pub type R = crate::R<Vid4wrSpec>;
#[doc = "Register `vid4wr` writer"]
pub type W = crate::W<Vid4wrSpec>;
#[doc = "Field `user` reader - This value is propagated to SCU as AWUSERS."]
pub type UserR = crate::FieldReader;
#[doc = "Field `user` writer - This value is propagated to SCU as AWUSERS."]
pub type UserW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `page` reader - AWADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
pub type PageR = crate::FieldReader;
#[doc = "Field `page` writer - AWADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
pub type PageW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `mid` reader - The 12-bit ID of the master to remap to 3-bit virtual ID N, where N is the 3-bit ID to use."]
pub type MidR = crate::FieldReader<u16>;
#[doc = "Field `mid` writer - The 12-bit ID of the master to remap to 3-bit virtual ID N, where N is the 3-bit ID to use."]
pub type MidW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
#[doc = "Field `force` reader - Set to 1 to force the mapping between the 12-bit ID and 3-bit virtual ID N. Set to 0 to allow the 3-bit ID N to be dynamically allocated."]
pub type ForceR = crate::BitReader;
#[doc = "Field `force` writer - Set to 1 to force the mapping between the 12-bit ID and 3-bit virtual ID N. Set to 0 to allow the 3-bit ID N to be dynamically allocated."]
pub type ForceW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 4:8 - This value is propagated to SCU as AWUSERS."]
    #[inline(always)]
    pub fn user(&self) -> UserR {
        UserR::new(((self.bits >> 4) & 0x1f) as u8)
    }
    #[doc = "Bits 12:13 - AWADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
    #[inline(always)]
    pub fn page(&self) -> PageR {
        PageR::new(((self.bits >> 12) & 3) as u8)
    }
    #[doc = "Bits 16:27 - The 12-bit ID of the master to remap to 3-bit virtual ID N, where N is the 3-bit ID to use."]
    #[inline(always)]
    pub fn mid(&self) -> MidR {
        MidR::new(((self.bits >> 16) & 0x0fff) as u16)
    }
    #[doc = "Bit 31 - Set to 1 to force the mapping between the 12-bit ID and 3-bit virtual ID N. Set to 0 to allow the 3-bit ID N to be dynamically allocated."]
    #[inline(always)]
    pub fn force(&self) -> ForceR {
        ForceR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 4:8 - This value is propagated to SCU as AWUSERS."]
    #[inline(always)]
    #[must_use]
    pub fn user(&mut self) -> UserW<Vid4wrSpec> {
        UserW::new(self, 4)
    }
    #[doc = "Bits 12:13 - AWADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
    #[inline(always)]
    #[must_use]
    pub fn page(&mut self) -> PageW<Vid4wrSpec> {
        PageW::new(self, 12)
    }
    #[doc = "Bits 16:27 - The 12-bit ID of the master to remap to 3-bit virtual ID N, where N is the 3-bit ID to use."]
    #[inline(always)]
    #[must_use]
    pub fn mid(&mut self) -> MidW<Vid4wrSpec> {
        MidW::new(self, 16)
    }
    #[doc = "Bit 31 - Set to 1 to force the mapping between the 12-bit ID and 3-bit virtual ID N. Set to 0 to allow the 3-bit ID N to be dynamically allocated."]
    #[inline(always)]
    #[must_use]
    pub fn force(&mut self) -> ForceW<Vid4wrSpec> {
        ForceW::new(self, 31)
    }
}
#[doc = "The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid4wr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vid4wr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Vid4wrSpec;
impl crate::RegisterSpec for Vid4wrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`vid4wr::R`](R) reader structure"]
impl crate::Readable for Vid4wrSpec {}
#[doc = "`write(|w| ..)` method takes [`vid4wr::W`](W) writer structure"]
impl crate::Writable for Vid4wrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets vid4wr to value 0"]
impl crate::Resettable for Vid4wrSpec {
    const RESET_VALUE: u32 = 0;
}
