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
#[doc = "Register `AIRCR` reader"]
pub type R = crate::R<AircrSpec>;
#[doc = "Register `AIRCR` writer"]
pub type W = crate::W<AircrSpec>;
#[doc = "Field `VECTRESET` reader - VECTRESET"]
pub type VectresetR = crate::BitReader;
#[doc = "Field `VECTRESET` writer - VECTRESET"]
pub type VectresetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VECTCLRACTIVE` reader - VECTCLRACTIVE"]
pub type VectclractiveR = crate::BitReader;
#[doc = "Field `VECTCLRACTIVE` writer - VECTCLRACTIVE"]
pub type VectclractiveW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SYSRESETREQ` reader - SYSRESETREQ"]
pub type SysresetreqR = crate::BitReader;
#[doc = "Field `SYSRESETREQ` writer - SYSRESETREQ"]
pub type SysresetreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PRIGROUP` reader - PRIGROUP"]
pub type PrigroupR = crate::FieldReader;
#[doc = "Field `PRIGROUP` writer - PRIGROUP"]
pub type PrigroupW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `ENDIANESS` reader - ENDIANESS"]
pub type EndianessR = crate::BitReader;
#[doc = "Field `ENDIANESS` writer - ENDIANESS"]
pub type EndianessW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VECTKEYSTAT` reader - Register key"]
pub type VectkeystatR = crate::FieldReader<u16>;
#[doc = "Field `VECTKEYSTAT` writer - Register key"]
pub type VectkeystatW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bit 0 - VECTRESET"]
    #[inline(always)]
    pub fn vectreset(&self) -> VectresetR {
        VectresetR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - VECTCLRACTIVE"]
    #[inline(always)]
    pub fn vectclractive(&self) -> VectclractiveR {
        VectclractiveR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - SYSRESETREQ"]
    #[inline(always)]
    pub fn sysresetreq(&self) -> SysresetreqR {
        SysresetreqR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bits 8:10 - PRIGROUP"]
    #[inline(always)]
    pub fn prigroup(&self) -> PrigroupR {
        PrigroupR::new(((self.bits >> 8) & 7) as u8)
    }
    #[doc = "Bit 15 - ENDIANESS"]
    #[inline(always)]
    pub fn endianess(&self) -> EndianessR {
        EndianessR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bits 16:31 - Register key"]
    #[inline(always)]
    pub fn vectkeystat(&self) -> VectkeystatR {
        VectkeystatR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bit 0 - VECTRESET"]
    #[inline(always)]
    #[must_use]
    pub fn vectreset(&mut self) -> VectresetW<AircrSpec> {
        VectresetW::new(self, 0)
    }
    #[doc = "Bit 1 - VECTCLRACTIVE"]
    #[inline(always)]
    #[must_use]
    pub fn vectclractive(&mut self) -> VectclractiveW<AircrSpec> {
        VectclractiveW::new(self, 1)
    }
    #[doc = "Bit 2 - SYSRESETREQ"]
    #[inline(always)]
    #[must_use]
    pub fn sysresetreq(&mut self) -> SysresetreqW<AircrSpec> {
        SysresetreqW::new(self, 2)
    }
    #[doc = "Bits 8:10 - PRIGROUP"]
    #[inline(always)]
    #[must_use]
    pub fn prigroup(&mut self) -> PrigroupW<AircrSpec> {
        PrigroupW::new(self, 8)
    }
    #[doc = "Bit 15 - ENDIANESS"]
    #[inline(always)]
    #[must_use]
    pub fn endianess(&mut self) -> EndianessW<AircrSpec> {
        EndianessW::new(self, 15)
    }
    #[doc = "Bits 16:31 - Register key"]
    #[inline(always)]
    #[must_use]
    pub fn vectkeystat(&mut self) -> VectkeystatW<AircrSpec> {
        VectkeystatW::new(self, 16)
    }
}
#[doc = "Application interrupt and reset control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`aircr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`aircr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct AircrSpec;
impl crate::RegisterSpec for AircrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`aircr::R`](R) reader structure"]
impl crate::Readable for AircrSpec {}
#[doc = "`write(|w| ..)` method takes [`aircr::W`](W) writer structure"]
impl crate::Writable for AircrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AIRCR to value 0"]
impl crate::Resettable for AircrSpec {
    const RESET_VALUE: u32 = 0;
}
