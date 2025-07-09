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
#[doc = "Register `devwr` reader"]
pub type R = crate::R<DevwrSpec>;
#[doc = "Register `devwr` writer"]
pub type W = crate::W<DevwrSpec>;
#[doc = "Field `wropcode` reader - Write Opcode"]
pub type WropcodeR = crate::FieldReader;
#[doc = "Field `wropcode` writer - Write Opcode"]
pub type WropcodeW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Sets write address transfer width (1, 2, or 4 bits).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Addrwidth {
    #[doc = "0: `0`"]
    Single = 0,
    #[doc = "1: `1`"]
    Dual = 1,
    #[doc = "2: `10`"]
    Quad = 2,
}
impl From<Addrwidth> for u8 {
    #[inline(always)]
    fn from(variant: Addrwidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Addrwidth {
    type Ux = u8;
}
#[doc = "Field `addrwidth` reader - Sets write address transfer width (1, 2, or 4 bits)."]
pub type AddrwidthR = crate::FieldReader<Addrwidth>;
impl AddrwidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Addrwidth> {
        match self.bits {
            0 => Some(Addrwidth::Single),
            1 => Some(Addrwidth::Dual),
            2 => Some(Addrwidth::Quad),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_single(&self) -> bool {
        *self == Addrwidth::Single
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_dual(&self) -> bool {
        *self == Addrwidth::Dual
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_quad(&self) -> bool {
        *self == Addrwidth::Quad
    }
}
#[doc = "Field `addrwidth` writer - Sets write address transfer width (1, 2, or 4 bits)."]
pub type AddrwidthW<'a, REG> = crate::FieldWriter<'a, REG, 2, Addrwidth>;
impl<'a, REG> AddrwidthW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn single(self) -> &'a mut crate::W<REG> {
        self.variant(Addrwidth::Single)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn dual(self) -> &'a mut crate::W<REG> {
        self.variant(Addrwidth::Dual)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn quad(self) -> &'a mut crate::W<REG> {
        self.variant(Addrwidth::Quad)
    }
}
#[doc = "Sets write data transfer width (1, 2, or 4 bits).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Datawidth {
    #[doc = "0: `0`"]
    Single = 0,
    #[doc = "1: `1`"]
    Dual = 1,
    #[doc = "2: `10`"]
    Quad = 2,
}
impl From<Datawidth> for u8 {
    #[inline(always)]
    fn from(variant: Datawidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Datawidth {
    type Ux = u8;
}
#[doc = "Field `datawidth` reader - Sets write data transfer width (1, 2, or 4 bits)."]
pub type DatawidthR = crate::FieldReader<Datawidth>;
impl DatawidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Datawidth> {
        match self.bits {
            0 => Some(Datawidth::Single),
            1 => Some(Datawidth::Dual),
            2 => Some(Datawidth::Quad),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_single(&self) -> bool {
        *self == Datawidth::Single
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_dual(&self) -> bool {
        *self == Datawidth::Dual
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_quad(&self) -> bool {
        *self == Datawidth::Quad
    }
}
#[doc = "Field `datawidth` writer - Sets write data transfer width (1, 2, or 4 bits)."]
pub type DatawidthW<'a, REG> = crate::FieldWriter<'a, REG, 2, Datawidth>;
impl<'a, REG> DatawidthW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn single(self) -> &'a mut crate::W<REG> {
        self.variant(Datawidth::Single)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn dual(self) -> &'a mut crate::W<REG> {
        self.variant(Datawidth::Dual)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn quad(self) -> &'a mut crate::W<REG> {
        self.variant(Datawidth::Quad)
    }
}
#[doc = "Field `dummywrclks` reader - Number of dummy clock cycles required by device for write instruction."]
pub type DummywrclksR = crate::FieldReader;
#[doc = "Field `dummywrclks` writer - Number of dummy clock cycles required by device for write instruction."]
pub type DummywrclksW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:7 - Write Opcode"]
    #[inline(always)]
    pub fn wropcode(&self) -> WropcodeR {
        WropcodeR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 12:13 - Sets write address transfer width (1, 2, or 4 bits)."]
    #[inline(always)]
    pub fn addrwidth(&self) -> AddrwidthR {
        AddrwidthR::new(((self.bits >> 12) & 3) as u8)
    }
    #[doc = "Bits 16:17 - Sets write data transfer width (1, 2, or 4 bits)."]
    #[inline(always)]
    pub fn datawidth(&self) -> DatawidthR {
        DatawidthR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bits 24:28 - Number of dummy clock cycles required by device for write instruction."]
    #[inline(always)]
    pub fn dummywrclks(&self) -> DummywrclksR {
        DummywrclksR::new(((self.bits >> 24) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Write Opcode"]
    #[inline(always)]
    #[must_use]
    pub fn wropcode(&mut self) -> WropcodeW<DevwrSpec> {
        WropcodeW::new(self, 0)
    }
    #[doc = "Bits 12:13 - Sets write address transfer width (1, 2, or 4 bits)."]
    #[inline(always)]
    #[must_use]
    pub fn addrwidth(&mut self) -> AddrwidthW<DevwrSpec> {
        AddrwidthW::new(self, 12)
    }
    #[doc = "Bits 16:17 - Sets write data transfer width (1, 2, or 4 bits)."]
    #[inline(always)]
    #[must_use]
    pub fn datawidth(&mut self) -> DatawidthW<DevwrSpec> {
        DatawidthW::new(self, 16)
    }
    #[doc = "Bits 24:28 - Number of dummy clock cycles required by device for write instruction."]
    #[inline(always)]
    #[must_use]
    pub fn dummywrclks(&mut self) -> DummywrclksW<DevwrSpec> {
        DummywrclksW::new(self, 24)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devwr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devwr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevwrSpec;
impl crate::RegisterSpec for DevwrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`devwr::R`](R) reader structure"]
impl crate::Readable for DevwrSpec {}
#[doc = "`write(|w| ..)` method takes [`devwr::W`](W) writer structure"]
impl crate::Writable for DevwrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devwr to value 0x02"]
impl crate::Resettable for DevwrSpec {
    const RESET_VALUE: u32 = 0x02;
}
