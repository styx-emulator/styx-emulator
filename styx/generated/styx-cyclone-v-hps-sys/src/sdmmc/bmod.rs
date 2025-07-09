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
#[doc = "Register `bmod` reader"]
pub type R = crate::R<BmodSpec>;
#[doc = "Register `bmod` writer"]
pub type W = crate::W<BmodSpec>;
#[doc = "This bit resets all internal registers of the DMA Controller. It is automatically cleared after 1 clock cycle.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Swr {
    #[doc = "1: `1`"]
    Sftreset = 1,
    #[doc = "0: `0`"]
    Nosftreset = 0,
}
impl From<Swr> for bool {
    #[inline(always)]
    fn from(variant: Swr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `swr` reader - This bit resets all internal registers of the DMA Controller. It is automatically cleared after 1 clock cycle."]
pub type SwrR = crate::BitReader<Swr>;
impl SwrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Swr {
        match self.bits {
            true => Swr::Sftreset,
            false => Swr::Nosftreset,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_sftreset(&self) -> bool {
        *self == Swr::Sftreset
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nosftreset(&self) -> bool {
        *self == Swr::Nosftreset
    }
}
#[doc = "Field `swr` writer - This bit resets all internal registers of the DMA Controller. It is automatically cleared after 1 clock cycle."]
pub type SwrW<'a, REG> = crate::BitWriter<'a, REG, Swr>;
impl<'a, REG> SwrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn sftreset(self) -> &'a mut crate::W<REG> {
        self.variant(Swr::Sftreset)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nosftreset(self) -> &'a mut crate::W<REG> {
        self.variant(Swr::Nosftreset)
    }
}
#[doc = "Controls whether the AHB Master interface performs fixed burst transfers or not. Will use only SINGLE, INCR4, INCR8 or INCR16 during start of normal burst transfers.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fb {
    #[doc = "1: `1`"]
    Fixedbrst = 1,
    #[doc = "0: `0`"]
    Nofixedbrst = 0,
}
impl From<Fb> for bool {
    #[inline(always)]
    fn from(variant: Fb) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fb` reader - Controls whether the AHB Master interface performs fixed burst transfers or not. Will use only SINGLE, INCR4, INCR8 or INCR16 during start of normal burst transfers."]
pub type FbR = crate::BitReader<Fb>;
impl FbR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fb {
        match self.bits {
            true => Fb::Fixedbrst,
            false => Fb::Nofixedbrst,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fixedbrst(&self) -> bool {
        *self == Fb::Fixedbrst
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nofixedbrst(&self) -> bool {
        *self == Fb::Nofixedbrst
    }
}
#[doc = "Field `fb` writer - Controls whether the AHB Master interface performs fixed burst transfers or not. Will use only SINGLE, INCR4, INCR8 or INCR16 during start of normal burst transfers."]
pub type FbW<'a, REG> = crate::BitWriter<'a, REG, Fb>;
impl<'a, REG> FbW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn fixedbrst(self) -> &'a mut crate::W<REG> {
        self.variant(Fb::Fixedbrst)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nofixedbrst(self) -> &'a mut crate::W<REG> {
        self.variant(Fb::Nofixedbrst)
    }
}
#[doc = "Field `dsl` reader - Specifies the number of HWord/Word/Dword (depending on 16/32/64-bit bus) to skip between two unchained descriptors."]
pub type DslR = crate::FieldReader;
#[doc = "Field `dsl` writer - Specifies the number of HWord/Word/Dword (depending on 16/32/64-bit bus) to skip between two unchained descriptors."]
pub type DslW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Enables and Disables Internal DMA.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum De {
    #[doc = "1: `1`"]
    Enabled = 1,
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<De> for bool {
    #[inline(always)]
    fn from(variant: De) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `de` reader - Enables and Disables Internal DMA."]
pub type DeR = crate::BitReader<De>;
impl DeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> De {
        match self.bits {
            true => De::Enabled,
            false => De::Disabled,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == De::Enabled
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == De::Disabled
    }
}
#[doc = "Field `de` writer - Enables and Disables Internal DMA."]
pub type DeW<'a, REG> = crate::BitWriter<'a, REG, De>;
impl<'a, REG> DeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(De::Enabled)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(De::Disabled)
    }
}
#[doc = "These bits indicate the maximum number of beats to be performed in one IDMAC transaction. The IDMAC will always attempt to burst as specified in PBL each time it starts a Burst transfer on the host bus. This value is the mirror of MSIZE of FIFOTH register. In order to change this value, write the required value to FIFOTH register. This is an encode value as follows.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Pbl {
    #[doc = "0: `0`"]
    Trans1 = 0,
    #[doc = "1: `1`"]
    Trans4 = 1,
    #[doc = "2: `10`"]
    Trans8 = 2,
    #[doc = "3: `11`"]
    Trans16 = 3,
    #[doc = "4: `100`"]
    Trans32 = 4,
    #[doc = "5: `101`"]
    Trans64 = 5,
    #[doc = "6: `110`"]
    Trans128 = 6,
    #[doc = "7: `111`"]
    Trans256 = 7,
}
impl From<Pbl> for u8 {
    #[inline(always)]
    fn from(variant: Pbl) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Pbl {
    type Ux = u8;
}
#[doc = "Field `pbl` reader - These bits indicate the maximum number of beats to be performed in one IDMAC transaction. The IDMAC will always attempt to burst as specified in PBL each time it starts a Burst transfer on the host bus. This value is the mirror of MSIZE of FIFOTH register. In order to change this value, write the required value to FIFOTH register. This is an encode value as follows."]
pub type PblR = crate::FieldReader<Pbl>;
impl PblR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pbl {
        match self.bits {
            0 => Pbl::Trans1,
            1 => Pbl::Trans4,
            2 => Pbl::Trans8,
            3 => Pbl::Trans16,
            4 => Pbl::Trans32,
            5 => Pbl::Trans64,
            6 => Pbl::Trans128,
            7 => Pbl::Trans256,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_trans1(&self) -> bool {
        *self == Pbl::Trans1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_trans4(&self) -> bool {
        *self == Pbl::Trans4
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_trans8(&self) -> bool {
        *self == Pbl::Trans8
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_trans16(&self) -> bool {
        *self == Pbl::Trans16
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_trans32(&self) -> bool {
        *self == Pbl::Trans32
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_trans64(&self) -> bool {
        *self == Pbl::Trans64
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_trans128(&self) -> bool {
        *self == Pbl::Trans128
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_trans256(&self) -> bool {
        *self == Pbl::Trans256
    }
}
#[doc = "Field `pbl` writer - These bits indicate the maximum number of beats to be performed in one IDMAC transaction. The IDMAC will always attempt to burst as specified in PBL each time it starts a Burst transfer on the host bus. This value is the mirror of MSIZE of FIFOTH register. In order to change this value, write the required value to FIFOTH register. This is an encode value as follows."]
pub type PblW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bit 0 - This bit resets all internal registers of the DMA Controller. It is automatically cleared after 1 clock cycle."]
    #[inline(always)]
    pub fn swr(&self) -> SwrR {
        SwrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls whether the AHB Master interface performs fixed burst transfers or not. Will use only SINGLE, INCR4, INCR8 or INCR16 during start of normal burst transfers."]
    #[inline(always)]
    pub fn fb(&self) -> FbR {
        FbR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bits 2:6 - Specifies the number of HWord/Word/Dword (depending on 16/32/64-bit bus) to skip between two unchained descriptors."]
    #[inline(always)]
    pub fn dsl(&self) -> DslR {
        DslR::new(((self.bits >> 2) & 0x1f) as u8)
    }
    #[doc = "Bit 7 - Enables and Disables Internal DMA."]
    #[inline(always)]
    pub fn de(&self) -> DeR {
        DeR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:10 - These bits indicate the maximum number of beats to be performed in one IDMAC transaction. The IDMAC will always attempt to burst as specified in PBL each time it starts a Burst transfer on the host bus. This value is the mirror of MSIZE of FIFOTH register. In order to change this value, write the required value to FIFOTH register. This is an encode value as follows."]
    #[inline(always)]
    pub fn pbl(&self) -> PblR {
        PblR::new(((self.bits >> 8) & 7) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - This bit resets all internal registers of the DMA Controller. It is automatically cleared after 1 clock cycle."]
    #[inline(always)]
    #[must_use]
    pub fn swr(&mut self) -> SwrW<BmodSpec> {
        SwrW::new(self, 0)
    }
    #[doc = "Bit 1 - Controls whether the AHB Master interface performs fixed burst transfers or not. Will use only SINGLE, INCR4, INCR8 or INCR16 during start of normal burst transfers."]
    #[inline(always)]
    #[must_use]
    pub fn fb(&mut self) -> FbW<BmodSpec> {
        FbW::new(self, 1)
    }
    #[doc = "Bits 2:6 - Specifies the number of HWord/Word/Dword (depending on 16/32/64-bit bus) to skip between two unchained descriptors."]
    #[inline(always)]
    #[must_use]
    pub fn dsl(&mut self) -> DslW<BmodSpec> {
        DslW::new(self, 2)
    }
    #[doc = "Bit 7 - Enables and Disables Internal DMA."]
    #[inline(always)]
    #[must_use]
    pub fn de(&mut self) -> DeW<BmodSpec> {
        DeW::new(self, 7)
    }
    #[doc = "Bits 8:10 - These bits indicate the maximum number of beats to be performed in one IDMAC transaction. The IDMAC will always attempt to burst as specified in PBL each time it starts a Burst transfer on the host bus. This value is the mirror of MSIZE of FIFOTH register. In order to change this value, write the required value to FIFOTH register. This is an encode value as follows."]
    #[inline(always)]
    #[must_use]
    pub fn pbl(&mut self) -> PblW<BmodSpec> {
        PblW::new(self, 8)
    }
}
#[doc = "Details different bus operating modes.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bmod::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bmod::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BmodSpec;
impl crate::RegisterSpec for BmodSpec {
    type Ux = u32;
    const OFFSET: u64 = 128u64;
}
#[doc = "`read()` method returns [`bmod::R`](R) reader structure"]
impl crate::Readable for BmodSpec {}
#[doc = "`write(|w| ..)` method takes [`bmod::W`](W) writer structure"]
impl crate::Writable for BmodSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets bmod to value 0"]
impl crate::Resettable for BmodSpec {
    const RESET_VALUE: u32 = 0;
}
