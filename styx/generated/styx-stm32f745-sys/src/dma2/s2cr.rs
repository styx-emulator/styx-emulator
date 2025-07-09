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
#[doc = "Register `S2CR` reader"]
pub type R = crate::R<S2crSpec>;
#[doc = "Register `S2CR` writer"]
pub type W = crate::W<S2crSpec>;
#[doc = "Field `EN` reader - Stream enable / flag stream ready when read low"]
pub type EnR = crate::BitReader;
#[doc = "Field `EN` writer - Stream enable / flag stream ready when read low"]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMEIE` reader - Direct mode error interrupt enable"]
pub type DmeieR = crate::BitReader;
#[doc = "Field `DMEIE` writer - Direct mode error interrupt enable"]
pub type DmeieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TEIE` reader - Transfer error interrupt enable"]
pub type TeieR = crate::BitReader;
#[doc = "Field `TEIE` writer - Transfer error interrupt enable"]
pub type TeieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HTIE` reader - Half transfer interrupt enable"]
pub type HtieR = crate::BitReader;
#[doc = "Field `HTIE` writer - Half transfer interrupt enable"]
pub type HtieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TCIE` reader - Transfer complete interrupt enable"]
pub type TcieR = crate::BitReader;
#[doc = "Field `TCIE` writer - Transfer complete interrupt enable"]
pub type TcieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PFCTRL` reader - Peripheral flow controller"]
pub type PfctrlR = crate::BitReader;
#[doc = "Field `PFCTRL` writer - Peripheral flow controller"]
pub type PfctrlW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DIR` reader - Data transfer direction"]
pub type DirR = crate::FieldReader;
#[doc = "Field `DIR` writer - Data transfer direction"]
pub type DirW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `CIRC` reader - Circular mode"]
pub type CircR = crate::BitReader;
#[doc = "Field `CIRC` writer - Circular mode"]
pub type CircW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PINC` reader - Peripheral increment mode"]
pub type PincR = crate::BitReader;
#[doc = "Field `PINC` writer - Peripheral increment mode"]
pub type PincW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MINC` reader - Memory increment mode"]
pub type MincR = crate::BitReader;
#[doc = "Field `MINC` writer - Memory increment mode"]
pub type MincW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PSIZE` reader - Peripheral data size"]
pub type PsizeR = crate::FieldReader;
#[doc = "Field `PSIZE` writer - Peripheral data size"]
pub type PsizeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `MSIZE` reader - Memory data size"]
pub type MsizeR = crate::FieldReader;
#[doc = "Field `MSIZE` writer - Memory data size"]
pub type MsizeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `PINCOS` reader - Peripheral increment offset size"]
pub type PincosR = crate::BitReader;
#[doc = "Field `PINCOS` writer - Peripheral increment offset size"]
pub type PincosW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PL` reader - Priority level"]
pub type PlR = crate::FieldReader;
#[doc = "Field `PL` writer - Priority level"]
pub type PlW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `DBM` reader - Double buffer mode"]
pub type DbmR = crate::BitReader;
#[doc = "Field `DBM` writer - Double buffer mode"]
pub type DbmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CT` reader - Current target (only in double buffer mode)"]
pub type CtR = crate::BitReader;
#[doc = "Field `CT` writer - Current target (only in double buffer mode)"]
pub type CtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ACK` reader - ACK"]
pub type AckR = crate::BitReader;
#[doc = "Field `ACK` writer - ACK"]
pub type AckW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PBURST` reader - Peripheral burst transfer configuration"]
pub type PburstR = crate::FieldReader;
#[doc = "Field `PBURST` writer - Peripheral burst transfer configuration"]
pub type PburstW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `MBURST` reader - Memory burst transfer configuration"]
pub type MburstR = crate::FieldReader;
#[doc = "Field `MBURST` writer - Memory burst transfer configuration"]
pub type MburstW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `CHSEL` reader - Channel selection"]
pub type ChselR = crate::FieldReader;
#[doc = "Field `CHSEL` writer - Channel selection"]
pub type ChselW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bit 0 - Stream enable / flag stream ready when read low"]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Direct mode error interrupt enable"]
    #[inline(always)]
    pub fn dmeie(&self) -> DmeieR {
        DmeieR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Transfer error interrupt enable"]
    #[inline(always)]
    pub fn teie(&self) -> TeieR {
        TeieR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Half transfer interrupt enable"]
    #[inline(always)]
    pub fn htie(&self) -> HtieR {
        HtieR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Transfer complete interrupt enable"]
    #[inline(always)]
    pub fn tcie(&self) -> TcieR {
        TcieR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Peripheral flow controller"]
    #[inline(always)]
    pub fn pfctrl(&self) -> PfctrlR {
        PfctrlR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bits 6:7 - Data transfer direction"]
    #[inline(always)]
    pub fn dir(&self) -> DirR {
        DirR::new(((self.bits >> 6) & 3) as u8)
    }
    #[doc = "Bit 8 - Circular mode"]
    #[inline(always)]
    pub fn circ(&self) -> CircR {
        CircR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Peripheral increment mode"]
    #[inline(always)]
    pub fn pinc(&self) -> PincR {
        PincR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Memory increment mode"]
    #[inline(always)]
    pub fn minc(&self) -> MincR {
        MincR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bits 11:12 - Peripheral data size"]
    #[inline(always)]
    pub fn psize(&self) -> PsizeR {
        PsizeR::new(((self.bits >> 11) & 3) as u8)
    }
    #[doc = "Bits 13:14 - Memory data size"]
    #[inline(always)]
    pub fn msize(&self) -> MsizeR {
        MsizeR::new(((self.bits >> 13) & 3) as u8)
    }
    #[doc = "Bit 15 - Peripheral increment offset size"]
    #[inline(always)]
    pub fn pincos(&self) -> PincosR {
        PincosR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bits 16:17 - Priority level"]
    #[inline(always)]
    pub fn pl(&self) -> PlR {
        PlR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bit 18 - Double buffer mode"]
    #[inline(always)]
    pub fn dbm(&self) -> DbmR {
        DbmR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Current target (only in double buffer mode)"]
    #[inline(always)]
    pub fn ct(&self) -> CtR {
        CtR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - ACK"]
    #[inline(always)]
    pub fn ack(&self) -> AckR {
        AckR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bits 21:22 - Peripheral burst transfer configuration"]
    #[inline(always)]
    pub fn pburst(&self) -> PburstR {
        PburstR::new(((self.bits >> 21) & 3) as u8)
    }
    #[doc = "Bits 23:24 - Memory burst transfer configuration"]
    #[inline(always)]
    pub fn mburst(&self) -> MburstR {
        MburstR::new(((self.bits >> 23) & 3) as u8)
    }
    #[doc = "Bits 25:28 - Channel selection"]
    #[inline(always)]
    pub fn chsel(&self) -> ChselR {
        ChselR::new(((self.bits >> 25) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Stream enable / flag stream ready when read low"]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<S2crSpec> {
        EnW::new(self, 0)
    }
    #[doc = "Bit 1 - Direct mode error interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn dmeie(&mut self) -> DmeieW<S2crSpec> {
        DmeieW::new(self, 1)
    }
    #[doc = "Bit 2 - Transfer error interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn teie(&mut self) -> TeieW<S2crSpec> {
        TeieW::new(self, 2)
    }
    #[doc = "Bit 3 - Half transfer interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn htie(&mut self) -> HtieW<S2crSpec> {
        HtieW::new(self, 3)
    }
    #[doc = "Bit 4 - Transfer complete interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn tcie(&mut self) -> TcieW<S2crSpec> {
        TcieW::new(self, 4)
    }
    #[doc = "Bit 5 - Peripheral flow controller"]
    #[inline(always)]
    #[must_use]
    pub fn pfctrl(&mut self) -> PfctrlW<S2crSpec> {
        PfctrlW::new(self, 5)
    }
    #[doc = "Bits 6:7 - Data transfer direction"]
    #[inline(always)]
    #[must_use]
    pub fn dir(&mut self) -> DirW<S2crSpec> {
        DirW::new(self, 6)
    }
    #[doc = "Bit 8 - Circular mode"]
    #[inline(always)]
    #[must_use]
    pub fn circ(&mut self) -> CircW<S2crSpec> {
        CircW::new(self, 8)
    }
    #[doc = "Bit 9 - Peripheral increment mode"]
    #[inline(always)]
    #[must_use]
    pub fn pinc(&mut self) -> PincW<S2crSpec> {
        PincW::new(self, 9)
    }
    #[doc = "Bit 10 - Memory increment mode"]
    #[inline(always)]
    #[must_use]
    pub fn minc(&mut self) -> MincW<S2crSpec> {
        MincW::new(self, 10)
    }
    #[doc = "Bits 11:12 - Peripheral data size"]
    #[inline(always)]
    #[must_use]
    pub fn psize(&mut self) -> PsizeW<S2crSpec> {
        PsizeW::new(self, 11)
    }
    #[doc = "Bits 13:14 - Memory data size"]
    #[inline(always)]
    #[must_use]
    pub fn msize(&mut self) -> MsizeW<S2crSpec> {
        MsizeW::new(self, 13)
    }
    #[doc = "Bit 15 - Peripheral increment offset size"]
    #[inline(always)]
    #[must_use]
    pub fn pincos(&mut self) -> PincosW<S2crSpec> {
        PincosW::new(self, 15)
    }
    #[doc = "Bits 16:17 - Priority level"]
    #[inline(always)]
    #[must_use]
    pub fn pl(&mut self) -> PlW<S2crSpec> {
        PlW::new(self, 16)
    }
    #[doc = "Bit 18 - Double buffer mode"]
    #[inline(always)]
    #[must_use]
    pub fn dbm(&mut self) -> DbmW<S2crSpec> {
        DbmW::new(self, 18)
    }
    #[doc = "Bit 19 - Current target (only in double buffer mode)"]
    #[inline(always)]
    #[must_use]
    pub fn ct(&mut self) -> CtW<S2crSpec> {
        CtW::new(self, 19)
    }
    #[doc = "Bit 20 - ACK"]
    #[inline(always)]
    #[must_use]
    pub fn ack(&mut self) -> AckW<S2crSpec> {
        AckW::new(self, 20)
    }
    #[doc = "Bits 21:22 - Peripheral burst transfer configuration"]
    #[inline(always)]
    #[must_use]
    pub fn pburst(&mut self) -> PburstW<S2crSpec> {
        PburstW::new(self, 21)
    }
    #[doc = "Bits 23:24 - Memory burst transfer configuration"]
    #[inline(always)]
    #[must_use]
    pub fn mburst(&mut self) -> MburstW<S2crSpec> {
        MburstW::new(self, 23)
    }
    #[doc = "Bits 25:28 - Channel selection"]
    #[inline(always)]
    #[must_use]
    pub fn chsel(&mut self) -> ChselW<S2crSpec> {
        ChselW::new(self, 25)
    }
}
#[doc = "stream x configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s2cr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s2cr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct S2crSpec;
impl crate::RegisterSpec for S2crSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`s2cr::R`](R) reader structure"]
impl crate::Readable for S2crSpec {}
#[doc = "`write(|w| ..)` method takes [`s2cr::W`](W) writer structure"]
impl crate::Writable for S2crSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets S2CR to value 0"]
impl crate::Resettable for S2crSpec {
    const RESET_VALUE: u32 = 0;
}
