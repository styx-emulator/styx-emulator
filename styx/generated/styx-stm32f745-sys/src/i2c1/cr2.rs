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
#[doc = "Register `CR2` reader"]
pub type R = crate::R<Cr2Spec>;
#[doc = "Register `CR2` writer"]
pub type W = crate::W<Cr2Spec>;
#[doc = "Field `SADD` reader - Slave address bit (master mode)"]
pub type SaddR = crate::FieldReader<u16>;
#[doc = "Field `SADD` writer - Slave address bit (master mode)"]
pub type SaddW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
#[doc = "Field `RD_WRN` reader - Transfer direction (master mode)"]
pub type RdWrnR = crate::BitReader;
#[doc = "Field `RD_WRN` writer - Transfer direction (master mode)"]
pub type RdWrnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADD10` reader - 10-bit addressing mode (master mode)"]
pub type Add10R = crate::BitReader;
#[doc = "Field `ADD10` writer - 10-bit addressing mode (master mode)"]
pub type Add10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HEAD10R` reader - 10-bit address header only read direction (master receiver mode)"]
pub type Head10rR = crate::BitReader;
#[doc = "Field `HEAD10R` writer - 10-bit address header only read direction (master receiver mode)"]
pub type Head10rW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `START` reader - Start generation"]
pub type StartR = crate::BitReader;
#[doc = "Field `START` writer - Start generation"]
pub type StartW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STOP` reader - Stop generation (master mode)"]
pub type StopR = crate::BitReader;
#[doc = "Field `STOP` writer - Stop generation (master mode)"]
pub type StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NACK` reader - NACK generation (slave mode)"]
pub type NackR = crate::BitReader;
#[doc = "Field `NACK` writer - NACK generation (slave mode)"]
pub type NackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NBYTES` reader - Number of bytes"]
pub type NbytesR = crate::FieldReader;
#[doc = "Field `NBYTES` writer - Number of bytes"]
pub type NbytesW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `RELOAD` reader - NBYTES reload mode"]
pub type ReloadR = crate::BitReader;
#[doc = "Field `RELOAD` writer - NBYTES reload mode"]
pub type ReloadW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AUTOEND` reader - Automatic end mode (master mode)"]
pub type AutoendR = crate::BitReader;
#[doc = "Field `AUTOEND` writer - Automatic end mode (master mode)"]
pub type AutoendW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PECBYTE` reader - Packet error checking byte"]
pub type PecbyteR = crate::BitReader;
#[doc = "Field `PECBYTE` writer - Packet error checking byte"]
pub type PecbyteW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:9 - Slave address bit (master mode)"]
    #[inline(always)]
    pub fn sadd(&self) -> SaddR {
        SaddR::new((self.bits & 0x03ff) as u16)
    }
    #[doc = "Bit 10 - Transfer direction (master mode)"]
    #[inline(always)]
    pub fn rd_wrn(&self) -> RdWrnR {
        RdWrnR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - 10-bit addressing mode (master mode)"]
    #[inline(always)]
    pub fn add10(&self) -> Add10R {
        Add10R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - 10-bit address header only read direction (master receiver mode)"]
    #[inline(always)]
    pub fn head10r(&self) -> Head10rR {
        Head10rR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Start generation"]
    #[inline(always)]
    pub fn start(&self) -> StartR {
        StartR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Stop generation (master mode)"]
    #[inline(always)]
    pub fn stop(&self) -> StopR {
        StopR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - NACK generation (slave mode)"]
    #[inline(always)]
    pub fn nack(&self) -> NackR {
        NackR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bits 16:23 - Number of bytes"]
    #[inline(always)]
    pub fn nbytes(&self) -> NbytesR {
        NbytesR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bit 24 - NBYTES reload mode"]
    #[inline(always)]
    pub fn reload(&self) -> ReloadR {
        ReloadR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Automatic end mode (master mode)"]
    #[inline(always)]
    pub fn autoend(&self) -> AutoendR {
        AutoendR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Packet error checking byte"]
    #[inline(always)]
    pub fn pecbyte(&self) -> PecbyteR {
        PecbyteR::new(((self.bits >> 26) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:9 - Slave address bit (master mode)"]
    #[inline(always)]
    #[must_use]
    pub fn sadd(&mut self) -> SaddW<Cr2Spec> {
        SaddW::new(self, 0)
    }
    #[doc = "Bit 10 - Transfer direction (master mode)"]
    #[inline(always)]
    #[must_use]
    pub fn rd_wrn(&mut self) -> RdWrnW<Cr2Spec> {
        RdWrnW::new(self, 10)
    }
    #[doc = "Bit 11 - 10-bit addressing mode (master mode)"]
    #[inline(always)]
    #[must_use]
    pub fn add10(&mut self) -> Add10W<Cr2Spec> {
        Add10W::new(self, 11)
    }
    #[doc = "Bit 12 - 10-bit address header only read direction (master receiver mode)"]
    #[inline(always)]
    #[must_use]
    pub fn head10r(&mut self) -> Head10rW<Cr2Spec> {
        Head10rW::new(self, 12)
    }
    #[doc = "Bit 13 - Start generation"]
    #[inline(always)]
    #[must_use]
    pub fn start(&mut self) -> StartW<Cr2Spec> {
        StartW::new(self, 13)
    }
    #[doc = "Bit 14 - Stop generation (master mode)"]
    #[inline(always)]
    #[must_use]
    pub fn stop(&mut self) -> StopW<Cr2Spec> {
        StopW::new(self, 14)
    }
    #[doc = "Bit 15 - NACK generation (slave mode)"]
    #[inline(always)]
    #[must_use]
    pub fn nack(&mut self) -> NackW<Cr2Spec> {
        NackW::new(self, 15)
    }
    #[doc = "Bits 16:23 - Number of bytes"]
    #[inline(always)]
    #[must_use]
    pub fn nbytes(&mut self) -> NbytesW<Cr2Spec> {
        NbytesW::new(self, 16)
    }
    #[doc = "Bit 24 - NBYTES reload mode"]
    #[inline(always)]
    #[must_use]
    pub fn reload(&mut self) -> ReloadW<Cr2Spec> {
        ReloadW::new(self, 24)
    }
    #[doc = "Bit 25 - Automatic end mode (master mode)"]
    #[inline(always)]
    #[must_use]
    pub fn autoend(&mut self) -> AutoendW<Cr2Spec> {
        AutoendW::new(self, 25)
    }
    #[doc = "Bit 26 - Packet error checking byte"]
    #[inline(always)]
    #[must_use]
    pub fn pecbyte(&mut self) -> PecbyteW<Cr2Spec> {
        PecbyteW::new(self, 26)
    }
}
#[doc = "Control register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Cr2Spec;
impl crate::RegisterSpec for Cr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`cr2::R`](R) reader structure"]
impl crate::Readable for Cr2Spec {}
#[doc = "`write(|w| ..)` method takes [`cr2::W`](W) writer structure"]
impl crate::Writable for Cr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR2 to value 0"]
impl crate::Resettable for Cr2Spec {
    const RESET_VALUE: u32 = 0;
}
