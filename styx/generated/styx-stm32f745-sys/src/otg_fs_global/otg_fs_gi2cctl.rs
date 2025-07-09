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
#[doc = "Register `OTG_FS_GI2CCTL` reader"]
pub type R = crate::R<OtgFsGi2cctlSpec>;
#[doc = "Register `OTG_FS_GI2CCTL` writer"]
pub type W = crate::W<OtgFsGi2cctlSpec>;
#[doc = "Field `RWDATA` reader - I2C Read/Write Data"]
pub type RwdataR = crate::FieldReader;
#[doc = "Field `RWDATA` writer - I2C Read/Write Data"]
pub type RwdataW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `REGADDR` reader - I2C Register Address"]
pub type RegaddrR = crate::FieldReader;
#[doc = "Field `REGADDR` writer - I2C Register Address"]
pub type RegaddrW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `ADDR` reader - I2C Address"]
pub type AddrR = crate::FieldReader;
#[doc = "Field `ADDR` writer - I2C Address"]
pub type AddrW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `I2CEN` reader - I2C Enable"]
pub type I2cenR = crate::BitReader;
#[doc = "Field `I2CEN` writer - I2C Enable"]
pub type I2cenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ACK` reader - I2C ACK"]
pub type AckR = crate::BitReader;
#[doc = "Field `ACK` writer - I2C ACK"]
pub type AckW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `I2CDEVADR` reader - I2C Device Address"]
pub type I2cdevadrR = crate::FieldReader;
#[doc = "Field `I2CDEVADR` writer - I2C Device Address"]
pub type I2cdevadrW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `I2CDATSE0` reader - I2C DatSe0 USB mode"]
pub type I2cdatse0R = crate::BitReader;
#[doc = "Field `I2CDATSE0` writer - I2C DatSe0 USB mode"]
pub type I2cdatse0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RW` reader - Read/Write Indicator"]
pub type RwR = crate::BitReader;
#[doc = "Field `RW` writer - Read/Write Indicator"]
pub type RwW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BSYDNE` reader - I2C Busy/Done"]
pub type BsydneR = crate::BitReader;
#[doc = "Field `BSYDNE` writer - I2C Busy/Done"]
pub type BsydneW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:7 - I2C Read/Write Data"]
    #[inline(always)]
    pub fn rwdata(&self) -> RwdataR {
        RwdataR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - I2C Register Address"]
    #[inline(always)]
    pub fn regaddr(&self) -> RegaddrR {
        RegaddrR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:22 - I2C Address"]
    #[inline(always)]
    pub fn addr(&self) -> AddrR {
        AddrR::new(((self.bits >> 16) & 0x7f) as u8)
    }
    #[doc = "Bit 23 - I2C Enable"]
    #[inline(always)]
    pub fn i2cen(&self) -> I2cenR {
        I2cenR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - I2C ACK"]
    #[inline(always)]
    pub fn ack(&self) -> AckR {
        AckR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bits 26:27 - I2C Device Address"]
    #[inline(always)]
    pub fn i2cdevadr(&self) -> I2cdevadrR {
        I2cdevadrR::new(((self.bits >> 26) & 3) as u8)
    }
    #[doc = "Bit 28 - I2C DatSe0 USB mode"]
    #[inline(always)]
    pub fn i2cdatse0(&self) -> I2cdatse0R {
        I2cdatse0R::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 30 - Read/Write Indicator"]
    #[inline(always)]
    pub fn rw(&self) -> RwR {
        RwR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - I2C Busy/Done"]
    #[inline(always)]
    pub fn bsydne(&self) -> BsydneR {
        BsydneR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:7 - I2C Read/Write Data"]
    #[inline(always)]
    #[must_use]
    pub fn rwdata(&mut self) -> RwdataW<OtgFsGi2cctlSpec> {
        RwdataW::new(self, 0)
    }
    #[doc = "Bits 8:15 - I2C Register Address"]
    #[inline(always)]
    #[must_use]
    pub fn regaddr(&mut self) -> RegaddrW<OtgFsGi2cctlSpec> {
        RegaddrW::new(self, 8)
    }
    #[doc = "Bits 16:22 - I2C Address"]
    #[inline(always)]
    #[must_use]
    pub fn addr(&mut self) -> AddrW<OtgFsGi2cctlSpec> {
        AddrW::new(self, 16)
    }
    #[doc = "Bit 23 - I2C Enable"]
    #[inline(always)]
    #[must_use]
    pub fn i2cen(&mut self) -> I2cenW<OtgFsGi2cctlSpec> {
        I2cenW::new(self, 23)
    }
    #[doc = "Bit 24 - I2C ACK"]
    #[inline(always)]
    #[must_use]
    pub fn ack(&mut self) -> AckW<OtgFsGi2cctlSpec> {
        AckW::new(self, 24)
    }
    #[doc = "Bits 26:27 - I2C Device Address"]
    #[inline(always)]
    #[must_use]
    pub fn i2cdevadr(&mut self) -> I2cdevadrW<OtgFsGi2cctlSpec> {
        I2cdevadrW::new(self, 26)
    }
    #[doc = "Bit 28 - I2C DatSe0 USB mode"]
    #[inline(always)]
    #[must_use]
    pub fn i2cdatse0(&mut self) -> I2cdatse0W<OtgFsGi2cctlSpec> {
        I2cdatse0W::new(self, 28)
    }
    #[doc = "Bit 30 - Read/Write Indicator"]
    #[inline(always)]
    #[must_use]
    pub fn rw(&mut self) -> RwW<OtgFsGi2cctlSpec> {
        RwW::new(self, 30)
    }
    #[doc = "Bit 31 - I2C Busy/Done"]
    #[inline(always)]
    #[must_use]
    pub fn bsydne(&mut self) -> BsydneW<OtgFsGi2cctlSpec> {
        BsydneW::new(self, 31)
    }
}
#[doc = "OTG I2C access register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gi2cctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gi2cctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsGi2cctlSpec;
impl crate::RegisterSpec for OtgFsGi2cctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`otg_fs_gi2cctl::R`](R) reader structure"]
impl crate::Readable for OtgFsGi2cctlSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_gi2cctl::W`](W) writer structure"]
impl crate::Writable for OtgFsGi2cctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_GI2CCTL to value 0x0200_0400"]
impl crate::Resettable for OtgFsGi2cctlSpec {
    const RESET_VALUE: u32 = 0x0200_0400;
}
