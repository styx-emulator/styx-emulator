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
#[doc = "Register `bootinfo` reader"]
pub type R = crate::R<BootinfoSpec>;
#[doc = "Register `bootinfo` writer"]
pub type W = crate::W<BootinfoSpec>;
#[doc = "The boot select field specifies the boot source. It is read by the Boot ROM code on a cold or warm reset to determine the boot source. The HPS BSEL pins value are sampled upon deassertion of cold reset.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Bsel {
    #[doc = "1: `1`"]
    Fpga = 1,
    #[doc = "2: `10`"]
    NandFlash1_8v = 2,
    #[doc = "3: `11`"]
    NandFlash3_0v = 3,
    #[doc = "4: `100`"]
    SdMmcExternalTransceiver1_8v = 4,
    #[doc = "5: `101`"]
    SdMmcInternalTransceiver3_0v = 5,
    #[doc = "6: `110`"]
    QspiFlash1_8v = 6,
    #[doc = "7: `111`"]
    QspiFlash3_0v = 7,
}
impl From<Bsel> for u8 {
    #[inline(always)]
    fn from(variant: Bsel) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Bsel {
    type Ux = u8;
}
#[doc = "Field `bsel` reader - The boot select field specifies the boot source. It is read by the Boot ROM code on a cold or warm reset to determine the boot source. The HPS BSEL pins value are sampled upon deassertion of cold reset."]
pub type BselR = crate::FieldReader<Bsel>;
impl BselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bsel {
        match self.bits {
            1 => Bsel::Fpga,
            2 => Bsel::NandFlash1_8v,
            3 => Bsel::NandFlash3_0v,
            4 => Bsel::SdMmcExternalTransceiver1_8v,
            5 => Bsel::SdMmcInternalTransceiver3_0v,
            6 => Bsel::QspiFlash1_8v,
            7 => Bsel::QspiFlash3_0v,
            _ => unreachable!(),
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fpga(&self) -> bool {
        *self == Bsel::Fpga
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_nand_flash_1_8v(&self) -> bool {
        *self == Bsel::NandFlash1_8v
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_nand_flash_3_0v(&self) -> bool {
        *self == Bsel::NandFlash3_0v
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_sd_mmc_external_transceiver_1_8v(&self) -> bool {
        *self == Bsel::SdMmcExternalTransceiver1_8v
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_sd_mmc_internal_transceiver_3_0v(&self) -> bool {
        *self == Bsel::SdMmcInternalTransceiver3_0v
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_qspi_flash_1_8v(&self) -> bool {
        *self == Bsel::QspiFlash1_8v
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_qspi_flash_3_0v(&self) -> bool {
        *self == Bsel::QspiFlash3_0v
    }
}
#[doc = "Field `bsel` writer - The boot select field specifies the boot source. It is read by the Boot ROM code on a cold or warm reset to determine the boot source. The HPS BSEL pins value are sampled upon deassertion of cold reset."]
pub type BselW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "The clock select field specifies clock information for booting. The clock select encoding is a function of the CSEL value. The clock select field is read by the Boot ROM code on a cold or warm reset when booting from a flash device to get information about how to setup the HPS clocking to boot from the specified clock device. The encoding of the clock select field is specified by the enum associated with this field. The HPS CSEL pins value are sampled upon deassertion of cold reset.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Csel {
    #[doc = "0: `0`"]
    Csel0 = 0,
    #[doc = "1: `1`"]
    Csel1 = 1,
    #[doc = "2: `10`"]
    Csel2 = 2,
    #[doc = "3: `11`"]
    Csel3 = 3,
}
impl From<Csel> for u8 {
    #[inline(always)]
    fn from(variant: Csel) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Csel {
    type Ux = u8;
}
#[doc = "Field `csel` reader - The clock select field specifies clock information for booting. The clock select encoding is a function of the CSEL value. The clock select field is read by the Boot ROM code on a cold or warm reset when booting from a flash device to get information about how to setup the HPS clocking to boot from the specified clock device. The encoding of the clock select field is specified by the enum associated with this field. The HPS CSEL pins value are sampled upon deassertion of cold reset."]
pub type CselR = crate::FieldReader<Csel>;
impl CselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Csel {
        match self.bits {
            0 => Csel::Csel0,
            1 => Csel::Csel1,
            2 => Csel::Csel2,
            3 => Csel::Csel3,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_csel_0(&self) -> bool {
        *self == Csel::Csel0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_csel_1(&self) -> bool {
        *self == Csel::Csel1
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_csel_2(&self) -> bool {
        *self == Csel::Csel2
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_csel_3(&self) -> bool {
        *self == Csel::Csel3
    }
}
#[doc = "Field `csel` writer - The clock select field specifies clock information for booting. The clock select encoding is a function of the CSEL value. The clock select field is read by the Boot ROM code on a cold or warm reset when booting from a flash device to get information about how to setup the HPS clocking to boot from the specified clock device. The encoding of the clock select field is specified by the enum associated with this field. The HPS CSEL pins value are sampled upon deassertion of cold reset."]
pub type CselW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `pinbsel` reader - Specifies the sampled value of the HPS BSEL pins. The value of HPS BSEL pins are sampled upon deassertion of cold reset."]
pub type PinbselR = crate::FieldReader;
#[doc = "Field `pinbsel` writer - Specifies the sampled value of the HPS BSEL pins. The value of HPS BSEL pins are sampled upon deassertion of cold reset."]
pub type PinbselW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `pincsel` reader - Specifies the sampled value of the HPS CSEL pins. The value of HPS CSEL pins are sampled upon deassertion of cold reset."]
pub type PincselR = crate::FieldReader;
#[doc = "Field `pincsel` writer - Specifies the sampled value of the HPS CSEL pins. The value of HPS CSEL pins are sampled upon deassertion of cold reset."]
pub type PincselW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:2 - The boot select field specifies the boot source. It is read by the Boot ROM code on a cold or warm reset to determine the boot source. The HPS BSEL pins value are sampled upon deassertion of cold reset."]
    #[inline(always)]
    pub fn bsel(&self) -> BselR {
        BselR::new((self.bits & 7) as u8)
    }
    #[doc = "Bits 3:4 - The clock select field specifies clock information for booting. The clock select encoding is a function of the CSEL value. The clock select field is read by the Boot ROM code on a cold or warm reset when booting from a flash device to get information about how to setup the HPS clocking to boot from the specified clock device. The encoding of the clock select field is specified by the enum associated with this field. The HPS CSEL pins value are sampled upon deassertion of cold reset."]
    #[inline(always)]
    pub fn csel(&self) -> CselR {
        CselR::new(((self.bits >> 3) & 3) as u8)
    }
    #[doc = "Bits 5:7 - Specifies the sampled value of the HPS BSEL pins. The value of HPS BSEL pins are sampled upon deassertion of cold reset."]
    #[inline(always)]
    pub fn pinbsel(&self) -> PinbselR {
        PinbselR::new(((self.bits >> 5) & 7) as u8)
    }
    #[doc = "Bits 8:9 - Specifies the sampled value of the HPS CSEL pins. The value of HPS CSEL pins are sampled upon deassertion of cold reset."]
    #[inline(always)]
    pub fn pincsel(&self) -> PincselR {
        PincselR::new(((self.bits >> 8) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:2 - The boot select field specifies the boot source. It is read by the Boot ROM code on a cold or warm reset to determine the boot source. The HPS BSEL pins value are sampled upon deassertion of cold reset."]
    #[inline(always)]
    #[must_use]
    pub fn bsel(&mut self) -> BselW<BootinfoSpec> {
        BselW::new(self, 0)
    }
    #[doc = "Bits 3:4 - The clock select field specifies clock information for booting. The clock select encoding is a function of the CSEL value. The clock select field is read by the Boot ROM code on a cold or warm reset when booting from a flash device to get information about how to setup the HPS clocking to boot from the specified clock device. The encoding of the clock select field is specified by the enum associated with this field. The HPS CSEL pins value are sampled upon deassertion of cold reset."]
    #[inline(always)]
    #[must_use]
    pub fn csel(&mut self) -> CselW<BootinfoSpec> {
        CselW::new(self, 3)
    }
    #[doc = "Bits 5:7 - Specifies the sampled value of the HPS BSEL pins. The value of HPS BSEL pins are sampled upon deassertion of cold reset."]
    #[inline(always)]
    #[must_use]
    pub fn pinbsel(&mut self) -> PinbselW<BootinfoSpec> {
        PinbselW::new(self, 5)
    }
    #[doc = "Bits 8:9 - Specifies the sampled value of the HPS CSEL pins. The value of HPS CSEL pins are sampled upon deassertion of cold reset."]
    #[inline(always)]
    #[must_use]
    pub fn pincsel(&mut self) -> PincselW<BootinfoSpec> {
        PincselW::new(self, 8)
    }
}
#[doc = "Provides access to boot configuration information.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bootinfo::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BootinfoSpec;
impl crate::RegisterSpec for BootinfoSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`bootinfo::R`](R) reader structure"]
impl crate::Readable for BootinfoSpec {}
#[doc = "`reset()` method sets bootinfo to value 0"]
impl crate::Resettable for BootinfoSpec {
    const RESET_VALUE: u32 = 0;
}
