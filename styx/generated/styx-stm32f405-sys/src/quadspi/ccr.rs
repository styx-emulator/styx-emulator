// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CCR` reader"]
pub type R = crate::R<CcrSpec>;
#[doc = "Register `CCR` writer"]
pub type W = crate::W<CcrSpec>;
#[doc = "Field `INSTRUCTION` reader - Instruction"]
pub type InstructionR = crate::FieldReader;
#[doc = "Field `INSTRUCTION` writer - Instruction"]
pub type InstructionW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `IMODE` reader - Instruction mode"]
pub type ImodeR = crate::FieldReader;
#[doc = "Field `IMODE` writer - Instruction mode"]
pub type ImodeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `ADMODE` reader - Address mode"]
pub type AdmodeR = crate::FieldReader;
#[doc = "Field `ADMODE` writer - Address mode"]
pub type AdmodeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `ADSIZE` reader - Address size"]
pub type AdsizeR = crate::FieldReader;
#[doc = "Field `ADSIZE` writer - Address size"]
pub type AdsizeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `ABMODE` reader - Alternate bytes mode"]
pub type AbmodeR = crate::FieldReader;
#[doc = "Field `ABMODE` writer - Alternate bytes mode"]
pub type AbmodeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `ABSIZE` reader - Alternate bytes size"]
pub type AbsizeR = crate::FieldReader;
#[doc = "Field `ABSIZE` writer - Alternate bytes size"]
pub type AbsizeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `DCYC` reader - Number of dummy cycles"]
pub type DcycR = crate::FieldReader;
#[doc = "Field `DCYC` writer - Number of dummy cycles"]
pub type DcycW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `DMODE` reader - Data mode"]
pub type DmodeR = crate::FieldReader;
#[doc = "Field `DMODE` writer - Data mode"]
pub type DmodeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `FMODE` reader - Functional mode"]
pub type FmodeR = crate::FieldReader;
#[doc = "Field `FMODE` writer - Functional mode"]
pub type FmodeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `SIOO` reader - Send instruction only once mode"]
pub type SiooR = crate::BitReader;
#[doc = "Field `SIOO` writer - Send instruction only once mode"]
pub type SiooW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DHHC` reader - DDR hold half cycle"]
pub type DhhcR = crate::BitReader;
#[doc = "Field `DHHC` writer - DDR hold half cycle"]
pub type DhhcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DDRM` reader - Double data rate mode"]
pub type DdrmR = crate::BitReader;
#[doc = "Field `DDRM` writer - Double data rate mode"]
pub type DdrmW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:7 - Instruction"]
    #[inline(always)]
    pub fn instruction(&self) -> InstructionR {
        InstructionR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:9 - Instruction mode"]
    #[inline(always)]
    pub fn imode(&self) -> ImodeR {
        ImodeR::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bits 10:11 - Address mode"]
    #[inline(always)]
    pub fn admode(&self) -> AdmodeR {
        AdmodeR::new(((self.bits >> 10) & 3) as u8)
    }
    #[doc = "Bits 12:13 - Address size"]
    #[inline(always)]
    pub fn adsize(&self) -> AdsizeR {
        AdsizeR::new(((self.bits >> 12) & 3) as u8)
    }
    #[doc = "Bits 14:15 - Alternate bytes mode"]
    #[inline(always)]
    pub fn abmode(&self) -> AbmodeR {
        AbmodeR::new(((self.bits >> 14) & 3) as u8)
    }
    #[doc = "Bits 16:17 - Alternate bytes size"]
    #[inline(always)]
    pub fn absize(&self) -> AbsizeR {
        AbsizeR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bits 18:22 - Number of dummy cycles"]
    #[inline(always)]
    pub fn dcyc(&self) -> DcycR {
        DcycR::new(((self.bits >> 18) & 0x1f) as u8)
    }
    #[doc = "Bits 24:25 - Data mode"]
    #[inline(always)]
    pub fn dmode(&self) -> DmodeR {
        DmodeR::new(((self.bits >> 24) & 3) as u8)
    }
    #[doc = "Bits 26:27 - Functional mode"]
    #[inline(always)]
    pub fn fmode(&self) -> FmodeR {
        FmodeR::new(((self.bits >> 26) & 3) as u8)
    }
    #[doc = "Bit 28 - Send instruction only once mode"]
    #[inline(always)]
    pub fn sioo(&self) -> SiooR {
        SiooR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 30 - DDR hold half cycle"]
    #[inline(always)]
    pub fn dhhc(&self) -> DhhcR {
        DhhcR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Double data rate mode"]
    #[inline(always)]
    pub fn ddrm(&self) -> DdrmR {
        DdrmR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:7 - Instruction"]
    #[inline(always)]
    #[must_use]
    pub fn instruction(&mut self) -> InstructionW<CcrSpec> {
        InstructionW::new(self, 0)
    }
    #[doc = "Bits 8:9 - Instruction mode"]
    #[inline(always)]
    #[must_use]
    pub fn imode(&mut self) -> ImodeW<CcrSpec> {
        ImodeW::new(self, 8)
    }
    #[doc = "Bits 10:11 - Address mode"]
    #[inline(always)]
    #[must_use]
    pub fn admode(&mut self) -> AdmodeW<CcrSpec> {
        AdmodeW::new(self, 10)
    }
    #[doc = "Bits 12:13 - Address size"]
    #[inline(always)]
    #[must_use]
    pub fn adsize(&mut self) -> AdsizeW<CcrSpec> {
        AdsizeW::new(self, 12)
    }
    #[doc = "Bits 14:15 - Alternate bytes mode"]
    #[inline(always)]
    #[must_use]
    pub fn abmode(&mut self) -> AbmodeW<CcrSpec> {
        AbmodeW::new(self, 14)
    }
    #[doc = "Bits 16:17 - Alternate bytes size"]
    #[inline(always)]
    #[must_use]
    pub fn absize(&mut self) -> AbsizeW<CcrSpec> {
        AbsizeW::new(self, 16)
    }
    #[doc = "Bits 18:22 - Number of dummy cycles"]
    #[inline(always)]
    #[must_use]
    pub fn dcyc(&mut self) -> DcycW<CcrSpec> {
        DcycW::new(self, 18)
    }
    #[doc = "Bits 24:25 - Data mode"]
    #[inline(always)]
    #[must_use]
    pub fn dmode(&mut self) -> DmodeW<CcrSpec> {
        DmodeW::new(self, 24)
    }
    #[doc = "Bits 26:27 - Functional mode"]
    #[inline(always)]
    #[must_use]
    pub fn fmode(&mut self) -> FmodeW<CcrSpec> {
        FmodeW::new(self, 26)
    }
    #[doc = "Bit 28 - Send instruction only once mode"]
    #[inline(always)]
    #[must_use]
    pub fn sioo(&mut self) -> SiooW<CcrSpec> {
        SiooW::new(self, 28)
    }
    #[doc = "Bit 30 - DDR hold half cycle"]
    #[inline(always)]
    #[must_use]
    pub fn dhhc(&mut self) -> DhhcW<CcrSpec> {
        DhhcW::new(self, 30)
    }
    #[doc = "Bit 31 - Double data rate mode"]
    #[inline(always)]
    #[must_use]
    pub fn ddrm(&mut self) -> DdrmW<CcrSpec> {
        DdrmW::new(self, 31)
    }
}
#[doc = "communication configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ccr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ccr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CcrSpec;
impl crate::RegisterSpec for CcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`ccr::R`](R) reader structure"]
impl crate::Readable for CcrSpec {}
#[doc = "`write(|w| ..)` method takes [`ccr::W`](W) writer structure"]
impl crate::Writable for CcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CCR to value 0"]
impl crate::Resettable for CcrSpec {
    const RESET_VALUE: u32 = 0;
}
