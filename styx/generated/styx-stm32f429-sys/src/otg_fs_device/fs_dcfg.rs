// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FS_DCFG` reader"]
pub type R = crate::R<FsDcfgSpec>;
#[doc = "Register `FS_DCFG` writer"]
pub type W = crate::W<FsDcfgSpec>;
#[doc = "Field `DSPD` reader - Device speed"]
pub type DspdR = crate::FieldReader;
#[doc = "Field `DSPD` writer - Device speed"]
pub type DspdW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `NZLSOHSK` reader - Non-zero-length status OUT handshake"]
pub type NzlsohskR = crate::BitReader;
#[doc = "Field `NZLSOHSK` writer - Non-zero-length status OUT handshake"]
pub type NzlsohskW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DAD` reader - Device address"]
pub type DadR = crate::FieldReader;
#[doc = "Field `DAD` writer - Device address"]
pub type DadW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `PFIVL` reader - Periodic frame interval"]
pub type PfivlR = crate::FieldReader;
#[doc = "Field `PFIVL` writer - Periodic frame interval"]
pub type PfivlW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Device speed"]
    #[inline(always)]
    pub fn dspd(&self) -> DspdR {
        DspdR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 2 - Non-zero-length status OUT handshake"]
    #[inline(always)]
    pub fn nzlsohsk(&self) -> NzlsohskR {
        NzlsohskR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bits 4:10 - Device address"]
    #[inline(always)]
    pub fn dad(&self) -> DadR {
        DadR::new(((self.bits >> 4) & 0x7f) as u8)
    }
    #[doc = "Bits 11:12 - Periodic frame interval"]
    #[inline(always)]
    pub fn pfivl(&self) -> PfivlR {
        PfivlR::new(((self.bits >> 11) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Device speed"]
    #[inline(always)]
    #[must_use]
    pub fn dspd(&mut self) -> DspdW<FsDcfgSpec> {
        DspdW::new(self, 0)
    }
    #[doc = "Bit 2 - Non-zero-length status OUT handshake"]
    #[inline(always)]
    #[must_use]
    pub fn nzlsohsk(&mut self) -> NzlsohskW<FsDcfgSpec> {
        NzlsohskW::new(self, 2)
    }
    #[doc = "Bits 4:10 - Device address"]
    #[inline(always)]
    #[must_use]
    pub fn dad(&mut self) -> DadW<FsDcfgSpec> {
        DadW::new(self, 4)
    }
    #[doc = "Bits 11:12 - Periodic frame interval"]
    #[inline(always)]
    #[must_use]
    pub fn pfivl(&mut self) -> PfivlW<FsDcfgSpec> {
        PfivlW::new(self, 11)
    }
}
#[doc = "OTG_FS device configuration register (OTG_FS_DCFG)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_dcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_dcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FsDcfgSpec;
impl crate::RegisterSpec for FsDcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`fs_dcfg::R`](R) reader structure"]
impl crate::Readable for FsDcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`fs_dcfg::W`](W) writer structure"]
impl crate::Writable for FsDcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FS_DCFG to value 0x0220_0000"]
impl crate::Resettable for FsDcfgSpec {
    const RESET_VALUE: u32 = 0x0220_0000;
}
