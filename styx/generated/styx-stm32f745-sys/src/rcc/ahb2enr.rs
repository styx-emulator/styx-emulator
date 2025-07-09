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
#[doc = "Register `AHB2ENR` reader"]
pub type R = crate::R<Ahb2enrSpec>;
#[doc = "Register `AHB2ENR` writer"]
pub type W = crate::W<Ahb2enrSpec>;
#[doc = "Field `DCMIEN` reader - Camera interface enable"]
pub type DcmienR = crate::BitReader;
#[doc = "Field `DCMIEN` writer - Camera interface enable"]
pub type DcmienW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CRYPEN` reader - Cryptographic modules clock enable"]
pub type CrypenR = crate::BitReader;
#[doc = "Field `CRYPEN` writer - Cryptographic modules clock enable"]
pub type CrypenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HASHEN` reader - Hash modules clock enable"]
pub type HashenR = crate::BitReader;
#[doc = "Field `HASHEN` writer - Hash modules clock enable"]
pub type HashenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RNGEN` reader - Random number generator clock enable"]
pub type RngenR = crate::BitReader;
#[doc = "Field `RNGEN` writer - Random number generator clock enable"]
pub type RngenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OTGFSEN` reader - USB OTG FS clock enable"]
pub type OtgfsenR = crate::BitReader;
#[doc = "Field `OTGFSEN` writer - USB OTG FS clock enable"]
pub type OtgfsenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Camera interface enable"]
    #[inline(always)]
    pub fn dcmien(&self) -> DcmienR {
        DcmienR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 4 - Cryptographic modules clock enable"]
    #[inline(always)]
    pub fn crypen(&self) -> CrypenR {
        CrypenR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Hash modules clock enable"]
    #[inline(always)]
    pub fn hashen(&self) -> HashenR {
        HashenR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Random number generator clock enable"]
    #[inline(always)]
    pub fn rngen(&self) -> RngenR {
        RngenR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - USB OTG FS clock enable"]
    #[inline(always)]
    pub fn otgfsen(&self) -> OtgfsenR {
        OtgfsenR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Camera interface enable"]
    #[inline(always)]
    #[must_use]
    pub fn dcmien(&mut self) -> DcmienW<Ahb2enrSpec> {
        DcmienW::new(self, 0)
    }
    #[doc = "Bit 4 - Cryptographic modules clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn crypen(&mut self) -> CrypenW<Ahb2enrSpec> {
        CrypenW::new(self, 4)
    }
    #[doc = "Bit 5 - Hash modules clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn hashen(&mut self) -> HashenW<Ahb2enrSpec> {
        HashenW::new(self, 5)
    }
    #[doc = "Bit 6 - Random number generator clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn rngen(&mut self) -> RngenW<Ahb2enrSpec> {
        RngenW::new(self, 6)
    }
    #[doc = "Bit 7 - USB OTG FS clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn otgfsen(&mut self) -> OtgfsenW<Ahb2enrSpec> {
        OtgfsenW::new(self, 7)
    }
}
#[doc = "AHB2 peripheral clock enable register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ahb2enr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ahb2enr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ahb2enrSpec;
impl crate::RegisterSpec for Ahb2enrSpec {
    type Ux = u32;
    const OFFSET: u64 = 52u64;
}
#[doc = "`read()` method returns [`ahb2enr::R`](R) reader structure"]
impl crate::Readable for Ahb2enrSpec {}
#[doc = "`write(|w| ..)` method takes [`ahb2enr::W`](W) writer structure"]
impl crate::Writable for Ahb2enrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AHB2ENR to value 0"]
impl crate::Resettable for Ahb2enrSpec {
    const RESET_VALUE: u32 = 0;
}
