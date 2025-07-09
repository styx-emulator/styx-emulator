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
#[doc = "Register `OTG_HS_DTHRCTL` reader"]
pub type R = crate::R<OtgHsDthrctlSpec>;
#[doc = "Register `OTG_HS_DTHRCTL` writer"]
pub type W = crate::W<OtgHsDthrctlSpec>;
#[doc = "Field `NONISOTHREN` reader - Nonisochronous IN endpoints threshold enable"]
pub type NonisothrenR = crate::BitReader;
#[doc = "Field `NONISOTHREN` writer - Nonisochronous IN endpoints threshold enable"]
pub type NonisothrenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ISOTHREN` reader - ISO IN endpoint threshold enable"]
pub type IsothrenR = crate::BitReader;
#[doc = "Field `ISOTHREN` writer - ISO IN endpoint threshold enable"]
pub type IsothrenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXTHRLEN` reader - Transmit threshold length"]
pub type TxthrlenR = crate::FieldReader<u16>;
#[doc = "Field `TXTHRLEN` writer - Transmit threshold length"]
pub type TxthrlenW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
#[doc = "Field `RXTHREN` reader - Receive threshold enable"]
pub type RxthrenR = crate::BitReader;
#[doc = "Field `RXTHREN` writer - Receive threshold enable"]
pub type RxthrenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXTHRLEN` reader - Receive threshold length"]
pub type RxthrlenR = crate::FieldReader<u16>;
#[doc = "Field `RXTHRLEN` writer - Receive threshold length"]
pub type RxthrlenW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
#[doc = "Field `ARPEN` reader - Arbiter parking enable"]
pub type ArpenR = crate::BitReader;
#[doc = "Field `ARPEN` writer - Arbiter parking enable"]
pub type ArpenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Nonisochronous IN endpoints threshold enable"]
    #[inline(always)]
    pub fn nonisothren(&self) -> NonisothrenR {
        NonisothrenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - ISO IN endpoint threshold enable"]
    #[inline(always)]
    pub fn isothren(&self) -> IsothrenR {
        IsothrenR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bits 2:10 - Transmit threshold length"]
    #[inline(always)]
    pub fn txthrlen(&self) -> TxthrlenR {
        TxthrlenR::new(((self.bits >> 2) & 0x01ff) as u16)
    }
    #[doc = "Bit 16 - Receive threshold enable"]
    #[inline(always)]
    pub fn rxthren(&self) -> RxthrenR {
        RxthrenR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bits 17:25 - Receive threshold length"]
    #[inline(always)]
    pub fn rxthrlen(&self) -> RxthrlenR {
        RxthrlenR::new(((self.bits >> 17) & 0x01ff) as u16)
    }
    #[doc = "Bit 27 - Arbiter parking enable"]
    #[inline(always)]
    pub fn arpen(&self) -> ArpenR {
        ArpenR::new(((self.bits >> 27) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Nonisochronous IN endpoints threshold enable"]
    #[inline(always)]
    #[must_use]
    pub fn nonisothren(&mut self) -> NonisothrenW<OtgHsDthrctlSpec> {
        NonisothrenW::new(self, 0)
    }
    #[doc = "Bit 1 - ISO IN endpoint threshold enable"]
    #[inline(always)]
    #[must_use]
    pub fn isothren(&mut self) -> IsothrenW<OtgHsDthrctlSpec> {
        IsothrenW::new(self, 1)
    }
    #[doc = "Bits 2:10 - Transmit threshold length"]
    #[inline(always)]
    #[must_use]
    pub fn txthrlen(&mut self) -> TxthrlenW<OtgHsDthrctlSpec> {
        TxthrlenW::new(self, 2)
    }
    #[doc = "Bit 16 - Receive threshold enable"]
    #[inline(always)]
    #[must_use]
    pub fn rxthren(&mut self) -> RxthrenW<OtgHsDthrctlSpec> {
        RxthrenW::new(self, 16)
    }
    #[doc = "Bits 17:25 - Receive threshold length"]
    #[inline(always)]
    #[must_use]
    pub fn rxthrlen(&mut self) -> RxthrlenW<OtgHsDthrctlSpec> {
        RxthrlenW::new(self, 17)
    }
    #[doc = "Bit 27 - Arbiter parking enable"]
    #[inline(always)]
    #[must_use]
    pub fn arpen(&mut self) -> ArpenW<OtgHsDthrctlSpec> {
        ArpenW::new(self, 27)
    }
}
#[doc = "OTG_HS Device threshold control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dthrctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dthrctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsDthrctlSpec;
impl crate::RegisterSpec for OtgHsDthrctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`otg_hs_dthrctl::R`](R) reader structure"]
impl crate::Readable for OtgHsDthrctlSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_dthrctl::W`](W) writer structure"]
impl crate::Writable for OtgHsDthrctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_DTHRCTL to value 0"]
impl crate::Resettable for OtgHsDthrctlSpec {
    const RESET_VALUE: u32 = 0;
}
