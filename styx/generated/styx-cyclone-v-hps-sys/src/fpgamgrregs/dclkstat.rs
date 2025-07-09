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
#[doc = "Register `dclkstat` reader"]
pub type R = crate::R<DclkstatSpec>;
#[doc = "Register `dclkstat` writer"]
pub type W = crate::W<DclkstatSpec>;
#[doc = "This bit is write one to clear. This bit gets set after the DCLKCNT has counted down to zero (transition from 1 to 0).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dcntdone {
    #[doc = "0: `0`"]
    Notdone = 0,
    #[doc = "1: `1`"]
    Done = 1,
}
impl From<Dcntdone> for bool {
    #[inline(always)]
    fn from(variant: Dcntdone) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dcntdone` reader - This bit is write one to clear. This bit gets set after the DCLKCNT has counted down to zero (transition from 1 to 0)."]
pub type DcntdoneR = crate::BitReader<Dcntdone>;
impl DcntdoneR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dcntdone {
        match self.bits {
            false => Dcntdone::Notdone,
            true => Dcntdone::Done,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notdone(&self) -> bool {
        *self == Dcntdone::Notdone
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_done(&self) -> bool {
        *self == Dcntdone::Done
    }
}
#[doc = "Field `dcntdone` writer - This bit is write one to clear. This bit gets set after the DCLKCNT has counted down to zero (transition from 1 to 0)."]
pub type DcntdoneW<'a, REG> = crate::BitWriter1C<'a, REG, Dcntdone>;
impl<'a, REG> DcntdoneW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notdone(self) -> &'a mut crate::W<REG> {
        self.variant(Dcntdone::Notdone)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn done(self) -> &'a mut crate::W<REG> {
        self.variant(Dcntdone::Done)
    }
}
impl R {
    #[doc = "Bit 0 - This bit is write one to clear. This bit gets set after the DCLKCNT has counted down to zero (transition from 1 to 0)."]
    #[inline(always)]
    pub fn dcntdone(&self) -> DcntdoneR {
        DcntdoneR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit is write one to clear. This bit gets set after the DCLKCNT has counted down to zero (transition from 1 to 0)."]
    #[inline(always)]
    #[must_use]
    pub fn dcntdone(&mut self) -> DcntdoneW<DclkstatSpec> {
        DcntdoneW::new(self, 0)
    }
}
#[doc = "This write one to clear register indicates that the DCLKCNT has counted down to zero. The DCLKCNT is used by software to drive spurious DCLKs to the FPGA. Software will poll this bit after writing DCLKCNT to know when all of the DCLKs have been sent.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dclkstat::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dclkstat::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DclkstatSpec;
impl crate::RegisterSpec for DclkstatSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`dclkstat::R`](R) reader structure"]
impl crate::Readable for DclkstatSpec {}
#[doc = "`write(|w| ..)` method takes [`dclkstat::W`](W) writer structure"]
impl crate::Writable for DclkstatSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x01;
}
#[doc = "`reset()` method sets dclkstat to value 0"]
impl crate::Resettable for DclkstatSpec {
    const RESET_VALUE: u32 = 0;
}
