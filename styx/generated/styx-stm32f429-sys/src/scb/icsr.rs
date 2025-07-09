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
#[doc = "Register `ICSR` reader"]
pub type R = crate::R<IcsrSpec>;
#[doc = "Register `ICSR` writer"]
pub type W = crate::W<IcsrSpec>;
#[doc = "Field `VECTACTIVE` reader - Active vector"]
pub type VectactiveR = crate::FieldReader<u16>;
#[doc = "Field `VECTACTIVE` writer - Active vector"]
pub type VectactiveW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
#[doc = "Field `RETTOBASE` reader - Return to base level"]
pub type RettobaseR = crate::BitReader;
#[doc = "Field `RETTOBASE` writer - Return to base level"]
pub type RettobaseW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VECTPENDING` reader - Pending vector"]
pub type VectpendingR = crate::FieldReader;
#[doc = "Field `VECTPENDING` writer - Pending vector"]
pub type VectpendingW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `ISRPENDING` reader - Interrupt pending flag"]
pub type IsrpendingR = crate::BitReader;
#[doc = "Field `ISRPENDING` writer - Interrupt pending flag"]
pub type IsrpendingW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PENDSTCLR` reader - SysTick exception clear-pending bit"]
pub type PendstclrR = crate::BitReader;
#[doc = "Field `PENDSTCLR` writer - SysTick exception clear-pending bit"]
pub type PendstclrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PENDSTSET` reader - SysTick exception set-pending bit"]
pub type PendstsetR = crate::BitReader;
#[doc = "Field `PENDSTSET` writer - SysTick exception set-pending bit"]
pub type PendstsetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PENDSVCLR` reader - PendSV clear-pending bit"]
pub type PendsvclrR = crate::BitReader;
#[doc = "Field `PENDSVCLR` writer - PendSV clear-pending bit"]
pub type PendsvclrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PENDSVSET` reader - PendSV set-pending bit"]
pub type PendsvsetR = crate::BitReader;
#[doc = "Field `PENDSVSET` writer - PendSV set-pending bit"]
pub type PendsvsetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NMIPENDSET` reader - NMI set-pending bit."]
pub type NmipendsetR = crate::BitReader;
#[doc = "Field `NMIPENDSET` writer - NMI set-pending bit."]
pub type NmipendsetW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:8 - Active vector"]
    #[inline(always)]
    pub fn vectactive(&self) -> VectactiveR {
        VectactiveR::new((self.bits & 0x01ff) as u16)
    }
    #[doc = "Bit 11 - Return to base level"]
    #[inline(always)]
    pub fn rettobase(&self) -> RettobaseR {
        RettobaseR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bits 12:18 - Pending vector"]
    #[inline(always)]
    pub fn vectpending(&self) -> VectpendingR {
        VectpendingR::new(((self.bits >> 12) & 0x7f) as u8)
    }
    #[doc = "Bit 22 - Interrupt pending flag"]
    #[inline(always)]
    pub fn isrpending(&self) -> IsrpendingR {
        IsrpendingR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 25 - SysTick exception clear-pending bit"]
    #[inline(always)]
    pub fn pendstclr(&self) -> PendstclrR {
        PendstclrR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - SysTick exception set-pending bit"]
    #[inline(always)]
    pub fn pendstset(&self) -> PendstsetR {
        PendstsetR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - PendSV clear-pending bit"]
    #[inline(always)]
    pub fn pendsvclr(&self) -> PendsvclrR {
        PendsvclrR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - PendSV set-pending bit"]
    #[inline(always)]
    pub fn pendsvset(&self) -> PendsvsetR {
        PendsvsetR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 31 - NMI set-pending bit."]
    #[inline(always)]
    pub fn nmipendset(&self) -> NmipendsetR {
        NmipendsetR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:8 - Active vector"]
    #[inline(always)]
    #[must_use]
    pub fn vectactive(&mut self) -> VectactiveW<IcsrSpec> {
        VectactiveW::new(self, 0)
    }
    #[doc = "Bit 11 - Return to base level"]
    #[inline(always)]
    #[must_use]
    pub fn rettobase(&mut self) -> RettobaseW<IcsrSpec> {
        RettobaseW::new(self, 11)
    }
    #[doc = "Bits 12:18 - Pending vector"]
    #[inline(always)]
    #[must_use]
    pub fn vectpending(&mut self) -> VectpendingW<IcsrSpec> {
        VectpendingW::new(self, 12)
    }
    #[doc = "Bit 22 - Interrupt pending flag"]
    #[inline(always)]
    #[must_use]
    pub fn isrpending(&mut self) -> IsrpendingW<IcsrSpec> {
        IsrpendingW::new(self, 22)
    }
    #[doc = "Bit 25 - SysTick exception clear-pending bit"]
    #[inline(always)]
    #[must_use]
    pub fn pendstclr(&mut self) -> PendstclrW<IcsrSpec> {
        PendstclrW::new(self, 25)
    }
    #[doc = "Bit 26 - SysTick exception set-pending bit"]
    #[inline(always)]
    #[must_use]
    pub fn pendstset(&mut self) -> PendstsetW<IcsrSpec> {
        PendstsetW::new(self, 26)
    }
    #[doc = "Bit 27 - PendSV clear-pending bit"]
    #[inline(always)]
    #[must_use]
    pub fn pendsvclr(&mut self) -> PendsvclrW<IcsrSpec> {
        PendsvclrW::new(self, 27)
    }
    #[doc = "Bit 28 - PendSV set-pending bit"]
    #[inline(always)]
    #[must_use]
    pub fn pendsvset(&mut self) -> PendsvsetW<IcsrSpec> {
        PendsvsetW::new(self, 28)
    }
    #[doc = "Bit 31 - NMI set-pending bit."]
    #[inline(always)]
    #[must_use]
    pub fn nmipendset(&mut self) -> NmipendsetW<IcsrSpec> {
        NmipendsetW::new(self, 31)
    }
}
#[doc = "Interrupt control and state register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`icsr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icsr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcsrSpec;
impl crate::RegisterSpec for IcsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`icsr::R`](R) reader structure"]
impl crate::Readable for IcsrSpec {}
#[doc = "`write(|w| ..)` method takes [`icsr::W`](W) writer structure"]
impl crate::Writable for IcsrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ICSR to value 0"]
impl crate::Resettable for IcsrSpec {
    const RESET_VALUE: u32 = 0;
}
