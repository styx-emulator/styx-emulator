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
#[doc = "Register `srt` reader"]
pub type R = crate::R<SrtSpec>;
#[doc = "Register `srt` writer"]
pub type W = crate::W<SrtSpec>;
#[doc = "This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the Rx trigger bit gets updated. This is used to select the trigger level in the receiver FIFO at which the Received Data Available Interrupt will be generated. It also determines when the uart_dma_rx_req_n signal will be asserted when DMA Mode (FCR\\[3\\]) is set to one. The enum below shows trigger levels that are supported.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Srt {
    #[doc = "0: `0`"]
    Onechar = 0,
    #[doc = "1: `1`"]
    Quarterfull = 1,
    #[doc = "2: `10`"]
    Halffull = 2,
    #[doc = "3: `11`"]
    Fullless2 = 3,
}
impl From<Srt> for u8 {
    #[inline(always)]
    fn from(variant: Srt) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Srt {
    type Ux = u8;
}
#[doc = "Field `srt` reader - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the Rx trigger bit gets updated. This is used to select the trigger level in the receiver FIFO at which the Received Data Available Interrupt will be generated. It also determines when the uart_dma_rx_req_n signal will be asserted when DMA Mode (FCR\\[3\\]) is set to one. The enum below shows trigger levels that are supported."]
pub type SrtR = crate::FieldReader<Srt>;
impl SrtR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Srt {
        match self.bits {
            0 => Srt::Onechar,
            1 => Srt::Quarterfull,
            2 => Srt::Halffull,
            3 => Srt::Fullless2,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_onechar(&self) -> bool {
        *self == Srt::Onechar
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_quarterfull(&self) -> bool {
        *self == Srt::Quarterfull
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_halffull(&self) -> bool {
        *self == Srt::Halffull
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_fullless2(&self) -> bool {
        *self == Srt::Fullless2
    }
}
#[doc = "Field `srt` writer - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the Rx trigger bit gets updated. This is used to select the trigger level in the receiver FIFO at which the Received Data Available Interrupt will be generated. It also determines when the uart_dma_rx_req_n signal will be asserted when DMA Mode (FCR\\[3\\]) is set to one. The enum below shows trigger levels that are supported."]
pub type SrtW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Srt>;
impl<'a, REG> SrtW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn onechar(self) -> &'a mut crate::W<REG> {
        self.variant(Srt::Onechar)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn quarterfull(self) -> &'a mut crate::W<REG> {
        self.variant(Srt::Quarterfull)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn halffull(self) -> &'a mut crate::W<REG> {
        self.variant(Srt::Halffull)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn fullless2(self) -> &'a mut crate::W<REG> {
        self.variant(Srt::Fullless2)
    }
}
impl R {
    #[doc = "Bits 0:1 - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the Rx trigger bit gets updated. This is used to select the trigger level in the receiver FIFO at which the Received Data Available Interrupt will be generated. It also determines when the uart_dma_rx_req_n signal will be asserted when DMA Mode (FCR\\[3\\]) is set to one. The enum below shows trigger levels that are supported."]
    #[inline(always)]
    pub fn srt(&self) -> SrtR {
        SrtR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the Rx trigger bit gets updated. This is used to select the trigger level in the receiver FIFO at which the Received Data Available Interrupt will be generated. It also determines when the uart_dma_rx_req_n signal will be asserted when DMA Mode (FCR\\[3\\]) is set to one. The enum below shows trigger levels that are supported."]
    #[inline(always)]
    #[must_use]
    pub fn srt(&mut self) -> SrtW<SrtSpec> {
        SrtW::new(self, 0)
    }
}
#[doc = "This is a shadow register for the Rx trigger bits (FCR\\[7:6\\]).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`srt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`srt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrtSpec;
impl crate::RegisterSpec for SrtSpec {
    type Ux = u32;
    const OFFSET: u64 = 156u64;
}
#[doc = "`read()` method returns [`srt::R`](R) reader structure"]
impl crate::Readable for SrtSpec {}
#[doc = "`write(|w| ..)` method takes [`srt::W`](W) writer structure"]
impl crate::Writable for SrtSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets srt to value 0"]
impl crate::Resettable for SrtSpec {
    const RESET_VALUE: u32 = 0;
}
