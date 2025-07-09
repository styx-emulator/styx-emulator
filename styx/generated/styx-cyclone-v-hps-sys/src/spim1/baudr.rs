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
#[doc = "Register `baudr` reader"]
pub type R = crate::R<BaudrSpec>;
#[doc = "Register `baudr` writer"]
pub type W = crate::W<BaudrSpec>;
#[doc = "Field `sckdv` reader - The LSB for this field is always set to 0 and is unaffected by a write operation, which ensures an even value is held in this register. If the value is 0, the serial output clock (spim_sclk_out) is disabled. The frequency of the spim_sclk_out is derived from the following equation: Fspim_sclk_out = Fspi_m_clk/SCKDV where SCKDV is any even value between 2 and 65534. For example: for Fspi_m_clk = 3.6864MHz and SCKDV =2 Fspim_sclk_out = 3.6864/2 = 1.8432MHz"]
pub type SckdvR = crate::FieldReader<u16>;
#[doc = "Field `sckdv` writer - The LSB for this field is always set to 0 and is unaffected by a write operation, which ensures an even value is held in this register. If the value is 0, the serial output clock (spim_sclk_out) is disabled. The frequency of the spim_sclk_out is derived from the following equation: Fspim_sclk_out = Fspi_m_clk/SCKDV where SCKDV is any even value between 2 and 65534. For example: for Fspi_m_clk = 3.6864MHz and SCKDV =2 Fspim_sclk_out = 3.6864/2 = 1.8432MHz"]
pub type SckdvW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - The LSB for this field is always set to 0 and is unaffected by a write operation, which ensures an even value is held in this register. If the value is 0, the serial output clock (spim_sclk_out) is disabled. The frequency of the spim_sclk_out is derived from the following equation: Fspim_sclk_out = Fspi_m_clk/SCKDV where SCKDV is any even value between 2 and 65534. For example: for Fspi_m_clk = 3.6864MHz and SCKDV =2 Fspim_sclk_out = 3.6864/2 = 1.8432MHz"]
    #[inline(always)]
    pub fn sckdv(&self) -> SckdvR {
        SckdvR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - The LSB for this field is always set to 0 and is unaffected by a write operation, which ensures an even value is held in this register. If the value is 0, the serial output clock (spim_sclk_out) is disabled. The frequency of the spim_sclk_out is derived from the following equation: Fspim_sclk_out = Fspi_m_clk/SCKDV where SCKDV is any even value between 2 and 65534. For example: for Fspi_m_clk = 3.6864MHz and SCKDV =2 Fspim_sclk_out = 3.6864/2 = 1.8432MHz"]
    #[inline(always)]
    #[must_use]
    pub fn sckdv(&mut self) -> SckdvW<BaudrSpec> {
        SckdvW::new(self, 0)
    }
}
#[doc = "This register derives the frequency of the serial clock that regulates the data transfer. The 16-bit field in this register defines the spi_m_clk divider value. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`baudr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`baudr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BaudrSpec;
impl crate::RegisterSpec for BaudrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`baudr::R`](R) reader structure"]
impl crate::Readable for BaudrSpec {}
#[doc = "`write(|w| ..)` method takes [`baudr::W`](W) writer structure"]
impl crate::Writable for BaudrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets baudr to value 0"]
impl crate::Resettable for BaudrSpec {
    const RESET_VALUE: u32 = 0;
}
