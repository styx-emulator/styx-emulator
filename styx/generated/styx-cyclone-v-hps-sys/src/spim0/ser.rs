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
#[doc = "Register `ser` reader"]
pub type R = crate::R<SerSpec>;
#[doc = "Register `ser` writer"]
pub type W = crate::W<SerSpec>;
#[doc = "Each bit in this register corresponds to a slave select line (spim_ss_x_n\\]
from the SPI Master. When a bit in this register is set (1), the corresponding slave select line from the master is activated when a serial transfer begins. It should be noted that setting or clearing bits in this register have no effect on the corresponding slave select outputs until a transfer is started. Before beginning a transfer, you should enable the bit in this register that corresponds to the slave device with which the master wants to communicate. When not operating in broadcast mode, only one bit in this field should be set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ser {
    #[doc = "0: `0`"]
    Notselected = 0,
    #[doc = "1: `1`"]
    Selected = 1,
}
impl From<Ser> for u8 {
    #[inline(always)]
    fn from(variant: Ser) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Ser {
    type Ux = u8;
}
#[doc = "Field `ser` reader - Each bit in this register corresponds to a slave select line (spim_ss_x_n\\]
from the SPI Master. When a bit in this register is set (1), the corresponding slave select line from the master is activated when a serial transfer begins. It should be noted that setting or clearing bits in this register have no effect on the corresponding slave select outputs until a transfer is started. Before beginning a transfer, you should enable the bit in this register that corresponds to the slave device with which the master wants to communicate. When not operating in broadcast mode, only one bit in this field should be set."]
pub type SerR = crate::FieldReader<Ser>;
impl SerR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Ser> {
        match self.bits {
            0 => Some(Ser::Notselected),
            1 => Some(Ser::Selected),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notselected(&self) -> bool {
        *self == Ser::Notselected
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_selected(&self) -> bool {
        *self == Ser::Selected
    }
}
#[doc = "Field `ser` writer - Each bit in this register corresponds to a slave select line (spim_ss_x_n\\]
from the SPI Master. When a bit in this register is set (1), the corresponding slave select line from the master is activated when a serial transfer begins. It should be noted that setting or clearing bits in this register have no effect on the corresponding slave select outputs until a transfer is started. Before beginning a transfer, you should enable the bit in this register that corresponds to the slave device with which the master wants to communicate. When not operating in broadcast mode, only one bit in this field should be set."]
pub type SerW<'a, REG> = crate::FieldWriter<'a, REG, 4, Ser>;
impl<'a, REG> SerW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notselected(self) -> &'a mut crate::W<REG> {
        self.variant(Ser::Notselected)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn selected(self) -> &'a mut crate::W<REG> {
        self.variant(Ser::Selected)
    }
}
impl R {
    #[doc = "Bits 0:3 - Each bit in this register corresponds to a slave select line (spim_ss_x_n\\]
from the SPI Master. When a bit in this register is set (1), the corresponding slave select line from the master is activated when a serial transfer begins. It should be noted that setting or clearing bits in this register have no effect on the corresponding slave select outputs until a transfer is started. Before beginning a transfer, you should enable the bit in this register that corresponds to the slave device with which the master wants to communicate. When not operating in broadcast mode, only one bit in this field should be set."]
    #[inline(always)]
    pub fn ser(&self) -> SerR {
        SerR::new((self.bits & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Each bit in this register corresponds to a slave select line (spim_ss_x_n\\]
from the SPI Master. When a bit in this register is set (1), the corresponding slave select line from the master is activated when a serial transfer begins. It should be noted that setting or clearing bits in this register have no effect on the corresponding slave select outputs until a transfer is started. Before beginning a transfer, you should enable the bit in this register that corresponds to the slave device with which the master wants to communicate. When not operating in broadcast mode, only one bit in this field should be set."]
    #[inline(always)]
    #[must_use]
    pub fn ser(&mut self) -> SerW<SerSpec> {
        SerW::new(self, 0)
    }
}
#[doc = "The register enables the individual slave select output lines from the SPI Master. Up to 4 slave-select output pins are available on the SPI Master. You cannot write to this register when SPI Master is busy and when SPI_EN = 1.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ser::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ser::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SerSpec;
impl crate::RegisterSpec for SerSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`ser::R`](R) reader structure"]
impl crate::Readable for SerSpec {}
#[doc = "`write(|w| ..)` method takes [`ser::W`](W) writer structure"]
impl crate::Writable for SerSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ser to value 0"]
impl crate::Resettable for SerSpec {
    const RESET_VALUE: u32 = 0;
}
