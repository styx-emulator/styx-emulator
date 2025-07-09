// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmacr` reader"]
pub type R = crate::R<DmacrSpec>;
#[doc = "Register `dmacr` writer"]
pub type W = crate::W<DmacrSpec>;
#[doc = "This bit enables/disables the receive FIFO DMA channel.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rdmae {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rdmae> for bool {
    #[inline(always)]
    fn from(variant: Rdmae) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rdmae` reader - This bit enables/disables the receive FIFO DMA channel."]
pub type RdmaeR = crate::BitReader<Rdmae>;
impl RdmaeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rdmae {
        match self.bits {
            false => Rdmae::Disabled,
            true => Rdmae::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rdmae::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rdmae::Enabled
    }
}
#[doc = "Field `rdmae` writer - This bit enables/disables the receive FIFO DMA channel."]
pub type RdmaeW<'a, REG> = crate::BitWriter<'a, REG, Rdmae>;
impl<'a, REG> RdmaeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rdmae::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rdmae::Enabled)
    }
}
#[doc = "This bit enables/disables the transmit FIFO DMA channel.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tdmae {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Tdmae> for bool {
    #[inline(always)]
    fn from(variant: Tdmae) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tdmae` reader - This bit enables/disables the transmit FIFO DMA channel."]
pub type TdmaeR = crate::BitReader<Tdmae>;
impl TdmaeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tdmae {
        match self.bits {
            false => Tdmae::Disabled,
            true => Tdmae::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Tdmae::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Tdmae::Enabled
    }
}
#[doc = "Field `tdmae` writer - This bit enables/disables the transmit FIFO DMA channel."]
pub type TdmaeW<'a, REG> = crate::BitWriter<'a, REG, Tdmae>;
impl<'a, REG> TdmaeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tdmae::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Tdmae::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - This bit enables/disables the receive FIFO DMA channel."]
    #[inline(always)]
    pub fn rdmae(&self) -> RdmaeR {
        RdmaeR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This bit enables/disables the transmit FIFO DMA channel."]
    #[inline(always)]
    pub fn tdmae(&self) -> TdmaeR {
        TdmaeR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit enables/disables the receive FIFO DMA channel."]
    #[inline(always)]
    #[must_use]
    pub fn rdmae(&mut self) -> RdmaeW<DmacrSpec> {
        RdmaeW::new(self, 0)
    }
    #[doc = "Bit 1 - This bit enables/disables the transmit FIFO DMA channel."]
    #[inline(always)]
    #[must_use]
    pub fn tdmae(&mut self) -> TdmaeW<DmacrSpec> {
        TdmaeW::new(self, 1)
    }
}
#[doc = "This register is used to enable the DMA Controller interface operation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmacr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmacr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmacrSpec;
impl crate::RegisterSpec for DmacrSpec {
    type Ux = u32;
    const OFFSET: u64 = 76u64;
}
#[doc = "`read()` method returns [`dmacr::R`](R) reader structure"]
impl crate::Readable for DmacrSpec {}
#[doc = "`write(|w| ..)` method takes [`dmacr::W`](W) writer structure"]
impl crate::Writable for DmacrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmacr to value 0"]
impl crate::Resettable for DmacrSpec {
    const RESET_VALUE: u32 = 0;
}
