// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_dma_cr` reader"]
pub type R = crate::R<IcDmaCrSpec>;
#[doc = "Register `ic_dma_cr` writer"]
pub type W = crate::W<IcDmaCrSpec>;
#[doc = "This bit enables/disables the receive FIFO DMA channel.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rdmae {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
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
            false => Rdmae::Disable,
            true => Rdmae::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Rdmae::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Rdmae::Enable
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
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Rdmae::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Rdmae::Enable)
    }
}
#[doc = "This bit enables/disables the transmit FIFO DMA channel.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tdmae {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
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
            false => Tdmae::Disable,
            true => Tdmae::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Tdmae::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Tdmae::Enable
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
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Tdmae::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Tdmae::Enable)
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
    pub fn rdmae(&mut self) -> RdmaeW<IcDmaCrSpec> {
        RdmaeW::new(self, 0)
    }
    #[doc = "Bit 1 - This bit enables/disables the transmit FIFO DMA channel."]
    #[inline(always)]
    #[must_use]
    pub fn tdmae(&mut self) -> TdmaeW<IcDmaCrSpec> {
        TdmaeW::new(self, 1)
    }
}
#[doc = "The register is used to enable the DMA Controller interface operation. There is a separate bit for transmit and receive. This can be programmed regardless of the state of IC_ENABLE.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_dma_cr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_dma_cr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcDmaCrSpec;
impl crate::RegisterSpec for IcDmaCrSpec {
    type Ux = u32;
    const OFFSET: u64 = 136u64;
}
#[doc = "`read()` method returns [`ic_dma_cr::R`](R) reader structure"]
impl crate::Readable for IcDmaCrSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_dma_cr::W`](W) writer structure"]
impl crate::Writable for IcDmaCrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_dma_cr to value 0"]
impl crate::Resettable for IcDmaCrSpec {
    const RESET_VALUE: u32 = 0;
}
