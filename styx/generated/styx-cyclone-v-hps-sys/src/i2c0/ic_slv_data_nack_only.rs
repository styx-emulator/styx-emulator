// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_slv_data_nack_only` reader"]
pub type R = crate::R<IcSlvDataNackOnlySpec>;
#[doc = "Register `ic_slv_data_nack_only` writer"]
pub type W = crate::W<IcSlvDataNackOnlySpec>;
#[doc = "This Bit control Nack generation\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nack {
    #[doc = "1: `1`"]
    Afterdbyte = 1,
    #[doc = "0: `0`"]
    Norm = 0,
}
impl From<Nack> for bool {
    #[inline(always)]
    fn from(variant: Nack) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nack` reader - This Bit control Nack generation"]
pub type NackR = crate::BitReader<Nack>;
impl NackR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nack {
        match self.bits {
            true => Nack::Afterdbyte,
            false => Nack::Norm,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_afterdbyte(&self) -> bool {
        *self == Nack::Afterdbyte
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_norm(&self) -> bool {
        *self == Nack::Norm
    }
}
#[doc = "Field `nack` writer - This Bit control Nack generation"]
pub type NackW<'a, REG> = crate::BitWriter<'a, REG, Nack>;
impl<'a, REG> NackW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn afterdbyte(self) -> &'a mut crate::W<REG> {
        self.variant(Nack::Afterdbyte)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn norm(self) -> &'a mut crate::W<REG> {
        self.variant(Nack::Norm)
    }
}
impl R {
    #[doc = "Bit 0 - This Bit control Nack generation"]
    #[inline(always)]
    pub fn nack(&self) -> NackR {
        NackR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This Bit control Nack generation"]
    #[inline(always)]
    #[must_use]
    pub fn nack(&mut self) -> NackW<IcSlvDataNackOnlySpec> {
        NackW::new(self, 0)
    }
}
#[doc = "The register is used to generate a NACK for the data part of a transfer when i2c is acting as a slave-receiver.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_slv_data_nack_only::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_slv_data_nack_only::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcSlvDataNackOnlySpec;
impl crate::RegisterSpec for IcSlvDataNackOnlySpec {
    type Ux = u32;
    const OFFSET: u64 = 132u64;
}
#[doc = "`read()` method returns [`ic_slv_data_nack_only::R`](R) reader structure"]
impl crate::Readable for IcSlvDataNackOnlySpec {}
#[doc = "`write(|w| ..)` method takes [`ic_slv_data_nack_only::W`](W) writer structure"]
impl crate::Writable for IcSlvDataNackOnlySpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_slv_data_nack_only to value 0"]
impl crate::Resettable for IcSlvDataNackOnlySpec {
    const RESET_VALUE: u32 = 0;
}
