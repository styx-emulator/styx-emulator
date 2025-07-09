// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `risr` reader"]
pub type R = crate::R<RisrSpec>;
#[doc = "Register `risr` writer"]
pub type W = crate::W<RisrSpec>;
#[doc = "The interrupt is active or inactive prior to masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txeir {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txeir> for bool {
    #[inline(always)]
    fn from(variant: Txeir) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txeir` reader - The interrupt is active or inactive prior to masking."]
pub type TxeirR = crate::BitReader<Txeir>;
impl TxeirR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txeir {
        match self.bits {
            false => Txeir::Inactive,
            true => Txeir::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txeir::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txeir::Active
    }
}
#[doc = "Field `txeir` writer - The interrupt is active or inactive prior to masking."]
pub type TxeirW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The interrupt is active or inactive prior to masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txoir {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txoir> for bool {
    #[inline(always)]
    fn from(variant: Txoir) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txoir` reader - The interrupt is active or inactive prior to masking."]
pub type TxoirR = crate::BitReader<Txoir>;
impl TxoirR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txoir {
        match self.bits {
            false => Txoir::Inactive,
            true => Txoir::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txoir::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txoir::Active
    }
}
#[doc = "Field `txoir` writer - The interrupt is active or inactive prior to masking."]
pub type TxoirW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The interrupt is active or inactive prior to masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxuir {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxuir> for bool {
    #[inline(always)]
    fn from(variant: Rxuir) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxuir` reader - The interrupt is active or inactive prior to masking."]
pub type RxuirR = crate::BitReader<Rxuir>;
impl RxuirR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxuir {
        match self.bits {
            false => Rxuir::Inactive,
            true => Rxuir::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxuir::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxuir::Active
    }
}
#[doc = "Field `rxuir` writer - The interrupt is active or inactive prior to masking."]
pub type RxuirW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The interrupt is active or inactive prior to masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxoir {
    #[doc = "0: `0`"]
    Inactove = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxoir> for bool {
    #[inline(always)]
    fn from(variant: Rxoir) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxoir` reader - The interrupt is active or inactive prior to masking."]
pub type RxoirR = crate::BitReader<Rxoir>;
impl RxoirR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxoir {
        match self.bits {
            false => Rxoir::Inactove,
            true => Rxoir::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactove(&self) -> bool {
        *self == Rxoir::Inactove
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxoir::Active
    }
}
#[doc = "Field `rxoir` writer - The interrupt is active or inactive prior to masking."]
pub type RxoirW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The interrupt is active or inactive prior to masking.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxfir {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxfir> for bool {
    #[inline(always)]
    fn from(variant: Rxfir) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxfir` reader - The interrupt is active or inactive prior to masking."]
pub type RxfirR = crate::BitReader<Rxfir>;
impl RxfirR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxfir {
        match self.bits {
            false => Rxfir::Inactive,
            true => Rxfir::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxfir::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxfir::Active
    }
}
#[doc = "Field `rxfir` writer - The interrupt is active or inactive prior to masking."]
pub type RxfirW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - The interrupt is active or inactive prior to masking."]
    #[inline(always)]
    pub fn txeir(&self) -> TxeirR {
        TxeirR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - The interrupt is active or inactive prior to masking."]
    #[inline(always)]
    pub fn txoir(&self) -> TxoirR {
        TxoirR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - The interrupt is active or inactive prior to masking."]
    #[inline(always)]
    pub fn rxuir(&self) -> RxuirR {
        RxuirR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - The interrupt is active or inactive prior to masking."]
    #[inline(always)]
    pub fn rxoir(&self) -> RxoirR {
        RxoirR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - The interrupt is active or inactive prior to masking."]
    #[inline(always)]
    pub fn rxfir(&self) -> RxfirR {
        RxfirR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - The interrupt is active or inactive prior to masking."]
    #[inline(always)]
    #[must_use]
    pub fn txeir(&mut self) -> TxeirW<RisrSpec> {
        TxeirW::new(self, 0)
    }
    #[doc = "Bit 1 - The interrupt is active or inactive prior to masking."]
    #[inline(always)]
    #[must_use]
    pub fn txoir(&mut self) -> TxoirW<RisrSpec> {
        TxoirW::new(self, 1)
    }
    #[doc = "Bit 2 - The interrupt is active or inactive prior to masking."]
    #[inline(always)]
    #[must_use]
    pub fn rxuir(&mut self) -> RxuirW<RisrSpec> {
        RxuirW::new(self, 2)
    }
    #[doc = "Bit 3 - The interrupt is active or inactive prior to masking."]
    #[inline(always)]
    #[must_use]
    pub fn rxoir(&mut self) -> RxoirW<RisrSpec> {
        RxoirW::new(self, 3)
    }
    #[doc = "Bit 4 - The interrupt is active or inactive prior to masking."]
    #[inline(always)]
    #[must_use]
    pub fn rxfir(&mut self) -> RxfirW<RisrSpec> {
        RxfirW::new(self, 4)
    }
}
#[doc = "This register reports the status of the SPI Master interrupts prior to masking.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`risr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RisrSpec;
impl crate::RegisterSpec for RisrSpec {
    type Ux = u32;
    const OFFSET: u64 = 52u64;
}
#[doc = "`read()` method returns [`risr::R`](R) reader structure"]
impl crate::Readable for RisrSpec {}
#[doc = "`reset()` method sets risr to value 0"]
impl crate::Resettable for RisrSpec {
    const RESET_VALUE: u32 = 0;
}
