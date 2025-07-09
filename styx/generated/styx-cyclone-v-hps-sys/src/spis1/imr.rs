// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `imr` reader"]
pub type R = crate::R<ImrSpec>;
#[doc = "Register `imr` writer"]
pub type W = crate::W<ImrSpec>;
#[doc = "Empty mask.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txeim {
    #[doc = "0: `0`"]
    Masked = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txeim> for bool {
    #[inline(always)]
    fn from(variant: Txeim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txeim` reader - Empty mask."]
pub type TxeimR = crate::BitReader<Txeim>;
impl TxeimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txeim {
        match self.bits {
            false => Txeim::Masked,
            true => Txeim::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_masked(&self) -> bool {
        *self == Txeim::Masked
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txeim::Enabled
    }
}
#[doc = "Field `txeim` writer - Empty mask."]
pub type TxeimW<'a, REG> = crate::BitWriter<'a, REG, Txeim>;
impl<'a, REG> TxeimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn masked(self) -> &'a mut crate::W<REG> {
        self.variant(Txeim::Masked)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Txeim::Enabled)
    }
}
#[doc = "Overflow mask.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txoim {
    #[doc = "0: `0`"]
    Masked = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Txoim> for bool {
    #[inline(always)]
    fn from(variant: Txoim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txoim` reader - Overflow mask."]
pub type TxoimR = crate::BitReader<Txoim>;
impl TxoimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txoim {
        match self.bits {
            false => Txoim::Masked,
            true => Txoim::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_masked(&self) -> bool {
        *self == Txoim::Masked
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Txoim::Enabled
    }
}
#[doc = "Field `txoim` writer - Overflow mask."]
pub type TxoimW<'a, REG> = crate::BitWriter<'a, REG, Txoim>;
impl<'a, REG> TxoimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn masked(self) -> &'a mut crate::W<REG> {
        self.variant(Txoim::Masked)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Txoim::Enabled)
    }
}
#[doc = "Underfow Mask\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxuim {
    #[doc = "0: `0`"]
    Masked = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rxuim> for bool {
    #[inline(always)]
    fn from(variant: Rxuim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxuim` reader - Underfow Mask"]
pub type RxuimR = crate::BitReader<Rxuim>;
impl RxuimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxuim {
        match self.bits {
            false => Rxuim::Masked,
            true => Rxuim::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_masked(&self) -> bool {
        *self == Rxuim::Masked
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rxuim::Enabled
    }
}
#[doc = "Field `rxuim` writer - Underfow Mask"]
pub type RxuimW<'a, REG> = crate::BitWriter<'a, REG, Rxuim>;
impl<'a, REG> RxuimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn masked(self) -> &'a mut crate::W<REG> {
        self.variant(Rxuim::Masked)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rxuim::Enabled)
    }
}
#[doc = "Overflow Mask.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxoim {
    #[doc = "0: `0`"]
    Masked = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rxoim> for bool {
    #[inline(always)]
    fn from(variant: Rxoim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxoim` reader - Overflow Mask."]
pub type RxoimR = crate::BitReader<Rxoim>;
impl RxoimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxoim {
        match self.bits {
            false => Rxoim::Masked,
            true => Rxoim::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_masked(&self) -> bool {
        *self == Rxoim::Masked
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rxoim::Enabled
    }
}
#[doc = "Field `rxoim` writer - Overflow Mask."]
pub type RxoimW<'a, REG> = crate::BitWriter<'a, REG, Rxoim>;
impl<'a, REG> RxoimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn masked(self) -> &'a mut crate::W<REG> {
        self.variant(Rxoim::Masked)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rxoim::Enabled)
    }
}
#[doc = "FIFO Full Mask.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxfim {
    #[doc = "0: `0`"]
    Masked = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rxfim> for bool {
    #[inline(always)]
    fn from(variant: Rxfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxfim` reader - FIFO Full Mask."]
pub type RxfimR = crate::BitReader<Rxfim>;
impl RxfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxfim {
        match self.bits {
            false => Rxfim::Masked,
            true => Rxfim::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_masked(&self) -> bool {
        *self == Rxfim::Masked
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rxfim::Enabled
    }
}
#[doc = "Field `rxfim` writer - FIFO Full Mask."]
pub type RxfimW<'a, REG> = crate::BitWriter<'a, REG, Rxfim>;
impl<'a, REG> RxfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn masked(self) -> &'a mut crate::W<REG> {
        self.variant(Rxfim::Masked)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rxfim::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - Empty mask."]
    #[inline(always)]
    pub fn txeim(&self) -> TxeimR {
        TxeimR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Overflow mask."]
    #[inline(always)]
    pub fn txoim(&self) -> TxoimR {
        TxoimR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Underfow Mask"]
    #[inline(always)]
    pub fn rxuim(&self) -> RxuimR {
        RxuimR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Overflow Mask."]
    #[inline(always)]
    pub fn rxoim(&self) -> RxoimR {
        RxoimR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - FIFO Full Mask."]
    #[inline(always)]
    pub fn rxfim(&self) -> RxfimR {
        RxfimR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Empty mask."]
    #[inline(always)]
    #[must_use]
    pub fn txeim(&mut self) -> TxeimW<ImrSpec> {
        TxeimW::new(self, 0)
    }
    #[doc = "Bit 1 - Overflow mask."]
    #[inline(always)]
    #[must_use]
    pub fn txoim(&mut self) -> TxoimW<ImrSpec> {
        TxoimW::new(self, 1)
    }
    #[doc = "Bit 2 - Underfow Mask"]
    #[inline(always)]
    #[must_use]
    pub fn rxuim(&mut self) -> RxuimW<ImrSpec> {
        RxuimW::new(self, 2)
    }
    #[doc = "Bit 3 - Overflow Mask."]
    #[inline(always)]
    #[must_use]
    pub fn rxoim(&mut self) -> RxoimW<ImrSpec> {
        RxoimW::new(self, 3)
    }
    #[doc = "Bit 4 - FIFO Full Mask."]
    #[inline(always)]
    #[must_use]
    pub fn rxfim(&mut self) -> RxfimW<ImrSpec> {
        RxfimW::new(self, 4)
    }
}
#[doc = "This register masks or enables all interrupts generated by the SPI Slave.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`imr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`imr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ImrSpec;
impl crate::RegisterSpec for ImrSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`imr::R`](R) reader structure"]
impl crate::Readable for ImrSpec {}
#[doc = "`write(|w| ..)` method takes [`imr::W`](W) writer structure"]
impl crate::Writable for ImrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets imr to value 0x1f"]
impl crate::Resettable for ImrSpec {
    const RESET_VALUE: u32 = 0x1f;
}
