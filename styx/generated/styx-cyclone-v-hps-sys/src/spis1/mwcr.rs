// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `mwcr` reader"]
pub type R = crate::R<MwcrSpec>;
#[doc = "Register `mwcr` writer"]
pub type W = crate::W<MwcrSpec>;
#[doc = "Defines whether the Microwire transfer is sequential or non-sequential. When sequential mode is used, only one control word is needed to transmit or receive a block of data words. When non-sequential mode is used, there must be a control word for each data word that is transmitted or received.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mwmod {
    #[doc = "0: `0`"]
    Nonseq = 0,
    #[doc = "1: `1`"]
    Seq = 1,
}
impl From<Mwmod> for bool {
    #[inline(always)]
    fn from(variant: Mwmod) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mwmod` reader - Defines whether the Microwire transfer is sequential or non-sequential. When sequential mode is used, only one control word is needed to transmit or receive a block of data words. When non-sequential mode is used, there must be a control word for each data word that is transmitted or received."]
pub type MwmodR = crate::BitReader<Mwmod>;
impl MwmodR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mwmod {
        match self.bits {
            false => Mwmod::Nonseq,
            true => Mwmod::Seq,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nonseq(&self) -> bool {
        *self == Mwmod::Nonseq
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_seq(&self) -> bool {
        *self == Mwmod::Seq
    }
}
#[doc = "Field `mwmod` writer - Defines whether the Microwire transfer is sequential or non-sequential. When sequential mode is used, only one control word is needed to transmit or receive a block of data words. When non-sequential mode is used, there must be a control word for each data word that is transmitted or received."]
pub type MwmodW<'a, REG> = crate::BitWriter<'a, REG, Mwmod>;
impl<'a, REG> MwmodW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nonseq(self) -> &'a mut crate::W<REG> {
        self.variant(Mwmod::Nonseq)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn seq(self) -> &'a mut crate::W<REG> {
        self.variant(Mwmod::Seq)
    }
}
#[doc = "Defines the direction of the data word when the Microwire serial protocol is used.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mdd {
    #[doc = "0: `0`"]
    Rxmode = 0,
    #[doc = "1: `1`"]
    Txmode = 1,
}
impl From<Mdd> for bool {
    #[inline(always)]
    fn from(variant: Mdd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `mdd` reader - Defines the direction of the data word when the Microwire serial protocol is used."]
pub type MddR = crate::BitReader<Mdd>;
impl MddR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Mdd {
        match self.bits {
            false => Mdd::Rxmode,
            true => Mdd::Txmode,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_rxmode(&self) -> bool {
        *self == Mdd::Rxmode
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_txmode(&self) -> bool {
        *self == Mdd::Txmode
    }
}
#[doc = "Field `mdd` writer - Defines the direction of the data word when the Microwire serial protocol is used."]
pub type MddW<'a, REG> = crate::BitWriter<'a, REG, Mdd>;
impl<'a, REG> MddW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn rxmode(self) -> &'a mut crate::W<REG> {
        self.variant(Mdd::Rxmode)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn txmode(self) -> &'a mut crate::W<REG> {
        self.variant(Mdd::Txmode)
    }
}
impl R {
    #[doc = "Bit 0 - Defines whether the Microwire transfer is sequential or non-sequential. When sequential mode is used, only one control word is needed to transmit or receive a block of data words. When non-sequential mode is used, there must be a control word for each data word that is transmitted or received."]
    #[inline(always)]
    pub fn mwmod(&self) -> MwmodR {
        MwmodR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Defines the direction of the data word when the Microwire serial protocol is used."]
    #[inline(always)]
    pub fn mdd(&self) -> MddR {
        MddR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Defines whether the Microwire transfer is sequential or non-sequential. When sequential mode is used, only one control word is needed to transmit or receive a block of data words. When non-sequential mode is used, there must be a control word for each data word that is transmitted or received."]
    #[inline(always)]
    #[must_use]
    pub fn mwmod(&mut self) -> MwmodW<MwcrSpec> {
        MwmodW::new(self, 0)
    }
    #[doc = "Bit 1 - Defines the direction of the data word when the Microwire serial protocol is used."]
    #[inline(always)]
    #[must_use]
    pub fn mdd(&mut self) -> MddW<MwcrSpec> {
        MddW::new(self, 1)
    }
}
#[doc = "This register controls the direction of the data word for the half-duplex Microwire serial protocol. It is impossible to write to this register when the SPI Slave is enabled. The SPI Slave is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mwcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mwcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MwcrSpec;
impl crate::RegisterSpec for MwcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`mwcr::R`](R) reader structure"]
impl crate::Readable for MwcrSpec {}
#[doc = "`write(|w| ..)` method takes [`mwcr::W`](W) writer structure"]
impl crate::Writable for MwcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mwcr to value 0"]
impl crate::Resettable for MwcrSpec {
    const RESET_VALUE: u32 = 0;
}
