// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `stet` reader"]
pub type R = crate::R<StetSpec>;
#[doc = "Register `stet` writer"]
pub type W = crate::W<StetSpec>;
#[doc = "This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the Tx empty trigger bit gets updated. This is used to select the empty threshold level at which the THRE Interrupts will be generated when the mode is active. These threshold levels are also described in. The enum trigger levels are supported.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stet {
    #[doc = "0: `0`"]
    Fifoempty = 0,
    #[doc = "1: `1`"]
    Twochars = 1,
    #[doc = "2: `10`"]
    Quarterfull = 2,
    #[doc = "3: `11`"]
    Halffull = 3,
}
impl From<Stet> for u8 {
    #[inline(always)]
    fn from(variant: Stet) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Stet {
    type Ux = u8;
}
#[doc = "Field `stet` reader - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the Tx empty trigger bit gets updated. This is used to select the empty threshold level at which the THRE Interrupts will be generated when the mode is active. These threshold levels are also described in. The enum trigger levels are supported."]
pub type StetR = crate::FieldReader<Stet>;
impl StetR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Stet {
        match self.bits {
            0 => Stet::Fifoempty,
            1 => Stet::Twochars,
            2 => Stet::Quarterfull,
            3 => Stet::Halffull,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fifoempty(&self) -> bool {
        *self == Stet::Fifoempty
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_twochars(&self) -> bool {
        *self == Stet::Twochars
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_quarterfull(&self) -> bool {
        *self == Stet::Quarterfull
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_halffull(&self) -> bool {
        *self == Stet::Halffull
    }
}
#[doc = "Field `stet` writer - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the Tx empty trigger bit gets updated. This is used to select the empty threshold level at which the THRE Interrupts will be generated when the mode is active. These threshold levels are also described in. The enum trigger levels are supported."]
pub type StetW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Stet>;
impl<'a, REG> StetW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn fifoempty(self) -> &'a mut crate::W<REG> {
        self.variant(Stet::Fifoempty)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn twochars(self) -> &'a mut crate::W<REG> {
        self.variant(Stet::Twochars)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn quarterfull(self) -> &'a mut crate::W<REG> {
        self.variant(Stet::Quarterfull)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn halffull(self) -> &'a mut crate::W<REG> {
        self.variant(Stet::Halffull)
    }
}
impl R {
    #[doc = "Bits 0:1 - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the Tx empty trigger bit gets updated. This is used to select the empty threshold level at which the THRE Interrupts will be generated when the mode is active. These threshold levels are also described in. The enum trigger levels are supported."]
    #[inline(always)]
    pub fn stet(&self) -> StetR {
        StetR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the Tx empty trigger bit gets updated. This is used to select the empty threshold level at which the THRE Interrupts will be generated when the mode is active. These threshold levels are also described in. The enum trigger levels are supported."]
    #[inline(always)]
    #[must_use]
    pub fn stet(&mut self) -> StetW<StetSpec> {
        StetW::new(self, 0)
    }
}
#[doc = "This is a shadow register for the Tx empty trigger bits (FCR\\[5:4\\]).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`stet::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`stet::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StetSpec;
impl crate::RegisterSpec for StetSpec {
    type Ux = u32;
    const OFFSET: u64 = 160u64;
}
#[doc = "`read()` method returns [`stet::R`](R) reader structure"]
impl crate::Readable for StetSpec {}
#[doc = "`write(|w| ..)` method takes [`stet::W`](W) writer structure"]
impl crate::Writable for StetSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets stet to value 0"]
impl crate::Resettable for StetSpec {
    const RESET_VALUE: u32 = 0;
}
