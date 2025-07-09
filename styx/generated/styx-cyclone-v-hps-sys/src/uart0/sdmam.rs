// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `sdmam` reader"]
pub type R = crate::R<SdmamSpec>;
#[doc = "Register `sdmam` writer"]
pub type W = crate::W<SdmamSpec>;
#[doc = "This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the DMA Mode bit gets updated.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sdmam {
    #[doc = "0: `0`"]
    Single = 0,
    #[doc = "1: `1`"]
    Multiple = 1,
}
impl From<Sdmam> for bool {
    #[inline(always)]
    fn from(variant: Sdmam) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sdmam` reader - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the DMA Mode bit gets updated."]
pub type SdmamR = crate::BitReader<Sdmam>;
impl SdmamR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sdmam {
        match self.bits {
            false => Sdmam::Single,
            true => Sdmam::Multiple,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_single(&self) -> bool {
        *self == Sdmam::Single
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_multiple(&self) -> bool {
        *self == Sdmam::Multiple
    }
}
#[doc = "Field `sdmam` writer - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the DMA Mode bit gets updated."]
pub type SdmamW<'a, REG> = crate::BitWriter<'a, REG, Sdmam>;
impl<'a, REG> SdmamW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn single(self) -> &'a mut crate::W<REG> {
        self.variant(Sdmam::Single)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn multiple(self) -> &'a mut crate::W<REG> {
        self.variant(Sdmam::Multiple)
    }
}
impl R {
    #[doc = "Bit 0 - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the DMA Mode bit gets updated."]
    #[inline(always)]
    pub fn sdmam(&self) -> SdmamR {
        SdmamR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This can be used to remove the burden of having to store the previously written value to the FCR in memory and having to mask this value so that only the DMA Mode bit gets updated."]
    #[inline(always)]
    #[must_use]
    pub fn sdmam(&mut self) -> SdmamW<SdmamSpec> {
        SdmamW::new(self, 0)
    }
}
#[doc = "This is a shadow register for the DMA mode bit (FCR\\[3\\]).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdmam::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdmam::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SdmamSpec;
impl crate::RegisterSpec for SdmamSpec {
    type Ux = u32;
    const OFFSET: u64 = 148u64;
}
#[doc = "`read()` method returns [`sdmam::R`](R) reader structure"]
impl crate::Readable for SdmamSpec {}
#[doc = "`write(|w| ..)` method takes [`sdmam::W`](W) writer structure"]
impl crate::Writable for SdmamSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets sdmam to value 0"]
impl crate::Resettable for SdmamSpec {
    const RESET_VALUE: u32 = 0;
}
