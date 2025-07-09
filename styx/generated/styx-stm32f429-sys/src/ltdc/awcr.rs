// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AWCR` reader"]
pub type R = crate::R<AwcrSpec>;
#[doc = "Register `AWCR` writer"]
pub type W = crate::W<AwcrSpec>;
#[doc = "Field `AAH` reader - Accumulated Active Height (in units of horizontal scan line)"]
pub type AahR = crate::FieldReader<u16>;
#[doc = "Field `AAH` writer - Accumulated Active Height (in units of horizontal scan line)"]
pub type AahW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
#[doc = "Field `AAV` reader - AAV"]
pub type AavR = crate::FieldReader<u16>;
#[doc = "Field `AAV` writer - AAV"]
pub type AavW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
impl R {
    #[doc = "Bits 0:10 - Accumulated Active Height (in units of horizontal scan line)"]
    #[inline(always)]
    pub fn aah(&self) -> AahR {
        AahR::new((self.bits & 0x07ff) as u16)
    }
    #[doc = "Bits 16:25 - AAV"]
    #[inline(always)]
    pub fn aav(&self) -> AavR {
        AavR::new(((self.bits >> 16) & 0x03ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:10 - Accumulated Active Height (in units of horizontal scan line)"]
    #[inline(always)]
    #[must_use]
    pub fn aah(&mut self) -> AahW<AwcrSpec> {
        AahW::new(self, 0)
    }
    #[doc = "Bits 16:25 - AAV"]
    #[inline(always)]
    #[must_use]
    pub fn aav(&mut self) -> AavW<AwcrSpec> {
        AavW::new(self, 16)
    }
}
#[doc = "Active Width Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`awcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`awcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct AwcrSpec;
impl crate::RegisterSpec for AwcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`awcr::R`](R) reader structure"]
impl crate::Readable for AwcrSpec {}
#[doc = "`write(|w| ..)` method takes [`awcr::W`](W) writer structure"]
impl crate::Writable for AwcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AWCR to value 0"]
impl crate::Resettable for AwcrSpec {
    const RESET_VALUE: u32 = 0;
}
