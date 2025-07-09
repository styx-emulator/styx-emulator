// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dbaddr` reader"]
pub type R = crate::R<DbaddrSpec>;
#[doc = "Register `dbaddr` writer"]
pub type W = crate::W<DbaddrSpec>;
#[doc = "Field `sdl` reader - Contains the base address of the First Descriptor. This is the byte address divided by 4."]
pub type SdlR = crate::FieldReader<u32>;
#[doc = "Field `sdl` writer - Contains the base address of the First Descriptor. This is the byte address divided by 4."]
pub type SdlW<'a, REG> = crate::FieldWriter<'a, REG, 30, u32>;
impl R {
    #[doc = "Bits 2:31 - Contains the base address of the First Descriptor. This is the byte address divided by 4."]
    #[inline(always)]
    pub fn sdl(&self) -> SdlR {
        SdlR::new((self.bits >> 2) & 0x3fff_ffff)
    }
}
impl W {
    #[doc = "Bits 2:31 - Contains the base address of the First Descriptor. This is the byte address divided by 4."]
    #[inline(always)]
    #[must_use]
    pub fn sdl(&mut self) -> SdlW<DbaddrSpec> {
        SdlW::new(self, 2)
    }
}
#[doc = "See Field Descriptor\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dbaddr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dbaddr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DbaddrSpec;
impl crate::RegisterSpec for DbaddrSpec {
    type Ux = u32;
    const OFFSET: u64 = 136u64;
}
#[doc = "`read()` method returns [`dbaddr::R`](R) reader structure"]
impl crate::Readable for DbaddrSpec {}
#[doc = "`write(|w| ..)` method takes [`dbaddr::W`](W) writer structure"]
impl crate::Writable for DbaddrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dbaddr to value 0"]
impl crate::Resettable for DbaddrSpec {
    const RESET_VALUE: u32 = 0;
}
