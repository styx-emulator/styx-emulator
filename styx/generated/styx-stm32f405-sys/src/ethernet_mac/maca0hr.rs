// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MACA0HR` reader"]
pub type R = crate::R<Maca0hrSpec>;
#[doc = "Register `MACA0HR` writer"]
pub type W = crate::W<Maca0hrSpec>;
#[doc = "Field `MACA0H` reader - MAC address0 high"]
pub type Maca0hR = crate::FieldReader<u16>;
#[doc = "Field `MACA0H` writer - MAC address0 high"]
pub type Maca0hW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `MO` reader - Always 1"]
pub type MoR = crate::BitReader;
#[doc = "Field `MO` writer - Always 1"]
pub type MoW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:15 - MAC address0 high"]
    #[inline(always)]
    pub fn maca0h(&self) -> Maca0hR {
        Maca0hR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bit 31 - Always 1"]
    #[inline(always)]
    pub fn mo(&self) -> MoR {
        MoR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:15 - MAC address0 high"]
    #[inline(always)]
    #[must_use]
    pub fn maca0h(&mut self) -> Maca0hW<Maca0hrSpec> {
        Maca0hW::new(self, 0)
    }
    #[doc = "Bit 31 - Always 1"]
    #[inline(always)]
    #[must_use]
    pub fn mo(&mut self) -> MoW<Maca0hrSpec> {
        MoW::new(self, 31)
    }
}
#[doc = "Ethernet MAC address 0 high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`maca0hr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`maca0hr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Maca0hrSpec;
impl crate::RegisterSpec for Maca0hrSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`maca0hr::R`](R) reader structure"]
impl crate::Readable for Maca0hrSpec {}
#[doc = "`write(|w| ..)` method takes [`maca0hr::W`](W) writer structure"]
impl crate::Writable for Maca0hrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACA0HR to value 0x0010_ffff"]
impl crate::Resettable for Maca0hrSpec {
    const RESET_VALUE: u32 = 0x0010_ffff;
}
