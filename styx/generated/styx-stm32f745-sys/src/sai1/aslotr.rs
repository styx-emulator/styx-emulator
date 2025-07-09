// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ASLOTR` reader"]
pub type R = crate::R<AslotrSpec>;
#[doc = "Register `ASLOTR` writer"]
pub type W = crate::W<AslotrSpec>;
#[doc = "Field `FBOFF` reader - First bit offset"]
pub type FboffR = crate::FieldReader;
#[doc = "Field `FBOFF` writer - First bit offset"]
pub type FboffW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `SLOTSZ` reader - Slot size"]
pub type SlotszR = crate::FieldReader;
#[doc = "Field `SLOTSZ` writer - Slot size"]
pub type SlotszW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `NBSLOT` reader - Number of slots in an audio frame"]
pub type NbslotR = crate::FieldReader;
#[doc = "Field `NBSLOT` writer - Number of slots in an audio frame"]
pub type NbslotW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `SLOTEN` reader - Slot enable"]
pub type SlotenR = crate::FieldReader<u16>;
#[doc = "Field `SLOTEN` writer - Slot enable"]
pub type SlotenW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:4 - First bit offset"]
    #[inline(always)]
    pub fn fboff(&self) -> FboffR {
        FboffR::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bits 6:7 - Slot size"]
    #[inline(always)]
    pub fn slotsz(&self) -> SlotszR {
        SlotszR::new(((self.bits >> 6) & 3) as u8)
    }
    #[doc = "Bits 8:11 - Number of slots in an audio frame"]
    #[inline(always)]
    pub fn nbslot(&self) -> NbslotR {
        NbslotR::new(((self.bits >> 8) & 0x0f) as u8)
    }
    #[doc = "Bits 16:31 - Slot enable"]
    #[inline(always)]
    pub fn sloten(&self) -> SlotenR {
        SlotenR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:4 - First bit offset"]
    #[inline(always)]
    #[must_use]
    pub fn fboff(&mut self) -> FboffW<AslotrSpec> {
        FboffW::new(self, 0)
    }
    #[doc = "Bits 6:7 - Slot size"]
    #[inline(always)]
    #[must_use]
    pub fn slotsz(&mut self) -> SlotszW<AslotrSpec> {
        SlotszW::new(self, 6)
    }
    #[doc = "Bits 8:11 - Number of slots in an audio frame"]
    #[inline(always)]
    #[must_use]
    pub fn nbslot(&mut self) -> NbslotW<AslotrSpec> {
        NbslotW::new(self, 8)
    }
    #[doc = "Bits 16:31 - Slot enable"]
    #[inline(always)]
    #[must_use]
    pub fn sloten(&mut self) -> SlotenW<AslotrSpec> {
        SlotenW::new(self, 16)
    }
}
#[doc = "ASlot register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`aslotr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`aslotr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct AslotrSpec;
impl crate::RegisterSpec for AslotrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`aslotr::R`](R) reader structure"]
impl crate::Readable for AslotrSpec {}
#[doc = "`write(|w| ..)` method takes [`aslotr::W`](W) writer structure"]
impl crate::Writable for AslotrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ASLOTR to value 0"]
impl crate::Resettable for AslotrSpec {
    const RESET_VALUE: u32 = 0;
}
