// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `romcodegrp_initswlastld` reader"]
pub type R = crate::R<RomcodegrpInitswlastldSpec>;
#[doc = "Register `romcodegrp_initswlastld` writer"]
pub type W = crate::W<RomcodegrpInitswlastldSpec>;
#[doc = "Field `index` reader - Index of last image loaded."]
pub type IndexR = crate::FieldReader;
#[doc = "Field `index` writer - Index of last image loaded."]
pub type IndexW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Index of last image loaded."]
    #[inline(always)]
    pub fn index(&self) -> IndexR {
        IndexR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Index of last image loaded."]
    #[inline(always)]
    #[must_use]
    pub fn index(&mut self) -> IndexW<RomcodegrpInitswlastldSpec> {
        IndexW::new(self, 0)
    }
}
#[doc = "Contains the index of the last preloader software image loaded by the Boot ROM from the boot device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_initswlastld::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_initswlastld::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RomcodegrpInitswlastldSpec;
impl crate::RegisterSpec for RomcodegrpInitswlastldSpec {
    type Ux = u32;
    const OFFSET: u64 = 204u64;
}
#[doc = "`read()` method returns [`romcodegrp_initswlastld::R`](R) reader structure"]
impl crate::Readable for RomcodegrpInitswlastldSpec {}
#[doc = "`write(|w| ..)` method takes [`romcodegrp_initswlastld::W`](W) writer structure"]
impl crate::Writable for RomcodegrpInitswlastldSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets romcodegrp_initswlastld to value 0"]
impl crate::Resettable for RomcodegrpInitswlastldSpec {
    const RESET_VALUE: u32 = 0;
}
