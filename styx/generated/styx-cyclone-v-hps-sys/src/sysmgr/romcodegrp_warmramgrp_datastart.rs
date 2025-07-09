// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `romcodegrp_warmramgrp_datastart` reader"]
pub type R = crate::R<RomcodegrpWarmramgrpDatastartSpec>;
#[doc = "Register `romcodegrp_warmramgrp_datastart` writer"]
pub type W = crate::W<RomcodegrpWarmramgrpDatastartSpec>;
#[doc = "Field `offset` reader - Contains the byte offset into the On-chip RAM of the start of the On-chip RAM region for the warm boot CRC validation. The offset must be an integer multiple of 4 (i.e. aligned to a word). The Boot ROM code will set the top 16 bits to 0xFFFF and clear the bottom 2 bits."]
pub type OffsetR = crate::FieldReader<u16>;
#[doc = "Field `offset` writer - Contains the byte offset into the On-chip RAM of the start of the On-chip RAM region for the warm boot CRC validation. The offset must be an integer multiple of 4 (i.e. aligned to a word). The Boot ROM code will set the top 16 bits to 0xFFFF and clear the bottom 2 bits."]
pub type OffsetW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Contains the byte offset into the On-chip RAM of the start of the On-chip RAM region for the warm boot CRC validation. The offset must be an integer multiple of 4 (i.e. aligned to a word). The Boot ROM code will set the top 16 bits to 0xFFFF and clear the bottom 2 bits."]
    #[inline(always)]
    pub fn offset(&self) -> OffsetR {
        OffsetR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Contains the byte offset into the On-chip RAM of the start of the On-chip RAM region for the warm boot CRC validation. The offset must be an integer multiple of 4 (i.e. aligned to a word). The Boot ROM code will set the top 16 bits to 0xFFFF and clear the bottom 2 bits."]
    #[inline(always)]
    #[must_use]
    pub fn offset(&mut self) -> OffsetW<RomcodegrpWarmramgrpDatastartSpec> {
        OffsetW::new(self, 0)
    }
}
#[doc = "Offset into On-chip RAM of the start of the region for CRC validation\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_warmramgrp_datastart::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_warmramgrp_datastart::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RomcodegrpWarmramgrpDatastartSpec;
impl crate::RegisterSpec for RomcodegrpWarmramgrpDatastartSpec {
    type Ux = u32;
    const OFFSET: u64 = 228u64;
}
#[doc = "`read()` method returns [`romcodegrp_warmramgrp_datastart::R`](R) reader structure"]
impl crate::Readable for RomcodegrpWarmramgrpDatastartSpec {}
#[doc = "`write(|w| ..)` method takes [`romcodegrp_warmramgrp_datastart::W`](W) writer structure"]
impl crate::Writable for RomcodegrpWarmramgrpDatastartSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets romcodegrp_warmramgrp_datastart to value 0"]
impl crate::Resettable for RomcodegrpWarmramgrpDatastartSpec {
    const RESET_VALUE: u32 = 0;
}
