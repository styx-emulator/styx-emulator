// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `vid4rd` reader"]
pub type R = crate::R<Vid4rdSpec>;
#[doc = "Register `vid4rd` writer"]
pub type W = crate::W<Vid4rdSpec>;
#[doc = "Field `user` reader - This value is propagated to SCU as ARUSERS."]
pub type UserR = crate::FieldReader;
#[doc = "Field `user` writer - This value is propagated to SCU as ARUSERS."]
pub type UserW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `page` reader - ARADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
pub type PageR = crate::FieldReader;
#[doc = "Field `page` writer - ARADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
pub type PageW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `mid` reader - The 12-bit ID of the master to remap to 3-bit virtual ID N, where N is the 3-bit ID to use."]
pub type MidR = crate::FieldReader<u16>;
#[doc = "Field `mid` writer - The 12-bit ID of the master to remap to 3-bit virtual ID N, where N is the 3-bit ID to use."]
pub type MidW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
#[doc = "Field `force` reader - Set to 1 to force the mapping between the 12-bit ID and 3-bit virtual ID N. Set to 0 to allow the 3-bit ID N to be dynamically allocated."]
pub type ForceR = crate::BitReader;
#[doc = "Field `force` writer - Set to 1 to force the mapping between the 12-bit ID and 3-bit virtual ID N. Set to 0 to allow the 3-bit ID N to be dynamically allocated."]
pub type ForceW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 4:8 - This value is propagated to SCU as ARUSERS."]
    #[inline(always)]
    pub fn user(&self) -> UserR {
        UserR::new(((self.bits >> 4) & 0x1f) as u8)
    }
    #[doc = "Bits 12:13 - ARADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
    #[inline(always)]
    pub fn page(&self) -> PageR {
        PageR::new(((self.bits >> 12) & 3) as u8)
    }
    #[doc = "Bits 16:27 - The 12-bit ID of the master to remap to 3-bit virtual ID N, where N is the 3-bit ID to use."]
    #[inline(always)]
    pub fn mid(&self) -> MidR {
        MidR::new(((self.bits >> 16) & 0x0fff) as u16)
    }
    #[doc = "Bit 31 - Set to 1 to force the mapping between the 12-bit ID and 3-bit virtual ID N. Set to 0 to allow the 3-bit ID N to be dynamically allocated."]
    #[inline(always)]
    pub fn force(&self) -> ForceR {
        ForceR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 4:8 - This value is propagated to SCU as ARUSERS."]
    #[inline(always)]
    #[must_use]
    pub fn user(&mut self) -> UserW<Vid4rdSpec> {
        UserW::new(self, 4)
    }
    #[doc = "Bits 12:13 - ARADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
    #[inline(always)]
    #[must_use]
    pub fn page(&mut self) -> PageW<Vid4rdSpec> {
        PageW::new(self, 12)
    }
    #[doc = "Bits 16:27 - The 12-bit ID of the master to remap to 3-bit virtual ID N, where N is the 3-bit ID to use."]
    #[inline(always)]
    #[must_use]
    pub fn mid(&mut self) -> MidW<Vid4rdSpec> {
        MidW::new(self, 16)
    }
    #[doc = "Bit 31 - Set to 1 to force the mapping between the 12-bit ID and 3-bit virtual ID N. Set to 0 to allow the 3-bit ID N to be dynamically allocated."]
    #[inline(always)]
    #[must_use]
    pub fn force(&mut self) -> ForceW<Vid4rdSpec> {
        ForceW::new(self, 31)
    }
}
#[doc = "The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid4rd::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vid4rd::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Vid4rdSpec;
impl crate::RegisterSpec for Vid4rdSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`vid4rd::R`](R) reader structure"]
impl crate::Readable for Vid4rdSpec {}
#[doc = "`write(|w| ..)` method takes [`vid4rd::W`](W) writer structure"]
impl crate::Writable for Vid4rdSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets vid4rd to value 0"]
impl crate::Resettable for Vid4rdSpec {
    const RESET_VALUE: u32 = 0;
}
