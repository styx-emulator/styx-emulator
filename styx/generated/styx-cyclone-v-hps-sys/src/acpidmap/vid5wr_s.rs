// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `vid5wr_s` reader"]
pub type R = crate::R<Vid5wrSSpec>;
#[doc = "Register `vid5wr_s` writer"]
pub type W = crate::W<Vid5wrSSpec>;
#[doc = "Field `user` reader - This value is propagated to SCU as AWUSERS."]
pub type UserR = crate::FieldReader;
#[doc = "Field `user` writer - This value is propagated to SCU as AWUSERS."]
pub type UserW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `page` reader - AWADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
pub type PageR = crate::FieldReader;
#[doc = "Field `page` writer - AWADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
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
    #[doc = "Bits 4:8 - This value is propagated to SCU as AWUSERS."]
    #[inline(always)]
    pub fn user(&self) -> UserR {
        UserR::new(((self.bits >> 4) & 0x1f) as u8)
    }
    #[doc = "Bits 12:13 - AWADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
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
    #[doc = "Bits 4:8 - This value is propagated to SCU as AWUSERS."]
    #[inline(always)]
    #[must_use]
    pub fn user(&mut self) -> UserW<Vid5wrSSpec> {
        UserW::new(self, 4)
    }
    #[doc = "Bits 12:13 - AWADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
    #[inline(always)]
    #[must_use]
    pub fn page(&mut self) -> PageW<Vid5wrSSpec> {
        PageW::new(self, 12)
    }
    #[doc = "Bits 16:27 - The 12-bit ID of the master to remap to 3-bit virtual ID N, where N is the 3-bit ID to use."]
    #[inline(always)]
    #[must_use]
    pub fn mid(&mut self) -> MidW<Vid5wrSSpec> {
        MidW::new(self, 16)
    }
    #[doc = "Bit 31 - Set to 1 to force the mapping between the 12-bit ID and 3-bit virtual ID N. Set to 0 to allow the 3-bit ID N to be dynamically allocated."]
    #[inline(always)]
    #[must_use]
    pub fn force(&mut self) -> ForceW<Vid5wrSSpec> {
        ForceW::new(self, 31)
    }
}
#[doc = "The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid5wr_s::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Vid5wrSSpec;
impl crate::RegisterSpec for Vid5wrSSpec {
    type Ux = u32;
    const OFFSET: u64 = 76u64;
}
#[doc = "`read()` method returns [`vid5wr_s::R`](R) reader structure"]
impl crate::Readable for Vid5wrSSpec {}
#[doc = "`reset()` method sets vid5wr_s to value 0"]
impl crate::Resettable for Vid5wrSSpec {
    const RESET_VALUE: u32 = 0;
}
