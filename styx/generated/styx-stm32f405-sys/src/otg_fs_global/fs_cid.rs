// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FS_CID` reader"]
pub type R = crate::R<FsCidSpec>;
#[doc = "Register `FS_CID` writer"]
pub type W = crate::W<FsCidSpec>;
#[doc = "Field `PRODUCT_ID` reader - Product ID field"]
pub type ProductIdR = crate::FieldReader<u32>;
#[doc = "Field `PRODUCT_ID` writer - Product ID field"]
pub type ProductIdW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Product ID field"]
    #[inline(always)]
    pub fn product_id(&self) -> ProductIdR {
        ProductIdR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Product ID field"]
    #[inline(always)]
    #[must_use]
    pub fn product_id(&mut self) -> ProductIdW<FsCidSpec> {
        ProductIdW::new(self, 0)
    }
}
#[doc = "core ID register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_cid::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_cid::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FsCidSpec;
impl crate::RegisterSpec for FsCidSpec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`read()` method returns [`fs_cid::R`](R) reader structure"]
impl crate::Readable for FsCidSpec {}
#[doc = "`write(|w| ..)` method takes [`fs_cid::W`](W) writer structure"]
impl crate::Writable for FsCidSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FS_CID to value 0x1000"]
impl crate::Resettable for FsCidSpec {
    const RESET_VALUE: u32 = 0x1000;
}
