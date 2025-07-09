// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `msgifgrp_IF1DB` reader"]
pub type R = crate::R<MsgifgrpIf1dbSpec>;
#[doc = "Register `msgifgrp_IF1DB` writer"]
pub type W = crate::W<MsgifgrpIf1dbSpec>;
#[doc = "Field `Data4` reader - 5th data byte of a CAN Data Frame"]
pub type Data4R = crate::FieldReader;
#[doc = "Field `Data4` writer - 5th data byte of a CAN Data Frame"]
pub type Data4W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `Data5` reader - 6th data byte of a CAN Data Frame"]
pub type Data5R = crate::FieldReader;
#[doc = "Field `Data5` writer - 6th data byte of a CAN Data Frame"]
pub type Data5W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `Data6` reader - 7th data byte of a CAN Data Frame"]
pub type Data6R = crate::FieldReader;
#[doc = "Field `Data6` writer - 7th data byte of a CAN Data Frame"]
pub type Data6W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `Data7` reader - 8th data byte of a CAN Data Frame"]
pub type Data7R = crate::FieldReader;
#[doc = "Field `Data7` writer - 8th data byte of a CAN Data Frame"]
pub type Data7W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - 5th data byte of a CAN Data Frame"]
    #[inline(always)]
    pub fn data4(&self) -> Data4R {
        Data4R::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - 6th data byte of a CAN Data Frame"]
    #[inline(always)]
    pub fn data5(&self) -> Data5R {
        Data5R::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - 7th data byte of a CAN Data Frame"]
    #[inline(always)]
    pub fn data6(&self) -> Data6R {
        Data6R::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - 8th data byte of a CAN Data Frame"]
    #[inline(always)]
    pub fn data7(&self) -> Data7R {
        Data7R::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - 5th data byte of a CAN Data Frame"]
    #[inline(always)]
    #[must_use]
    pub fn data4(&mut self) -> Data4W<MsgifgrpIf1dbSpec> {
        Data4W::new(self, 0)
    }
    #[doc = "Bits 8:15 - 6th data byte of a CAN Data Frame"]
    #[inline(always)]
    #[must_use]
    pub fn data5(&mut self) -> Data5W<MsgifgrpIf1dbSpec> {
        Data5W::new(self, 8)
    }
    #[doc = "Bits 16:23 - 7th data byte of a CAN Data Frame"]
    #[inline(always)]
    #[must_use]
    pub fn data6(&mut self) -> Data6W<MsgifgrpIf1dbSpec> {
        Data6W::new(self, 16)
    }
    #[doc = "Bits 24:31 - 8th data byte of a CAN Data Frame"]
    #[inline(always)]
    #[must_use]
    pub fn data7(&mut self) -> Data7W<MsgifgrpIf1dbSpec> {
        Data7W::new(self, 24)
    }
}
#[doc = "The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if1db::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if1db::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsgifgrpIf1dbSpec;
impl crate::RegisterSpec for MsgifgrpIf1dbSpec {
    type Ux = u32;
    const OFFSET: u64 = 276u64;
}
#[doc = "`read()` method returns [`msgifgrp_if1db::R`](R) reader structure"]
impl crate::Readable for MsgifgrpIf1dbSpec {}
#[doc = "`write(|w| ..)` method takes [`msgifgrp_if1db::W`](W) writer structure"]
impl crate::Writable for MsgifgrpIf1dbSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets msgifgrp_IF1DB to value 0"]
impl crate::Resettable for MsgifgrpIf1dbSpec {
    const RESET_VALUE: u32 = 0;
}
