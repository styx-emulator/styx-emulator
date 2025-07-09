// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `idr` reader"]
pub type R = crate::R<IdrSpec>;
#[doc = "Register `idr` writer"]
pub type W = crate::W<IdrSpec>;
#[doc = "Field `idr` reader - This register contains the peripherals identification code"]
pub type IdrR = crate::FieldReader<u32>;
#[doc = "Field `idr` writer - This register contains the peripherals identification code"]
pub type IdrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This register contains the peripherals identification code"]
    #[inline(always)]
    pub fn idr(&self) -> IdrR {
        IdrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This register contains the peripherals identification code"]
    #[inline(always)]
    #[must_use]
    pub fn idr(&mut self) -> IdrW<IdrSpec> {
        IdrW::new(self, 0)
    }
}
#[doc = "This register contains the peripherals identification code, which is 0x05510000.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdrSpec;
impl crate::RegisterSpec for IdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 88u64;
}
#[doc = "`read()` method returns [`idr::R`](R) reader structure"]
impl crate::Readable for IdrSpec {}
#[doc = "`reset()` method sets idr to value 0x0551_0000"]
impl crate::Resettable for IdrSpec {
    const RESET_VALUE: u32 = 0x0551_0000;
}
