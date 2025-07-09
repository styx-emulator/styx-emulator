// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PMEM` reader"]
pub type R = crate::R<PmemSpec>;
#[doc = "Register `PMEM` writer"]
pub type W = crate::W<PmemSpec>;
#[doc = "Field `MEMSETx` reader - MEMSETx"]
pub type MemsetxR = crate::FieldReader;
#[doc = "Field `MEMSETx` writer - MEMSETx"]
pub type MemsetxW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `MEMWAITx` reader - MEMWAITx"]
pub type MemwaitxR = crate::FieldReader;
#[doc = "Field `MEMWAITx` writer - MEMWAITx"]
pub type MemwaitxW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `MEMHOLDx` reader - MEMHOLDx"]
pub type MemholdxR = crate::FieldReader;
#[doc = "Field `MEMHOLDx` writer - MEMHOLDx"]
pub type MemholdxW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `MEMHIZx` reader - MEMHIZx"]
pub type MemhizxR = crate::FieldReader;
#[doc = "Field `MEMHIZx` writer - MEMHIZx"]
pub type MemhizxW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - MEMSETx"]
    #[inline(always)]
    pub fn memsetx(&self) -> MemsetxR {
        MemsetxR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - MEMWAITx"]
    #[inline(always)]
    pub fn memwaitx(&self) -> MemwaitxR {
        MemwaitxR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - MEMHOLDx"]
    #[inline(always)]
    pub fn memholdx(&self) -> MemholdxR {
        MemholdxR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - MEMHIZx"]
    #[inline(always)]
    pub fn memhizx(&self) -> MemhizxR {
        MemhizxR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - MEMSETx"]
    #[inline(always)]
    #[must_use]
    pub fn memsetx(&mut self) -> MemsetxW<PmemSpec> {
        MemsetxW::new(self, 0)
    }
    #[doc = "Bits 8:15 - MEMWAITx"]
    #[inline(always)]
    #[must_use]
    pub fn memwaitx(&mut self) -> MemwaitxW<PmemSpec> {
        MemwaitxW::new(self, 8)
    }
    #[doc = "Bits 16:23 - MEMHOLDx"]
    #[inline(always)]
    #[must_use]
    pub fn memholdx(&mut self) -> MemholdxW<PmemSpec> {
        MemholdxW::new(self, 16)
    }
    #[doc = "Bits 24:31 - MEMHIZx"]
    #[inline(always)]
    #[must_use]
    pub fn memhizx(&mut self) -> MemhizxW<PmemSpec> {
        MemhizxW::new(self, 24)
    }
}
#[doc = "Common memory space timing register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pmem::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pmem::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PmemSpec;
impl crate::RegisterSpec for PmemSpec {
    type Ux = u32;
    const OFFSET: u64 = 136u64;
}
#[doc = "`read()` method returns [`pmem::R`](R) reader structure"]
impl crate::Readable for PmemSpec {}
#[doc = "`write(|w| ..)` method takes [`pmem::W`](W) writer structure"]
impl crate::Writable for PmemSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PMEM to value 0xfcfc_fcfc"]
impl crate::Resettable for PmemSpec {
    const RESET_VALUE: u32 = 0xfcfc_fcfc;
}
