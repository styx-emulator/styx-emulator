// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MACFCR` reader"]
pub type R = crate::R<MacfcrSpec>;
#[doc = "Register `MACFCR` writer"]
pub type W = crate::W<MacfcrSpec>;
#[doc = "Field `FCB` reader - FCB"]
pub type FcbR = crate::BitReader;
#[doc = "Field `FCB` writer - FCB"]
pub type FcbW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TFCE` reader - TFCE"]
pub type TfceR = crate::BitReader;
#[doc = "Field `TFCE` writer - TFCE"]
pub type TfceW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RFCE` reader - RFCE"]
pub type RfceR = crate::BitReader;
#[doc = "Field `RFCE` writer - RFCE"]
pub type RfceW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UPFD` reader - UPFD"]
pub type UpfdR = crate::BitReader;
#[doc = "Field `UPFD` writer - UPFD"]
pub type UpfdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLT` reader - PLT"]
pub type PltR = crate::FieldReader;
#[doc = "Field `PLT` writer - PLT"]
pub type PltW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `ZQPD` reader - ZQPD"]
pub type ZqpdR = crate::BitReader;
#[doc = "Field `ZQPD` writer - ZQPD"]
pub type ZqpdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PT` reader - PT"]
pub type PtR = crate::FieldReader<u16>;
#[doc = "Field `PT` writer - PT"]
pub type PtW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bit 0 - FCB"]
    #[inline(always)]
    pub fn fcb(&self) -> FcbR {
        FcbR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - TFCE"]
    #[inline(always)]
    pub fn tfce(&self) -> TfceR {
        TfceR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - RFCE"]
    #[inline(always)]
    pub fn rfce(&self) -> RfceR {
        RfceR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - UPFD"]
    #[inline(always)]
    pub fn upfd(&self) -> UpfdR {
        UpfdR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 4:5 - PLT"]
    #[inline(always)]
    pub fn plt(&self) -> PltR {
        PltR::new(((self.bits >> 4) & 3) as u8)
    }
    #[doc = "Bit 7 - ZQPD"]
    #[inline(always)]
    pub fn zqpd(&self) -> ZqpdR {
        ZqpdR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 16:31 - PT"]
    #[inline(always)]
    pub fn pt(&self) -> PtR {
        PtR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bit 0 - FCB"]
    #[inline(always)]
    #[must_use]
    pub fn fcb(&mut self) -> FcbW<MacfcrSpec> {
        FcbW::new(self, 0)
    }
    #[doc = "Bit 1 - TFCE"]
    #[inline(always)]
    #[must_use]
    pub fn tfce(&mut self) -> TfceW<MacfcrSpec> {
        TfceW::new(self, 1)
    }
    #[doc = "Bit 2 - RFCE"]
    #[inline(always)]
    #[must_use]
    pub fn rfce(&mut self) -> RfceW<MacfcrSpec> {
        RfceW::new(self, 2)
    }
    #[doc = "Bit 3 - UPFD"]
    #[inline(always)]
    #[must_use]
    pub fn upfd(&mut self) -> UpfdW<MacfcrSpec> {
        UpfdW::new(self, 3)
    }
    #[doc = "Bits 4:5 - PLT"]
    #[inline(always)]
    #[must_use]
    pub fn plt(&mut self) -> PltW<MacfcrSpec> {
        PltW::new(self, 4)
    }
    #[doc = "Bit 7 - ZQPD"]
    #[inline(always)]
    #[must_use]
    pub fn zqpd(&mut self) -> ZqpdW<MacfcrSpec> {
        ZqpdW::new(self, 7)
    }
    #[doc = "Bits 16:31 - PT"]
    #[inline(always)]
    #[must_use]
    pub fn pt(&mut self) -> PtW<MacfcrSpec> {
        PtW::new(self, 16)
    }
}
#[doc = "Ethernet MAC flow control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`macfcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`macfcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MacfcrSpec;
impl crate::RegisterSpec for MacfcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`macfcr::R`](R) reader structure"]
impl crate::Readable for MacfcrSpec {}
#[doc = "`write(|w| ..)` method takes [`macfcr::W`](W) writer structure"]
impl crate::Writable for MacfcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACFCR to value 0"]
impl crate::Resettable for MacfcrSpec {
    const RESET_VALUE: u32 = 0;
}
