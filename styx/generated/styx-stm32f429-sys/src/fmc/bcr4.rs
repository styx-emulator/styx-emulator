// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `BCR4` reader"]
pub type R = crate::R<Bcr4Spec>;
#[doc = "Register `BCR4` writer"]
pub type W = crate::W<Bcr4Spec>;
#[doc = "Field `MBKEN` reader - MBKEN"]
pub type MbkenR = crate::BitReader;
#[doc = "Field `MBKEN` writer - MBKEN"]
pub type MbkenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MUXEN` reader - MUXEN"]
pub type MuxenR = crate::BitReader;
#[doc = "Field `MUXEN` writer - MUXEN"]
pub type MuxenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MTYP` reader - MTYP"]
pub type MtypR = crate::FieldReader;
#[doc = "Field `MTYP` writer - MTYP"]
pub type MtypW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `MWID` reader - MWID"]
pub type MwidR = crate::FieldReader;
#[doc = "Field `MWID` writer - MWID"]
pub type MwidW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `FACCEN` reader - FACCEN"]
pub type FaccenR = crate::BitReader;
#[doc = "Field `FACCEN` writer - FACCEN"]
pub type FaccenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BURSTEN` reader - BURSTEN"]
pub type BurstenR = crate::BitReader;
#[doc = "Field `BURSTEN` writer - BURSTEN"]
pub type BurstenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WAITPOL` reader - WAITPOL"]
pub type WaitpolR = crate::BitReader;
#[doc = "Field `WAITPOL` writer - WAITPOL"]
pub type WaitpolW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WRAPMOD` reader - WRAPMOD"]
pub type WrapmodR = crate::BitReader;
#[doc = "Field `WRAPMOD` writer - WRAPMOD"]
pub type WrapmodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WAITCFG` reader - WAITCFG"]
pub type WaitcfgR = crate::BitReader;
#[doc = "Field `WAITCFG` writer - WAITCFG"]
pub type WaitcfgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WREN` reader - WREN"]
pub type WrenR = crate::BitReader;
#[doc = "Field `WREN` writer - WREN"]
pub type WrenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WAITEN` reader - WAITEN"]
pub type WaitenR = crate::BitReader;
#[doc = "Field `WAITEN` writer - WAITEN"]
pub type WaitenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EXTMOD` reader - EXTMOD"]
pub type ExtmodR = crate::BitReader;
#[doc = "Field `EXTMOD` writer - EXTMOD"]
pub type ExtmodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ASYNCWAIT` reader - ASYNCWAIT"]
pub type AsyncwaitR = crate::BitReader;
#[doc = "Field `ASYNCWAIT` writer - ASYNCWAIT"]
pub type AsyncwaitW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CBURSTRW` reader - CBURSTRW"]
pub type CburstrwR = crate::BitReader;
#[doc = "Field `CBURSTRW` writer - CBURSTRW"]
pub type CburstrwW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - MBKEN"]
    #[inline(always)]
    pub fn mbken(&self) -> MbkenR {
        MbkenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - MUXEN"]
    #[inline(always)]
    pub fn muxen(&self) -> MuxenR {
        MuxenR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bits 2:3 - MTYP"]
    #[inline(always)]
    pub fn mtyp(&self) -> MtypR {
        MtypR::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bits 4:5 - MWID"]
    #[inline(always)]
    pub fn mwid(&self) -> MwidR {
        MwidR::new(((self.bits >> 4) & 3) as u8)
    }
    #[doc = "Bit 6 - FACCEN"]
    #[inline(always)]
    pub fn faccen(&self) -> FaccenR {
        FaccenR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8 - BURSTEN"]
    #[inline(always)]
    pub fn bursten(&self) -> BurstenR {
        BurstenR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - WAITPOL"]
    #[inline(always)]
    pub fn waitpol(&self) -> WaitpolR {
        WaitpolR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - WRAPMOD"]
    #[inline(always)]
    pub fn wrapmod(&self) -> WrapmodR {
        WrapmodR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - WAITCFG"]
    #[inline(always)]
    pub fn waitcfg(&self) -> WaitcfgR {
        WaitcfgR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - WREN"]
    #[inline(always)]
    pub fn wren(&self) -> WrenR {
        WrenR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - WAITEN"]
    #[inline(always)]
    pub fn waiten(&self) -> WaitenR {
        WaitenR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - EXTMOD"]
    #[inline(always)]
    pub fn extmod(&self) -> ExtmodR {
        ExtmodR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - ASYNCWAIT"]
    #[inline(always)]
    pub fn asyncwait(&self) -> AsyncwaitR {
        AsyncwaitR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 19 - CBURSTRW"]
    #[inline(always)]
    pub fn cburstrw(&self) -> CburstrwR {
        CburstrwR::new(((self.bits >> 19) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - MBKEN"]
    #[inline(always)]
    #[must_use]
    pub fn mbken(&mut self) -> MbkenW<Bcr4Spec> {
        MbkenW::new(self, 0)
    }
    #[doc = "Bit 1 - MUXEN"]
    #[inline(always)]
    #[must_use]
    pub fn muxen(&mut self) -> MuxenW<Bcr4Spec> {
        MuxenW::new(self, 1)
    }
    #[doc = "Bits 2:3 - MTYP"]
    #[inline(always)]
    #[must_use]
    pub fn mtyp(&mut self) -> MtypW<Bcr4Spec> {
        MtypW::new(self, 2)
    }
    #[doc = "Bits 4:5 - MWID"]
    #[inline(always)]
    #[must_use]
    pub fn mwid(&mut self) -> MwidW<Bcr4Spec> {
        MwidW::new(self, 4)
    }
    #[doc = "Bit 6 - FACCEN"]
    #[inline(always)]
    #[must_use]
    pub fn faccen(&mut self) -> FaccenW<Bcr4Spec> {
        FaccenW::new(self, 6)
    }
    #[doc = "Bit 8 - BURSTEN"]
    #[inline(always)]
    #[must_use]
    pub fn bursten(&mut self) -> BurstenW<Bcr4Spec> {
        BurstenW::new(self, 8)
    }
    #[doc = "Bit 9 - WAITPOL"]
    #[inline(always)]
    #[must_use]
    pub fn waitpol(&mut self) -> WaitpolW<Bcr4Spec> {
        WaitpolW::new(self, 9)
    }
    #[doc = "Bit 10 - WRAPMOD"]
    #[inline(always)]
    #[must_use]
    pub fn wrapmod(&mut self) -> WrapmodW<Bcr4Spec> {
        WrapmodW::new(self, 10)
    }
    #[doc = "Bit 11 - WAITCFG"]
    #[inline(always)]
    #[must_use]
    pub fn waitcfg(&mut self) -> WaitcfgW<Bcr4Spec> {
        WaitcfgW::new(self, 11)
    }
    #[doc = "Bit 12 - WREN"]
    #[inline(always)]
    #[must_use]
    pub fn wren(&mut self) -> WrenW<Bcr4Spec> {
        WrenW::new(self, 12)
    }
    #[doc = "Bit 13 - WAITEN"]
    #[inline(always)]
    #[must_use]
    pub fn waiten(&mut self) -> WaitenW<Bcr4Spec> {
        WaitenW::new(self, 13)
    }
    #[doc = "Bit 14 - EXTMOD"]
    #[inline(always)]
    #[must_use]
    pub fn extmod(&mut self) -> ExtmodW<Bcr4Spec> {
        ExtmodW::new(self, 14)
    }
    #[doc = "Bit 15 - ASYNCWAIT"]
    #[inline(always)]
    #[must_use]
    pub fn asyncwait(&mut self) -> AsyncwaitW<Bcr4Spec> {
        AsyncwaitW::new(self, 15)
    }
    #[doc = "Bit 19 - CBURSTRW"]
    #[inline(always)]
    #[must_use]
    pub fn cburstrw(&mut self) -> CburstrwW<Bcr4Spec> {
        CburstrwW::new(self, 19)
    }
}
#[doc = "SRAM/NOR-Flash chip-select control register 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bcr4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bcr4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Bcr4Spec;
impl crate::RegisterSpec for Bcr4Spec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`bcr4::R`](R) reader structure"]
impl crate::Readable for Bcr4Spec {}
#[doc = "`write(|w| ..)` method takes [`bcr4::W`](W) writer structure"]
impl crate::Writable for Bcr4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets BCR4 to value 0x30d0"]
impl crate::Resettable for Bcr4Spec {
    const RESET_VALUE: u32 = 0x30d0;
}
