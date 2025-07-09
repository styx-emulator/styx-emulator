// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `OTG_FS_GINTSTS` reader"]
pub type R = crate::R<OtgFsGintstsSpec>;
#[doc = "Register `OTG_FS_GINTSTS` writer"]
pub type W = crate::W<OtgFsGintstsSpec>;
#[doc = "Field `CMOD` reader - Current mode of operation"]
pub type CmodR = crate::BitReader;
#[doc = "Field `CMOD` writer - Current mode of operation"]
pub type CmodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MMIS` reader - Mode mismatch interrupt"]
pub type MmisR = crate::BitReader;
#[doc = "Field `MMIS` writer - Mode mismatch interrupt"]
pub type MmisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OTGINT` reader - OTG interrupt"]
pub type OtgintR = crate::BitReader;
#[doc = "Field `OTGINT` writer - OTG interrupt"]
pub type OtgintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SOF` reader - Start of frame"]
pub type SofR = crate::BitReader;
#[doc = "Field `SOF` writer - Start of frame"]
pub type SofW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXFLVL` reader - RxFIFO non-empty"]
pub type RxflvlR = crate::BitReader;
#[doc = "Field `RXFLVL` writer - RxFIFO non-empty"]
pub type RxflvlW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NPTXFE` reader - Non-periodic TxFIFO empty"]
pub type NptxfeR = crate::BitReader;
#[doc = "Field `NPTXFE` writer - Non-periodic TxFIFO empty"]
pub type NptxfeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GINAKEFF` reader - Global IN non-periodic NAK effective"]
pub type GinakeffR = crate::BitReader;
#[doc = "Field `GINAKEFF` writer - Global IN non-periodic NAK effective"]
pub type GinakeffW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GOUTNAKEFF` reader - Global OUT NAK effective"]
pub type GoutnakeffR = crate::BitReader;
#[doc = "Field `GOUTNAKEFF` writer - Global OUT NAK effective"]
pub type GoutnakeffW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ESUSP` reader - Early suspend"]
pub type EsuspR = crate::BitReader;
#[doc = "Field `ESUSP` writer - Early suspend"]
pub type EsuspW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USBSUSP` reader - USB suspend"]
pub type UsbsuspR = crate::BitReader;
#[doc = "Field `USBSUSP` writer - USB suspend"]
pub type UsbsuspW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USBRST` reader - USB reset"]
pub type UsbrstR = crate::BitReader;
#[doc = "Field `USBRST` writer - USB reset"]
pub type UsbrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ENUMDNE` reader - Enumeration done"]
pub type EnumdneR = crate::BitReader;
#[doc = "Field `ENUMDNE` writer - Enumeration done"]
pub type EnumdneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ISOODRP` reader - Isochronous OUT packet dropped interrupt"]
pub type IsoodrpR = crate::BitReader;
#[doc = "Field `ISOODRP` writer - Isochronous OUT packet dropped interrupt"]
pub type IsoodrpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EOPF` reader - End of periodic frame interrupt"]
pub type EopfR = crate::BitReader;
#[doc = "Field `EOPF` writer - End of periodic frame interrupt"]
pub type EopfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IEPINT` reader - IN endpoint interrupt"]
pub type IepintR = crate::BitReader;
#[doc = "Field `IEPINT` writer - IN endpoint interrupt"]
pub type IepintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OEPINT` reader - OUT endpoint interrupt"]
pub type OepintR = crate::BitReader;
#[doc = "Field `OEPINT` writer - OUT endpoint interrupt"]
pub type OepintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IISOIXFR` reader - Incomplete isochronous IN transfer"]
pub type IisoixfrR = crate::BitReader;
#[doc = "Field `IISOIXFR` writer - Incomplete isochronous IN transfer"]
pub type IisoixfrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IPXFR_INCOMPISOOUT` reader - Incomplete periodic transfer(Host mode)/Incomplete isochronous OUT transfer(Device mode)"]
pub type IpxfrIncompisooutR = crate::BitReader;
#[doc = "Field `IPXFR_INCOMPISOOUT` writer - Incomplete periodic transfer(Host mode)/Incomplete isochronous OUT transfer(Device mode)"]
pub type IpxfrIncompisooutW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RSTDET` reader - Reset detected interrupt"]
pub type RstdetR = crate::BitReader;
#[doc = "Field `RSTDET` writer - Reset detected interrupt"]
pub type RstdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HPRTINT` reader - Host port interrupt"]
pub type HprtintR = crate::BitReader;
#[doc = "Field `HPRTINT` writer - Host port interrupt"]
pub type HprtintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HCINT` reader - Host channels interrupt"]
pub type HcintR = crate::BitReader;
#[doc = "Field `HCINT` writer - Host channels interrupt"]
pub type HcintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PTXFE` reader - Periodic TxFIFO empty"]
pub type PtxfeR = crate::BitReader;
#[doc = "Field `PTXFE` writer - Periodic TxFIFO empty"]
pub type PtxfeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CIDSCHG` reader - Connector ID status change"]
pub type CidschgR = crate::BitReader;
#[doc = "Field `CIDSCHG` writer - Connector ID status change"]
pub type CidschgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DISCINT` reader - Disconnect detected interrupt"]
pub type DiscintR = crate::BitReader;
#[doc = "Field `DISCINT` writer - Disconnect detected interrupt"]
pub type DiscintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SRQINT` reader - Session request/new session detected interrupt"]
pub type SrqintR = crate::BitReader;
#[doc = "Field `SRQINT` writer - Session request/new session detected interrupt"]
pub type SrqintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WKUPINT` reader - Resume/remote wakeup detected interrupt"]
pub type WkupintR = crate::BitReader;
#[doc = "Field `WKUPINT` writer - Resume/remote wakeup detected interrupt"]
pub type WkupintW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Current mode of operation"]
    #[inline(always)]
    pub fn cmod(&self) -> CmodR {
        CmodR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Mode mismatch interrupt"]
    #[inline(always)]
    pub fn mmis(&self) -> MmisR {
        MmisR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - OTG interrupt"]
    #[inline(always)]
    pub fn otgint(&self) -> OtgintR {
        OtgintR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Start of frame"]
    #[inline(always)]
    pub fn sof(&self) -> SofR {
        SofR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - RxFIFO non-empty"]
    #[inline(always)]
    pub fn rxflvl(&self) -> RxflvlR {
        RxflvlR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Non-periodic TxFIFO empty"]
    #[inline(always)]
    pub fn nptxfe(&self) -> NptxfeR {
        NptxfeR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Global IN non-periodic NAK effective"]
    #[inline(always)]
    pub fn ginakeff(&self) -> GinakeffR {
        GinakeffR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Global OUT NAK effective"]
    #[inline(always)]
    pub fn goutnakeff(&self) -> GoutnakeffR {
        GoutnakeffR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 10 - Early suspend"]
    #[inline(always)]
    pub fn esusp(&self) -> EsuspR {
        EsuspR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - USB suspend"]
    #[inline(always)]
    pub fn usbsusp(&self) -> UsbsuspR {
        UsbsuspR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - USB reset"]
    #[inline(always)]
    pub fn usbrst(&self) -> UsbrstR {
        UsbrstR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Enumeration done"]
    #[inline(always)]
    pub fn enumdne(&self) -> EnumdneR {
        EnumdneR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Isochronous OUT packet dropped interrupt"]
    #[inline(always)]
    pub fn isoodrp(&self) -> IsoodrpR {
        IsoodrpR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - End of periodic frame interrupt"]
    #[inline(always)]
    pub fn eopf(&self) -> EopfR {
        EopfR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 18 - IN endpoint interrupt"]
    #[inline(always)]
    pub fn iepint(&self) -> IepintR {
        IepintR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - OUT endpoint interrupt"]
    #[inline(always)]
    pub fn oepint(&self) -> OepintR {
        OepintR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Incomplete isochronous IN transfer"]
    #[inline(always)]
    pub fn iisoixfr(&self) -> IisoixfrR {
        IisoixfrR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Incomplete periodic transfer(Host mode)/Incomplete isochronous OUT transfer(Device mode)"]
    #[inline(always)]
    pub fn ipxfr_incompisoout(&self) -> IpxfrIncompisooutR {
        IpxfrIncompisooutR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 23 - Reset detected interrupt"]
    #[inline(always)]
    pub fn rstdet(&self) -> RstdetR {
        RstdetR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Host port interrupt"]
    #[inline(always)]
    pub fn hprtint(&self) -> HprtintR {
        HprtintR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Host channels interrupt"]
    #[inline(always)]
    pub fn hcint(&self) -> HcintR {
        HcintR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Periodic TxFIFO empty"]
    #[inline(always)]
    pub fn ptxfe(&self) -> PtxfeR {
        PtxfeR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 28 - Connector ID status change"]
    #[inline(always)]
    pub fn cidschg(&self) -> CidschgR {
        CidschgR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Disconnect detected interrupt"]
    #[inline(always)]
    pub fn discint(&self) -> DiscintR {
        DiscintR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Session request/new session detected interrupt"]
    #[inline(always)]
    pub fn srqint(&self) -> SrqintR {
        SrqintR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Resume/remote wakeup detected interrupt"]
    #[inline(always)]
    pub fn wkupint(&self) -> WkupintR {
        WkupintR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Current mode of operation"]
    #[inline(always)]
    #[must_use]
    pub fn cmod(&mut self) -> CmodW<OtgFsGintstsSpec> {
        CmodW::new(self, 0)
    }
    #[doc = "Bit 1 - Mode mismatch interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn mmis(&mut self) -> MmisW<OtgFsGintstsSpec> {
        MmisW::new(self, 1)
    }
    #[doc = "Bit 2 - OTG interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn otgint(&mut self) -> OtgintW<OtgFsGintstsSpec> {
        OtgintW::new(self, 2)
    }
    #[doc = "Bit 3 - Start of frame"]
    #[inline(always)]
    #[must_use]
    pub fn sof(&mut self) -> SofW<OtgFsGintstsSpec> {
        SofW::new(self, 3)
    }
    #[doc = "Bit 4 - RxFIFO non-empty"]
    #[inline(always)]
    #[must_use]
    pub fn rxflvl(&mut self) -> RxflvlW<OtgFsGintstsSpec> {
        RxflvlW::new(self, 4)
    }
    #[doc = "Bit 5 - Non-periodic TxFIFO empty"]
    #[inline(always)]
    #[must_use]
    pub fn nptxfe(&mut self) -> NptxfeW<OtgFsGintstsSpec> {
        NptxfeW::new(self, 5)
    }
    #[doc = "Bit 6 - Global IN non-periodic NAK effective"]
    #[inline(always)]
    #[must_use]
    pub fn ginakeff(&mut self) -> GinakeffW<OtgFsGintstsSpec> {
        GinakeffW::new(self, 6)
    }
    #[doc = "Bit 7 - Global OUT NAK effective"]
    #[inline(always)]
    #[must_use]
    pub fn goutnakeff(&mut self) -> GoutnakeffW<OtgFsGintstsSpec> {
        GoutnakeffW::new(self, 7)
    }
    #[doc = "Bit 10 - Early suspend"]
    #[inline(always)]
    #[must_use]
    pub fn esusp(&mut self) -> EsuspW<OtgFsGintstsSpec> {
        EsuspW::new(self, 10)
    }
    #[doc = "Bit 11 - USB suspend"]
    #[inline(always)]
    #[must_use]
    pub fn usbsusp(&mut self) -> UsbsuspW<OtgFsGintstsSpec> {
        UsbsuspW::new(self, 11)
    }
    #[doc = "Bit 12 - USB reset"]
    #[inline(always)]
    #[must_use]
    pub fn usbrst(&mut self) -> UsbrstW<OtgFsGintstsSpec> {
        UsbrstW::new(self, 12)
    }
    #[doc = "Bit 13 - Enumeration done"]
    #[inline(always)]
    #[must_use]
    pub fn enumdne(&mut self) -> EnumdneW<OtgFsGintstsSpec> {
        EnumdneW::new(self, 13)
    }
    #[doc = "Bit 14 - Isochronous OUT packet dropped interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn isoodrp(&mut self) -> IsoodrpW<OtgFsGintstsSpec> {
        IsoodrpW::new(self, 14)
    }
    #[doc = "Bit 15 - End of periodic frame interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn eopf(&mut self) -> EopfW<OtgFsGintstsSpec> {
        EopfW::new(self, 15)
    }
    #[doc = "Bit 18 - IN endpoint interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn iepint(&mut self) -> IepintW<OtgFsGintstsSpec> {
        IepintW::new(self, 18)
    }
    #[doc = "Bit 19 - OUT endpoint interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn oepint(&mut self) -> OepintW<OtgFsGintstsSpec> {
        OepintW::new(self, 19)
    }
    #[doc = "Bit 20 - Incomplete isochronous IN transfer"]
    #[inline(always)]
    #[must_use]
    pub fn iisoixfr(&mut self) -> IisoixfrW<OtgFsGintstsSpec> {
        IisoixfrW::new(self, 20)
    }
    #[doc = "Bit 21 - Incomplete periodic transfer(Host mode)/Incomplete isochronous OUT transfer(Device mode)"]
    #[inline(always)]
    #[must_use]
    pub fn ipxfr_incompisoout(&mut self) -> IpxfrIncompisooutW<OtgFsGintstsSpec> {
        IpxfrIncompisooutW::new(self, 21)
    }
    #[doc = "Bit 23 - Reset detected interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn rstdet(&mut self) -> RstdetW<OtgFsGintstsSpec> {
        RstdetW::new(self, 23)
    }
    #[doc = "Bit 24 - Host port interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn hprtint(&mut self) -> HprtintW<OtgFsGintstsSpec> {
        HprtintW::new(self, 24)
    }
    #[doc = "Bit 25 - Host channels interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn hcint(&mut self) -> HcintW<OtgFsGintstsSpec> {
        HcintW::new(self, 25)
    }
    #[doc = "Bit 26 - Periodic TxFIFO empty"]
    #[inline(always)]
    #[must_use]
    pub fn ptxfe(&mut self) -> PtxfeW<OtgFsGintstsSpec> {
        PtxfeW::new(self, 26)
    }
    #[doc = "Bit 28 - Connector ID status change"]
    #[inline(always)]
    #[must_use]
    pub fn cidschg(&mut self) -> CidschgW<OtgFsGintstsSpec> {
        CidschgW::new(self, 28)
    }
    #[doc = "Bit 29 - Disconnect detected interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn discint(&mut self) -> DiscintW<OtgFsGintstsSpec> {
        DiscintW::new(self, 29)
    }
    #[doc = "Bit 30 - Session request/new session detected interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn srqint(&mut self) -> SrqintW<OtgFsGintstsSpec> {
        SrqintW::new(self, 30)
    }
    #[doc = "Bit 31 - Resume/remote wakeup detected interrupt"]
    #[inline(always)]
    #[must_use]
    pub fn wkupint(&mut self) -> WkupintW<OtgFsGintstsSpec> {
        WkupintW::new(self, 31)
    }
}
#[doc = "OTG_FS core interrupt register (OTG_FS_GINTSTS)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gintsts::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gintsts::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsGintstsSpec;
impl crate::RegisterSpec for OtgFsGintstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`otg_fs_gintsts::R`](R) reader structure"]
impl crate::Readable for OtgFsGintstsSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_gintsts::W`](W) writer structure"]
impl crate::Writable for OtgFsGintstsSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_GINTSTS to value 0x0400_0020"]
impl crate::Resettable for OtgFsGintstsSpec {
    const RESET_VALUE: u32 = 0x0400_0020;
}
