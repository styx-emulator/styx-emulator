// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FS_GINTMSK` reader"]
pub type R = crate::R<FsGintmskSpec>;
#[doc = "Register `FS_GINTMSK` writer"]
pub type W = crate::W<FsGintmskSpec>;
#[doc = "Field `MMISM` reader - Mode mismatch interrupt mask"]
pub type MmismR = crate::BitReader;
#[doc = "Field `MMISM` writer - Mode mismatch interrupt mask"]
pub type MmismW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OTGINT` reader - OTG interrupt mask"]
pub type OtgintR = crate::BitReader;
#[doc = "Field `OTGINT` writer - OTG interrupt mask"]
pub type OtgintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SOFM` reader - Start of frame mask"]
pub type SofmR = crate::BitReader;
#[doc = "Field `SOFM` writer - Start of frame mask"]
pub type SofmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXFLVLM` reader - Receive FIFO non-empty mask"]
pub type RxflvlmR = crate::BitReader;
#[doc = "Field `RXFLVLM` writer - Receive FIFO non-empty mask"]
pub type RxflvlmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NPTXFEM` reader - Non-periodic TxFIFO empty mask"]
pub type NptxfemR = crate::BitReader;
#[doc = "Field `NPTXFEM` writer - Non-periodic TxFIFO empty mask"]
pub type NptxfemW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GINAKEFFM` reader - Global non-periodic IN NAK effective mask"]
pub type GinakeffmR = crate::BitReader;
#[doc = "Field `GINAKEFFM` writer - Global non-periodic IN NAK effective mask"]
pub type GinakeffmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GONAKEFFM` reader - Global OUT NAK effective mask"]
pub type GonakeffmR = crate::BitReader;
#[doc = "Field `GONAKEFFM` writer - Global OUT NAK effective mask"]
pub type GonakeffmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ESUSPM` reader - Early suspend mask"]
pub type EsuspmR = crate::BitReader;
#[doc = "Field `ESUSPM` writer - Early suspend mask"]
pub type EsuspmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USBSUSPM` reader - USB suspend mask"]
pub type UsbsuspmR = crate::BitReader;
#[doc = "Field `USBSUSPM` writer - USB suspend mask"]
pub type UsbsuspmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USBRST` reader - USB reset mask"]
pub type UsbrstR = crate::BitReader;
#[doc = "Field `USBRST` writer - USB reset mask"]
pub type UsbrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ENUMDNEM` reader - Enumeration done mask"]
pub type EnumdnemR = crate::BitReader;
#[doc = "Field `ENUMDNEM` writer - Enumeration done mask"]
pub type EnumdnemW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ISOODRPM` reader - Isochronous OUT packet dropped interrupt mask"]
pub type IsoodrpmR = crate::BitReader;
#[doc = "Field `ISOODRPM` writer - Isochronous OUT packet dropped interrupt mask"]
pub type IsoodrpmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EOPFM` reader - End of periodic frame interrupt mask"]
pub type EopfmR = crate::BitReader;
#[doc = "Field `EOPFM` writer - End of periodic frame interrupt mask"]
pub type EopfmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPMISM` reader - Endpoint mismatch interrupt mask"]
pub type EpmismR = crate::BitReader;
#[doc = "Field `EPMISM` writer - Endpoint mismatch interrupt mask"]
pub type EpmismW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IEPINT` reader - IN endpoints interrupt mask"]
pub type IepintR = crate::BitReader;
#[doc = "Field `IEPINT` writer - IN endpoints interrupt mask"]
pub type IepintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OEPINT` reader - OUT endpoints interrupt mask"]
pub type OepintR = crate::BitReader;
#[doc = "Field `OEPINT` writer - OUT endpoints interrupt mask"]
pub type OepintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IISOIXFRM` reader - Incomplete isochronous IN transfer mask"]
pub type IisoixfrmR = crate::BitReader;
#[doc = "Field `IISOIXFRM` writer - Incomplete isochronous IN transfer mask"]
pub type IisoixfrmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IPXFRM_IISOOXFRM` reader - Incomplete periodic transfer mask(Host mode)/Incomplete isochronous OUT transfer mask(Device mode)"]
pub type IpxfrmIisooxfrmR = crate::BitReader;
#[doc = "Field `IPXFRM_IISOOXFRM` writer - Incomplete periodic transfer mask(Host mode)/Incomplete isochronous OUT transfer mask(Device mode)"]
pub type IpxfrmIisooxfrmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PRTIM` reader - Host port interrupt mask"]
pub type PrtimR = crate::BitReader;
#[doc = "Field `PRTIM` writer - Host port interrupt mask"]
pub type PrtimW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HCIM` reader - Host channels interrupt mask"]
pub type HcimR = crate::BitReader;
#[doc = "Field `HCIM` writer - Host channels interrupt mask"]
pub type HcimW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PTXFEM` reader - Periodic TxFIFO empty mask"]
pub type PtxfemR = crate::BitReader;
#[doc = "Field `PTXFEM` writer - Periodic TxFIFO empty mask"]
pub type PtxfemW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CIDSCHGM` reader - Connector ID status change mask"]
pub type CidschgmR = crate::BitReader;
#[doc = "Field `CIDSCHGM` writer - Connector ID status change mask"]
pub type CidschgmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DISCINT` reader - Disconnect detected interrupt mask"]
pub type DiscintR = crate::BitReader;
#[doc = "Field `DISCINT` writer - Disconnect detected interrupt mask"]
pub type DiscintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SRQIM` reader - Session request/new session detected interrupt mask"]
pub type SrqimR = crate::BitReader;
#[doc = "Field `SRQIM` writer - Session request/new session detected interrupt mask"]
pub type SrqimW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUIM` reader - Resume/remote wakeup detected interrupt mask"]
pub type WuimR = crate::BitReader;
#[doc = "Field `WUIM` writer - Resume/remote wakeup detected interrupt mask"]
pub type WuimW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 1 - Mode mismatch interrupt mask"]
    #[inline(always)]
    pub fn mmism(&self) -> MmismR {
        MmismR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - OTG interrupt mask"]
    #[inline(always)]
    pub fn otgint(&self) -> OtgintR {
        OtgintR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Start of frame mask"]
    #[inline(always)]
    pub fn sofm(&self) -> SofmR {
        SofmR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Receive FIFO non-empty mask"]
    #[inline(always)]
    pub fn rxflvlm(&self) -> RxflvlmR {
        RxflvlmR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Non-periodic TxFIFO empty mask"]
    #[inline(always)]
    pub fn nptxfem(&self) -> NptxfemR {
        NptxfemR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Global non-periodic IN NAK effective mask"]
    #[inline(always)]
    pub fn ginakeffm(&self) -> GinakeffmR {
        GinakeffmR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Global OUT NAK effective mask"]
    #[inline(always)]
    pub fn gonakeffm(&self) -> GonakeffmR {
        GonakeffmR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 10 - Early suspend mask"]
    #[inline(always)]
    pub fn esuspm(&self) -> EsuspmR {
        EsuspmR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - USB suspend mask"]
    #[inline(always)]
    pub fn usbsuspm(&self) -> UsbsuspmR {
        UsbsuspmR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - USB reset mask"]
    #[inline(always)]
    pub fn usbrst(&self) -> UsbrstR {
        UsbrstR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Enumeration done mask"]
    #[inline(always)]
    pub fn enumdnem(&self) -> EnumdnemR {
        EnumdnemR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Isochronous OUT packet dropped interrupt mask"]
    #[inline(always)]
    pub fn isoodrpm(&self) -> IsoodrpmR {
        IsoodrpmR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - End of periodic frame interrupt mask"]
    #[inline(always)]
    pub fn eopfm(&self) -> EopfmR {
        EopfmR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 17 - Endpoint mismatch interrupt mask"]
    #[inline(always)]
    pub fn epmism(&self) -> EpmismR {
        EpmismR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - IN endpoints interrupt mask"]
    #[inline(always)]
    pub fn iepint(&self) -> IepintR {
        IepintR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - OUT endpoints interrupt mask"]
    #[inline(always)]
    pub fn oepint(&self) -> OepintR {
        OepintR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Incomplete isochronous IN transfer mask"]
    #[inline(always)]
    pub fn iisoixfrm(&self) -> IisoixfrmR {
        IisoixfrmR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Incomplete periodic transfer mask(Host mode)/Incomplete isochronous OUT transfer mask(Device mode)"]
    #[inline(always)]
    pub fn ipxfrm_iisooxfrm(&self) -> IpxfrmIisooxfrmR {
        IpxfrmIisooxfrmR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 24 - Host port interrupt mask"]
    #[inline(always)]
    pub fn prtim(&self) -> PrtimR {
        PrtimR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Host channels interrupt mask"]
    #[inline(always)]
    pub fn hcim(&self) -> HcimR {
        HcimR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Periodic TxFIFO empty mask"]
    #[inline(always)]
    pub fn ptxfem(&self) -> PtxfemR {
        PtxfemR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 28 - Connector ID status change mask"]
    #[inline(always)]
    pub fn cidschgm(&self) -> CidschgmR {
        CidschgmR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Disconnect detected interrupt mask"]
    #[inline(always)]
    pub fn discint(&self) -> DiscintR {
        DiscintR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Session request/new session detected interrupt mask"]
    #[inline(always)]
    pub fn srqim(&self) -> SrqimR {
        SrqimR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Resume/remote wakeup detected interrupt mask"]
    #[inline(always)]
    pub fn wuim(&self) -> WuimR {
        WuimR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 1 - Mode mismatch interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn mmism(&mut self) -> MmismW<FsGintmskSpec> {
        MmismW::new(self, 1)
    }
    #[doc = "Bit 2 - OTG interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn otgint(&mut self) -> OtgintW<FsGintmskSpec> {
        OtgintW::new(self, 2)
    }
    #[doc = "Bit 3 - Start of frame mask"]
    #[inline(always)]
    #[must_use]
    pub fn sofm(&mut self) -> SofmW<FsGintmskSpec> {
        SofmW::new(self, 3)
    }
    #[doc = "Bit 4 - Receive FIFO non-empty mask"]
    #[inline(always)]
    #[must_use]
    pub fn rxflvlm(&mut self) -> RxflvlmW<FsGintmskSpec> {
        RxflvlmW::new(self, 4)
    }
    #[doc = "Bit 5 - Non-periodic TxFIFO empty mask"]
    #[inline(always)]
    #[must_use]
    pub fn nptxfem(&mut self) -> NptxfemW<FsGintmskSpec> {
        NptxfemW::new(self, 5)
    }
    #[doc = "Bit 6 - Global non-periodic IN NAK effective mask"]
    #[inline(always)]
    #[must_use]
    pub fn ginakeffm(&mut self) -> GinakeffmW<FsGintmskSpec> {
        GinakeffmW::new(self, 6)
    }
    #[doc = "Bit 7 - Global OUT NAK effective mask"]
    #[inline(always)]
    #[must_use]
    pub fn gonakeffm(&mut self) -> GonakeffmW<FsGintmskSpec> {
        GonakeffmW::new(self, 7)
    }
    #[doc = "Bit 10 - Early suspend mask"]
    #[inline(always)]
    #[must_use]
    pub fn esuspm(&mut self) -> EsuspmW<FsGintmskSpec> {
        EsuspmW::new(self, 10)
    }
    #[doc = "Bit 11 - USB suspend mask"]
    #[inline(always)]
    #[must_use]
    pub fn usbsuspm(&mut self) -> UsbsuspmW<FsGintmskSpec> {
        UsbsuspmW::new(self, 11)
    }
    #[doc = "Bit 12 - USB reset mask"]
    #[inline(always)]
    #[must_use]
    pub fn usbrst(&mut self) -> UsbrstW<FsGintmskSpec> {
        UsbrstW::new(self, 12)
    }
    #[doc = "Bit 13 - Enumeration done mask"]
    #[inline(always)]
    #[must_use]
    pub fn enumdnem(&mut self) -> EnumdnemW<FsGintmskSpec> {
        EnumdnemW::new(self, 13)
    }
    #[doc = "Bit 14 - Isochronous OUT packet dropped interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn isoodrpm(&mut self) -> IsoodrpmW<FsGintmskSpec> {
        IsoodrpmW::new(self, 14)
    }
    #[doc = "Bit 15 - End of periodic frame interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn eopfm(&mut self) -> EopfmW<FsGintmskSpec> {
        EopfmW::new(self, 15)
    }
    #[doc = "Bit 17 - Endpoint mismatch interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn epmism(&mut self) -> EpmismW<FsGintmskSpec> {
        EpmismW::new(self, 17)
    }
    #[doc = "Bit 18 - IN endpoints interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn iepint(&mut self) -> IepintW<FsGintmskSpec> {
        IepintW::new(self, 18)
    }
    #[doc = "Bit 19 - OUT endpoints interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn oepint(&mut self) -> OepintW<FsGintmskSpec> {
        OepintW::new(self, 19)
    }
    #[doc = "Bit 20 - Incomplete isochronous IN transfer mask"]
    #[inline(always)]
    #[must_use]
    pub fn iisoixfrm(&mut self) -> IisoixfrmW<FsGintmskSpec> {
        IisoixfrmW::new(self, 20)
    }
    #[doc = "Bit 21 - Incomplete periodic transfer mask(Host mode)/Incomplete isochronous OUT transfer mask(Device mode)"]
    #[inline(always)]
    #[must_use]
    pub fn ipxfrm_iisooxfrm(&mut self) -> IpxfrmIisooxfrmW<FsGintmskSpec> {
        IpxfrmIisooxfrmW::new(self, 21)
    }
    #[doc = "Bit 24 - Host port interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn prtim(&mut self) -> PrtimW<FsGintmskSpec> {
        PrtimW::new(self, 24)
    }
    #[doc = "Bit 25 - Host channels interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn hcim(&mut self) -> HcimW<FsGintmskSpec> {
        HcimW::new(self, 25)
    }
    #[doc = "Bit 26 - Periodic TxFIFO empty mask"]
    #[inline(always)]
    #[must_use]
    pub fn ptxfem(&mut self) -> PtxfemW<FsGintmskSpec> {
        PtxfemW::new(self, 26)
    }
    #[doc = "Bit 28 - Connector ID status change mask"]
    #[inline(always)]
    #[must_use]
    pub fn cidschgm(&mut self) -> CidschgmW<FsGintmskSpec> {
        CidschgmW::new(self, 28)
    }
    #[doc = "Bit 29 - Disconnect detected interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn discint(&mut self) -> DiscintW<FsGintmskSpec> {
        DiscintW::new(self, 29)
    }
    #[doc = "Bit 30 - Session request/new session detected interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn srqim(&mut self) -> SrqimW<FsGintmskSpec> {
        SrqimW::new(self, 30)
    }
    #[doc = "Bit 31 - Resume/remote wakeup detected interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn wuim(&mut self) -> WuimW<FsGintmskSpec> {
        WuimW::new(self, 31)
    }
}
#[doc = "OTG_FS interrupt mask register (OTG_FS_GINTMSK)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_gintmsk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_gintmsk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FsGintmskSpec;
impl crate::RegisterSpec for FsGintmskSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`fs_gintmsk::R`](R) reader structure"]
impl crate::Readable for FsGintmskSpec {}
#[doc = "`write(|w| ..)` method takes [`fs_gintmsk::W`](W) writer structure"]
impl crate::Writable for FsGintmskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FS_GINTMSK to value 0"]
impl crate::Resettable for FsGintmskSpec {
    const RESET_VALUE: u32 = 0;
}
