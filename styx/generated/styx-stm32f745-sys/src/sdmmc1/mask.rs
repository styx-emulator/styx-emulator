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
#[doc = "Register `MASK` reader"]
pub type R = crate::R<MaskSpec>;
#[doc = "Register `MASK` writer"]
pub type W = crate::W<MaskSpec>;
#[doc = "Field `CCRCFAILIE` reader - Command CRC fail interrupt enable"]
pub type CcrcfailieR = crate::BitReader;
#[doc = "Field `CCRCFAILIE` writer - Command CRC fail interrupt enable"]
pub type CcrcfailieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DCRCFAILIE` reader - Data CRC fail interrupt enable"]
pub type DcrcfailieR = crate::BitReader;
#[doc = "Field `DCRCFAILIE` writer - Data CRC fail interrupt enable"]
pub type DcrcfailieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTIMEOUTIE` reader - Command timeout interrupt enable"]
pub type CtimeoutieR = crate::BitReader;
#[doc = "Field `CTIMEOUTIE` writer - Command timeout interrupt enable"]
pub type CtimeoutieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DTIMEOUTIE` reader - Data timeout interrupt enable"]
pub type DtimeoutieR = crate::BitReader;
#[doc = "Field `DTIMEOUTIE` writer - Data timeout interrupt enable"]
pub type DtimeoutieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXUNDERRIE` reader - Tx FIFO underrun error interrupt enable"]
pub type TxunderrieR = crate::BitReader;
#[doc = "Field `TXUNDERRIE` writer - Tx FIFO underrun error interrupt enable"]
pub type TxunderrieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXOVERRIE` reader - Rx FIFO overrun error interrupt enable"]
pub type RxoverrieR = crate::BitReader;
#[doc = "Field `RXOVERRIE` writer - Rx FIFO overrun error interrupt enable"]
pub type RxoverrieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CMDRENDIE` reader - Command response received interrupt enable"]
pub type CmdrendieR = crate::BitReader;
#[doc = "Field `CMDRENDIE` writer - Command response received interrupt enable"]
pub type CmdrendieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CMDSENTIE` reader - Command sent interrupt enable"]
pub type CmdsentieR = crate::BitReader;
#[doc = "Field `CMDSENTIE` writer - Command sent interrupt enable"]
pub type CmdsentieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DATAENDIE` reader - Data end interrupt enable"]
pub type DataendieR = crate::BitReader;
#[doc = "Field `DATAENDIE` writer - Data end interrupt enable"]
pub type DataendieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STBITERRIE` reader - Start bit error interrupt enable"]
pub type StbiterrieR = crate::BitReader;
#[doc = "Field `STBITERRIE` writer - Start bit error interrupt enable"]
pub type StbiterrieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBCKENDIE` reader - Data block end interrupt enable"]
pub type DbckendieR = crate::BitReader;
#[doc = "Field `DBCKENDIE` writer - Data block end interrupt enable"]
pub type DbckendieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CMDACTIE` reader - Command acting interrupt enable"]
pub type CmdactieR = crate::BitReader;
#[doc = "Field `CMDACTIE` writer - Command acting interrupt enable"]
pub type CmdactieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXACTIE` reader - Data transmit acting interrupt enable"]
pub type TxactieR = crate::BitReader;
#[doc = "Field `TXACTIE` writer - Data transmit acting interrupt enable"]
pub type TxactieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXACTIE` reader - Data receive acting interrupt enable"]
pub type RxactieR = crate::BitReader;
#[doc = "Field `RXACTIE` writer - Data receive acting interrupt enable"]
pub type RxactieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXFIFOHEIE` reader - Tx FIFO half empty interrupt enable"]
pub type TxfifoheieR = crate::BitReader;
#[doc = "Field `TXFIFOHEIE` writer - Tx FIFO half empty interrupt enable"]
pub type TxfifoheieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXFIFOHFIE` reader - Rx FIFO half full interrupt enable"]
pub type RxfifohfieR = crate::BitReader;
#[doc = "Field `RXFIFOHFIE` writer - Rx FIFO half full interrupt enable"]
pub type RxfifohfieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXFIFOFIE` reader - Tx FIFO full interrupt enable"]
pub type TxfifofieR = crate::BitReader;
#[doc = "Field `TXFIFOFIE` writer - Tx FIFO full interrupt enable"]
pub type TxfifofieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXFIFOFIE` reader - Rx FIFO full interrupt enable"]
pub type RxfifofieR = crate::BitReader;
#[doc = "Field `RXFIFOFIE` writer - Rx FIFO full interrupt enable"]
pub type RxfifofieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXFIFOEIE` reader - Tx FIFO empty interrupt enable"]
pub type TxfifoeieR = crate::BitReader;
#[doc = "Field `TXFIFOEIE` writer - Tx FIFO empty interrupt enable"]
pub type TxfifoeieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXFIFOEIE` reader - Rx FIFO empty interrupt enable"]
pub type RxfifoeieR = crate::BitReader;
#[doc = "Field `RXFIFOEIE` writer - Rx FIFO empty interrupt enable"]
pub type RxfifoeieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXDAVLIE` reader - Data available in Tx FIFO interrupt enable"]
pub type TxdavlieR = crate::BitReader;
#[doc = "Field `TXDAVLIE` writer - Data available in Tx FIFO interrupt enable"]
pub type TxdavlieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RXDAVLIE` reader - Data available in Rx FIFO interrupt enable"]
pub type RxdavlieR = crate::BitReader;
#[doc = "Field `RXDAVLIE` writer - Data available in Rx FIFO interrupt enable"]
pub type RxdavlieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SDIOITIE` reader - SDIO mode interrupt received interrupt enable"]
pub type SdioitieR = crate::BitReader;
#[doc = "Field `SDIOITIE` writer - SDIO mode interrupt received interrupt enable"]
pub type SdioitieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CEATAENDIE` reader - CE-ATA command completion signal received interrupt enable"]
pub type CeataendieR = crate::BitReader;
#[doc = "Field `CEATAENDIE` writer - CE-ATA command completion signal received interrupt enable"]
pub type CeataendieW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Command CRC fail interrupt enable"]
    #[inline(always)]
    pub fn ccrcfailie(&self) -> CcrcfailieR {
        CcrcfailieR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Data CRC fail interrupt enable"]
    #[inline(always)]
    pub fn dcrcfailie(&self) -> DcrcfailieR {
        DcrcfailieR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Command timeout interrupt enable"]
    #[inline(always)]
    pub fn ctimeoutie(&self) -> CtimeoutieR {
        CtimeoutieR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Data timeout interrupt enable"]
    #[inline(always)]
    pub fn dtimeoutie(&self) -> DtimeoutieR {
        DtimeoutieR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Tx FIFO underrun error interrupt enable"]
    #[inline(always)]
    pub fn txunderrie(&self) -> TxunderrieR {
        TxunderrieR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Rx FIFO overrun error interrupt enable"]
    #[inline(always)]
    pub fn rxoverrie(&self) -> RxoverrieR {
        RxoverrieR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Command response received interrupt enable"]
    #[inline(always)]
    pub fn cmdrendie(&self) -> CmdrendieR {
        CmdrendieR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Command sent interrupt enable"]
    #[inline(always)]
    pub fn cmdsentie(&self) -> CmdsentieR {
        CmdsentieR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Data end interrupt enable"]
    #[inline(always)]
    pub fn dataendie(&self) -> DataendieR {
        DataendieR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Start bit error interrupt enable"]
    #[inline(always)]
    pub fn stbiterrie(&self) -> StbiterrieR {
        StbiterrieR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Data block end interrupt enable"]
    #[inline(always)]
    pub fn dbckendie(&self) -> DbckendieR {
        DbckendieR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Command acting interrupt enable"]
    #[inline(always)]
    pub fn cmdactie(&self) -> CmdactieR {
        CmdactieR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Data transmit acting interrupt enable"]
    #[inline(always)]
    pub fn txactie(&self) -> TxactieR {
        TxactieR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Data receive acting interrupt enable"]
    #[inline(always)]
    pub fn rxactie(&self) -> RxactieR {
        RxactieR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Tx FIFO half empty interrupt enable"]
    #[inline(always)]
    pub fn txfifoheie(&self) -> TxfifoheieR {
        TxfifoheieR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Rx FIFO half full interrupt enable"]
    #[inline(always)]
    pub fn rxfifohfie(&self) -> RxfifohfieR {
        RxfifohfieR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Tx FIFO full interrupt enable"]
    #[inline(always)]
    pub fn txfifofie(&self) -> TxfifofieR {
        TxfifofieR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Rx FIFO full interrupt enable"]
    #[inline(always)]
    pub fn rxfifofie(&self) -> RxfifofieR {
        RxfifofieR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Tx FIFO empty interrupt enable"]
    #[inline(always)]
    pub fn txfifoeie(&self) -> TxfifoeieR {
        TxfifoeieR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Rx FIFO empty interrupt enable"]
    #[inline(always)]
    pub fn rxfifoeie(&self) -> RxfifoeieR {
        RxfifoeieR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Data available in Tx FIFO interrupt enable"]
    #[inline(always)]
    pub fn txdavlie(&self) -> TxdavlieR {
        TxdavlieR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Data available in Rx FIFO interrupt enable"]
    #[inline(always)]
    pub fn rxdavlie(&self) -> RxdavlieR {
        RxdavlieR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - SDIO mode interrupt received interrupt enable"]
    #[inline(always)]
    pub fn sdioitie(&self) -> SdioitieR {
        SdioitieR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - CE-ATA command completion signal received interrupt enable"]
    #[inline(always)]
    pub fn ceataendie(&self) -> CeataendieR {
        CeataendieR::new(((self.bits >> 23) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Command CRC fail interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn ccrcfailie(&mut self) -> CcrcfailieW<MaskSpec> {
        CcrcfailieW::new(self, 0)
    }
    #[doc = "Bit 1 - Data CRC fail interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn dcrcfailie(&mut self) -> DcrcfailieW<MaskSpec> {
        DcrcfailieW::new(self, 1)
    }
    #[doc = "Bit 2 - Command timeout interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn ctimeoutie(&mut self) -> CtimeoutieW<MaskSpec> {
        CtimeoutieW::new(self, 2)
    }
    #[doc = "Bit 3 - Data timeout interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn dtimeoutie(&mut self) -> DtimeoutieW<MaskSpec> {
        DtimeoutieW::new(self, 3)
    }
    #[doc = "Bit 4 - Tx FIFO underrun error interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn txunderrie(&mut self) -> TxunderrieW<MaskSpec> {
        TxunderrieW::new(self, 4)
    }
    #[doc = "Bit 5 - Rx FIFO overrun error interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn rxoverrie(&mut self) -> RxoverrieW<MaskSpec> {
        RxoverrieW::new(self, 5)
    }
    #[doc = "Bit 6 - Command response received interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn cmdrendie(&mut self) -> CmdrendieW<MaskSpec> {
        CmdrendieW::new(self, 6)
    }
    #[doc = "Bit 7 - Command sent interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn cmdsentie(&mut self) -> CmdsentieW<MaskSpec> {
        CmdsentieW::new(self, 7)
    }
    #[doc = "Bit 8 - Data end interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn dataendie(&mut self) -> DataendieW<MaskSpec> {
        DataendieW::new(self, 8)
    }
    #[doc = "Bit 9 - Start bit error interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn stbiterrie(&mut self) -> StbiterrieW<MaskSpec> {
        StbiterrieW::new(self, 9)
    }
    #[doc = "Bit 10 - Data block end interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn dbckendie(&mut self) -> DbckendieW<MaskSpec> {
        DbckendieW::new(self, 10)
    }
    #[doc = "Bit 11 - Command acting interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn cmdactie(&mut self) -> CmdactieW<MaskSpec> {
        CmdactieW::new(self, 11)
    }
    #[doc = "Bit 12 - Data transmit acting interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn txactie(&mut self) -> TxactieW<MaskSpec> {
        TxactieW::new(self, 12)
    }
    #[doc = "Bit 13 - Data receive acting interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn rxactie(&mut self) -> RxactieW<MaskSpec> {
        RxactieW::new(self, 13)
    }
    #[doc = "Bit 14 - Tx FIFO half empty interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn txfifoheie(&mut self) -> TxfifoheieW<MaskSpec> {
        TxfifoheieW::new(self, 14)
    }
    #[doc = "Bit 15 - Rx FIFO half full interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn rxfifohfie(&mut self) -> RxfifohfieW<MaskSpec> {
        RxfifohfieW::new(self, 15)
    }
    #[doc = "Bit 16 - Tx FIFO full interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn txfifofie(&mut self) -> TxfifofieW<MaskSpec> {
        TxfifofieW::new(self, 16)
    }
    #[doc = "Bit 17 - Rx FIFO full interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn rxfifofie(&mut self) -> RxfifofieW<MaskSpec> {
        RxfifofieW::new(self, 17)
    }
    #[doc = "Bit 18 - Tx FIFO empty interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn txfifoeie(&mut self) -> TxfifoeieW<MaskSpec> {
        TxfifoeieW::new(self, 18)
    }
    #[doc = "Bit 19 - Rx FIFO empty interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn rxfifoeie(&mut self) -> RxfifoeieW<MaskSpec> {
        RxfifoeieW::new(self, 19)
    }
    #[doc = "Bit 20 - Data available in Tx FIFO interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn txdavlie(&mut self) -> TxdavlieW<MaskSpec> {
        TxdavlieW::new(self, 20)
    }
    #[doc = "Bit 21 - Data available in Rx FIFO interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn rxdavlie(&mut self) -> RxdavlieW<MaskSpec> {
        RxdavlieW::new(self, 21)
    }
    #[doc = "Bit 22 - SDIO mode interrupt received interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn sdioitie(&mut self) -> SdioitieW<MaskSpec> {
        SdioitieW::new(self, 22)
    }
    #[doc = "Bit 23 - CE-ATA command completion signal received interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn ceataendie(&mut self) -> CeataendieW<MaskSpec> {
        CeataendieW::new(self, 23)
    }
}
#[doc = "mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mask::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mask::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MaskSpec;
impl crate::RegisterSpec for MaskSpec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`read()` method returns [`mask::R`](R) reader structure"]
impl crate::Readable for MaskSpec {}
#[doc = "`write(|w| ..)` method takes [`mask::W`](W) writer structure"]
impl crate::Writable for MaskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MASK to value 0"]
impl crate::Resettable for MaskSpec {
    const RESET_VALUE: u32 = 0;
}
