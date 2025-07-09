// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `fcr` reader"]
pub type R = crate::R<FcrSpec>;
#[doc = "Register `fcr` writer"]
pub type W = crate::W<FcrSpec>;
#[doc = "Field `fifoe` reader - Enables/disables the transmit (Tx) and receive (Rx ) FIFO's. Whenever the value of this bit is changed both the Tx and Rx controller portion of FIFO's will be reset."]
pub type FifoeR = crate::BitReader;
#[doc = "Enables/disables the transmit (Tx) and receive (Rx ) FIFO's. Whenever the value of this bit is changed both the Tx and Rx controller portion of FIFO's will be reset.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fifoe {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Fifoe> for bool {
    #[inline(always)]
    fn from(variant: Fifoe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fifoe` writer - Enables/disables the transmit (Tx) and receive (Rx ) FIFO's. Whenever the value of this bit is changed both the Tx and Rx controller portion of FIFO's will be reset."]
pub type FifoeW<'a, REG> = crate::BitWriter<'a, REG, Fifoe>;
impl<'a, REG> FifoeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Fifoe::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Fifoe::Enabled)
    }
}
#[doc = "Field `rfifor` reader - Resets the control portion of the receive FIFO and treats the FIFO as empty. This will also de-assert the DMA Rxrequest and single signals. Note that this bit is self-clearing' and it is not necessary to clear this bit."]
pub type RfiforR = crate::BitReader;
#[doc = "Resets the control portion of the receive FIFO and treats the FIFO as empty. This will also de-assert the DMA Rxrequest and single signals. Note that this bit is self-clearing' and it is not necessary to clear this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rfifor {
    #[doc = "0: `0`"]
    Noreset = 0,
    #[doc = "1: `1`"]
    Reset = 1,
}
impl From<Rfifor> for bool {
    #[inline(always)]
    fn from(variant: Rfifor) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rfifor` writer - Resets the control portion of the receive FIFO and treats the FIFO as empty. This will also de-assert the DMA Rxrequest and single signals. Note that this bit is self-clearing' and it is not necessary to clear this bit."]
pub type RfiforW<'a, REG> = crate::BitWriter<'a, REG, Rfifor>;
impl<'a, REG> RfiforW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noreset(self) -> &'a mut crate::W<REG> {
        self.variant(Rfifor::Noreset)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn reset(self) -> &'a mut crate::W<REG> {
        self.variant(Rfifor::Reset)
    }
}
#[doc = "Field `xfifor` reader - Resets the control portion of the transmit FIFO and treats the FIFO as empty. This will also de-assert the DMA Tx request and single signals when additional DMA handshaking is used. Note that this bit is 'self-clearing' and it is not necessary to clear this bit."]
pub type XfiforR = crate::BitReader;
#[doc = "Resets the control portion of the transmit FIFO and treats the FIFO as empty. This will also de-assert the DMA Tx request and single signals when additional DMA handshaking is used. Note that this bit is 'self-clearing' and it is not necessary to clear this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Xfifor {
    #[doc = "0: `0`"]
    Noreset = 0,
    #[doc = "1: `1`"]
    Reset = 1,
}
impl From<Xfifor> for bool {
    #[inline(always)]
    fn from(variant: Xfifor) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `xfifor` writer - Resets the control portion of the transmit FIFO and treats the FIFO as empty. This will also de-assert the DMA Tx request and single signals when additional DMA handshaking is used. Note that this bit is 'self-clearing' and it is not necessary to clear this bit."]
pub type XfiforW<'a, REG> = crate::BitWriter<'a, REG, Xfifor>;
impl<'a, REG> XfiforW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noreset(self) -> &'a mut crate::W<REG> {
        self.variant(Xfifor::Noreset)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn reset(self) -> &'a mut crate::W<REG> {
        self.variant(Xfifor::Reset)
    }
}
#[doc = "Field `dmam` reader - This determines the DMA signalling mode used for the uart_dma_tx_req_n and uart_dma_rx_req_n output signals when additional DMA handshaking signals are not selected. DMA mode 0 supports single DMA data transfers at a time. In mode 0, the uart_dma_tx_req_n signal goes active low under the following conditions: -When the Transmitter Holding Register is empty in non-FIFO mode. -When the transmitter FIFO is empty in FIFO mode with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is at or below the programmed threshold with Programmable THRE interrupt mode enabled. It goes inactive under the following conditions -When a single character has been written into the Transmitter Holding Register or transmitter FIFO with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is above the threshold with Programmable THRE interrupt mode enabled. DMA mode 1 supports multi-DMA data transfers, where multiple transfers are made continuously until the receiver FIFO has been emptied or the transmit FIFO has been filled. In mode 1 the uart_dma_tx_req_n signal is asserted under the following conditions: -When the transmitter FIFO is empty with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is at or below the programmed threshold with Programmable THRE interrupt mode enabled."]
pub type DmamR = crate::BitReader;
#[doc = "This determines the DMA signalling mode used for the uart_dma_tx_req_n and uart_dma_rx_req_n output signals when additional DMA handshaking signals are not selected. DMA mode 0 supports single DMA data transfers at a time. In mode 0, the uart_dma_tx_req_n signal goes active low under the following conditions: -When the Transmitter Holding Register is empty in non-FIFO mode. -When the transmitter FIFO is empty in FIFO mode with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is at or below the programmed threshold with Programmable THRE interrupt mode enabled. It goes inactive under the following conditions -When a single character has been written into the Transmitter Holding Register or transmitter FIFO with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is above the threshold with Programmable THRE interrupt mode enabled. DMA mode 1 supports multi-DMA data transfers, where multiple transfers are made continuously until the receiver FIFO has been emptied or the transmit FIFO has been filled. In mode 1 the uart_dma_tx_req_n signal is asserted under the following conditions: -When the transmitter FIFO is empty with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is at or below the programmed threshold with Programmable THRE interrupt mode enabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dmam {
    #[doc = "0: `0`"]
    Single = 0,
    #[doc = "1: `1`"]
    Multiple = 1,
}
impl From<Dmam> for bool {
    #[inline(always)]
    fn from(variant: Dmam) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dmam` writer - This determines the DMA signalling mode used for the uart_dma_tx_req_n and uart_dma_rx_req_n output signals when additional DMA handshaking signals are not selected. DMA mode 0 supports single DMA data transfers at a time. In mode 0, the uart_dma_tx_req_n signal goes active low under the following conditions: -When the Transmitter Holding Register is empty in non-FIFO mode. -When the transmitter FIFO is empty in FIFO mode with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is at or below the programmed threshold with Programmable THRE interrupt mode enabled. It goes inactive under the following conditions -When a single character has been written into the Transmitter Holding Register or transmitter FIFO with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is above the threshold with Programmable THRE interrupt mode enabled. DMA mode 1 supports multi-DMA data transfers, where multiple transfers are made continuously until the receiver FIFO has been emptied or the transmit FIFO has been filled. In mode 1 the uart_dma_tx_req_n signal is asserted under the following conditions: -When the transmitter FIFO is empty with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is at or below the programmed threshold with Programmable THRE interrupt mode enabled."]
pub type DmamW<'a, REG> = crate::BitWriter<'a, REG, Dmam>;
impl<'a, REG> DmamW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn single(self) -> &'a mut crate::W<REG> {
        self.variant(Dmam::Single)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn multiple(self) -> &'a mut crate::W<REG> {
        self.variant(Dmam::Multiple)
    }
}
#[doc = "Field `tet` reader - This is used to select the empty threshold level at which the THRE Interrupts will be generated when the mode is active. It also determines when the uart DMA transmit request signal uart_dma_tx_req_n will be asserted when in certain modes of operation."]
pub type TetR = crate::FieldReader;
#[doc = "This is used to select the empty threshold level at which the THRE Interrupts will be generated when the mode is active. It also determines when the uart DMA transmit request signal uart_dma_tx_req_n will be asserted when in certain modes of operation.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tet {
    #[doc = "0: `0`"]
    Fifoempty = 0,
    #[doc = "1: `1`"]
    Twochars = 1,
    #[doc = "2: `10`"]
    Quarterfull = 2,
    #[doc = "3: `11`"]
    Halffull = 3,
}
impl From<Tet> for u8 {
    #[inline(always)]
    fn from(variant: Tet) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Tet {
    type Ux = u8;
}
#[doc = "Field `tet` writer - This is used to select the empty threshold level at which the THRE Interrupts will be generated when the mode is active. It also determines when the uart DMA transmit request signal uart_dma_tx_req_n will be asserted when in certain modes of operation."]
pub type TetW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Tet>;
impl<'a, REG> TetW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn fifoempty(self) -> &'a mut crate::W<REG> {
        self.variant(Tet::Fifoempty)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn twochars(self) -> &'a mut crate::W<REG> {
        self.variant(Tet::Twochars)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn quarterfull(self) -> &'a mut crate::W<REG> {
        self.variant(Tet::Quarterfull)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn halffull(self) -> &'a mut crate::W<REG> {
        self.variant(Tet::Halffull)
    }
}
#[doc = "Field `rt` reader - This register is configured to implement FIFOs. Bits\\[7:6\\], Rx Trigger (or RT): This is used to select the trigger level in the receiver FIFO at which the Received Data Available Interrupt will be generated. In auto flow control mode it is used to determine when the uart_rts_n signal will be de-asserted. It also determines when the uart_dma_rx_req_n signal will be asserted when in certain modes of operation."]
pub type RtR = crate::FieldReader;
#[doc = "This register is configured to implement FIFOs. Bits\\[7:6\\], Rx Trigger (or RT): This is used to select the trigger level in the receiver FIFO at which the Received Data Available Interrupt will be generated. In auto flow control mode it is used to determine when the uart_rts_n signal will be de-asserted. It also determines when the uart_dma_rx_req_n signal will be asserted when in certain modes of operation.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rt {
    #[doc = "0: `0`"]
    Onechar = 0,
    #[doc = "1: `1`"]
    Quarterfull = 1,
    #[doc = "2: `10`"]
    Halffull = 2,
    #[doc = "3: `11`"]
    Fullless2 = 3,
}
impl From<Rt> for u8 {
    #[inline(always)]
    fn from(variant: Rt) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Rt {
    type Ux = u8;
}
#[doc = "Field `rt` writer - This register is configured to implement FIFOs. Bits\\[7:6\\], Rx Trigger (or RT): This is used to select the trigger level in the receiver FIFO at which the Received Data Available Interrupt will be generated. In auto flow control mode it is used to determine when the uart_rts_n signal will be de-asserted. It also determines when the uart_dma_rx_req_n signal will be asserted when in certain modes of operation."]
pub type RtW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Rt>;
impl<'a, REG> RtW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn onechar(self) -> &'a mut crate::W<REG> {
        self.variant(Rt::Onechar)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn quarterfull(self) -> &'a mut crate::W<REG> {
        self.variant(Rt::Quarterfull)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn halffull(self) -> &'a mut crate::W<REG> {
        self.variant(Rt::Halffull)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn fullless2(self) -> &'a mut crate::W<REG> {
        self.variant(Rt::Fullless2)
    }
}
impl R {
    #[doc = "Bit 0 - Enables/disables the transmit (Tx) and receive (Rx ) FIFO's. Whenever the value of this bit is changed both the Tx and Rx controller portion of FIFO's will be reset."]
    #[inline(always)]
    pub fn fifoe(&self) -> FifoeR {
        FifoeR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Resets the control portion of the receive FIFO and treats the FIFO as empty. This will also de-assert the DMA Rxrequest and single signals. Note that this bit is self-clearing' and it is not necessary to clear this bit."]
    #[inline(always)]
    pub fn rfifor(&self) -> RfiforR {
        RfiforR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Resets the control portion of the transmit FIFO and treats the FIFO as empty. This will also de-assert the DMA Tx request and single signals when additional DMA handshaking is used. Note that this bit is 'self-clearing' and it is not necessary to clear this bit."]
    #[inline(always)]
    pub fn xfifor(&self) -> XfiforR {
        XfiforR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This determines the DMA signalling mode used for the uart_dma_tx_req_n and uart_dma_rx_req_n output signals when additional DMA handshaking signals are not selected. DMA mode 0 supports single DMA data transfers at a time. In mode 0, the uart_dma_tx_req_n signal goes active low under the following conditions: -When the Transmitter Holding Register is empty in non-FIFO mode. -When the transmitter FIFO is empty in FIFO mode with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is at or below the programmed threshold with Programmable THRE interrupt mode enabled. It goes inactive under the following conditions -When a single character has been written into the Transmitter Holding Register or transmitter FIFO with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is above the threshold with Programmable THRE interrupt mode enabled. DMA mode 1 supports multi-DMA data transfers, where multiple transfers are made continuously until the receiver FIFO has been emptied or the transmit FIFO has been filled. In mode 1 the uart_dma_tx_req_n signal is asserted under the following conditions: -When the transmitter FIFO is empty with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is at or below the programmed threshold with Programmable THRE interrupt mode enabled."]
    #[inline(always)]
    pub fn dmam(&self) -> DmamR {
        DmamR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 4:5 - This is used to select the empty threshold level at which the THRE Interrupts will be generated when the mode is active. It also determines when the uart DMA transmit request signal uart_dma_tx_req_n will be asserted when in certain modes of operation."]
    #[inline(always)]
    pub fn tet(&self) -> TetR {
        TetR::new(((self.bits >> 4) & 3) as u8)
    }
    #[doc = "Bits 6:7 - This register is configured to implement FIFOs. Bits\\[7:6\\], Rx Trigger (or RT): This is used to select the trigger level in the receiver FIFO at which the Received Data Available Interrupt will be generated. In auto flow control mode it is used to determine when the uart_rts_n signal will be de-asserted. It also determines when the uart_dma_rx_req_n signal will be asserted when in certain modes of operation."]
    #[inline(always)]
    pub fn rt(&self) -> RtR {
        RtR::new(((self.bits >> 6) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Enables/disables the transmit (Tx) and receive (Rx ) FIFO's. Whenever the value of this bit is changed both the Tx and Rx controller portion of FIFO's will be reset."]
    #[inline(always)]
    #[must_use]
    pub fn fifoe(&mut self) -> FifoeW<FcrSpec> {
        FifoeW::new(self, 0)
    }
    #[doc = "Bit 1 - Resets the control portion of the receive FIFO and treats the FIFO as empty. This will also de-assert the DMA Rxrequest and single signals. Note that this bit is self-clearing' and it is not necessary to clear this bit."]
    #[inline(always)]
    #[must_use]
    pub fn rfifor(&mut self) -> RfiforW<FcrSpec> {
        RfiforW::new(self, 1)
    }
    #[doc = "Bit 2 - Resets the control portion of the transmit FIFO and treats the FIFO as empty. This will also de-assert the DMA Tx request and single signals when additional DMA handshaking is used. Note that this bit is 'self-clearing' and it is not necessary to clear this bit."]
    #[inline(always)]
    #[must_use]
    pub fn xfifor(&mut self) -> XfiforW<FcrSpec> {
        XfiforW::new(self, 2)
    }
    #[doc = "Bit 3 - This determines the DMA signalling mode used for the uart_dma_tx_req_n and uart_dma_rx_req_n output signals when additional DMA handshaking signals are not selected. DMA mode 0 supports single DMA data transfers at a time. In mode 0, the uart_dma_tx_req_n signal goes active low under the following conditions: -When the Transmitter Holding Register is empty in non-FIFO mode. -When the transmitter FIFO is empty in FIFO mode with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is at or below the programmed threshold with Programmable THRE interrupt mode enabled. It goes inactive under the following conditions -When a single character has been written into the Transmitter Holding Register or transmitter FIFO with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is above the threshold with Programmable THRE interrupt mode enabled. DMA mode 1 supports multi-DMA data transfers, where multiple transfers are made continuously until the receiver FIFO has been emptied or the transmit FIFO has been filled. In mode 1 the uart_dma_tx_req_n signal is asserted under the following conditions: -When the transmitter FIFO is empty with Programmable THRE interrupt mode disabled. -When the transmitter FIFO is at or below the programmed threshold with Programmable THRE interrupt mode enabled."]
    #[inline(always)]
    #[must_use]
    pub fn dmam(&mut self) -> DmamW<FcrSpec> {
        DmamW::new(self, 3)
    }
    #[doc = "Bits 4:5 - This is used to select the empty threshold level at which the THRE Interrupts will be generated when the mode is active. It also determines when the uart DMA transmit request signal uart_dma_tx_req_n will be asserted when in certain modes of operation."]
    #[inline(always)]
    #[must_use]
    pub fn tet(&mut self) -> TetW<FcrSpec> {
        TetW::new(self, 4)
    }
    #[doc = "Bits 6:7 - This register is configured to implement FIFOs. Bits\\[7:6\\], Rx Trigger (or RT): This is used to select the trigger level in the receiver FIFO at which the Received Data Available Interrupt will be generated. In auto flow control mode it is used to determine when the uart_rts_n signal will be de-asserted. It also determines when the uart_dma_rx_req_n signal will be asserted when in certain modes of operation."]
    #[inline(always)]
    #[must_use]
    pub fn rt(&mut self) -> RtW<FcrSpec> {
        RtW::new(self, 6)
    }
}
#[doc = "Controls FIFO Operations when written.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fcr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FcrSpec;
impl crate::RegisterSpec for FcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`write(|w| ..)` method takes [`fcr::W`](W) writer structure"]
impl crate::Writable for FcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets fcr to value 0"]
impl crate::Resettable for FcrSpec {
    const RESET_VALUE: u32 = 0;
}
