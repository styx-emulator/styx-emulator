// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `status` reader"]
pub type R = crate::R<StatusSpec>;
#[doc = "Register `status` writer"]
pub type W = crate::W<StatusSpec>;
#[doc = "FIFO reached Receive watermark level; not qualified with data transfer\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FifoRxWatermark {
    #[doc = "0: `0`"]
    Rxwatermark = 0,
    #[doc = "1: `1`"]
    Norxwatermark = 1,
}
impl From<FifoRxWatermark> for bool {
    #[inline(always)]
    fn from(variant: FifoRxWatermark) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fifo_rx_watermark` reader - FIFO reached Receive watermark level; not qualified with data transfer"]
pub type FifoRxWatermarkR = crate::BitReader<FifoRxWatermark>;
impl FifoRxWatermarkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> FifoRxWatermark {
        match self.bits {
            false => FifoRxWatermark::Rxwatermark,
            true => FifoRxWatermark::Norxwatermark,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_rxwatermark(&self) -> bool {
        *self == FifoRxWatermark::Rxwatermark
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_norxwatermark(&self) -> bool {
        *self == FifoRxWatermark::Norxwatermark
    }
}
#[doc = "Field `fifo_rx_watermark` writer - FIFO reached Receive watermark level; not qualified with data transfer"]
pub type FifoRxWatermarkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "FIFO reached Transmit watermark level; not qualified with data transfer.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FifoTxWatermark {
    #[doc = "1: `1`"]
    Txwatermark = 1,
    #[doc = "0: `0`"]
    Notxwatermark = 0,
}
impl From<FifoTxWatermark> for bool {
    #[inline(always)]
    fn from(variant: FifoTxWatermark) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fifo_tx_watermark` reader - FIFO reached Transmit watermark level; not qualified with data transfer."]
pub type FifoTxWatermarkR = crate::BitReader<FifoTxWatermark>;
impl FifoTxWatermarkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> FifoTxWatermark {
        match self.bits {
            true => FifoTxWatermark::Txwatermark,
            false => FifoTxWatermark::Notxwatermark,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_txwatermark(&self) -> bool {
        *self == FifoTxWatermark::Txwatermark
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notxwatermark(&self) -> bool {
        *self == FifoTxWatermark::Notxwatermark
    }
}
#[doc = "Field `fifo_tx_watermark` writer - FIFO reached Transmit watermark level; not qualified with data transfer."]
pub type FifoTxWatermarkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "FIFO is empty status.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FifoEmpty {
    #[doc = "1: `1`"]
    Fifoempty = 1,
    #[doc = "0: `0`"]
    Fifonotempty = 0,
}
impl From<FifoEmpty> for bool {
    #[inline(always)]
    fn from(variant: FifoEmpty) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fifo_empty` reader - FIFO is empty status."]
pub type FifoEmptyR = crate::BitReader<FifoEmpty>;
impl FifoEmptyR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> FifoEmpty {
        match self.bits {
            true => FifoEmpty::Fifoempty,
            false => FifoEmpty::Fifonotempty,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fifoempty(&self) -> bool {
        *self == FifoEmpty::Fifoempty
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fifonotempty(&self) -> bool {
        *self == FifoEmpty::Fifonotempty
    }
}
#[doc = "Field `fifo_empty` writer - FIFO is empty status."]
pub type FifoEmptyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "FIFO is full status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FifoFull {
    #[doc = "0: `0`"]
    Fifofull = 0,
    #[doc = "1: `1`"]
    Fifonotfull = 1,
}
impl From<FifoFull> for bool {
    #[inline(always)]
    fn from(variant: FifoFull) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fifo_full` reader - FIFO is full status."]
pub type FifoFullR = crate::BitReader<FifoFull>;
impl FifoFullR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> FifoFull {
        match self.bits {
            false => FifoFull::Fifofull,
            true => FifoFull::Fifonotfull,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fifofull(&self) -> bool {
        *self == FifoFull::Fifofull
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fifonotfull(&self) -> bool {
        *self == FifoFull::Fifonotfull
    }
}
#[doc = "Field `fifo_full` writer - FIFO is full status."]
pub type FifoFullW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The command FSM state.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandFsmStates {
    #[doc = "0: `0`"]
    Idleandothers = 0,
    #[doc = "1: `1`"]
    Sendinitseq = 1,
    #[doc = "2: `10`"]
    Txcmdstart = 2,
    #[doc = "3: `11`"]
    Txcmdtxbit = 3,
    #[doc = "4: `100`"]
    Txcmdindxarg = 4,
    #[doc = "5: `101`"]
    Txcmdcrc7 = 5,
    #[doc = "6: `110`"]
    Txcmdend = 6,
    #[doc = "7: `111`"]
    Rxrespstart = 7,
    #[doc = "8: `1000`"]
    Rxrespirq = 8,
    #[doc = "9: `1001`"]
    Rxresptx = 9,
    #[doc = "10: `1010`"]
    Rxrespcmdidx = 10,
    #[doc = "11: `1011`"]
    Rxrespdata = 11,
    #[doc = "12: `1100`"]
    Rxrespcrc7 = 12,
    #[doc = "13: `1101`"]
    Rxrespend = 13,
    #[doc = "14: `1110`"]
    Cmdpathwait = 14,
    #[doc = "15: `1111`"]
    Waitcmdturn = 15,
}
impl From<CommandFsmStates> for u8 {
    #[inline(always)]
    fn from(variant: CommandFsmStates) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for CommandFsmStates {
    type Ux = u8;
}
#[doc = "Field `command_fsm_states` reader - The command FSM state."]
pub type CommandFsmStatesR = crate::FieldReader<CommandFsmStates>;
impl CommandFsmStatesR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> CommandFsmStates {
        match self.bits {
            0 => CommandFsmStates::Idleandothers,
            1 => CommandFsmStates::Sendinitseq,
            2 => CommandFsmStates::Txcmdstart,
            3 => CommandFsmStates::Txcmdtxbit,
            4 => CommandFsmStates::Txcmdindxarg,
            5 => CommandFsmStates::Txcmdcrc7,
            6 => CommandFsmStates::Txcmdend,
            7 => CommandFsmStates::Rxrespstart,
            8 => CommandFsmStates::Rxrespirq,
            9 => CommandFsmStates::Rxresptx,
            10 => CommandFsmStates::Rxrespcmdidx,
            11 => CommandFsmStates::Rxrespdata,
            12 => CommandFsmStates::Rxrespcrc7,
            13 => CommandFsmStates::Rxrespend,
            14 => CommandFsmStates::Cmdpathwait,
            15 => CommandFsmStates::Waitcmdturn,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_idleandothers(&self) -> bool {
        *self == CommandFsmStates::Idleandothers
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_sendinitseq(&self) -> bool {
        *self == CommandFsmStates::Sendinitseq
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_txcmdstart(&self) -> bool {
        *self == CommandFsmStates::Txcmdstart
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_txcmdtxbit(&self) -> bool {
        *self == CommandFsmStates::Txcmdtxbit
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_txcmdindxarg(&self) -> bool {
        *self == CommandFsmStates::Txcmdindxarg
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_txcmdcrc7(&self) -> bool {
        *self == CommandFsmStates::Txcmdcrc7
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_txcmdend(&self) -> bool {
        *self == CommandFsmStates::Txcmdend
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_rxrespstart(&self) -> bool {
        *self == CommandFsmStates::Rxrespstart
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_rxrespirq(&self) -> bool {
        *self == CommandFsmStates::Rxrespirq
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_rxresptx(&self) -> bool {
        *self == CommandFsmStates::Rxresptx
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_rxrespcmdidx(&self) -> bool {
        *self == CommandFsmStates::Rxrespcmdidx
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_rxrespdata(&self) -> bool {
        *self == CommandFsmStates::Rxrespdata
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_rxrespcrc7(&self) -> bool {
        *self == CommandFsmStates::Rxrespcrc7
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_rxrespend(&self) -> bool {
        *self == CommandFsmStates::Rxrespend
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_cmdpathwait(&self) -> bool {
        *self == CommandFsmStates::Cmdpathwait
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_waitcmdturn(&self) -> bool {
        *self == CommandFsmStates::Waitcmdturn
    }
}
#[doc = "Field `command_fsm_states` writer - The command FSM state."]
pub type CommandFsmStatesW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Raw selected card_data\\[3\\]; checks whether card is present. The default can be cardpresent or not present depend on cdata_in.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Data3Status {
    #[doc = "1: `1`"]
    Cardpresent = 1,
    #[doc = "0: `0`"]
    Cardnotpresent = 0,
}
impl From<Data3Status> for bool {
    #[inline(always)]
    fn from(variant: Data3Status) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `data_3_status` reader - Raw selected card_data\\[3\\]; checks whether card is present. The default can be cardpresent or not present depend on cdata_in."]
pub type Data3StatusR = crate::BitReader<Data3Status>;
impl Data3StatusR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Data3Status {
        match self.bits {
            true => Data3Status::Cardpresent,
            false => Data3Status::Cardnotpresent,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_cardpresent(&self) -> bool {
        *self == Data3Status::Cardpresent
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_cardnotpresent(&self) -> bool {
        *self == Data3Status::Cardnotpresent
    }
}
#[doc = "Field `data_3_status` writer - Raw selected card_data\\[3\\]; checks whether card is present. The default can be cardpresent or not present depend on cdata_in."]
pub type Data3StatusW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Inverted version of raw selected card_data\\[0\\]. The default can be cardpresent or not present depend on cdata_in.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataBusy {
    #[doc = "1: `1`"]
    Cardbusy = 1,
    #[doc = "0: `0`"]
    Cardnotbusy = 0,
}
impl From<DataBusy> for bool {
    #[inline(always)]
    fn from(variant: DataBusy) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `data_busy` reader - Inverted version of raw selected card_data\\[0\\]. The default can be cardpresent or not present depend on cdata_in."]
pub type DataBusyR = crate::BitReader<DataBusy>;
impl DataBusyR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> DataBusy {
        match self.bits {
            true => DataBusy::Cardbusy,
            false => DataBusy::Cardnotbusy,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_cardbusy(&self) -> bool {
        *self == DataBusy::Cardbusy
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_cardnotbusy(&self) -> bool {
        *self == DataBusy::Cardnotbusy
    }
}
#[doc = "Field `data_busy` writer - Inverted version of raw selected card_data\\[0\\]. The default can be cardpresent or not present depend on cdata_in."]
pub type DataBusyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Data transmit or receive state-machine is busy.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataStateMcBusy {
    #[doc = "1: `1`"]
    Datastatebsy = 1,
    #[doc = "0: `0`"]
    Datastatenotbsy = 0,
}
impl From<DataStateMcBusy> for bool {
    #[inline(always)]
    fn from(variant: DataStateMcBusy) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `data_state_mc_busy` reader - Data transmit or receive state-machine is busy."]
pub type DataStateMcBusyR = crate::BitReader<DataStateMcBusy>;
impl DataStateMcBusyR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> DataStateMcBusy {
        match self.bits {
            true => DataStateMcBusy::Datastatebsy,
            false => DataStateMcBusy::Datastatenotbsy,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_datastatebsy(&self) -> bool {
        *self == DataStateMcBusy::Datastatebsy
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_datastatenotbsy(&self) -> bool {
        *self == DataStateMcBusy::Datastatenotbsy
    }
}
#[doc = "Field `data_state_mc_busy` writer - Data transmit or receive state-machine is busy."]
pub type DataStateMcBusyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `response_index` reader - Index of previous response, including any auto-stop sent by core"]
pub type ResponseIndexR = crate::FieldReader;
#[doc = "Field `response_index` writer - Index of previous response, including any auto-stop sent by core"]
pub type ResponseIndexW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `fifo_count` reader - FIFO count - Number of filled locations in FIFO"]
pub type FifoCountR = crate::FieldReader<u16>;
#[doc = "Field `fifo_count` writer - FIFO count - Number of filled locations in FIFO"]
pub type FifoCountW<'a, REG> = crate::FieldWriter<'a, REG, 13, u16>;
impl R {
    #[doc = "Bit 0 - FIFO reached Receive watermark level; not qualified with data transfer"]
    #[inline(always)]
    pub fn fifo_rx_watermark(&self) -> FifoRxWatermarkR {
        FifoRxWatermarkR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - FIFO reached Transmit watermark level; not qualified with data transfer."]
    #[inline(always)]
    pub fn fifo_tx_watermark(&self) -> FifoTxWatermarkR {
        FifoTxWatermarkR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - FIFO is empty status."]
    #[inline(always)]
    pub fn fifo_empty(&self) -> FifoEmptyR {
        FifoEmptyR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - FIFO is full status."]
    #[inline(always)]
    pub fn fifo_full(&self) -> FifoFullR {
        FifoFullR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 4:7 - The command FSM state."]
    #[inline(always)]
    pub fn command_fsm_states(&self) -> CommandFsmStatesR {
        CommandFsmStatesR::new(((self.bits >> 4) & 0x0f) as u8)
    }
    #[doc = "Bit 8 - Raw selected card_data\\[3\\]; checks whether card is present. The default can be cardpresent or not present depend on cdata_in."]
    #[inline(always)]
    pub fn data_3_status(&self) -> Data3StatusR {
        Data3StatusR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Inverted version of raw selected card_data\\[0\\]. The default can be cardpresent or not present depend on cdata_in."]
    #[inline(always)]
    pub fn data_busy(&self) -> DataBusyR {
        DataBusyR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Data transmit or receive state-machine is busy."]
    #[inline(always)]
    pub fn data_state_mc_busy(&self) -> DataStateMcBusyR {
        DataStateMcBusyR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bits 11:16 - Index of previous response, including any auto-stop sent by core"]
    #[inline(always)]
    pub fn response_index(&self) -> ResponseIndexR {
        ResponseIndexR::new(((self.bits >> 11) & 0x3f) as u8)
    }
    #[doc = "Bits 17:29 - FIFO count - Number of filled locations in FIFO"]
    #[inline(always)]
    pub fn fifo_count(&self) -> FifoCountR {
        FifoCountR::new(((self.bits >> 17) & 0x1fff) as u16)
    }
}
impl W {
    #[doc = "Bit 0 - FIFO reached Receive watermark level; not qualified with data transfer"]
    #[inline(always)]
    #[must_use]
    pub fn fifo_rx_watermark(&mut self) -> FifoRxWatermarkW<StatusSpec> {
        FifoRxWatermarkW::new(self, 0)
    }
    #[doc = "Bit 1 - FIFO reached Transmit watermark level; not qualified with data transfer."]
    #[inline(always)]
    #[must_use]
    pub fn fifo_tx_watermark(&mut self) -> FifoTxWatermarkW<StatusSpec> {
        FifoTxWatermarkW::new(self, 1)
    }
    #[doc = "Bit 2 - FIFO is empty status."]
    #[inline(always)]
    #[must_use]
    pub fn fifo_empty(&mut self) -> FifoEmptyW<StatusSpec> {
        FifoEmptyW::new(self, 2)
    }
    #[doc = "Bit 3 - FIFO is full status."]
    #[inline(always)]
    #[must_use]
    pub fn fifo_full(&mut self) -> FifoFullW<StatusSpec> {
        FifoFullW::new(self, 3)
    }
    #[doc = "Bits 4:7 - The command FSM state."]
    #[inline(always)]
    #[must_use]
    pub fn command_fsm_states(&mut self) -> CommandFsmStatesW<StatusSpec> {
        CommandFsmStatesW::new(self, 4)
    }
    #[doc = "Bit 8 - Raw selected card_data\\[3\\]; checks whether card is present. The default can be cardpresent or not present depend on cdata_in."]
    #[inline(always)]
    #[must_use]
    pub fn data_3_status(&mut self) -> Data3StatusW<StatusSpec> {
        Data3StatusW::new(self, 8)
    }
    #[doc = "Bit 9 - Inverted version of raw selected card_data\\[0\\]. The default can be cardpresent or not present depend on cdata_in."]
    #[inline(always)]
    #[must_use]
    pub fn data_busy(&mut self) -> DataBusyW<StatusSpec> {
        DataBusyW::new(self, 9)
    }
    #[doc = "Bit 10 - Data transmit or receive state-machine is busy."]
    #[inline(always)]
    #[must_use]
    pub fn data_state_mc_busy(&mut self) -> DataStateMcBusyW<StatusSpec> {
        DataStateMcBusyW::new(self, 10)
    }
    #[doc = "Bits 11:16 - Index of previous response, including any auto-stop sent by core"]
    #[inline(always)]
    #[must_use]
    pub fn response_index(&mut self) -> ResponseIndexW<StatusSpec> {
        ResponseIndexW::new(self, 11)
    }
    #[doc = "Bits 17:29 - FIFO count - Number of filled locations in FIFO"]
    #[inline(always)]
    #[must_use]
    pub fn fifo_count(&mut self) -> FifoCountW<StatusSpec> {
        FifoCountW::new(self, 17)
    }
}
#[doc = "Reports various operting status conditions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StatusSpec;
impl crate::RegisterSpec for StatusSpec {
    type Ux = u32;
    const OFFSET: u64 = 72u64;
}
#[doc = "`read()` method returns [`status::R`](R) reader structure"]
impl crate::Readable for StatusSpec {}
#[doc = "`reset()` method sets status to value 0x0106"]
impl crate::Resettable for StatusSpec {
    const RESET_VALUE: u32 = 0x0106;
}
