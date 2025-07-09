// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_raw_intr_stat` reader"]
pub type R = crate::R<IcRawIntrStatSpec>;
#[doc = "Register `ic_raw_intr_stat` writer"]
pub type W = crate::W<IcRawIntrStatSpec>;
#[doc = "Field `rx_under` reader - Set if the processor attempts to read the receive buffer when it is empty by reading from the ic_data_cmd register. If the module is disabled ic_enable\\[0\\]=0, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
pub type RxUnderR = crate::BitReader;
#[doc = "Field `rx_under` writer - Set if the processor attempts to read the receive buffer when it is empty by reading from the ic_data_cmd register. If the module is disabled ic_enable\\[0\\]=0, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
pub type RxUnderW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rx_over` reader - Set if the receive buffer is completely filled to 64 and an additional byte is received from an external I2C device. The I2C acknowledges this, but any data bytes received after the FIFO is full are lost. If the module is disabled ic_enable\\[0\\]=0), this bit keeps its level until the master or slave state machines go into then, this interrupt is cleared."]
pub type RxOverR = crate::BitReader;
#[doc = "Field `rx_over` writer - Set if the receive buffer is completely filled to 64 and an additional byte is received from an external I2C device. The I2C acknowledges this, but any data bytes received after the FIFO is full are lost. If the module is disabled ic_enable\\[0\\]=0), this bit keeps its level until the master or slave state machines go into then, this interrupt is cleared."]
pub type RxOverW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rx_full` reader - Set when the receive buffer reaches or goes above the RX_TL threshold in the ic_rx_tl register. It is automatically cleared by hardware when buffer level goes below the threshold. If the module is disabled ic_enable\\[0\\]=0, the RX FIFO is flushed and held in reset; therefore the RX FIFO is not full. So this bit is cleared once the ic_enable bit 0 is programmed with a 0, regardless of the activity that continues."]
pub type RxFullR = crate::BitReader;
#[doc = "Field `rx_full` writer - Set when the receive buffer reaches or goes above the RX_TL threshold in the ic_rx_tl register. It is automatically cleared by hardware when buffer level goes below the threshold. If the module is disabled ic_enable\\[0\\]=0, the RX FIFO is flushed and held in reset; therefore the RX FIFO is not full. So this bit is cleared once the ic_enable bit 0 is programmed with a 0, regardless of the activity that continues."]
pub type RxFullW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `tx_over` reader - Set during transmit if the transmit buffer is filled to 64 and the processor attempts to issue another I2C command by writing to the ic_data_cmd register. When the module is disabled, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
pub type TxOverR = crate::BitReader;
#[doc = "Field `tx_over` writer - Set during transmit if the transmit buffer is filled to 64 and the processor attempts to issue another I2C command by writing to the ic_data_cmd register. When the module is disabled, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
pub type TxOverW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `tx_empty` reader - This bit is set to 1 when the transmit buffer is at or below the threshold value set in the ic_tx_tl register. It is automatically cleared by hardware when the buffer level goes above the threshold. When the IC_ENABLE bit 0 is 0, the TX FIFO is flushed and held in reset. There the TX FIFO looks like it has no data within it, so this bit is set to 1, provided there is activity in the master or slave state machines. When there is no longer activity, then this bit is set to 0."]
pub type TxEmptyR = crate::BitReader;
#[doc = "Field `tx_empty` writer - This bit is set to 1 when the transmit buffer is at or below the threshold value set in the ic_tx_tl register. It is automatically cleared by hardware when the buffer level goes above the threshold. When the IC_ENABLE bit 0 is 0, the TX FIFO is flushed and held in reset. There the TX FIFO looks like it has no data within it, so this bit is set to 1, provided there is activity in the master or slave state machines. When there is no longer activity, then this bit is set to 0."]
pub type TxEmptyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rd_req` reader - This bit is set to 1 when I2C is acting as a slave and another I2C master is attempting to read data from I2C. The i2c holds the I2C bus in a wait state (SCL=0) until this interrupt is serviced, which means that the slave has been addressed by a remote master that is asking for data to be transferred. The processor must respond to this interrupt and then write the requested data to the ic_data_cmd register. This bit is set to 0 just after the processor reads the ic_clr_rd_req register."]
pub type RdReqR = crate::BitReader;
#[doc = "Field `rd_req` writer - This bit is set to 1 when I2C is acting as a slave and another I2C master is attempting to read data from I2C. The i2c holds the I2C bus in a wait state (SCL=0) until this interrupt is serviced, which means that the slave has been addressed by a remote master that is asking for data to be transferred. The processor must respond to this interrupt and then write the requested data to the ic_data_cmd register. This bit is set to 0 just after the processor reads the ic_clr_rd_req register."]
pub type RdReqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `tx_abrt` reader - This bit indicates if I2C, as an I2C transmitter, is unable to complete the intended actions on the contents of the transmit FIFO. This situation can occur both as an I2C master or an I2C slave, and is referred to as a 'transmit abort'. When this bit is set to 1, the IC_TX_ABRT_SOURCE register indicates the reason why the transmit abort takes places. NOTE: The I2C flushes/resets/empties the TX FIFO whenever this bit is set. The TX FIFO remains in this flushed state until the register ic_clr_tx_abrt is read. Once this read is performed, the TX FIFO is then ready to accept more data bytes from the APB interface."]
pub type TxAbrtR = crate::BitReader;
#[doc = "Field `tx_abrt` writer - This bit indicates if I2C, as an I2C transmitter, is unable to complete the intended actions on the contents of the transmit FIFO. This situation can occur both as an I2C master or an I2C slave, and is referred to as a 'transmit abort'. When this bit is set to 1, the IC_TX_ABRT_SOURCE register indicates the reason why the transmit abort takes places. NOTE: The I2C flushes/resets/empties the TX FIFO whenever this bit is set. The TX FIFO remains in this flushed state until the register ic_clr_tx_abrt is read. Once this read is performed, the TX FIFO is then ready to accept more data bytes from the APB interface."]
pub type TxAbrtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rx_done` reader - When the I2C is acting as a slave-transmitter, this bit is set to 1 if the master does not acknowledge a transmitted byte. This occurs on the last byte of the transmission, indicating that the transmission is done."]
pub type RxDoneR = crate::BitReader;
#[doc = "Field `rx_done` writer - When the I2C is acting as a slave-transmitter, this bit is set to 1 if the master does not acknowledge a transmitted byte. This occurs on the last byte of the transmission, indicating that the transmission is done."]
pub type RxDoneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `activity` reader - This bit captures i2c activity and stays set until it is cleared. There are four ways to clear it: - Disabling the I2C - Reading the ic_clr_activity register - Reading the ic_clr_intr register - System reset Once this bit is set, it stays set unless one of the four methods is used to clear it. Even if the i2c module is idle, this bit remains set until cleared, indicating that there was activity on the bus."]
pub type ActivityR = crate::BitReader;
#[doc = "Field `activity` writer - This bit captures i2c activity and stays set until it is cleared. There are four ways to clear it: - Disabling the I2C - Reading the ic_clr_activity register - Reading the ic_clr_intr register - System reset Once this bit is set, it stays set unless one of the four methods is used to clear it. Even if the i2c module is idle, this bit remains set until cleared, indicating that there was activity on the bus."]
pub type ActivityW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `stop_det` reader - Indicates whether a STOP condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
pub type StopDetR = crate::BitReader;
#[doc = "Field `stop_det` writer - Indicates whether a STOP condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
pub type StopDetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `start_det` reader - Indicates whether a START or RESTART condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
pub type StartDetR = crate::BitReader;
#[doc = "Field `start_det` writer - Indicates whether a START or RESTART condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
pub type StartDetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `gen_call` reader - Set only when a General Call address is received and it is acknowledged. It stays set until it is cleared either by disabling I2C or when the CPU reads bit 0 of the ic_clr_gen_call register. I2C stores the received data in the Rx buffer."]
pub type GenCallR = crate::BitReader;
#[doc = "Field `gen_call` writer - Set only when a General Call address is received and it is acknowledged. It stays set until it is cleared either by disabling I2C or when the CPU reads bit 0 of the ic_clr_gen_call register. I2C stores the received data in the Rx buffer."]
pub type GenCallW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Set if the processor attempts to read the receive buffer when it is empty by reading from the ic_data_cmd register. If the module is disabled ic_enable\\[0\\]=0, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
    #[inline(always)]
    pub fn rx_under(&self) -> RxUnderR {
        RxUnderR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Set if the receive buffer is completely filled to 64 and an additional byte is received from an external I2C device. The I2C acknowledges this, but any data bytes received after the FIFO is full are lost. If the module is disabled ic_enable\\[0\\]=0), this bit keeps its level until the master or slave state machines go into then, this interrupt is cleared."]
    #[inline(always)]
    pub fn rx_over(&self) -> RxOverR {
        RxOverR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Set when the receive buffer reaches or goes above the RX_TL threshold in the ic_rx_tl register. It is automatically cleared by hardware when buffer level goes below the threshold. If the module is disabled ic_enable\\[0\\]=0, the RX FIFO is flushed and held in reset; therefore the RX FIFO is not full. So this bit is cleared once the ic_enable bit 0 is programmed with a 0, regardless of the activity that continues."]
    #[inline(always)]
    pub fn rx_full(&self) -> RxFullR {
        RxFullR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Set during transmit if the transmit buffer is filled to 64 and the processor attempts to issue another I2C command by writing to the ic_data_cmd register. When the module is disabled, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
    #[inline(always)]
    pub fn tx_over(&self) -> TxOverR {
        TxOverR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit is set to 1 when the transmit buffer is at or below the threshold value set in the ic_tx_tl register. It is automatically cleared by hardware when the buffer level goes above the threshold. When the IC_ENABLE bit 0 is 0, the TX FIFO is flushed and held in reset. There the TX FIFO looks like it has no data within it, so this bit is set to 1, provided there is activity in the master or slave state machines. When there is no longer activity, then this bit is set to 0."]
    #[inline(always)]
    pub fn tx_empty(&self) -> TxEmptyR {
        TxEmptyR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This bit is set to 1 when I2C is acting as a slave and another I2C master is attempting to read data from I2C. The i2c holds the I2C bus in a wait state (SCL=0) until this interrupt is serviced, which means that the slave has been addressed by a remote master that is asking for data to be transferred. The processor must respond to this interrupt and then write the requested data to the ic_data_cmd register. This bit is set to 0 just after the processor reads the ic_clr_rd_req register."]
    #[inline(always)]
    pub fn rd_req(&self) -> RdReqR {
        RdReqR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit indicates if I2C, as an I2C transmitter, is unable to complete the intended actions on the contents of the transmit FIFO. This situation can occur both as an I2C master or an I2C slave, and is referred to as a 'transmit abort'. When this bit is set to 1, the IC_TX_ABRT_SOURCE register indicates the reason why the transmit abort takes places. NOTE: The I2C flushes/resets/empties the TX FIFO whenever this bit is set. The TX FIFO remains in this flushed state until the register ic_clr_tx_abrt is read. Once this read is performed, the TX FIFO is then ready to accept more data bytes from the APB interface."]
    #[inline(always)]
    pub fn tx_abrt(&self) -> TxAbrtR {
        TxAbrtR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - When the I2C is acting as a slave-transmitter, this bit is set to 1 if the master does not acknowledge a transmitted byte. This occurs on the last byte of the transmission, indicating that the transmission is done."]
    #[inline(always)]
    pub fn rx_done(&self) -> RxDoneR {
        RxDoneR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - This bit captures i2c activity and stays set until it is cleared. There are four ways to clear it: - Disabling the I2C - Reading the ic_clr_activity register - Reading the ic_clr_intr register - System reset Once this bit is set, it stays set unless one of the four methods is used to clear it. Even if the i2c module is idle, this bit remains set until cleared, indicating that there was activity on the bus."]
    #[inline(always)]
    pub fn activity(&self) -> ActivityR {
        ActivityR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Indicates whether a STOP condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
    #[inline(always)]
    pub fn stop_det(&self) -> StopDetR {
        StopDetR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Indicates whether a START or RESTART condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
    #[inline(always)]
    pub fn start_det(&self) -> StartDetR {
        StartDetR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Set only when a General Call address is received and it is acknowledged. It stays set until it is cleared either by disabling I2C or when the CPU reads bit 0 of the ic_clr_gen_call register. I2C stores the received data in the Rx buffer."]
    #[inline(always)]
    pub fn gen_call(&self) -> GenCallR {
        GenCallR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Set if the processor attempts to read the receive buffer when it is empty by reading from the ic_data_cmd register. If the module is disabled ic_enable\\[0\\]=0, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn rx_under(&mut self) -> RxUnderW<IcRawIntrStatSpec> {
        RxUnderW::new(self, 0)
    }
    #[doc = "Bit 1 - Set if the receive buffer is completely filled to 64 and an additional byte is received from an external I2C device. The I2C acknowledges this, but any data bytes received after the FIFO is full are lost. If the module is disabled ic_enable\\[0\\]=0), this bit keeps its level until the master or slave state machines go into then, this interrupt is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn rx_over(&mut self) -> RxOverW<IcRawIntrStatSpec> {
        RxOverW::new(self, 1)
    }
    #[doc = "Bit 2 - Set when the receive buffer reaches or goes above the RX_TL threshold in the ic_rx_tl register. It is automatically cleared by hardware when buffer level goes below the threshold. If the module is disabled ic_enable\\[0\\]=0, the RX FIFO is flushed and held in reset; therefore the RX FIFO is not full. So this bit is cleared once the ic_enable bit 0 is programmed with a 0, regardless of the activity that continues."]
    #[inline(always)]
    #[must_use]
    pub fn rx_full(&mut self) -> RxFullW<IcRawIntrStatSpec> {
        RxFullW::new(self, 2)
    }
    #[doc = "Bit 3 - Set during transmit if the transmit buffer is filled to 64 and the processor attempts to issue another I2C command by writing to the ic_data_cmd register. When the module is disabled, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn tx_over(&mut self) -> TxOverW<IcRawIntrStatSpec> {
        TxOverW::new(self, 3)
    }
    #[doc = "Bit 4 - This bit is set to 1 when the transmit buffer is at or below the threshold value set in the ic_tx_tl register. It is automatically cleared by hardware when the buffer level goes above the threshold. When the IC_ENABLE bit 0 is 0, the TX FIFO is flushed and held in reset. There the TX FIFO looks like it has no data within it, so this bit is set to 1, provided there is activity in the master or slave state machines. When there is no longer activity, then this bit is set to 0."]
    #[inline(always)]
    #[must_use]
    pub fn tx_empty(&mut self) -> TxEmptyW<IcRawIntrStatSpec> {
        TxEmptyW::new(self, 4)
    }
    #[doc = "Bit 5 - This bit is set to 1 when I2C is acting as a slave and another I2C master is attempting to read data from I2C. The i2c holds the I2C bus in a wait state (SCL=0) until this interrupt is serviced, which means that the slave has been addressed by a remote master that is asking for data to be transferred. The processor must respond to this interrupt and then write the requested data to the ic_data_cmd register. This bit is set to 0 just after the processor reads the ic_clr_rd_req register."]
    #[inline(always)]
    #[must_use]
    pub fn rd_req(&mut self) -> RdReqW<IcRawIntrStatSpec> {
        RdReqW::new(self, 5)
    }
    #[doc = "Bit 6 - This bit indicates if I2C, as an I2C transmitter, is unable to complete the intended actions on the contents of the transmit FIFO. This situation can occur both as an I2C master or an I2C slave, and is referred to as a 'transmit abort'. When this bit is set to 1, the IC_TX_ABRT_SOURCE register indicates the reason why the transmit abort takes places. NOTE: The I2C flushes/resets/empties the TX FIFO whenever this bit is set. The TX FIFO remains in this flushed state until the register ic_clr_tx_abrt is read. Once this read is performed, the TX FIFO is then ready to accept more data bytes from the APB interface."]
    #[inline(always)]
    #[must_use]
    pub fn tx_abrt(&mut self) -> TxAbrtW<IcRawIntrStatSpec> {
        TxAbrtW::new(self, 6)
    }
    #[doc = "Bit 7 - When the I2C is acting as a slave-transmitter, this bit is set to 1 if the master does not acknowledge a transmitted byte. This occurs on the last byte of the transmission, indicating that the transmission is done."]
    #[inline(always)]
    #[must_use]
    pub fn rx_done(&mut self) -> RxDoneW<IcRawIntrStatSpec> {
        RxDoneW::new(self, 7)
    }
    #[doc = "Bit 8 - This bit captures i2c activity and stays set until it is cleared. There are four ways to clear it: - Disabling the I2C - Reading the ic_clr_activity register - Reading the ic_clr_intr register - System reset Once this bit is set, it stays set unless one of the four methods is used to clear it. Even if the i2c module is idle, this bit remains set until cleared, indicating that there was activity on the bus."]
    #[inline(always)]
    #[must_use]
    pub fn activity(&mut self) -> ActivityW<IcRawIntrStatSpec> {
        ActivityW::new(self, 8)
    }
    #[doc = "Bit 9 - Indicates whether a STOP condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
    #[inline(always)]
    #[must_use]
    pub fn stop_det(&mut self) -> StopDetW<IcRawIntrStatSpec> {
        StopDetW::new(self, 9)
    }
    #[doc = "Bit 10 - Indicates whether a START or RESTART condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
    #[inline(always)]
    #[must_use]
    pub fn start_det(&mut self) -> StartDetW<IcRawIntrStatSpec> {
        StartDetW::new(self, 10)
    }
    #[doc = "Bit 11 - Set only when a General Call address is received and it is acknowledged. It stays set until it is cleared either by disabling I2C or when the CPU reads bit 0 of the ic_clr_gen_call register. I2C stores the received data in the Rx buffer."]
    #[inline(always)]
    #[must_use]
    pub fn gen_call(&mut self) -> GenCallW<IcRawIntrStatSpec> {
        GenCallW::new(self, 11)
    }
}
#[doc = "Unlike the ic_intr_stat register, these bits are not masked so they always show the true status of the I2C.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_raw_intr_stat::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcRawIntrStatSpec;
impl crate::RegisterSpec for IcRawIntrStatSpec {
    type Ux = u32;
    const OFFSET: u64 = 52u64;
}
#[doc = "`read()` method returns [`ic_raw_intr_stat::R`](R) reader structure"]
impl crate::Readable for IcRawIntrStatSpec {}
#[doc = "`reset()` method sets ic_raw_intr_stat to value 0"]
impl crate::Resettable for IcRawIntrStatSpec {
    const RESET_VALUE: u32 = 0;
}
