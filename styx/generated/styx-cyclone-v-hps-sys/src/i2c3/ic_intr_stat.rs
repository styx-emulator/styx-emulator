// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_intr_stat` reader"]
pub type R = crate::R<IcIntrStatSpec>;
#[doc = "Register `ic_intr_stat` writer"]
pub type W = crate::W<IcIntrStatSpec>;
#[doc = "Field `r_rx_under` reader - Set if the processor attempts to read the receive buffer when it is empty by reading from the Tx Rx Data and Command Register. If the module is disabled, Enable Register is set to 0, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
pub type RRxUnderR = crate::BitReader;
#[doc = "Field `r_rx_under` writer - Set if the processor attempts to read the receive buffer when it is empty by reading from the Tx Rx Data and Command Register. If the module is disabled, Enable Register is set to 0, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
pub type RRxUnderW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `r_rx_over` reader - Set if the receive buffer is completely filled to 64 and an additional byte is received from an external I2C device. The I2C acknowledges this, but any data bytes received after the FIFO is full are lost. If the module is disabled, Enable Register bit\\[0\\]
is set to 0 this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
pub type RRxOverR = crate::BitReader;
#[doc = "Field `r_rx_over` writer - Set if the receive buffer is completely filled to 64 and an additional byte is received from an external I2C device. The I2C acknowledges this, but any data bytes received after the FIFO is full are lost. If the module is disabled, Enable Register bit\\[0\\]
is set to 0 this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
pub type RRxOverW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `r_rx_full` reader - Set when the receive buffer reaches or goes above the Receive FIFO Threshold Value(rx_tl). It is automatically cleared by hardware when buffer level goes below the threshold. If the module is disabled, Bit \\[0\\]
of the Enable Register set to 0, the RX FIFO is flushed and held in reset; therefore the RX FIFO is not full. So this bit is cleared once the Enable Register Bit 0 is programmed with a 0, regardless of the activity that continues."]
pub type RRxFullR = crate::BitReader;
#[doc = "Field `r_rx_full` writer - Set when the receive buffer reaches or goes above the Receive FIFO Threshold Value(rx_tl). It is automatically cleared by hardware when buffer level goes below the threshold. If the module is disabled, Bit \\[0\\]
of the Enable Register set to 0, the RX FIFO is flushed and held in reset; therefore the RX FIFO is not full. So this bit is cleared once the Enable Register Bit 0 is programmed with a 0, regardless of the activity that continues."]
pub type RRxFullW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `r_tx_over` reader - Set during transmit if the transmit buffer is filled to 64 and the processor attempts to issue another I2C command by writing to the Data and Command Register. When the module is disabled, this bit keeps its level until the master or slave state machines goes into idle, then interrupt is cleared."]
pub type RTxOverR = crate::BitReader;
#[doc = "Field `r_tx_over` writer - Set during transmit if the transmit buffer is filled to 64 and the processor attempts to issue another I2C command by writing to the Data and Command Register. When the module is disabled, this bit keeps its level until the master or slave state machines goes into idle, then interrupt is cleared."]
pub type RTxOverW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `r_tx_empty` reader - This bit is set to 1 when the transmit buffer is at or below the threshold value set in the ic_tx_tl register. It is automatically cleared by hardware when the buffer level goes above the threshold. When the ic_enable bit 0 is 0, the TX FIFO is flushed and held in reset. There the TX FIFO looks like it has no data within it, so this bit is set to 1, provided there is activity in the master or slave state machines. When there is no longer activity, this bit is set to 0."]
pub type RTxEmptyR = crate::BitReader;
#[doc = "Field `r_tx_empty` writer - This bit is set to 1 when the transmit buffer is at or below the threshold value set in the ic_tx_tl register. It is automatically cleared by hardware when the buffer level goes above the threshold. When the ic_enable bit 0 is 0, the TX FIFO is flushed and held in reset. There the TX FIFO looks like it has no data within it, so this bit is set to 1, provided there is activity in the master or slave state machines. When there is no longer activity, this bit is set to 0."]
pub type RTxEmptyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `r_rd_req` reader - This bit is set to 1 when i2c is acting as a slave and another I2C master is attempting to read data from I2C. The I2C holds the I2C bus in a wait state (SCL=0) until this interrupt is serviced, which means that the slave has been addressed by a remote master that is asking for data to be transferred. The processor must respond to this interrupt and then write the requested data to the IC_DATA_CMD register. This bit is set to 0 just after the processor reads the ic_clr_rd_req register."]
pub type RRdReqR = crate::BitReader;
#[doc = "Field `r_rd_req` writer - This bit is set to 1 when i2c is acting as a slave and another I2C master is attempting to read data from I2C. The I2C holds the I2C bus in a wait state (SCL=0) until this interrupt is serviced, which means that the slave has been addressed by a remote master that is asking for data to be transferred. The processor must respond to this interrupt and then write the requested data to the IC_DATA_CMD register. This bit is set to 0 just after the processor reads the ic_clr_rd_req register."]
pub type RRdReqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `r_tx_abrt` reader - This bit indicates if I2C, as an I2C transmitter, is unable to complete the intended actions on the contents of the transmit FIFO. This situation can occur both as an I2C master or an I2C slave, and is referred to as a 'transmit abort'.When this bit is set to 1, the ic_tx_abrt_source register indicates the reason why the transmit abort takes places. NOTE: The I2C flushes/resets/empties the TX FIFO whenever this bit is set. The TX FIFO remains in this flushed state until the register ic_clr_tx_abrt is read. Once this read is performed, the TX FIFO is then ready to accept more data bytes from the APB interface."]
pub type RTxAbrtR = crate::BitReader;
#[doc = "Field `r_tx_abrt` writer - This bit indicates if I2C, as an I2C transmitter, is unable to complete the intended actions on the contents of the transmit FIFO. This situation can occur both as an I2C master or an I2C slave, and is referred to as a 'transmit abort'.When this bit is set to 1, the ic_tx_abrt_source register indicates the reason why the transmit abort takes places. NOTE: The I2C flushes/resets/empties the TX FIFO whenever this bit is set. The TX FIFO remains in this flushed state until the register ic_clr_tx_abrt is read. Once this read is performed, the TX FIFO is then ready to accept more data bytes from the APB interface."]
pub type RTxAbrtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `r_rx_done` reader - When the I2C is acting as a slave-transmitter, this bit is set to 1, if the master does not acknowledge a transmitted byte. This occurs on the last byte of the transmission, indicating that the transmission is done."]
pub type RRxDoneR = crate::BitReader;
#[doc = "Field `r_rx_done` writer - When the I2C is acting as a slave-transmitter, this bit is set to 1, if the master does not acknowledge a transmitted byte. This occurs on the last byte of the transmission, indicating that the transmission is done."]
pub type RRxDoneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `r_activity` reader - This bit captures I2C activity and stays set until it is cleared. There are four ways to clear it: - Disabling the I2C - Reading the ic_clr_activity register - Reading the ic_clr_intr register - I2C reset Once this bit is set, it stays set unless one of the four methods is used to clear it. Even if the I2C module is idle, this bit remains set until cleared, indicating that there was activity on the bus."]
pub type RActivityR = crate::BitReader;
#[doc = "Field `r_activity` writer - This bit captures I2C activity and stays set until it is cleared. There are four ways to clear it: - Disabling the I2C - Reading the ic_clr_activity register - Reading the ic_clr_intr register - I2C reset Once this bit is set, it stays set unless one of the four methods is used to clear it. Even if the I2C module is idle, this bit remains set until cleared, indicating that there was activity on the bus."]
pub type RActivityW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `r_stop_det` reader - Indicates whether a STOP condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
pub type RStopDetR = crate::BitReader;
#[doc = "Field `r_stop_det` writer - Indicates whether a STOP condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
pub type RStopDetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `r_start_det` reader - Indicates whether a START or RESTART condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
pub type RStartDetR = crate::BitReader;
#[doc = "Field `r_start_det` writer - Indicates whether a START or RESTART condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
pub type RStartDetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `r_gen_call` reader - Set only when a General Call address is received and it is acknowledged. It stays set until it is cleared either by disabling I2C or when the CPU reads bit 0 of the ic_clr_gen_call register. I2C stores the received data in the Rx buffer."]
pub type RGenCallR = crate::BitReader;
#[doc = "Field `r_gen_call` writer - Set only when a General Call address is received and it is acknowledged. It stays set until it is cleared either by disabling I2C or when the CPU reads bit 0 of the ic_clr_gen_call register. I2C stores the received data in the Rx buffer."]
pub type RGenCallW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Set if the processor attempts to read the receive buffer when it is empty by reading from the Tx Rx Data and Command Register. If the module is disabled, Enable Register is set to 0, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
    #[inline(always)]
    pub fn r_rx_under(&self) -> RRxUnderR {
        RRxUnderR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Set if the receive buffer is completely filled to 64 and an additional byte is received from an external I2C device. The I2C acknowledges this, but any data bytes received after the FIFO is full are lost. If the module is disabled, Enable Register bit\\[0\\]
is set to 0 this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
    #[inline(always)]
    pub fn r_rx_over(&self) -> RRxOverR {
        RRxOverR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Set when the receive buffer reaches or goes above the Receive FIFO Threshold Value(rx_tl). It is automatically cleared by hardware when buffer level goes below the threshold. If the module is disabled, Bit \\[0\\]
of the Enable Register set to 0, the RX FIFO is flushed and held in reset; therefore the RX FIFO is not full. So this bit is cleared once the Enable Register Bit 0 is programmed with a 0, regardless of the activity that continues."]
    #[inline(always)]
    pub fn r_rx_full(&self) -> RRxFullR {
        RRxFullR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Set during transmit if the transmit buffer is filled to 64 and the processor attempts to issue another I2C command by writing to the Data and Command Register. When the module is disabled, this bit keeps its level until the master or slave state machines goes into idle, then interrupt is cleared."]
    #[inline(always)]
    pub fn r_tx_over(&self) -> RTxOverR {
        RTxOverR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit is set to 1 when the transmit buffer is at or below the threshold value set in the ic_tx_tl register. It is automatically cleared by hardware when the buffer level goes above the threshold. When the ic_enable bit 0 is 0, the TX FIFO is flushed and held in reset. There the TX FIFO looks like it has no data within it, so this bit is set to 1, provided there is activity in the master or slave state machines. When there is no longer activity, this bit is set to 0."]
    #[inline(always)]
    pub fn r_tx_empty(&self) -> RTxEmptyR {
        RTxEmptyR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This bit is set to 1 when i2c is acting as a slave and another I2C master is attempting to read data from I2C. The I2C holds the I2C bus in a wait state (SCL=0) until this interrupt is serviced, which means that the slave has been addressed by a remote master that is asking for data to be transferred. The processor must respond to this interrupt and then write the requested data to the IC_DATA_CMD register. This bit is set to 0 just after the processor reads the ic_clr_rd_req register."]
    #[inline(always)]
    pub fn r_rd_req(&self) -> RRdReqR {
        RRdReqR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit indicates if I2C, as an I2C transmitter, is unable to complete the intended actions on the contents of the transmit FIFO. This situation can occur both as an I2C master or an I2C slave, and is referred to as a 'transmit abort'.When this bit is set to 1, the ic_tx_abrt_source register indicates the reason why the transmit abort takes places. NOTE: The I2C flushes/resets/empties the TX FIFO whenever this bit is set. The TX FIFO remains in this flushed state until the register ic_clr_tx_abrt is read. Once this read is performed, the TX FIFO is then ready to accept more data bytes from the APB interface."]
    #[inline(always)]
    pub fn r_tx_abrt(&self) -> RTxAbrtR {
        RTxAbrtR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - When the I2C is acting as a slave-transmitter, this bit is set to 1, if the master does not acknowledge a transmitted byte. This occurs on the last byte of the transmission, indicating that the transmission is done."]
    #[inline(always)]
    pub fn r_rx_done(&self) -> RRxDoneR {
        RRxDoneR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - This bit captures I2C activity and stays set until it is cleared. There are four ways to clear it: - Disabling the I2C - Reading the ic_clr_activity register - Reading the ic_clr_intr register - I2C reset Once this bit is set, it stays set unless one of the four methods is used to clear it. Even if the I2C module is idle, this bit remains set until cleared, indicating that there was activity on the bus."]
    #[inline(always)]
    pub fn r_activity(&self) -> RActivityR {
        RActivityR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Indicates whether a STOP condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
    #[inline(always)]
    pub fn r_stop_det(&self) -> RStopDetR {
        RStopDetR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Indicates whether a START or RESTART condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
    #[inline(always)]
    pub fn r_start_det(&self) -> RStartDetR {
        RStartDetR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Set only when a General Call address is received and it is acknowledged. It stays set until it is cleared either by disabling I2C or when the CPU reads bit 0 of the ic_clr_gen_call register. I2C stores the received data in the Rx buffer."]
    #[inline(always)]
    pub fn r_gen_call(&self) -> RGenCallR {
        RGenCallR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Set if the processor attempts to read the receive buffer when it is empty by reading from the Tx Rx Data and Command Register. If the module is disabled, Enable Register is set to 0, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn r_rx_under(&mut self) -> RRxUnderW<IcIntrStatSpec> {
        RRxUnderW::new(self, 0)
    }
    #[doc = "Bit 1 - Set if the receive buffer is completely filled to 64 and an additional byte is received from an external I2C device. The I2C acknowledges this, but any data bytes received after the FIFO is full are lost. If the module is disabled, Enable Register bit\\[0\\]
is set to 0 this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn r_rx_over(&mut self) -> RRxOverW<IcIntrStatSpec> {
        RRxOverW::new(self, 1)
    }
    #[doc = "Bit 2 - Set when the receive buffer reaches or goes above the Receive FIFO Threshold Value(rx_tl). It is automatically cleared by hardware when buffer level goes below the threshold. If the module is disabled, Bit \\[0\\]
of the Enable Register set to 0, the RX FIFO is flushed and held in reset; therefore the RX FIFO is not full. So this bit is cleared once the Enable Register Bit 0 is programmed with a 0, regardless of the activity that continues."]
    #[inline(always)]
    #[must_use]
    pub fn r_rx_full(&mut self) -> RRxFullW<IcIntrStatSpec> {
        RRxFullW::new(self, 2)
    }
    #[doc = "Bit 3 - Set during transmit if the transmit buffer is filled to 64 and the processor attempts to issue another I2C command by writing to the Data and Command Register. When the module is disabled, this bit keeps its level until the master or slave state machines goes into idle, then interrupt is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn r_tx_over(&mut self) -> RTxOverW<IcIntrStatSpec> {
        RTxOverW::new(self, 3)
    }
    #[doc = "Bit 4 - This bit is set to 1 when the transmit buffer is at or below the threshold value set in the ic_tx_tl register. It is automatically cleared by hardware when the buffer level goes above the threshold. When the ic_enable bit 0 is 0, the TX FIFO is flushed and held in reset. There the TX FIFO looks like it has no data within it, so this bit is set to 1, provided there is activity in the master or slave state machines. When there is no longer activity, this bit is set to 0."]
    #[inline(always)]
    #[must_use]
    pub fn r_tx_empty(&mut self) -> RTxEmptyW<IcIntrStatSpec> {
        RTxEmptyW::new(self, 4)
    }
    #[doc = "Bit 5 - This bit is set to 1 when i2c is acting as a slave and another I2C master is attempting to read data from I2C. The I2C holds the I2C bus in a wait state (SCL=0) until this interrupt is serviced, which means that the slave has been addressed by a remote master that is asking for data to be transferred. The processor must respond to this interrupt and then write the requested data to the IC_DATA_CMD register. This bit is set to 0 just after the processor reads the ic_clr_rd_req register."]
    #[inline(always)]
    #[must_use]
    pub fn r_rd_req(&mut self) -> RRdReqW<IcIntrStatSpec> {
        RRdReqW::new(self, 5)
    }
    #[doc = "Bit 6 - This bit indicates if I2C, as an I2C transmitter, is unable to complete the intended actions on the contents of the transmit FIFO. This situation can occur both as an I2C master or an I2C slave, and is referred to as a 'transmit abort'.When this bit is set to 1, the ic_tx_abrt_source register indicates the reason why the transmit abort takes places. NOTE: The I2C flushes/resets/empties the TX FIFO whenever this bit is set. The TX FIFO remains in this flushed state until the register ic_clr_tx_abrt is read. Once this read is performed, the TX FIFO is then ready to accept more data bytes from the APB interface."]
    #[inline(always)]
    #[must_use]
    pub fn r_tx_abrt(&mut self) -> RTxAbrtW<IcIntrStatSpec> {
        RTxAbrtW::new(self, 6)
    }
    #[doc = "Bit 7 - When the I2C is acting as a slave-transmitter, this bit is set to 1, if the master does not acknowledge a transmitted byte. This occurs on the last byte of the transmission, indicating that the transmission is done."]
    #[inline(always)]
    #[must_use]
    pub fn r_rx_done(&mut self) -> RRxDoneW<IcIntrStatSpec> {
        RRxDoneW::new(self, 7)
    }
    #[doc = "Bit 8 - This bit captures I2C activity and stays set until it is cleared. There are four ways to clear it: - Disabling the I2C - Reading the ic_clr_activity register - Reading the ic_clr_intr register - I2C reset Once this bit is set, it stays set unless one of the four methods is used to clear it. Even if the I2C module is idle, this bit remains set until cleared, indicating that there was activity on the bus."]
    #[inline(always)]
    #[must_use]
    pub fn r_activity(&mut self) -> RActivityW<IcIntrStatSpec> {
        RActivityW::new(self, 8)
    }
    #[doc = "Bit 9 - Indicates whether a STOP condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
    #[inline(always)]
    #[must_use]
    pub fn r_stop_det(&mut self) -> RStopDetW<IcIntrStatSpec> {
        RStopDetW::new(self, 9)
    }
    #[doc = "Bit 10 - Indicates whether a START or RESTART condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
    #[inline(always)]
    #[must_use]
    pub fn r_start_det(&mut self) -> RStartDetW<IcIntrStatSpec> {
        RStartDetW::new(self, 10)
    }
    #[doc = "Bit 11 - Set only when a General Call address is received and it is acknowledged. It stays set until it is cleared either by disabling I2C or when the CPU reads bit 0 of the ic_clr_gen_call register. I2C stores the received data in the Rx buffer."]
    #[inline(always)]
    #[must_use]
    pub fn r_gen_call(&mut self) -> RGenCallW<IcIntrStatSpec> {
        RGenCallW::new(self, 11)
    }
}
#[doc = "Each bit in this register has a corresponding mask bit in the Interrupt Mask Register. These bits are cleared by reading the matching Interrupt Clear Register. The unmasked raw versions of these bits are available in the Raw Interrupt Status Register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_intr_stat::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcIntrStatSpec;
impl crate::RegisterSpec for IcIntrStatSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`ic_intr_stat::R`](R) reader structure"]
impl crate::Readable for IcIntrStatSpec {}
#[doc = "`reset()` method sets ic_intr_stat to value 0"]
impl crate::Resettable for IcIntrStatSpec {
    const RESET_VALUE: u32 = 0;
}
