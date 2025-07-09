// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_intr_mask` reader"]
pub type R = crate::R<IcIntrMaskSpec>;
#[doc = "Register `ic_intr_mask` writer"]
pub type W = crate::W<IcIntrMaskSpec>;
#[doc = "Field `m_rx_under` reader - Set if the processor attempts to read the receive buffer when it is empty by reading from the ic_data_cmd register. If the module is disabled ic_enable\\[0\\]=0, this bit keeps its level until the master or slave state machines go into idle, and then this interrupt is cleared."]
pub type MRxUnderR = crate::BitReader;
#[doc = "Field `m_rx_under` writer - Set if the processor attempts to read the receive buffer when it is empty by reading from the ic_data_cmd register. If the module is disabled ic_enable\\[0\\]=0, this bit keeps its level until the master or slave state machines go into idle, and then this interrupt is cleared."]
pub type MRxUnderW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `m_rx_over` reader - Set if the receive buffer is completely filled to 64 and an additional byte is received from an external I2C device. The I2C acknowledges this, but any data bytes received after the FIFO is full are lost. If the module is disabled ic_enable\\[0\\]=0, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
pub type MRxOverR = crate::BitReader;
#[doc = "Field `m_rx_over` writer - Set if the receive buffer is completely filled to 64 and an additional byte is received from an external I2C device. The I2C acknowledges this, but any data bytes received after the FIFO is full are lost. If the module is disabled ic_enable\\[0\\]=0, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
pub type MRxOverW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `m_rx_full` reader - Set when the receive buffer reaches or goes above the RX_TL threshold in the ic_rx_tl register. It is automatically cleared by hardware when buffer level goes below the threshold. If the module is disabled ic_enable\\[0\\]=0, the RX FIFO is flushed and held in reset; therefore the RX FIFO is not full. So this bit is cleared once the ic_enable bit 0 is programmed with a 0, regardless of the activity that continues."]
pub type MRxFullR = crate::BitReader;
#[doc = "Field `m_rx_full` writer - Set when the receive buffer reaches or goes above the RX_TL threshold in the ic_rx_tl register. It is automatically cleared by hardware when buffer level goes below the threshold. If the module is disabled ic_enable\\[0\\]=0, the RX FIFO is flushed and held in reset; therefore the RX FIFO is not full. So this bit is cleared once the ic_enable bit 0 is programmed with a 0, regardless of the activity that continues."]
pub type MRxFullW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `m_tx_over` reader - Set during transmit if the transmit buffer is filled to 64 and the processor attempts to issue another I2C command by writing to the ic_data_cmd register. When the module is disabled, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
pub type MTxOverR = crate::BitReader;
#[doc = "Field `m_tx_over` writer - Set during transmit if the transmit buffer is filled to 64 and the processor attempts to issue another I2C command by writing to the ic_data_cmd register. When the module is disabled, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
pub type MTxOverW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `m_tx_empty` reader - This bit is set to 1 when the transmit buffer is at or below the threshold value set in the ic_tx_tl register. It is automatically cleared by hardware when the buffer level goes above the threshold. When the ic_enable bit 0 is 0, the TX FIFO is flushed and held in reset. There the TX FIFO looks like it has no data within it, so this bit is set to 1, provided there is activity in the master or slave state machines. When there is no longer activity, then this bit is set to 0."]
pub type MTxEmptyR = crate::BitReader;
#[doc = "Field `m_tx_empty` writer - This bit is set to 1 when the transmit buffer is at or below the threshold value set in the ic_tx_tl register. It is automatically cleared by hardware when the buffer level goes above the threshold. When the ic_enable bit 0 is 0, the TX FIFO is flushed and held in reset. There the TX FIFO looks like it has no data within it, so this bit is set to 1, provided there is activity in the master or slave state machines. When there is no longer activity, then this bit is set to 0."]
pub type MTxEmptyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `m_rd_req` reader - This bit is set to 1 when I2C is acting as a slave and another I2C master is attempting to read data from I2C. The I2C holds the I2C bus in a wait state (SCL=0) until this interrupt is serviced, which means that the slave has been addressed by a remote master that is asking for data to be transferred. The processor must respond to this interrupt and then write the requested data to the ic_data_cmd register. This bit is set to 0 just after the processor reads the ic_clr_rd_req register."]
pub type MRdReqR = crate::BitReader;
#[doc = "Field `m_rd_req` writer - This bit is set to 1 when I2C is acting as a slave and another I2C master is attempting to read data from I2C. The I2C holds the I2C bus in a wait state (SCL=0) until this interrupt is serviced, which means that the slave has been addressed by a remote master that is asking for data to be transferred. The processor must respond to this interrupt and then write the requested data to the ic_data_cmd register. This bit is set to 0 just after the processor reads the ic_clr_rd_req register."]
pub type MRdReqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `m_tx_abrt` reader - This bit indicates if I2C, as an I2C transmitter, is unable to complete the intended actions on the contents of the transmit FIFO. This situation can occur both as an I2C master or an I2C slave, and is referred to as a 'transmit abort'. When this bit is set to 1, the ic_tx_abrt_source register indicates the reason why the transmit abort takes places. NOTE: The I2C flushes/resets/empties the TX FIFO whenever this bit is set. The TX FIFO remains in this flushed state until the register ic_clr_tx_abrt is read. Once this read is performed, the TX FIFO is then ready to accept more data bytes from the APB interface."]
pub type MTxAbrtR = crate::BitReader;
#[doc = "Field `m_tx_abrt` writer - This bit indicates if I2C, as an I2C transmitter, is unable to complete the intended actions on the contents of the transmit FIFO. This situation can occur both as an I2C master or an I2C slave, and is referred to as a 'transmit abort'. When this bit is set to 1, the ic_tx_abrt_source register indicates the reason why the transmit abort takes places. NOTE: The I2C flushes/resets/empties the TX FIFO whenever this bit is set. The TX FIFO remains in this flushed state until the register ic_clr_tx_abrt is read. Once this read is performed, the TX FIFO is then ready to accept more data bytes from the APB interface."]
pub type MTxAbrtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `m_rx_done` reader - When the I2C is acting as a slave-transmitter, this bit is set to 1, if the master does not acknowledge a transmitted byte. This occurs on the last byte of the transmission, indicating that the transmission is done."]
pub type MRxDoneR = crate::BitReader;
#[doc = "Field `m_rx_done` writer - When the I2C is acting as a slave-transmitter, this bit is set to 1, if the master does not acknowledge a transmitted byte. This occurs on the last byte of the transmission, indicating that the transmission is done."]
pub type MRxDoneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `m_activity` reader - This bit captures i2c activity and stays set until it is cleared. There are four ways to clear it: - Disabling the i2c - Reading the ic_clr_activity register - Reading the ic_clr_intr register - System reset Once this bit is set, it stays set unless one of the four methods is used to clear it. Even if the I2C module is idle, this bit remains set until cleared, indicating that there was activity on the bus."]
pub type MActivityR = crate::BitReader;
#[doc = "Field `m_activity` writer - This bit captures i2c activity and stays set until it is cleared. There are four ways to clear it: - Disabling the i2c - Reading the ic_clr_activity register - Reading the ic_clr_intr register - System reset Once this bit is set, it stays set unless one of the four methods is used to clear it. Even if the I2C module is idle, this bit remains set until cleared, indicating that there was activity on the bus."]
pub type MActivityW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `m_stop_det` reader - Indicates whether a STOP condition has occurred on the I2C interface regardless of whether i2c is operating in slave or master mode."]
pub type MStopDetR = crate::BitReader;
#[doc = "Field `m_stop_det` writer - Indicates whether a STOP condition has occurred on the I2C interface regardless of whether i2c is operating in slave or master mode."]
pub type MStopDetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `m_start_det` reader - Indicates whether a START or RESTART condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
pub type MStartDetR = crate::BitReader;
#[doc = "Field `m_start_det` writer - Indicates whether a START or RESTART condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
pub type MStartDetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `m_gen_call` reader - Set only when a General Call address is received and it is acknowledged. It stays set until it is cleared either by disabling I2C or when the CPU reads bit 0 of the ic_clr_gen_call register. I2C stores the received data in the Rx buffer."]
pub type MGenCallR = crate::BitReader;
#[doc = "Field `m_gen_call` writer - Set only when a General Call address is received and it is acknowledged. It stays set until it is cleared either by disabling I2C or when the CPU reads bit 0 of the ic_clr_gen_call register. I2C stores the received data in the Rx buffer."]
pub type MGenCallW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Set if the processor attempts to read the receive buffer when it is empty by reading from the ic_data_cmd register. If the module is disabled ic_enable\\[0\\]=0, this bit keeps its level until the master or slave state machines go into idle, and then this interrupt is cleared."]
    #[inline(always)]
    pub fn m_rx_under(&self) -> MRxUnderR {
        MRxUnderR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Set if the receive buffer is completely filled to 64 and an additional byte is received from an external I2C device. The I2C acknowledges this, but any data bytes received after the FIFO is full are lost. If the module is disabled ic_enable\\[0\\]=0, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
    #[inline(always)]
    pub fn m_rx_over(&self) -> MRxOverR {
        MRxOverR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Set when the receive buffer reaches or goes above the RX_TL threshold in the ic_rx_tl register. It is automatically cleared by hardware when buffer level goes below the threshold. If the module is disabled ic_enable\\[0\\]=0, the RX FIFO is flushed and held in reset; therefore the RX FIFO is not full. So this bit is cleared once the ic_enable bit 0 is programmed with a 0, regardless of the activity that continues."]
    #[inline(always)]
    pub fn m_rx_full(&self) -> MRxFullR {
        MRxFullR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Set during transmit if the transmit buffer is filled to 64 and the processor attempts to issue another I2C command by writing to the ic_data_cmd register. When the module is disabled, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
    #[inline(always)]
    pub fn m_tx_over(&self) -> MTxOverR {
        MTxOverR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit is set to 1 when the transmit buffer is at or below the threshold value set in the ic_tx_tl register. It is automatically cleared by hardware when the buffer level goes above the threshold. When the ic_enable bit 0 is 0, the TX FIFO is flushed and held in reset. There the TX FIFO looks like it has no data within it, so this bit is set to 1, provided there is activity in the master or slave state machines. When there is no longer activity, then this bit is set to 0."]
    #[inline(always)]
    pub fn m_tx_empty(&self) -> MTxEmptyR {
        MTxEmptyR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This bit is set to 1 when I2C is acting as a slave and another I2C master is attempting to read data from I2C. The I2C holds the I2C bus in a wait state (SCL=0) until this interrupt is serviced, which means that the slave has been addressed by a remote master that is asking for data to be transferred. The processor must respond to this interrupt and then write the requested data to the ic_data_cmd register. This bit is set to 0 just after the processor reads the ic_clr_rd_req register."]
    #[inline(always)]
    pub fn m_rd_req(&self) -> MRdReqR {
        MRdReqR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit indicates if I2C, as an I2C transmitter, is unable to complete the intended actions on the contents of the transmit FIFO. This situation can occur both as an I2C master or an I2C slave, and is referred to as a 'transmit abort'. When this bit is set to 1, the ic_tx_abrt_source register indicates the reason why the transmit abort takes places. NOTE: The I2C flushes/resets/empties the TX FIFO whenever this bit is set. The TX FIFO remains in this flushed state until the register ic_clr_tx_abrt is read. Once this read is performed, the TX FIFO is then ready to accept more data bytes from the APB interface."]
    #[inline(always)]
    pub fn m_tx_abrt(&self) -> MTxAbrtR {
        MTxAbrtR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - When the I2C is acting as a slave-transmitter, this bit is set to 1, if the master does not acknowledge a transmitted byte. This occurs on the last byte of the transmission, indicating that the transmission is done."]
    #[inline(always)]
    pub fn m_rx_done(&self) -> MRxDoneR {
        MRxDoneR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - This bit captures i2c activity and stays set until it is cleared. There are four ways to clear it: - Disabling the i2c - Reading the ic_clr_activity register - Reading the ic_clr_intr register - System reset Once this bit is set, it stays set unless one of the four methods is used to clear it. Even if the I2C module is idle, this bit remains set until cleared, indicating that there was activity on the bus."]
    #[inline(always)]
    pub fn m_activity(&self) -> MActivityR {
        MActivityR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Indicates whether a STOP condition has occurred on the I2C interface regardless of whether i2c is operating in slave or master mode."]
    #[inline(always)]
    pub fn m_stop_det(&self) -> MStopDetR {
        MStopDetR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Indicates whether a START or RESTART condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
    #[inline(always)]
    pub fn m_start_det(&self) -> MStartDetR {
        MStartDetR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Set only when a General Call address is received and it is acknowledged. It stays set until it is cleared either by disabling I2C or when the CPU reads bit 0 of the ic_clr_gen_call register. I2C stores the received data in the Rx buffer."]
    #[inline(always)]
    pub fn m_gen_call(&self) -> MGenCallR {
        MGenCallR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Set if the processor attempts to read the receive buffer when it is empty by reading from the ic_data_cmd register. If the module is disabled ic_enable\\[0\\]=0, this bit keeps its level until the master or slave state machines go into idle, and then this interrupt is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn m_rx_under(&mut self) -> MRxUnderW<IcIntrMaskSpec> {
        MRxUnderW::new(self, 0)
    }
    #[doc = "Bit 1 - Set if the receive buffer is completely filled to 64 and an additional byte is received from an external I2C device. The I2C acknowledges this, but any data bytes received after the FIFO is full are lost. If the module is disabled ic_enable\\[0\\]=0, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn m_rx_over(&mut self) -> MRxOverW<IcIntrMaskSpec> {
        MRxOverW::new(self, 1)
    }
    #[doc = "Bit 2 - Set when the receive buffer reaches or goes above the RX_TL threshold in the ic_rx_tl register. It is automatically cleared by hardware when buffer level goes below the threshold. If the module is disabled ic_enable\\[0\\]=0, the RX FIFO is flushed and held in reset; therefore the RX FIFO is not full. So this bit is cleared once the ic_enable bit 0 is programmed with a 0, regardless of the activity that continues."]
    #[inline(always)]
    #[must_use]
    pub fn m_rx_full(&mut self) -> MRxFullW<IcIntrMaskSpec> {
        MRxFullW::new(self, 2)
    }
    #[doc = "Bit 3 - Set during transmit if the transmit buffer is filled to 64 and the processor attempts to issue another I2C command by writing to the ic_data_cmd register. When the module is disabled, this bit keeps its level until the master or slave state machines go into idle, then this interrupt is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn m_tx_over(&mut self) -> MTxOverW<IcIntrMaskSpec> {
        MTxOverW::new(self, 3)
    }
    #[doc = "Bit 4 - This bit is set to 1 when the transmit buffer is at or below the threshold value set in the ic_tx_tl register. It is automatically cleared by hardware when the buffer level goes above the threshold. When the ic_enable bit 0 is 0, the TX FIFO is flushed and held in reset. There the TX FIFO looks like it has no data within it, so this bit is set to 1, provided there is activity in the master or slave state machines. When there is no longer activity, then this bit is set to 0."]
    #[inline(always)]
    #[must_use]
    pub fn m_tx_empty(&mut self) -> MTxEmptyW<IcIntrMaskSpec> {
        MTxEmptyW::new(self, 4)
    }
    #[doc = "Bit 5 - This bit is set to 1 when I2C is acting as a slave and another I2C master is attempting to read data from I2C. The I2C holds the I2C bus in a wait state (SCL=0) until this interrupt is serviced, which means that the slave has been addressed by a remote master that is asking for data to be transferred. The processor must respond to this interrupt and then write the requested data to the ic_data_cmd register. This bit is set to 0 just after the processor reads the ic_clr_rd_req register."]
    #[inline(always)]
    #[must_use]
    pub fn m_rd_req(&mut self) -> MRdReqW<IcIntrMaskSpec> {
        MRdReqW::new(self, 5)
    }
    #[doc = "Bit 6 - This bit indicates if I2C, as an I2C transmitter, is unable to complete the intended actions on the contents of the transmit FIFO. This situation can occur both as an I2C master or an I2C slave, and is referred to as a 'transmit abort'. When this bit is set to 1, the ic_tx_abrt_source register indicates the reason why the transmit abort takes places. NOTE: The I2C flushes/resets/empties the TX FIFO whenever this bit is set. The TX FIFO remains in this flushed state until the register ic_clr_tx_abrt is read. Once this read is performed, the TX FIFO is then ready to accept more data bytes from the APB interface."]
    #[inline(always)]
    #[must_use]
    pub fn m_tx_abrt(&mut self) -> MTxAbrtW<IcIntrMaskSpec> {
        MTxAbrtW::new(self, 6)
    }
    #[doc = "Bit 7 - When the I2C is acting as a slave-transmitter, this bit is set to 1, if the master does not acknowledge a transmitted byte. This occurs on the last byte of the transmission, indicating that the transmission is done."]
    #[inline(always)]
    #[must_use]
    pub fn m_rx_done(&mut self) -> MRxDoneW<IcIntrMaskSpec> {
        MRxDoneW::new(self, 7)
    }
    #[doc = "Bit 8 - This bit captures i2c activity and stays set until it is cleared. There are four ways to clear it: - Disabling the i2c - Reading the ic_clr_activity register - Reading the ic_clr_intr register - System reset Once this bit is set, it stays set unless one of the four methods is used to clear it. Even if the I2C module is idle, this bit remains set until cleared, indicating that there was activity on the bus."]
    #[inline(always)]
    #[must_use]
    pub fn m_activity(&mut self) -> MActivityW<IcIntrMaskSpec> {
        MActivityW::new(self, 8)
    }
    #[doc = "Bit 9 - Indicates whether a STOP condition has occurred on the I2C interface regardless of whether i2c is operating in slave or master mode."]
    #[inline(always)]
    #[must_use]
    pub fn m_stop_det(&mut self) -> MStopDetW<IcIntrMaskSpec> {
        MStopDetW::new(self, 9)
    }
    #[doc = "Bit 10 - Indicates whether a START or RESTART condition has occurred on the I2C interface regardless of whether I2C is operating in slave or master mode."]
    #[inline(always)]
    #[must_use]
    pub fn m_start_det(&mut self) -> MStartDetW<IcIntrMaskSpec> {
        MStartDetW::new(self, 10)
    }
    #[doc = "Bit 11 - Set only when a General Call address is received and it is acknowledged. It stays set until it is cleared either by disabling I2C or when the CPU reads bit 0 of the ic_clr_gen_call register. I2C stores the received data in the Rx buffer."]
    #[inline(always)]
    #[must_use]
    pub fn m_gen_call(&mut self) -> MGenCallW<IcIntrMaskSpec> {
        MGenCallW::new(self, 11)
    }
}
#[doc = "These bits mask their corresponding interrupt status bits.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_intr_mask::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_intr_mask::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcIntrMaskSpec;
impl crate::RegisterSpec for IcIntrMaskSpec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`ic_intr_mask::R`](R) reader structure"]
impl crate::Readable for IcIntrMaskSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_intr_mask::W`](W) writer structure"]
impl crate::Writable for IcIntrMaskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_intr_mask to value 0x08ff"]
impl crate::Resettable for IcIntrMaskSpec {
    const RESET_VALUE: u32 = 0x08ff;
}
