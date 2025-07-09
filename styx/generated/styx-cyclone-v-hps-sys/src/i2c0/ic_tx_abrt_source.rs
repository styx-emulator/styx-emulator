// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_tx_abrt_source` reader"]
pub type R = crate::R<IcTxAbrtSourceSpec>;
#[doc = "Register `ic_tx_abrt_source` writer"]
pub type W = crate::W<IcTxAbrtSourceSpec>;
#[doc = "Field `abrt_7b_addr_noack` reader - Master is in 7-bit addressing mode and the address sent was not acknowledged by any slave. Role of i2c: Master-Transmitter or Master-Receiver"]
pub type Abrt7bAddrNoackR = crate::BitReader;
#[doc = "Field `abrt_7b_addr_noack` writer - Master is in 7-bit addressing mode and the address sent was not acknowledged by any slave. Role of i2c: Master-Transmitter or Master-Receiver"]
pub type Abrt7bAddrNoackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_10addr1_noack` reader - Master is in 10-bit address mode and the first 10-bit address byte was not acknowledged by any slave. Role of i2c: Master-Transmitter or Master-Receiver"]
pub type Abrt10addr1NoackR = crate::BitReader;
#[doc = "Field `abrt_10addr1_noack` writer - Master is in 10-bit address mode and the first 10-bit address byte was not acknowledged by any slave. Role of i2c: Master-Transmitter or Master-Receiver"]
pub type Abrt10addr1NoackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_10addr2_noack` reader - Master is in 10-bit address mode and the second address byte of the 10-bit address was not acknowledged by any slave. Role of i2c: Master-Transmitter or Master-Receiver"]
pub type Abrt10addr2NoackR = crate::BitReader;
#[doc = "Field `abrt_10addr2_noack` writer - Master is in 10-bit address mode and the second address byte of the 10-bit address was not acknowledged by any slave. Role of i2c: Master-Transmitter or Master-Receiver"]
pub type Abrt10addr2NoackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_txdata_noack` reader - This is a master-mode only bit. Master has received an acknowledgement for the address, but when it sent data byte(s) following the address, it did not receive an acknowledge from the remote slave(s). Role of i2c: Master-Transmitter"]
pub type AbrtTxdataNoackR = crate::BitReader;
#[doc = "Field `abrt_txdata_noack` writer - This is a master-mode only bit. Master has received an acknowledgement for the address, but when it sent data byte(s) following the address, it did not receive an acknowledge from the remote slave(s). Role of i2c: Master-Transmitter"]
pub type AbrtTxdataNoackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_gcall_noack` reader - i2c in master mode sent a General Call and no slave on the bus acknowledged the General Call. Role of i2c: Master-Transmitter"]
pub type AbrtGcallNoackR = crate::BitReader;
#[doc = "Field `abrt_gcall_noack` writer - i2c in master mode sent a General Call and no slave on the bus acknowledged the General Call. Role of i2c: Master-Transmitter"]
pub type AbrtGcallNoackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_gcall_read` reader - i2c in master mode sent a General Call but the user programmed the byte following the General Call to be a read from the bus (IC_DATA_CMD\\[9\\]
is set to 1). Role of i2c: Master-Transmitter"]
pub type AbrtGcallReadR = crate::BitReader;
#[doc = "Field `abrt_gcall_read` writer - i2c in master mode sent a General Call but the user programmed the byte following the General Call to be a read from the bus (IC_DATA_CMD\\[9\\]
is set to 1). Role of i2c: Master-Transmitter"]
pub type AbrtGcallReadW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_hs_ackdet` reader - Master is in High Speed mode and the High Speed Master code was acknowledged (wrong behavior). Role of i2c: Master"]
pub type AbrtHsAckdetR = crate::BitReader;
#[doc = "Field `abrt_hs_ackdet` writer - Master is in High Speed mode and the High Speed Master code was acknowledged (wrong behavior). Role of i2c: Master"]
pub type AbrtHsAckdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_sbyte_ackdet` reader - Master has sent a START Byte and the START Byte was acknowledged (wrong behavior). Role of i2c: Master"]
pub type AbrtSbyteAckdetR = crate::BitReader;
#[doc = "Field `abrt_sbyte_ackdet` writer - Master has sent a START Byte and the START Byte was acknowledged (wrong behavior). Role of i2c: Master"]
pub type AbrtSbyteAckdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_hs_norstrt` reader - The restart is disabled (IC_RESTART_EN bit (IC_CON\\[5\\]) =0) and the user is trying to use the master to transfer data in High Speed mode. Role of i2c: Master-Transmitter or Master-Receiver"]
pub type AbrtHsNorstrtR = crate::BitReader;
#[doc = "Field `abrt_hs_norstrt` writer - The restart is disabled (IC_RESTART_EN bit (IC_CON\\[5\\]) =0) and the user is trying to use the master to transfer data in High Speed mode. Role of i2c: Master-Transmitter or Master-Receiver"]
pub type AbrtHsNorstrtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_sbyte_norstrt` reader - To clear Bit 9, the source of then abrt_sbyte_norstrt must be fixed first; restart must be enabled (ic_con\\[5\\]=1), the SPECIAL bit must be cleared (ic_tar\\[11\\]), or the GC_OR_START bit must be cleared (ic_tar\\[10\\]). Once the source of the abrt_sbyte_norstrt is fixed, then this bit can be cleared in the same manner as other bits in this register. If the source of the abrt_sbyte_norstrt is not fixed before attempting to clear this bit, bit 9 clears for one cycle and then gets reasserted. 1: The restart is disabled (IC_RESTART_EN bit (ic_con\\[5\\]) =0) and the user is trying to send a START Byte. Role of I2C: Master"]
pub type AbrtSbyteNorstrtR = crate::BitReader;
#[doc = "Field `abrt_sbyte_norstrt` writer - To clear Bit 9, the source of then abrt_sbyte_norstrt must be fixed first; restart must be enabled (ic_con\\[5\\]=1), the SPECIAL bit must be cleared (ic_tar\\[11\\]), or the GC_OR_START bit must be cleared (ic_tar\\[10\\]). Once the source of the abrt_sbyte_norstrt is fixed, then this bit can be cleared in the same manner as other bits in this register. If the source of the abrt_sbyte_norstrt is not fixed before attempting to clear this bit, bit 9 clears for one cycle and then gets reasserted. 1: The restart is disabled (IC_RESTART_EN bit (ic_con\\[5\\]) =0) and the user is trying to send a START Byte. Role of I2C: Master"]
pub type AbrtSbyteNorstrtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_10b_rd_norstrt` reader - The restart is disabled (ic_restart_en bit (ic_con\\[5\\]) =0) and the master sends a read command in 10-bit addressing mode. Role of I2C: Master-Receiver"]
pub type Abrt10bRdNorstrtR = crate::BitReader;
#[doc = "Field `abrt_10b_rd_norstrt` writer - The restart is disabled (ic_restart_en bit (ic_con\\[5\\]) =0) and the master sends a read command in 10-bit addressing mode. Role of I2C: Master-Receiver"]
pub type Abrt10bRdNorstrtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_master_dis` reader - User tries to initiate a Master operation with the Master mode disabled. Role of I2C: Master-Transmitter or Master-Receiver"]
pub type AbrtMasterDisR = crate::BitReader;
#[doc = "Field `abrt_master_dis` writer - User tries to initiate a Master operation with the Master mode disabled. Role of I2C: Master-Transmitter or Master-Receiver"]
pub type AbrtMasterDisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `arb_lost` reader - Master has lost arbitration, or if IC_TX_ABRT_SOURCE\\[14\\]
is also set, then the slave transmitter has lost arbitration. Note: I2C can be both master and slave at the same time. Role of i2c: Master-Transmitter or Slave-Transmitter"]
pub type ArbLostR = crate::BitReader;
#[doc = "Field `arb_lost` writer - Master has lost arbitration, or if IC_TX_ABRT_SOURCE\\[14\\]
is also set, then the slave transmitter has lost arbitration. Note: I2C can be both master and slave at the same time. Role of i2c: Master-Transmitter or Slave-Transmitter"]
pub type ArbLostW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_slvflush_txfifo` reader - Slave has received a read command and some data exists in the TX FIFO so the slave issues a TX_ABRT interrupt to flush old data in TX FIFO. Role of I2C: Slave-Transmitter"]
pub type AbrtSlvflushTxfifoR = crate::BitReader;
#[doc = "Field `abrt_slvflush_txfifo` writer - Slave has received a read command and some data exists in the TX FIFO so the slave issues a TX_ABRT interrupt to flush old data in TX FIFO. Role of I2C: Slave-Transmitter"]
pub type AbrtSlvflushTxfifoW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_slv_arblost` reader - Slave lost the bus while transmitting data to a remote master. IC_TX_ABRT_SOURCE\\[12\\]
is set at the same time. Note: Even though the slave never 'owns' the bus, something could go wrong on the bus. This is a fail safe check. For instance, during a data transmission at the low-to-high transition of SCL, if what is on the data bus is not what is supposed to be transmitted, then i2c no longer own the bus. Role of I2C: Slave-Transmitter"]
pub type AbrtSlvArblostR = crate::BitReader;
#[doc = "Field `abrt_slv_arblost` writer - Slave lost the bus while transmitting data to a remote master. IC_TX_ABRT_SOURCE\\[12\\]
is set at the same time. Note: Even though the slave never 'owns' the bus, something could go wrong on the bus. This is a fail safe check. For instance, during a data transmission at the low-to-high transition of SCL, if what is on the data bus is not what is supposed to be transmitted, then i2c no longer own the bus. Role of I2C: Slave-Transmitter"]
pub type AbrtSlvArblostW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `abrt_slvrd_intx` reader - When the processor side responds to a slave mode request for data to be transmitted to a remote master and user writes a 1 in CMD (bit 8) of IC_DATA_CMD register. Role of I2C: Slave-Transmitter"]
pub type AbrtSlvrdIntxR = crate::BitReader;
#[doc = "Field `abrt_slvrd_intx` writer - When the processor side responds to a slave mode request for data to be transmitted to a remote master and user writes a 1 in CMD (bit 8) of IC_DATA_CMD register. Role of I2C: Slave-Transmitter"]
pub type AbrtSlvrdIntxW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Master is in 7-bit addressing mode and the address sent was not acknowledged by any slave. Role of i2c: Master-Transmitter or Master-Receiver"]
    #[inline(always)]
    pub fn abrt_7b_addr_noack(&self) -> Abrt7bAddrNoackR {
        Abrt7bAddrNoackR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Master is in 10-bit address mode and the first 10-bit address byte was not acknowledged by any slave. Role of i2c: Master-Transmitter or Master-Receiver"]
    #[inline(always)]
    pub fn abrt_10addr1_noack(&self) -> Abrt10addr1NoackR {
        Abrt10addr1NoackR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Master is in 10-bit address mode and the second address byte of the 10-bit address was not acknowledged by any slave. Role of i2c: Master-Transmitter or Master-Receiver"]
    #[inline(always)]
    pub fn abrt_10addr2_noack(&self) -> Abrt10addr2NoackR {
        Abrt10addr2NoackR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This is a master-mode only bit. Master has received an acknowledgement for the address, but when it sent data byte(s) following the address, it did not receive an acknowledge from the remote slave(s). Role of i2c: Master-Transmitter"]
    #[inline(always)]
    pub fn abrt_txdata_noack(&self) -> AbrtTxdataNoackR {
        AbrtTxdataNoackR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - i2c in master mode sent a General Call and no slave on the bus acknowledged the General Call. Role of i2c: Master-Transmitter"]
    #[inline(always)]
    pub fn abrt_gcall_noack(&self) -> AbrtGcallNoackR {
        AbrtGcallNoackR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - i2c in master mode sent a General Call but the user programmed the byte following the General Call to be a read from the bus (IC_DATA_CMD\\[9\\]
is set to 1). Role of i2c: Master-Transmitter"]
    #[inline(always)]
    pub fn abrt_gcall_read(&self) -> AbrtGcallReadR {
        AbrtGcallReadR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Master is in High Speed mode and the High Speed Master code was acknowledged (wrong behavior). Role of i2c: Master"]
    #[inline(always)]
    pub fn abrt_hs_ackdet(&self) -> AbrtHsAckdetR {
        AbrtHsAckdetR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Master has sent a START Byte and the START Byte was acknowledged (wrong behavior). Role of i2c: Master"]
    #[inline(always)]
    pub fn abrt_sbyte_ackdet(&self) -> AbrtSbyteAckdetR {
        AbrtSbyteAckdetR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - The restart is disabled (IC_RESTART_EN bit (IC_CON\\[5\\]) =0) and the user is trying to use the master to transfer data in High Speed mode. Role of i2c: Master-Transmitter or Master-Receiver"]
    #[inline(always)]
    pub fn abrt_hs_norstrt(&self) -> AbrtHsNorstrtR {
        AbrtHsNorstrtR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - To clear Bit 9, the source of then abrt_sbyte_norstrt must be fixed first; restart must be enabled (ic_con\\[5\\]=1), the SPECIAL bit must be cleared (ic_tar\\[11\\]), or the GC_OR_START bit must be cleared (ic_tar\\[10\\]). Once the source of the abrt_sbyte_norstrt is fixed, then this bit can be cleared in the same manner as other bits in this register. If the source of the abrt_sbyte_norstrt is not fixed before attempting to clear this bit, bit 9 clears for one cycle and then gets reasserted. 1: The restart is disabled (IC_RESTART_EN bit (ic_con\\[5\\]) =0) and the user is trying to send a START Byte. Role of I2C: Master"]
    #[inline(always)]
    pub fn abrt_sbyte_norstrt(&self) -> AbrtSbyteNorstrtR {
        AbrtSbyteNorstrtR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - The restart is disabled (ic_restart_en bit (ic_con\\[5\\]) =0) and the master sends a read command in 10-bit addressing mode. Role of I2C: Master-Receiver"]
    #[inline(always)]
    pub fn abrt_10b_rd_norstrt(&self) -> Abrt10bRdNorstrtR {
        Abrt10bRdNorstrtR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - User tries to initiate a Master operation with the Master mode disabled. Role of I2C: Master-Transmitter or Master-Receiver"]
    #[inline(always)]
    pub fn abrt_master_dis(&self) -> AbrtMasterDisR {
        AbrtMasterDisR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Master has lost arbitration, or if IC_TX_ABRT_SOURCE\\[14\\]
is also set, then the slave transmitter has lost arbitration. Note: I2C can be both master and slave at the same time. Role of i2c: Master-Transmitter or Slave-Transmitter"]
    #[inline(always)]
    pub fn arb_lost(&self) -> ArbLostR {
        ArbLostR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Slave has received a read command and some data exists in the TX FIFO so the slave issues a TX_ABRT interrupt to flush old data in TX FIFO. Role of I2C: Slave-Transmitter"]
    #[inline(always)]
    pub fn abrt_slvflush_txfifo(&self) -> AbrtSlvflushTxfifoR {
        AbrtSlvflushTxfifoR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Slave lost the bus while transmitting data to a remote master. IC_TX_ABRT_SOURCE\\[12\\]
is set at the same time. Note: Even though the slave never 'owns' the bus, something could go wrong on the bus. This is a fail safe check. For instance, during a data transmission at the low-to-high transition of SCL, if what is on the data bus is not what is supposed to be transmitted, then i2c no longer own the bus. Role of I2C: Slave-Transmitter"]
    #[inline(always)]
    pub fn abrt_slv_arblost(&self) -> AbrtSlvArblostR {
        AbrtSlvArblostR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - When the processor side responds to a slave mode request for data to be transmitted to a remote master and user writes a 1 in CMD (bit 8) of IC_DATA_CMD register. Role of I2C: Slave-Transmitter"]
    #[inline(always)]
    pub fn abrt_slvrd_intx(&self) -> AbrtSlvrdIntxR {
        AbrtSlvrdIntxR::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Master is in 7-bit addressing mode and the address sent was not acknowledged by any slave. Role of i2c: Master-Transmitter or Master-Receiver"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_7b_addr_noack(&mut self) -> Abrt7bAddrNoackW<IcTxAbrtSourceSpec> {
        Abrt7bAddrNoackW::new(self, 0)
    }
    #[doc = "Bit 1 - Master is in 10-bit address mode and the first 10-bit address byte was not acknowledged by any slave. Role of i2c: Master-Transmitter or Master-Receiver"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_10addr1_noack(&mut self) -> Abrt10addr1NoackW<IcTxAbrtSourceSpec> {
        Abrt10addr1NoackW::new(self, 1)
    }
    #[doc = "Bit 2 - Master is in 10-bit address mode and the second address byte of the 10-bit address was not acknowledged by any slave. Role of i2c: Master-Transmitter or Master-Receiver"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_10addr2_noack(&mut self) -> Abrt10addr2NoackW<IcTxAbrtSourceSpec> {
        Abrt10addr2NoackW::new(self, 2)
    }
    #[doc = "Bit 3 - This is a master-mode only bit. Master has received an acknowledgement for the address, but when it sent data byte(s) following the address, it did not receive an acknowledge from the remote slave(s). Role of i2c: Master-Transmitter"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_txdata_noack(&mut self) -> AbrtTxdataNoackW<IcTxAbrtSourceSpec> {
        AbrtTxdataNoackW::new(self, 3)
    }
    #[doc = "Bit 4 - i2c in master mode sent a General Call and no slave on the bus acknowledged the General Call. Role of i2c: Master-Transmitter"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_gcall_noack(&mut self) -> AbrtGcallNoackW<IcTxAbrtSourceSpec> {
        AbrtGcallNoackW::new(self, 4)
    }
    #[doc = "Bit 5 - i2c in master mode sent a General Call but the user programmed the byte following the General Call to be a read from the bus (IC_DATA_CMD\\[9\\]
is set to 1). Role of i2c: Master-Transmitter"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_gcall_read(&mut self) -> AbrtGcallReadW<IcTxAbrtSourceSpec> {
        AbrtGcallReadW::new(self, 5)
    }
    #[doc = "Bit 6 - Master is in High Speed mode and the High Speed Master code was acknowledged (wrong behavior). Role of i2c: Master"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_hs_ackdet(&mut self) -> AbrtHsAckdetW<IcTxAbrtSourceSpec> {
        AbrtHsAckdetW::new(self, 6)
    }
    #[doc = "Bit 7 - Master has sent a START Byte and the START Byte was acknowledged (wrong behavior). Role of i2c: Master"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_sbyte_ackdet(&mut self) -> AbrtSbyteAckdetW<IcTxAbrtSourceSpec> {
        AbrtSbyteAckdetW::new(self, 7)
    }
    #[doc = "Bit 8 - The restart is disabled (IC_RESTART_EN bit (IC_CON\\[5\\]) =0) and the user is trying to use the master to transfer data in High Speed mode. Role of i2c: Master-Transmitter or Master-Receiver"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_hs_norstrt(&mut self) -> AbrtHsNorstrtW<IcTxAbrtSourceSpec> {
        AbrtHsNorstrtW::new(self, 8)
    }
    #[doc = "Bit 9 - To clear Bit 9, the source of then abrt_sbyte_norstrt must be fixed first; restart must be enabled (ic_con\\[5\\]=1), the SPECIAL bit must be cleared (ic_tar\\[11\\]), or the GC_OR_START bit must be cleared (ic_tar\\[10\\]). Once the source of the abrt_sbyte_norstrt is fixed, then this bit can be cleared in the same manner as other bits in this register. If the source of the abrt_sbyte_norstrt is not fixed before attempting to clear this bit, bit 9 clears for one cycle and then gets reasserted. 1: The restart is disabled (IC_RESTART_EN bit (ic_con\\[5\\]) =0) and the user is trying to send a START Byte. Role of I2C: Master"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_sbyte_norstrt(&mut self) -> AbrtSbyteNorstrtW<IcTxAbrtSourceSpec> {
        AbrtSbyteNorstrtW::new(self, 9)
    }
    #[doc = "Bit 10 - The restart is disabled (ic_restart_en bit (ic_con\\[5\\]) =0) and the master sends a read command in 10-bit addressing mode. Role of I2C: Master-Receiver"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_10b_rd_norstrt(&mut self) -> Abrt10bRdNorstrtW<IcTxAbrtSourceSpec> {
        Abrt10bRdNorstrtW::new(self, 10)
    }
    #[doc = "Bit 11 - User tries to initiate a Master operation with the Master mode disabled. Role of I2C: Master-Transmitter or Master-Receiver"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_master_dis(&mut self) -> AbrtMasterDisW<IcTxAbrtSourceSpec> {
        AbrtMasterDisW::new(self, 11)
    }
    #[doc = "Bit 12 - Master has lost arbitration, or if IC_TX_ABRT_SOURCE\\[14\\]
is also set, then the slave transmitter has lost arbitration. Note: I2C can be both master and slave at the same time. Role of i2c: Master-Transmitter or Slave-Transmitter"]
    #[inline(always)]
    #[must_use]
    pub fn arb_lost(&mut self) -> ArbLostW<IcTxAbrtSourceSpec> {
        ArbLostW::new(self, 12)
    }
    #[doc = "Bit 13 - Slave has received a read command and some data exists in the TX FIFO so the slave issues a TX_ABRT interrupt to flush old data in TX FIFO. Role of I2C: Slave-Transmitter"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_slvflush_txfifo(&mut self) -> AbrtSlvflushTxfifoW<IcTxAbrtSourceSpec> {
        AbrtSlvflushTxfifoW::new(self, 13)
    }
    #[doc = "Bit 14 - Slave lost the bus while transmitting data to a remote master. IC_TX_ABRT_SOURCE\\[12\\]
is set at the same time. Note: Even though the slave never 'owns' the bus, something could go wrong on the bus. This is a fail safe check. For instance, during a data transmission at the low-to-high transition of SCL, if what is on the data bus is not what is supposed to be transmitted, then i2c no longer own the bus. Role of I2C: Slave-Transmitter"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_slv_arblost(&mut self) -> AbrtSlvArblostW<IcTxAbrtSourceSpec> {
        AbrtSlvArblostW::new(self, 14)
    }
    #[doc = "Bit 15 - When the processor side responds to a slave mode request for data to be transmitted to a remote master and user writes a 1 in CMD (bit 8) of IC_DATA_CMD register. Role of I2C: Slave-Transmitter"]
    #[inline(always)]
    #[must_use]
    pub fn abrt_slvrd_intx(&mut self) -> AbrtSlvrdIntxW<IcTxAbrtSourceSpec> {
        AbrtSlvrdIntxW::new(self, 15)
    }
}
#[doc = "This register has 16 bits that indicate the source of the TX_ABRT bit. Except for Bit 9, this register is cleared whenever the ic_clr_tx_abrt register or the ic_clr_intr register is read. To clear Bit 9, the source of the abrt_sbyte_norstrt must be fixed first; RESTART must be enabled (ic_con\\[5\\]=1), the special bit must be cleared (ic_tar\\[11\\]), or the gc_or_start bit must be cleared (ic_tar\\[10\\]). Once the source of the abrt_sbyte_norstrt is fixed, then this bit can be cleared in the same manner as other bits in this register. If the source of the abrt_sbyte_norstrt is not fixed before attempting to clear this bit, Bit 9 clears for one cycle and is then re-asserted.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_tx_abrt_source::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_tx_abrt_source::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcTxAbrtSourceSpec;
impl crate::RegisterSpec for IcTxAbrtSourceSpec {
    type Ux = u32;
    const OFFSET: u64 = 128u64;
}
#[doc = "`read()` method returns [`ic_tx_abrt_source::R`](R) reader structure"]
impl crate::Readable for IcTxAbrtSourceSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_tx_abrt_source::W`](W) writer structure"]
impl crate::Writable for IcTxAbrtSourceSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_tx_abrt_source to value 0"]
impl crate::Resettable for IcTxAbrtSourceSpec {
    const RESET_VALUE: u32 = 0;
}
