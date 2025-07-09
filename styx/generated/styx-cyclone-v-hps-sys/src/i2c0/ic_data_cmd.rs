// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_data_cmd` reader"]
pub type R = crate::R<IcDataCmdSpec>;
#[doc = "Register `ic_data_cmd` writer"]
pub type W = crate::W<IcDataCmdSpec>;
#[doc = "Field `dat` reader - This Field contains the data to be transmitted or received on the I2C bus. If you are writing to these bits and want to perform a read, bits 7:0 (dat) are ignored by the I2C. However, when you read from this register, these bits return the value of data received on the I2C interface."]
pub type DatR = crate::FieldReader;
#[doc = "Field `dat` writer - This Field contains the data to be transmitted or received on the I2C bus. If you are writing to these bits and want to perform a read, bits 7:0 (dat) are ignored by the I2C. However, when you read from this register, these bits return the value of data received on the I2C interface."]
pub type DatW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `cmd` reader - This bit controls whether a read or a write is performed. This bit does not control the direction when the I2C acts as a slave. It controls only the direction when it acts as a master. When a command is entered in the TX FIFO, this bit distinguishes the write and read commands. In slave-receiver mode, this bit is a 'don't care' because writes to this register are not required. In slave-transmitter mode, a '0' indicates that the CPU data is to be transmitted. When programming this bit, you should remember the following: attempting to perform a read operation after a General Call command has been sent results in a tx_abrt interrupt (bit 6 of the Raw Intr Status Register), unless bit 11 special in the Target Address Register has been cleared. If a '1' is written to this bit after receiving a RD_REQ interrupt, then a tx_abrt interrupt occurs. NOTE: It is possible that while attempting a master I2C read transfer on I2C, a RD_REQ interrupt may have occurred simultaneously due to a remote I2C master addressing I2C. In this type of scenario, I2C ignores the Data Cmd write, generates a tx_abrt interrupt, and waits to service the RD_REQ interrupt."]
pub type CmdR = crate::BitReader;
#[doc = "This bit controls whether a read or a write is performed. This bit does not control the direction when the I2C acts as a slave. It controls only the direction when it acts as a master. When a command is entered in the TX FIFO, this bit distinguishes the write and read commands. In slave-receiver mode, this bit is a 'don't care' because writes to this register are not required. In slave-transmitter mode, a '0' indicates that the CPU data is to be transmitted. When programming this bit, you should remember the following: attempting to perform a read operation after a General Call command has been sent results in a tx_abrt interrupt (bit 6 of the Raw Intr Status Register), unless bit 11 special in the Target Address Register has been cleared. If a '1' is written to this bit after receiving a RD_REQ interrupt, then a tx_abrt interrupt occurs. NOTE: It is possible that while attempting a master I2C read transfer on I2C, a RD_REQ interrupt may have occurred simultaneously due to a remote I2C master addressing I2C. In this type of scenario, I2C ignores the Data Cmd write, generates a tx_abrt interrupt, and waits to service the RD_REQ interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    #[doc = "1: `1`"]
    Rd = 1,
    #[doc = "0: `0`"]
    Wr = 0,
}
impl From<Cmd> for bool {
    #[inline(always)]
    fn from(variant: Cmd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cmd` writer - This bit controls whether a read or a write is performed. This bit does not control the direction when the I2C acts as a slave. It controls only the direction when it acts as a master. When a command is entered in the TX FIFO, this bit distinguishes the write and read commands. In slave-receiver mode, this bit is a 'don't care' because writes to this register are not required. In slave-transmitter mode, a '0' indicates that the CPU data is to be transmitted. When programming this bit, you should remember the following: attempting to perform a read operation after a General Call command has been sent results in a tx_abrt interrupt (bit 6 of the Raw Intr Status Register), unless bit 11 special in the Target Address Register has been cleared. If a '1' is written to this bit after receiving a RD_REQ interrupt, then a tx_abrt interrupt occurs. NOTE: It is possible that while attempting a master I2C read transfer on I2C, a RD_REQ interrupt may have occurred simultaneously due to a remote I2C master addressing I2C. In this type of scenario, I2C ignores the Data Cmd write, generates a tx_abrt interrupt, and waits to service the RD_REQ interrupt."]
pub type CmdW<'a, REG> = crate::BitWriter<'a, REG, Cmd>;
impl<'a, REG> CmdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn rd(self) -> &'a mut crate::W<REG> {
        self.variant(Cmd::Rd)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn wr(self) -> &'a mut crate::W<REG> {
        self.variant(Cmd::Wr)
    }
}
#[doc = "Field `stop` reader - This bit controls whether a STOP is issued after the byte is sent or received. 1 = STOP is issued after this byte, regardless of whether or not the Tx FIFO is empty. If the Tx FIFO is not empty, the master immediately tries to start a new transfer by issuing a START and arbitrating for the bus. 0 = STOP is not issued after this byte, regardless of whether or not the Tx FIFO is empty. If the Tx FIFO is not empty, the master continues the current transfer by sending/receiving data bytes according to the value of the CMD bit. If the Tx FIFO is empty, the master holds the SCL line low and stalls the bus until a new command is available in the Tx FIFO."]
pub type StopR = crate::BitReader;
#[doc = "This bit controls whether a STOP is issued after the byte is sent or received. 1 = STOP is issued after this byte, regardless of whether or not the Tx FIFO is empty. If the Tx FIFO is not empty, the master immediately tries to start a new transfer by issuing a START and arbitrating for the bus. 0 = STOP is not issued after this byte, regardless of whether or not the Tx FIFO is empty. If the Tx FIFO is not empty, the master continues the current transfer by sending/receiving data bytes according to the value of the CMD bit. If the Tx FIFO is empty, the master holds the SCL line low and stalls the bus until a new command is available in the Tx FIFO.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    #[doc = "1: `1`"]
    Stop = 1,
    #[doc = "0: `0`"]
    NoStop = 0,
}
impl From<Stop> for bool {
    #[inline(always)]
    fn from(variant: Stop) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `stop` writer - This bit controls whether a STOP is issued after the byte is sent or received. 1 = STOP is issued after this byte, regardless of whether or not the Tx FIFO is empty. If the Tx FIFO is not empty, the master immediately tries to start a new transfer by issuing a START and arbitrating for the bus. 0 = STOP is not issued after this byte, regardless of whether or not the Tx FIFO is empty. If the Tx FIFO is not empty, the master continues the current transfer by sending/receiving data bytes according to the value of the CMD bit. If the Tx FIFO is empty, the master holds the SCL line low and stalls the bus until a new command is available in the Tx FIFO."]
pub type StopW<'a, REG> = crate::BitWriter<'a, REG, Stop>;
impl<'a, REG> StopW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn stop(self) -> &'a mut crate::W<REG> {
        self.variant(Stop::Stop)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn no_stop(self) -> &'a mut crate::W<REG> {
        self.variant(Stop::NoStop)
    }
}
#[doc = "Field `restart` reader - This bit controls whether a RESTART is issued before the byte is sent or received. 1 = A RESTART is issued before the data is sent/received (according to the value of CMD), regardless of whether or not the transfer direction is changing from the previous command. 0 = A RESTART is issued only if the transfer direction is changing from the previous command."]
pub type RestartR = crate::BitReader;
#[doc = "This bit controls whether a RESTART is issued before the byte is sent or received. 1 = A RESTART is issued before the data is sent/received (according to the value of CMD), regardless of whether or not the transfer direction is changing from the previous command. 0 = A RESTART is issued only if the transfer direction is changing from the previous command.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restart {
    #[doc = "1: `1`"]
    Restart = 1,
    #[doc = "0: `0`"]
    RestartOnDirChange = 0,
}
impl From<Restart> for bool {
    #[inline(always)]
    fn from(variant: Restart) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `restart` writer - This bit controls whether a RESTART is issued before the byte is sent or received. 1 = A RESTART is issued before the data is sent/received (according to the value of CMD), regardless of whether or not the transfer direction is changing from the previous command. 0 = A RESTART is issued only if the transfer direction is changing from the previous command."]
pub type RestartW<'a, REG> = crate::BitWriter<'a, REG, Restart>;
impl<'a, REG> RestartW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn restart(self) -> &'a mut crate::W<REG> {
        self.variant(Restart::Restart)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn restart_on_dir_change(self) -> &'a mut crate::W<REG> {
        self.variant(Restart::RestartOnDirChange)
    }
}
impl R {
    #[doc = "Bits 0:7 - This Field contains the data to be transmitted or received on the I2C bus. If you are writing to these bits and want to perform a read, bits 7:0 (dat) are ignored by the I2C. However, when you read from this register, these bits return the value of data received on the I2C interface."]
    #[inline(always)]
    pub fn dat(&self) -> DatR {
        DatR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bit 8 - This bit controls whether a read or a write is performed. This bit does not control the direction when the I2C acts as a slave. It controls only the direction when it acts as a master. When a command is entered in the TX FIFO, this bit distinguishes the write and read commands. In slave-receiver mode, this bit is a 'don't care' because writes to this register are not required. In slave-transmitter mode, a '0' indicates that the CPU data is to be transmitted. When programming this bit, you should remember the following: attempting to perform a read operation after a General Call command has been sent results in a tx_abrt interrupt (bit 6 of the Raw Intr Status Register), unless bit 11 special in the Target Address Register has been cleared. If a '1' is written to this bit after receiving a RD_REQ interrupt, then a tx_abrt interrupt occurs. NOTE: It is possible that while attempting a master I2C read transfer on I2C, a RD_REQ interrupt may have occurred simultaneously due to a remote I2C master addressing I2C. In this type of scenario, I2C ignores the Data Cmd write, generates a tx_abrt interrupt, and waits to service the RD_REQ interrupt."]
    #[inline(always)]
    pub fn cmd(&self) -> CmdR {
        CmdR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - This bit controls whether a STOP is issued after the byte is sent or received. 1 = STOP is issued after this byte, regardless of whether or not the Tx FIFO is empty. If the Tx FIFO is not empty, the master immediately tries to start a new transfer by issuing a START and arbitrating for the bus. 0 = STOP is not issued after this byte, regardless of whether or not the Tx FIFO is empty. If the Tx FIFO is not empty, the master continues the current transfer by sending/receiving data bytes according to the value of the CMD bit. If the Tx FIFO is empty, the master holds the SCL line low and stalls the bus until a new command is available in the Tx FIFO."]
    #[inline(always)]
    pub fn stop(&self) -> StopR {
        StopR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - This bit controls whether a RESTART is issued before the byte is sent or received. 1 = A RESTART is issued before the data is sent/received (according to the value of CMD), regardless of whether or not the transfer direction is changing from the previous command. 0 = A RESTART is issued only if the transfer direction is changing from the previous command."]
    #[inline(always)]
    pub fn restart(&self) -> RestartR {
        RestartR::new(((self.bits >> 10) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:7 - This Field contains the data to be transmitted or received on the I2C bus. If you are writing to these bits and want to perform a read, bits 7:0 (dat) are ignored by the I2C. However, when you read from this register, these bits return the value of data received on the I2C interface."]
    #[inline(always)]
    #[must_use]
    pub fn dat(&mut self) -> DatW<IcDataCmdSpec> {
        DatW::new(self, 0)
    }
    #[doc = "Bit 8 - This bit controls whether a read or a write is performed. This bit does not control the direction when the I2C acts as a slave. It controls only the direction when it acts as a master. When a command is entered in the TX FIFO, this bit distinguishes the write and read commands. In slave-receiver mode, this bit is a 'don't care' because writes to this register are not required. In slave-transmitter mode, a '0' indicates that the CPU data is to be transmitted. When programming this bit, you should remember the following: attempting to perform a read operation after a General Call command has been sent results in a tx_abrt interrupt (bit 6 of the Raw Intr Status Register), unless bit 11 special in the Target Address Register has been cleared. If a '1' is written to this bit after receiving a RD_REQ interrupt, then a tx_abrt interrupt occurs. NOTE: It is possible that while attempting a master I2C read transfer on I2C, a RD_REQ interrupt may have occurred simultaneously due to a remote I2C master addressing I2C. In this type of scenario, I2C ignores the Data Cmd write, generates a tx_abrt interrupt, and waits to service the RD_REQ interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn cmd(&mut self) -> CmdW<IcDataCmdSpec> {
        CmdW::new(self, 8)
    }
    #[doc = "Bit 9 - This bit controls whether a STOP is issued after the byte is sent or received. 1 = STOP is issued after this byte, regardless of whether or not the Tx FIFO is empty. If the Tx FIFO is not empty, the master immediately tries to start a new transfer by issuing a START and arbitrating for the bus. 0 = STOP is not issued after this byte, regardless of whether or not the Tx FIFO is empty. If the Tx FIFO is not empty, the master continues the current transfer by sending/receiving data bytes according to the value of the CMD bit. If the Tx FIFO is empty, the master holds the SCL line low and stalls the bus until a new command is available in the Tx FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn stop(&mut self) -> StopW<IcDataCmdSpec> {
        StopW::new(self, 9)
    }
    #[doc = "Bit 10 - This bit controls whether a RESTART is issued before the byte is sent or received. 1 = A RESTART is issued before the data is sent/received (according to the value of CMD), regardless of whether or not the transfer direction is changing from the previous command. 0 = A RESTART is issued only if the transfer direction is changing from the previous command."]
    #[inline(always)]
    #[must_use]
    pub fn restart(&mut self) -> RestartW<IcDataCmdSpec> {
        RestartW::new(self, 10)
    }
}
#[doc = "This is the register the CPU writes to when filling the TX FIFO. Reading from this register returns bytes from RX FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_data_cmd::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_data_cmd::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcDataCmdSpec;
impl crate::RegisterSpec for IcDataCmdSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`ic_data_cmd::R`](R) reader structure"]
impl crate::Readable for IcDataCmdSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_data_cmd::W`](W) writer structure"]
impl crate::Writable for IcDataCmdSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_data_cmd to value 0"]
impl crate::Resettable for IcDataCmdSpec {
    const RESET_VALUE: u32 = 0;
}
