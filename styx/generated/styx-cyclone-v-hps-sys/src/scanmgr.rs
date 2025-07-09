// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    stat: Stat,
    en: En,
    _reserved2: [u8; 0x08],
    fifosinglebyte: Fifosinglebyte,
    fifodoublebyte: Fifodoublebyte,
    fifotriplebyte: Fifotriplebyte,
    fifoquadbyte: Fifoquadbyte,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Consist of control bit and status information."]
    #[inline(always)]
    pub const fn stat(&self) -> &Stat {
        &self.stat
    }
    #[doc = "0x04 - This register is used to enable one of the 5 scan-chains (0-3 and 7). Only one scan-chain must be enabled at a time. A scan-chain is enabled by writing its corresponding enable field. Software must use the System Manager to put the corresponding I/O scan-chain into the frozen state before attempting to send I/O configuration data to the I/O scan-chain. Software must only write to this register when the Scan-Chain Engine is inactive.Writing this field at any other time has unpredictable results. This means that before writing to this field, software must read the STAT register and check that the ACTIVE and WFIFOCNT fields are both zero. The name of this register in ARM documentation is PSEL."]
    #[inline(always)]
    pub const fn en(&self) -> &En {
        &self.en
    }
    #[doc = "0x10 - Writes to the FIFO Single Byte Register write a single byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Single Byte FIFO Register read a single byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO1 for writes and BRFIFO1 for reads."]
    #[inline(always)]
    pub const fn fifosinglebyte(&self) -> &Fifosinglebyte {
        &self.fifosinglebyte
    }
    #[doc = "0x14 - Writes to the FIFO Double Byte Register write a double byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Double Byte FIFO Register read a double byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO2 for writes and BRFIFO2 for reads."]
    #[inline(always)]
    pub const fn fifodoublebyte(&self) -> &Fifodoublebyte {
        &self.fifodoublebyte
    }
    #[doc = "0x18 - Writes to the FIFO Triple Byte Register write a triple byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Triple Byte FIFO Register read a triple byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO3 for writes and BRFIFO3 for reads."]
    #[inline(always)]
    pub const fn fifotriplebyte(&self) -> &Fifotriplebyte {
        &self.fifotriplebyte
    }
    #[doc = "0x1c - Writes to the FIFO Quad Byte Register write a quad byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Quad Byte FIFO Register read a quad byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO4 for writes and BRFIFO4 for reads."]
    #[inline(always)]
    pub const fn fifoquadbyte(&self) -> &Fifoquadbyte {
        &self.fifoquadbyte
    }
}
#[doc = "stat (rw) register accessor: Consist of control bit and status information.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`stat::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`stat::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@stat`]
module"]
#[doc(alias = "stat")]
pub type Stat = crate::Reg<stat::StatSpec>;
#[doc = "Consist of control bit and status information."]
pub mod stat;
#[doc = "en (rw) register accessor: This register is used to enable one of the 5 scan-chains (0-3 and 7). Only one scan-chain must be enabled at a time. A scan-chain is enabled by writing its corresponding enable field. Software must use the System Manager to put the corresponding I/O scan-chain into the frozen state before attempting to send I/O configuration data to the I/O scan-chain. Software must only write to this register when the Scan-Chain Engine is inactive.Writing this field at any other time has unpredictable results. This means that before writing to this field, software must read the STAT register and check that the ACTIVE and WFIFOCNT fields are both zero. The name of this register in ARM documentation is PSEL.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`en::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`en::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@en`]
module"]
#[doc(alias = "en")]
pub type En = crate::Reg<en::EnSpec>;
#[doc = "This register is used to enable one of the 5 scan-chains (0-3 and 7). Only one scan-chain must be enabled at a time. A scan-chain is enabled by writing its corresponding enable field. Software must use the System Manager to put the corresponding I/O scan-chain into the frozen state before attempting to send I/O configuration data to the I/O scan-chain. Software must only write to this register when the Scan-Chain Engine is inactive.Writing this field at any other time has unpredictable results. This means that before writing to this field, software must read the STAT register and check that the ACTIVE and WFIFOCNT fields are both zero. The name of this register in ARM documentation is PSEL."]
pub mod en;
#[doc = "fifosinglebyte (rw) register accessor: Writes to the FIFO Single Byte Register write a single byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Single Byte FIFO Register read a single byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO1 for writes and BRFIFO1 for reads.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifosinglebyte::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fifosinglebyte::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fifosinglebyte`]
module"]
#[doc(alias = "fifosinglebyte")]
pub type Fifosinglebyte = crate::Reg<fifosinglebyte::FifosinglebyteSpec>;
#[doc = "Writes to the FIFO Single Byte Register write a single byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Single Byte FIFO Register read a single byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO1 for writes and BRFIFO1 for reads."]
pub mod fifosinglebyte;
#[doc = "fifodoublebyte (rw) register accessor: Writes to the FIFO Double Byte Register write a double byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Double Byte FIFO Register read a double byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO2 for writes and BRFIFO2 for reads.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifodoublebyte::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fifodoublebyte::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fifodoublebyte`]
module"]
#[doc(alias = "fifodoublebyte")]
pub type Fifodoublebyte = crate::Reg<fifodoublebyte::FifodoublebyteSpec>;
#[doc = "Writes to the FIFO Double Byte Register write a double byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Double Byte FIFO Register read a double byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO2 for writes and BRFIFO2 for reads."]
pub mod fifodoublebyte;
#[doc = "fifotriplebyte (rw) register accessor: Writes to the FIFO Triple Byte Register write a triple byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Triple Byte FIFO Register read a triple byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO3 for writes and BRFIFO3 for reads.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifotriplebyte::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fifotriplebyte::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fifotriplebyte`]
module"]
#[doc(alias = "fifotriplebyte")]
pub type Fifotriplebyte = crate::Reg<fifotriplebyte::FifotriplebyteSpec>;
#[doc = "Writes to the FIFO Triple Byte Register write a triple byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Triple Byte FIFO Register read a triple byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO3 for writes and BRFIFO3 for reads."]
pub mod fifotriplebyte;
#[doc = "fifoquadbyte (rw) register accessor: Writes to the FIFO Quad Byte Register write a quad byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Quad Byte FIFO Register read a quad byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO4 for writes and BRFIFO4 for reads.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifoquadbyte::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fifoquadbyte::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fifoquadbyte`]
module"]
#[doc(alias = "fifoquadbyte")]
pub type Fifoquadbyte = crate::Reg<fifoquadbyte::FifoquadbyteSpec>;
#[doc = "Writes to the FIFO Quad Byte Register write a quad byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Quad Byte FIFO Register read a quad byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO4 for writes and BRFIFO4 for reads."]
pub mod fifoquadbyte;
