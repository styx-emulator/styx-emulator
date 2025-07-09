// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    ic_con: IcCon,
    ic_tar: IcTar,
    ic_sar: IcSar,
    _reserved3: [u8; 0x04],
    ic_data_cmd: IcDataCmd,
    ic_ss_scl_hcnt: IcSsSclHcnt,
    ic_ss_scl_lcnt: IcSsSclLcnt,
    ic_fs_scl_hcnt: IcFsSclHcnt,
    ic_fs_scl_lcnt: IcFsSclLcnt,
    _reserved8: [u8; 0x08],
    ic_intr_stat: IcIntrStat,
    ic_intr_mask: IcIntrMask,
    ic_raw_intr_stat: IcRawIntrStat,
    ic_rx_tl: IcRxTl,
    ic_tx_tl: IcTxTl,
    ic_clr_intr: IcClrIntr,
    ic_clr_rx_under: IcClrRxUnder,
    ic_clr_rx_over: IcClrRxOver,
    ic_clr_tx_over: IcClrTxOver,
    ic_clr_rd_req: IcClrRdReq,
    ic_clr_tx_abrt: IcClrTxAbrt,
    ic_clr_rx_done: IcClrRxDone,
    ic_clr_activity: IcClrActivity,
    ic_clr_stop_det: IcClrStopDet,
    ic_clr_start_det: IcClrStartDet,
    ic_clr_gen_call: IcClrGenCall,
    ic_enable: IcEnable,
    ic_status: IcStatus,
    ic_txflr: IcTxflr,
    ic_rxflr: IcRxflr,
    ic_sda_hold: IcSdaHold,
    ic_tx_abrt_source: IcTxAbrtSource,
    ic_slv_data_nack_only: IcSlvDataNackOnly,
    ic_dma_cr: IcDmaCr,
    ic_dma_tdlr: IcDmaTdlr,
    ic_dma_rdlr: IcDmaRdlr,
    ic_sda_setup: IcSdaSetup,
    ic_ack_general_call: IcAckGeneralCall,
    ic_enable_status: IcEnableStatus,
    ic_fs_spklen: IcFsSpklen,
    _reserved38: [u8; 0x50],
    ic_comp_param_1: IcCompParam1,
    ic_comp_version: IcCompVersion,
    ic_comp_type: IcCompType,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - This register can be written only when the I2C is disabled, which corresponds to the Bit \\[0\\]
of the Enable Register being set to 0. Writes at other times have no effect."]
    #[inline(always)]
    pub const fn ic_con(&self) -> &IcCon {
        &self.ic_con
    }
    #[doc = "0x04 - This register can be written to only when the ic_enable register is set to 0. This register is 13 bits wide. All bits can be dynamically updated as long as any set of the following conditions are true, (Enable Register bit 0 is set to 0) or (Enable Register bit 0 is set to 1 AND (I2C is NOT engaged in any Master \\[tx, rx\\]
operation \\[ic_status register mst_activity bit 5 is set to 0\\]) AND (I2C is enabled to operate in Master mode\\[ic_con bit\\[0\\]
is set to one\\]) AND (there are NO entries in the TX FIFO Register \\[IC_STATUS bit \\[2\\]
is set to 1\\])"]
    #[inline(always)]
    pub const fn ic_tar(&self) -> &IcTar {
        &self.ic_tar
    }
    #[doc = "0x08 - Holds Address of Slave"]
    #[inline(always)]
    pub const fn ic_sar(&self) -> &IcSar {
        &self.ic_sar
    }
    #[doc = "0x10 - This is the register the CPU writes to when filling the TX FIFO. Reading from this register returns bytes from RX FIFO."]
    #[inline(always)]
    pub const fn ic_data_cmd(&self) -> &IcDataCmd {
        &self.ic_data_cmd
    }
    #[doc = "0x14 - This register sets the SCL clock high-period count for standard speed."]
    #[inline(always)]
    pub const fn ic_ss_scl_hcnt(&self) -> &IcSsSclHcnt {
        &self.ic_ss_scl_hcnt
    }
    #[doc = "0x18 - This register sets the SCL clock low-period count for standard speed"]
    #[inline(always)]
    pub const fn ic_ss_scl_lcnt(&self) -> &IcSsSclLcnt {
        &self.ic_ss_scl_lcnt
    }
    #[doc = "0x1c - This register sets the SCL clock high-period count for fast speed"]
    #[inline(always)]
    pub const fn ic_fs_scl_hcnt(&self) -> &IcFsSclHcnt {
        &self.ic_fs_scl_hcnt
    }
    #[doc = "0x20 - This register sets the SCL clock low period count"]
    #[inline(always)]
    pub const fn ic_fs_scl_lcnt(&self) -> &IcFsSclLcnt {
        &self.ic_fs_scl_lcnt
    }
    #[doc = "0x2c - Each bit in this register has a corresponding mask bit in the Interrupt Mask Register. These bits are cleared by reading the matching Interrupt Clear Register. The unmasked raw versions of these bits are available in the Raw Interrupt Status Register."]
    #[inline(always)]
    pub const fn ic_intr_stat(&self) -> &IcIntrStat {
        &self.ic_intr_stat
    }
    #[doc = "0x30 - These bits mask their corresponding interrupt status bits."]
    #[inline(always)]
    pub const fn ic_intr_mask(&self) -> &IcIntrMask {
        &self.ic_intr_mask
    }
    #[doc = "0x34 - Unlike the ic_intr_stat register, these bits are not masked so they always show the true status of the I2C."]
    #[inline(always)]
    pub const fn ic_raw_intr_stat(&self) -> &IcRawIntrStat {
        &self.ic_raw_intr_stat
    }
    #[doc = "0x38 - I2C Receive FIFO Threshold Register."]
    #[inline(always)]
    pub const fn ic_rx_tl(&self) -> &IcRxTl {
        &self.ic_rx_tl
    }
    #[doc = "0x3c - Sets FIFO depth for Interrupt."]
    #[inline(always)]
    pub const fn ic_tx_tl(&self) -> &IcTxTl {
        &self.ic_tx_tl
    }
    #[doc = "0x40 - Controls Interrupts"]
    #[inline(always)]
    pub const fn ic_clr_intr(&self) -> &IcClrIntr {
        &self.ic_clr_intr
    }
    #[doc = "0x44 - Rx Under Interrupt Bits."]
    #[inline(always)]
    pub const fn ic_clr_rx_under(&self) -> &IcClrRxUnder {
        &self.ic_clr_rx_under
    }
    #[doc = "0x48 - Clears Rx over Interrupt Bit"]
    #[inline(always)]
    pub const fn ic_clr_rx_over(&self) -> &IcClrRxOver {
        &self.ic_clr_rx_over
    }
    #[doc = "0x4c - Clears Over Interrupts"]
    #[inline(always)]
    pub const fn ic_clr_tx_over(&self) -> &IcClrTxOver {
        &self.ic_clr_tx_over
    }
    #[doc = "0x50 - Clear RD_REQ Interrupt Register"]
    #[inline(always)]
    pub const fn ic_clr_rd_req(&self) -> &IcClrRdReq {
        &self.ic_clr_rd_req
    }
    #[doc = "0x54 - Clear TX_ABRT Interrupt"]
    #[inline(always)]
    pub const fn ic_clr_tx_abrt(&self) -> &IcClrTxAbrt {
        &self.ic_clr_tx_abrt
    }
    #[doc = "0x58 - Clear RX_DONE Interrupt Register"]
    #[inline(always)]
    pub const fn ic_clr_rx_done(&self) -> &IcClrRxDone {
        &self.ic_clr_rx_done
    }
    #[doc = "0x5c - Clears ACTIVITY Interrupt"]
    #[inline(always)]
    pub const fn ic_clr_activity(&self) -> &IcClrActivity {
        &self.ic_clr_activity
    }
    #[doc = "0x60 - Clear Interrupts."]
    #[inline(always)]
    pub const fn ic_clr_stop_det(&self) -> &IcClrStopDet {
        &self.ic_clr_stop_det
    }
    #[doc = "0x64 - Clears START_DET Interrupt"]
    #[inline(always)]
    pub const fn ic_clr_start_det(&self) -> &IcClrStartDet {
        &self.ic_clr_start_det
    }
    #[doc = "0x68 - Clear GEN_CALL Interrupt Register"]
    #[inline(always)]
    pub const fn ic_clr_gen_call(&self) -> &IcClrGenCall {
        &self.ic_clr_gen_call
    }
    #[doc = "0x6c - Enable and disable i2c operation"]
    #[inline(always)]
    pub const fn ic_enable(&self) -> &IcEnable {
        &self.ic_enable
    }
    #[doc = "0x70 - This is a read-only register used to indicate the current transfer status and FIFO status. The status register may be read at any time. None of the bits in this register request an interrupt.When the I2C is disabled by writing 0 in bit 0 of the ic_enable register: - Bits 1 and 2 are set to 1 - Bits 3 and 4 are set to 0 When the master or slave state machines goes to idle - Bits 5 and 6 are set to 0"]
    #[inline(always)]
    pub const fn ic_status(&self) -> &IcStatus {
        &self.ic_status
    }
    #[doc = "0x74 - This register contains the number of valid data entries in the transmit FIFO buffer. It is cleared whenever: - The I2C is disabled - There is a transmit abort that is, TX_ABRT bit is set in the ic_raw_intr_stat register. The slave bulk transmit mode is aborted The register increments whenever data is placed into the transmit FIFO and decrements when data is taken from the transmit FIFO."]
    #[inline(always)]
    pub const fn ic_txflr(&self) -> &IcTxflr {
        &self.ic_txflr
    }
    #[doc = "0x78 - This register contains the number of valid data entries in the receive FIFO buffer. It is cleared whenever: - The I2C is disabled - Whenever there is a transmit abort caused by any of the events tracked in ic_tx_abrt_source The register increments whenever data is placed into the receive FIFO and decrements when data is taken from the receive FIFO."]
    #[inline(always)]
    pub const fn ic_rxflr(&self) -> &IcRxflr {
        &self.ic_rxflr
    }
    #[doc = "0x7c - This register controls the amount of time delay (in terms of number of l4_sp_clk clock periods) introduced in the falling edge of SCL, relative to SDA changing, when I2C services a read request in a slave-transmitter operation. The relevant I2C requirement is thd:DAT as detailed in the I2C Bus Specification."]
    #[inline(always)]
    pub const fn ic_sda_hold(&self) -> &IcSdaHold {
        &self.ic_sda_hold
    }
    #[doc = "0x80 - This register has 16 bits that indicate the source of the TX_ABRT bit. Except for Bit 9, this register is cleared whenever the ic_clr_tx_abrt register or the ic_clr_intr register is read. To clear Bit 9, the source of the abrt_sbyte_norstrt must be fixed first; RESTART must be enabled (ic_con\\[5\\]=1), the special bit must be cleared (ic_tar\\[11\\]), or the gc_or_start bit must be cleared (ic_tar\\[10\\]). Once the source of the abrt_sbyte_norstrt is fixed, then this bit can be cleared in the same manner as other bits in this register. If the source of the abrt_sbyte_norstrt is not fixed before attempting to clear this bit, Bit 9 clears for one cycle and is then re-asserted."]
    #[inline(always)]
    pub const fn ic_tx_abrt_source(&self) -> &IcTxAbrtSource {
        &self.ic_tx_abrt_source
    }
    #[doc = "0x84 - The register is used to generate a NACK for the data part of a transfer when i2c is acting as a slave-receiver."]
    #[inline(always)]
    pub const fn ic_slv_data_nack_only(&self) -> &IcSlvDataNackOnly {
        &self.ic_slv_data_nack_only
    }
    #[doc = "0x88 - The register is used to enable the DMA Controller interface operation. There is a separate bit for transmit and receive. This can be programmed regardless of the state of IC_ENABLE."]
    #[inline(always)]
    pub const fn ic_dma_cr(&self) -> &IcDmaCr {
        &self.ic_dma_cr
    }
    #[doc = "0x8c - This register supports DMA Transmit Operation."]
    #[inline(always)]
    pub const fn ic_dma_tdlr(&self) -> &IcDmaTdlr {
        &self.ic_dma_tdlr
    }
    #[doc = "0x90 - DMA Control Signals Interface."]
    #[inline(always)]
    pub const fn ic_dma_rdlr(&self) -> &IcDmaRdlr {
        &self.ic_dma_rdlr
    }
    #[doc = "0x94 - This register controls the amount of time delay (in terms of number of l4_sp_clk clock periods) introduced in the rising edge of SCL relative to SDA changing by holding SCL low when I2C services a read request while operating as a slave-transmitter. The relevant I2C requirement is tSU:DAT (note 4) as detailed in the I2C Bus Specification. This register must be programmed with a value equal to or greater than 2. Note: The length of setup time is calculated using \\[(IC_SDA_SETUP - 1) * (l4_sp_clk)\\], so if the user requires 10 l4_sp_clk periods of setup time, they should program a value of 11. The IC_SDA_SETUP register is only used by the I2C when operating as a slave transmitter."]
    #[inline(always)]
    pub const fn ic_sda_setup(&self) -> &IcSdaSetup {
        &self.ic_sda_setup
    }
    #[doc = "0x98 - The register controls whether i2c responds with a ACK or NACK when it receives an I2C General Call address."]
    #[inline(always)]
    pub const fn ic_ack_general_call(&self) -> &IcAckGeneralCall {
        &self.ic_ack_general_call
    }
    #[doc = "0x9c - This register is used to report the i2c hardware status when the IC_ENABLE register is set from 1 to 0; that is, when i2c is disabled. If IC_ENABLE has been set to 1, bits 2:1 are forced to 0, and bit 0 is forced to 1. If IC_ENABLE has been set to 0, bits 2:1 are only valid as soon as bit 0 is read as '0'. Note: When ic_enable has been written with '0' a delay occurs for bit 0 to be read as '0' because disabling the i2c depends on I2C bus activities."]
    #[inline(always)]
    pub const fn ic_enable_status(&self) -> &IcEnableStatus {
        &self.ic_enable_status
    }
    #[doc = "0xa0 - This register is used to store the duration, measured in ic_clk cycles, of the longest spike that is filtered out by the spike suppression logic when the component is operating in SS or FS modes."]
    #[inline(always)]
    pub const fn ic_fs_spklen(&self) -> &IcFsSpklen {
        &self.ic_fs_spklen
    }
    #[doc = "0xf4 - This is a constant read-only register that contains encoded information about the component's parameter settings."]
    #[inline(always)]
    pub const fn ic_comp_param_1(&self) -> &IcCompParam1 {
        &self.ic_comp_param_1
    }
    #[doc = "0xf8 - Describes the version of the I2C"]
    #[inline(always)]
    pub const fn ic_comp_version(&self) -> &IcCompVersion {
        &self.ic_comp_version
    }
    #[doc = "0xfc - Describes a unique ASCII value"]
    #[inline(always)]
    pub const fn ic_comp_type(&self) -> &IcCompType {
        &self.ic_comp_type
    }
}
#[doc = "ic_con (rw) register accessor: This register can be written only when the I2C is disabled, which corresponds to the Bit \\[0\\]
of the Enable Register being set to 0. Writes at other times have no effect.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_con::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_con::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_con`]
module"]
#[doc(alias = "ic_con")]
pub type IcCon = crate::Reg<ic_con::IcConSpec>;
#[doc = "This register can be written only when the I2C is disabled, which corresponds to the Bit \\[0\\]
of the Enable Register being set to 0. Writes at other times have no effect."]
pub mod ic_con;
#[doc = "ic_tar (rw) register accessor: This register can be written to only when the ic_enable register is set to 0. This register is 13 bits wide. All bits can be dynamically updated as long as any set of the following conditions are true, (Enable Register bit 0 is set to 0) or (Enable Register bit 0 is set to 1 AND (I2C is NOT engaged in any Master \\[tx, rx\\]
operation \\[ic_status register mst_activity bit 5 is set to 0\\]) AND (I2C is enabled to operate in Master mode\\[ic_con bit\\[0\\]
is set to one\\]) AND (there are NO entries in the TX FIFO Register \\[IC_STATUS bit \\[2\\]
is set to 1\\])\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_tar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_tar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_tar`]
module"]
#[doc(alias = "ic_tar")]
pub type IcTar = crate::Reg<ic_tar::IcTarSpec>;
#[doc = "This register can be written to only when the ic_enable register is set to 0. This register is 13 bits wide. All bits can be dynamically updated as long as any set of the following conditions are true, (Enable Register bit 0 is set to 0) or (Enable Register bit 0 is set to 1 AND (I2C is NOT engaged in any Master \\[tx, rx\\]
operation \\[ic_status register mst_activity bit 5 is set to 0\\]) AND (I2C is enabled to operate in Master mode\\[ic_con bit\\[0\\]
is set to one\\]) AND (there are NO entries in the TX FIFO Register \\[IC_STATUS bit \\[2\\]
is set to 1\\])"]
pub mod ic_tar;
#[doc = "ic_sar (rw) register accessor: Holds Address of Slave\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_sar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_sar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_sar`]
module"]
#[doc(alias = "ic_sar")]
pub type IcSar = crate::Reg<ic_sar::IcSarSpec>;
#[doc = "Holds Address of Slave"]
pub mod ic_sar;
#[doc = "ic_data_cmd (rw) register accessor: This is the register the CPU writes to when filling the TX FIFO. Reading from this register returns bytes from RX FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_data_cmd::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_data_cmd::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_data_cmd`]
module"]
#[doc(alias = "ic_data_cmd")]
pub type IcDataCmd = crate::Reg<ic_data_cmd::IcDataCmdSpec>;
#[doc = "This is the register the CPU writes to when filling the TX FIFO. Reading from this register returns bytes from RX FIFO."]
pub mod ic_data_cmd;
#[doc = "ic_ss_scl_hcnt (rw) register accessor: This register sets the SCL clock high-period count for standard speed.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_ss_scl_hcnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_ss_scl_hcnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_ss_scl_hcnt`]
module"]
#[doc(alias = "ic_ss_scl_hcnt")]
pub type IcSsSclHcnt = crate::Reg<ic_ss_scl_hcnt::IcSsSclHcntSpec>;
#[doc = "This register sets the SCL clock high-period count for standard speed."]
pub mod ic_ss_scl_hcnt;
#[doc = "ic_ss_scl_lcnt (rw) register accessor: This register sets the SCL clock low-period count for standard speed\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_ss_scl_lcnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_ss_scl_lcnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_ss_scl_lcnt`]
module"]
#[doc(alias = "ic_ss_scl_lcnt")]
pub type IcSsSclLcnt = crate::Reg<ic_ss_scl_lcnt::IcSsSclLcntSpec>;
#[doc = "This register sets the SCL clock low-period count for standard speed"]
pub mod ic_ss_scl_lcnt;
#[doc = "ic_fs_scl_hcnt (rw) register accessor: This register sets the SCL clock high-period count for fast speed\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_fs_scl_hcnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_fs_scl_hcnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_fs_scl_hcnt`]
module"]
#[doc(alias = "ic_fs_scl_hcnt")]
pub type IcFsSclHcnt = crate::Reg<ic_fs_scl_hcnt::IcFsSclHcntSpec>;
#[doc = "This register sets the SCL clock high-period count for fast speed"]
pub mod ic_fs_scl_hcnt;
#[doc = "ic_fs_scl_lcnt (rw) register accessor: This register sets the SCL clock low period count\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_fs_scl_lcnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_fs_scl_lcnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_fs_scl_lcnt`]
module"]
#[doc(alias = "ic_fs_scl_lcnt")]
pub type IcFsSclLcnt = crate::Reg<ic_fs_scl_lcnt::IcFsSclLcntSpec>;
#[doc = "This register sets the SCL clock low period count"]
pub mod ic_fs_scl_lcnt;
#[doc = "ic_intr_stat (r) register accessor: Each bit in this register has a corresponding mask bit in the Interrupt Mask Register. These bits are cleared by reading the matching Interrupt Clear Register. The unmasked raw versions of these bits are available in the Raw Interrupt Status Register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_intr_stat::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_intr_stat`]
module"]
#[doc(alias = "ic_intr_stat")]
pub type IcIntrStat = crate::Reg<ic_intr_stat::IcIntrStatSpec>;
#[doc = "Each bit in this register has a corresponding mask bit in the Interrupt Mask Register. These bits are cleared by reading the matching Interrupt Clear Register. The unmasked raw versions of these bits are available in the Raw Interrupt Status Register."]
pub mod ic_intr_stat;
#[doc = "ic_intr_mask (rw) register accessor: These bits mask their corresponding interrupt status bits.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_intr_mask::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_intr_mask::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_intr_mask`]
module"]
#[doc(alias = "ic_intr_mask")]
pub type IcIntrMask = crate::Reg<ic_intr_mask::IcIntrMaskSpec>;
#[doc = "These bits mask their corresponding interrupt status bits."]
pub mod ic_intr_mask;
#[doc = "ic_raw_intr_stat (r) register accessor: Unlike the ic_intr_stat register, these bits are not masked so they always show the true status of the I2C.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_raw_intr_stat::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_raw_intr_stat`]
module"]
#[doc(alias = "ic_raw_intr_stat")]
pub type IcRawIntrStat = crate::Reg<ic_raw_intr_stat::IcRawIntrStatSpec>;
#[doc = "Unlike the ic_intr_stat register, these bits are not masked so they always show the true status of the I2C."]
pub mod ic_raw_intr_stat;
#[doc = "ic_rx_tl (rw) register accessor: I2C Receive FIFO Threshold Register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_rx_tl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_rx_tl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_rx_tl`]
module"]
#[doc(alias = "ic_rx_tl")]
pub type IcRxTl = crate::Reg<ic_rx_tl::IcRxTlSpec>;
#[doc = "I2C Receive FIFO Threshold Register."]
pub mod ic_rx_tl;
#[doc = "ic_tx_tl (rw) register accessor: Sets FIFO depth for Interrupt.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_tx_tl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_tx_tl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_tx_tl`]
module"]
#[doc(alias = "ic_tx_tl")]
pub type IcTxTl = crate::Reg<ic_tx_tl::IcTxTlSpec>;
#[doc = "Sets FIFO depth for Interrupt."]
pub mod ic_tx_tl;
#[doc = "ic_clr_intr (r) register accessor: Controls Interrupts\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_intr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_clr_intr`]
module"]
#[doc(alias = "ic_clr_intr")]
pub type IcClrIntr = crate::Reg<ic_clr_intr::IcClrIntrSpec>;
#[doc = "Controls Interrupts"]
pub mod ic_clr_intr;
#[doc = "ic_clr_rx_under (r) register accessor: Rx Under Interrupt Bits.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_rx_under::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_clr_rx_under`]
module"]
#[doc(alias = "ic_clr_rx_under")]
pub type IcClrRxUnder = crate::Reg<ic_clr_rx_under::IcClrRxUnderSpec>;
#[doc = "Rx Under Interrupt Bits."]
pub mod ic_clr_rx_under;
#[doc = "ic_clr_rx_over (r) register accessor: Clears Rx over Interrupt Bit\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_rx_over::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_clr_rx_over`]
module"]
#[doc(alias = "ic_clr_rx_over")]
pub type IcClrRxOver = crate::Reg<ic_clr_rx_over::IcClrRxOverSpec>;
#[doc = "Clears Rx over Interrupt Bit"]
pub mod ic_clr_rx_over;
#[doc = "ic_clr_tx_over (r) register accessor: Clears Over Interrupts\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_tx_over::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_clr_tx_over`]
module"]
#[doc(alias = "ic_clr_tx_over")]
pub type IcClrTxOver = crate::Reg<ic_clr_tx_over::IcClrTxOverSpec>;
#[doc = "Clears Over Interrupts"]
pub mod ic_clr_tx_over;
#[doc = "ic_clr_rd_req (r) register accessor: Clear RD_REQ Interrupt Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_rd_req::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_clr_rd_req`]
module"]
#[doc(alias = "ic_clr_rd_req")]
pub type IcClrRdReq = crate::Reg<ic_clr_rd_req::IcClrRdReqSpec>;
#[doc = "Clear RD_REQ Interrupt Register"]
pub mod ic_clr_rd_req;
#[doc = "ic_clr_tx_abrt (r) register accessor: Clear TX_ABRT Interrupt\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_tx_abrt::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_clr_tx_abrt`]
module"]
#[doc(alias = "ic_clr_tx_abrt")]
pub type IcClrTxAbrt = crate::Reg<ic_clr_tx_abrt::IcClrTxAbrtSpec>;
#[doc = "Clear TX_ABRT Interrupt"]
pub mod ic_clr_tx_abrt;
#[doc = "ic_clr_rx_done (r) register accessor: Clear RX_DONE Interrupt Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_rx_done::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_clr_rx_done`]
module"]
#[doc(alias = "ic_clr_rx_done")]
pub type IcClrRxDone = crate::Reg<ic_clr_rx_done::IcClrRxDoneSpec>;
#[doc = "Clear RX_DONE Interrupt Register"]
pub mod ic_clr_rx_done;
#[doc = "ic_clr_activity (r) register accessor: Clears ACTIVITY Interrupt\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_activity::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_clr_activity`]
module"]
#[doc(alias = "ic_clr_activity")]
pub type IcClrActivity = crate::Reg<ic_clr_activity::IcClrActivitySpec>;
#[doc = "Clears ACTIVITY Interrupt"]
pub mod ic_clr_activity;
#[doc = "ic_clr_stop_det (r) register accessor: Clear Interrupts.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_stop_det::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_clr_stop_det`]
module"]
#[doc(alias = "ic_clr_stop_det")]
pub type IcClrStopDet = crate::Reg<ic_clr_stop_det::IcClrStopDetSpec>;
#[doc = "Clear Interrupts."]
pub mod ic_clr_stop_det;
#[doc = "ic_clr_start_det (r) register accessor: Clears START_DET Interrupt\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_start_det::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_clr_start_det`]
module"]
#[doc(alias = "ic_clr_start_det")]
pub type IcClrStartDet = crate::Reg<ic_clr_start_det::IcClrStartDetSpec>;
#[doc = "Clears START_DET Interrupt"]
pub mod ic_clr_start_det;
#[doc = "ic_clr_gen_call (r) register accessor: Clear GEN_CALL Interrupt Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_gen_call::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_clr_gen_call`]
module"]
#[doc(alias = "ic_clr_gen_call")]
pub type IcClrGenCall = crate::Reg<ic_clr_gen_call::IcClrGenCallSpec>;
#[doc = "Clear GEN_CALL Interrupt Register"]
pub mod ic_clr_gen_call;
#[doc = "ic_enable (rw) register accessor: Enable and disable i2c operation\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_enable::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_enable::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_enable`]
module"]
#[doc(alias = "ic_enable")]
pub type IcEnable = crate::Reg<ic_enable::IcEnableSpec>;
#[doc = "Enable and disable i2c operation"]
pub mod ic_enable;
#[doc = "ic_status (r) register accessor: This is a read-only register used to indicate the current transfer status and FIFO status. The status register may be read at any time. None of the bits in this register request an interrupt.When the I2C is disabled by writing 0 in bit 0 of the ic_enable register: - Bits 1 and 2 are set to 1 - Bits 3 and 4 are set to 0 When the master or slave state machines goes to idle - Bits 5 and 6 are set to 0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_status::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_status`]
module"]
#[doc(alias = "ic_status")]
pub type IcStatus = crate::Reg<ic_status::IcStatusSpec>;
#[doc = "This is a read-only register used to indicate the current transfer status and FIFO status. The status register may be read at any time. None of the bits in this register request an interrupt.When the I2C is disabled by writing 0 in bit 0 of the ic_enable register: - Bits 1 and 2 are set to 1 - Bits 3 and 4 are set to 0 When the master or slave state machines goes to idle - Bits 5 and 6 are set to 0"]
pub mod ic_status;
#[doc = "ic_txflr (r) register accessor: This register contains the number of valid data entries in the transmit FIFO buffer. It is cleared whenever: - The I2C is disabled - There is a transmit abort that is, TX_ABRT bit is set in the ic_raw_intr_stat register. The slave bulk transmit mode is aborted The register increments whenever data is placed into the transmit FIFO and decrements when data is taken from the transmit FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_txflr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_txflr`]
module"]
#[doc(alias = "ic_txflr")]
pub type IcTxflr = crate::Reg<ic_txflr::IcTxflrSpec>;
#[doc = "This register contains the number of valid data entries in the transmit FIFO buffer. It is cleared whenever: - The I2C is disabled - There is a transmit abort that is, TX_ABRT bit is set in the ic_raw_intr_stat register. The slave bulk transmit mode is aborted The register increments whenever data is placed into the transmit FIFO and decrements when data is taken from the transmit FIFO."]
pub mod ic_txflr;
#[doc = "ic_rxflr (r) register accessor: This register contains the number of valid data entries in the receive FIFO buffer. It is cleared whenever: - The I2C is disabled - Whenever there is a transmit abort caused by any of the events tracked in ic_tx_abrt_source The register increments whenever data is placed into the receive FIFO and decrements when data is taken from the receive FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_rxflr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_rxflr`]
module"]
#[doc(alias = "ic_rxflr")]
pub type IcRxflr = crate::Reg<ic_rxflr::IcRxflrSpec>;
#[doc = "This register contains the number of valid data entries in the receive FIFO buffer. It is cleared whenever: - The I2C is disabled - Whenever there is a transmit abort caused by any of the events tracked in ic_tx_abrt_source The register increments whenever data is placed into the receive FIFO and decrements when data is taken from the receive FIFO."]
pub mod ic_rxflr;
#[doc = "ic_sda_hold (rw) register accessor: This register controls the amount of time delay (in terms of number of l4_sp_clk clock periods) introduced in the falling edge of SCL, relative to SDA changing, when I2C services a read request in a slave-transmitter operation. The relevant I2C requirement is thd:DAT as detailed in the I2C Bus Specification.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_sda_hold::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_sda_hold::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_sda_hold`]
module"]
#[doc(alias = "ic_sda_hold")]
pub type IcSdaHold = crate::Reg<ic_sda_hold::IcSdaHoldSpec>;
#[doc = "This register controls the amount of time delay (in terms of number of l4_sp_clk clock periods) introduced in the falling edge of SCL, relative to SDA changing, when I2C services a read request in a slave-transmitter operation. The relevant I2C requirement is thd:DAT as detailed in the I2C Bus Specification."]
pub mod ic_sda_hold;
#[doc = "ic_tx_abrt_source (rw) register accessor: This register has 16 bits that indicate the source of the TX_ABRT bit. Except for Bit 9, this register is cleared whenever the ic_clr_tx_abrt register or the ic_clr_intr register is read. To clear Bit 9, the source of the abrt_sbyte_norstrt must be fixed first; RESTART must be enabled (ic_con\\[5\\]=1), the special bit must be cleared (ic_tar\\[11\\]), or the gc_or_start bit must be cleared (ic_tar\\[10\\]). Once the source of the abrt_sbyte_norstrt is fixed, then this bit can be cleared in the same manner as other bits in this register. If the source of the abrt_sbyte_norstrt is not fixed before attempting to clear this bit, Bit 9 clears for one cycle and is then re-asserted.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_tx_abrt_source::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_tx_abrt_source::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_tx_abrt_source`]
module"]
#[doc(alias = "ic_tx_abrt_source")]
pub type IcTxAbrtSource = crate::Reg<ic_tx_abrt_source::IcTxAbrtSourceSpec>;
#[doc = "This register has 16 bits that indicate the source of the TX_ABRT bit. Except for Bit 9, this register is cleared whenever the ic_clr_tx_abrt register or the ic_clr_intr register is read. To clear Bit 9, the source of the abrt_sbyte_norstrt must be fixed first; RESTART must be enabled (ic_con\\[5\\]=1), the special bit must be cleared (ic_tar\\[11\\]), or the gc_or_start bit must be cleared (ic_tar\\[10\\]). Once the source of the abrt_sbyte_norstrt is fixed, then this bit can be cleared in the same manner as other bits in this register. If the source of the abrt_sbyte_norstrt is not fixed before attempting to clear this bit, Bit 9 clears for one cycle and is then re-asserted."]
pub mod ic_tx_abrt_source;
#[doc = "ic_slv_data_nack_only (rw) register accessor: The register is used to generate a NACK for the data part of a transfer when i2c is acting as a slave-receiver.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_slv_data_nack_only::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_slv_data_nack_only::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_slv_data_nack_only`]
module"]
#[doc(alias = "ic_slv_data_nack_only")]
pub type IcSlvDataNackOnly = crate::Reg<ic_slv_data_nack_only::IcSlvDataNackOnlySpec>;
#[doc = "The register is used to generate a NACK for the data part of a transfer when i2c is acting as a slave-receiver."]
pub mod ic_slv_data_nack_only;
#[doc = "ic_dma_cr (rw) register accessor: The register is used to enable the DMA Controller interface operation. There is a separate bit for transmit and receive. This can be programmed regardless of the state of IC_ENABLE.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_dma_cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_dma_cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_dma_cr`]
module"]
#[doc(alias = "ic_dma_cr")]
pub type IcDmaCr = crate::Reg<ic_dma_cr::IcDmaCrSpec>;
#[doc = "The register is used to enable the DMA Controller interface operation. There is a separate bit for transmit and receive. This can be programmed regardless of the state of IC_ENABLE."]
pub mod ic_dma_cr;
#[doc = "ic_dma_tdlr (rw) register accessor: This register supports DMA Transmit Operation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_dma_tdlr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_dma_tdlr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_dma_tdlr`]
module"]
#[doc(alias = "ic_dma_tdlr")]
pub type IcDmaTdlr = crate::Reg<ic_dma_tdlr::IcDmaTdlrSpec>;
#[doc = "This register supports DMA Transmit Operation."]
pub mod ic_dma_tdlr;
#[doc = "ic_dma_rdlr (rw) register accessor: DMA Control Signals Interface.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_dma_rdlr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_dma_rdlr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_dma_rdlr`]
module"]
#[doc(alias = "ic_dma_rdlr")]
pub type IcDmaRdlr = crate::Reg<ic_dma_rdlr::IcDmaRdlrSpec>;
#[doc = "DMA Control Signals Interface."]
pub mod ic_dma_rdlr;
#[doc = "ic_sda_setup (rw) register accessor: This register controls the amount of time delay (in terms of number of l4_sp_clk clock periods) introduced in the rising edge of SCL relative to SDA changing by holding SCL low when I2C services a read request while operating as a slave-transmitter. The relevant I2C requirement is tSU:DAT (note 4) as detailed in the I2C Bus Specification. This register must be programmed with a value equal to or greater than 2. Note: The length of setup time is calculated using \\[(IC_SDA_SETUP - 1) * (l4_sp_clk)\\], so if the user requires 10 l4_sp_clk periods of setup time, they should program a value of 11. The IC_SDA_SETUP register is only used by the I2C when operating as a slave transmitter.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_sda_setup::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_sda_setup::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_sda_setup`]
module"]
#[doc(alias = "ic_sda_setup")]
pub type IcSdaSetup = crate::Reg<ic_sda_setup::IcSdaSetupSpec>;
#[doc = "This register controls the amount of time delay (in terms of number of l4_sp_clk clock periods) introduced in the rising edge of SCL relative to SDA changing by holding SCL low when I2C services a read request while operating as a slave-transmitter. The relevant I2C requirement is tSU:DAT (note 4) as detailed in the I2C Bus Specification. This register must be programmed with a value equal to or greater than 2. Note: The length of setup time is calculated using \\[(IC_SDA_SETUP - 1) * (l4_sp_clk)\\], so if the user requires 10 l4_sp_clk periods of setup time, they should program a value of 11. The IC_SDA_SETUP register is only used by the I2C when operating as a slave transmitter."]
pub mod ic_sda_setup;
#[doc = "ic_ack_general_call (rw) register accessor: The register controls whether i2c responds with a ACK or NACK when it receives an I2C General Call address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_ack_general_call::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_ack_general_call::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_ack_general_call`]
module"]
#[doc(alias = "ic_ack_general_call")]
pub type IcAckGeneralCall = crate::Reg<ic_ack_general_call::IcAckGeneralCallSpec>;
#[doc = "The register controls whether i2c responds with a ACK or NACK when it receives an I2C General Call address."]
pub mod ic_ack_general_call;
#[doc = "ic_enable_status (r) register accessor: This register is used to report the i2c hardware status when the IC_ENABLE register is set from 1 to 0; that is, when i2c is disabled. If IC_ENABLE has been set to 1, bits 2:1 are forced to 0, and bit 0 is forced to 1. If IC_ENABLE has been set to 0, bits 2:1 are only valid as soon as bit 0 is read as '0'. Note: When ic_enable has been written with '0' a delay occurs for bit 0 to be read as '0' because disabling the i2c depends on I2C bus activities.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_enable_status::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_enable_status`]
module"]
#[doc(alias = "ic_enable_status")]
pub type IcEnableStatus = crate::Reg<ic_enable_status::IcEnableStatusSpec>;
#[doc = "This register is used to report the i2c hardware status when the IC_ENABLE register is set from 1 to 0; that is, when i2c is disabled. If IC_ENABLE has been set to 1, bits 2:1 are forced to 0, and bit 0 is forced to 1. If IC_ENABLE has been set to 0, bits 2:1 are only valid as soon as bit 0 is read as '0'. Note: When ic_enable has been written with '0' a delay occurs for bit 0 to be read as '0' because disabling the i2c depends on I2C bus activities."]
pub mod ic_enable_status;
#[doc = "ic_fs_spklen (rw) register accessor: This register is used to store the duration, measured in ic_clk cycles, of the longest spike that is filtered out by the spike suppression logic when the component is operating in SS or FS modes.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_fs_spklen::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_fs_spklen::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_fs_spklen`]
module"]
#[doc(alias = "ic_fs_spklen")]
pub type IcFsSpklen = crate::Reg<ic_fs_spklen::IcFsSpklenSpec>;
#[doc = "This register is used to store the duration, measured in ic_clk cycles, of the longest spike that is filtered out by the spike suppression logic when the component is operating in SS or FS modes."]
pub mod ic_fs_spklen;
#[doc = "ic_comp_param_1 (r) register accessor: This is a constant read-only register that contains encoded information about the component's parameter settings.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_comp_param_1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_comp_param_1`]
module"]
#[doc(alias = "ic_comp_param_1")]
pub type IcCompParam1 = crate::Reg<ic_comp_param_1::IcCompParam1Spec>;
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings."]
pub mod ic_comp_param_1;
#[doc = "ic_comp_version (r) register accessor: Describes the version of the I2C\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_comp_version::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_comp_version`]
module"]
#[doc(alias = "ic_comp_version")]
pub type IcCompVersion = crate::Reg<ic_comp_version::IcCompVersionSpec>;
#[doc = "Describes the version of the I2C"]
pub mod ic_comp_version;
#[doc = "ic_comp_type (r) register accessor: Describes a unique ASCII value\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_comp_type::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ic_comp_type`]
module"]
#[doc(alias = "ic_comp_type")]
pub type IcCompType = crate::Reg<ic_comp_type::IcCompTypeSpec>;
#[doc = "Describes a unique ASCII value"]
pub mod ic_comp_type;
