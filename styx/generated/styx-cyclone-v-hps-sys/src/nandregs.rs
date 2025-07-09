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
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    config_device_reset: ConfigDeviceReset,
    _reserved1: [u8; 0x0c],
    config_transfer_spare_reg: ConfigTransferSpareReg,
    _reserved2: [u8; 0x0c],
    config_load_wait_cnt: ConfigLoadWaitCnt,
    _reserved3: [u8; 0x0c],
    config_program_wait_cnt: ConfigProgramWaitCnt,
    _reserved4: [u8; 0x0c],
    config_erase_wait_cnt: ConfigEraseWaitCnt,
    _reserved5: [u8; 0x0c],
    config_int_mon_cyccnt: ConfigIntMonCyccnt,
    _reserved6: [u8; 0x0c],
    config_rb_pin_enabled: ConfigRbPinEnabled,
    _reserved7: [u8; 0x0c],
    config_multiplane_operation: ConfigMultiplaneOperation,
    _reserved8: [u8; 0x0c],
    config_multiplane_read_enable: ConfigMultiplaneReadEnable,
    _reserved9: [u8; 0x0c],
    config_copyback_disable: ConfigCopybackDisable,
    _reserved10: [u8; 0x0c],
    config_cache_write_enable: ConfigCacheWriteEnable,
    _reserved11: [u8; 0x0c],
    config_cache_read_enable: ConfigCacheReadEnable,
    _reserved12: [u8; 0x0c],
    config_prefetch_mode: ConfigPrefetchMode,
    _reserved13: [u8; 0x0c],
    config_chip_enable_dont_care: ConfigChipEnableDontCare,
    _reserved14: [u8; 0x0c],
    config_ecc_enable: ConfigEccEnable,
    _reserved15: [u8; 0x0c],
    config_global_int_enable: ConfigGlobalIntEnable,
    _reserved16: [u8; 0x0c],
    config_twhr2_and_we_2_re: ConfigTwhr2AndWe2Re,
    _reserved17: [u8; 0x0c],
    config_tcwaw_and_addr_2_data: ConfigTcwawAndAddr2Data,
    _reserved18: [u8; 0x0c],
    config_re_2_we: ConfigRe2We,
    _reserved19: [u8; 0x0c],
    config_acc_clks: ConfigAccClks,
    _reserved20: [u8; 0x0c],
    config_number_of_planes: ConfigNumberOfPlanes,
    _reserved21: [u8; 0x0c],
    config_pages_per_block: ConfigPagesPerBlock,
    _reserved22: [u8; 0x0c],
    config_device_width: ConfigDeviceWidth,
    _reserved23: [u8; 0x0c],
    config_device_main_area_size: ConfigDeviceMainAreaSize,
    _reserved24: [u8; 0x0c],
    config_device_spare_area_size: ConfigDeviceSpareAreaSize,
    _reserved25: [u8; 0x0c],
    config_two_row_addr_cycles: ConfigTwoRowAddrCycles,
    _reserved26: [u8; 0x0c],
    config_multiplane_addr_restrict: ConfigMultiplaneAddrRestrict,
    _reserved27: [u8; 0x0c],
    config_ecc_correction: ConfigEccCorrection,
    _reserved28: [u8; 0x0c],
    config_read_mode: ConfigReadMode,
    _reserved29: [u8; 0x0c],
    config_write_mode: ConfigWriteMode,
    _reserved30: [u8; 0x0c],
    config_copyback_mode: ConfigCopybackMode,
    _reserved31: [u8; 0x0c],
    config_rdwr_en_lo_cnt: ConfigRdwrEnLoCnt,
    _reserved32: [u8; 0x0c],
    config_rdwr_en_hi_cnt: ConfigRdwrEnHiCnt,
    _reserved33: [u8; 0x0c],
    config_max_rd_delay: ConfigMaxRdDelay,
    _reserved34: [u8; 0x0c],
    config_cs_setup_cnt: ConfigCsSetupCnt,
    _reserved35: [u8; 0x0c],
    config_spare_area_skip_bytes: ConfigSpareAreaSkipBytes,
    _reserved36: [u8; 0x0c],
    config_spare_area_marker: ConfigSpareAreaMarker,
    _reserved37: [u8; 0x0c],
    config_devices_connected: ConfigDevicesConnected,
    _reserved38: [u8; 0x0c],
    config_die_mask: ConfigDieMask,
    _reserved39: [u8; 0x0c],
    config_first_block_of_next_plane: ConfigFirstBlockOfNextPlane,
    _reserved40: [u8; 0x0c],
    config_write_protect: ConfigWriteProtect,
    _reserved41: [u8; 0x0c],
    config_re_2_re: ConfigRe2Re,
    _reserved42: [u8; 0x0c],
    config_por_reset_count: ConfigPorResetCount,
    _reserved43: [u8; 0x0c],
    config_watchdog_reset_count: ConfigWatchdogResetCount,
    _reserved44: [u8; 0x4c],
    param_manufacturer_id: ParamManufacturerId,
    _reserved45: [u8; 0x0c],
    param_device_id: ParamDeviceId,
    _reserved46: [u8; 0x0c],
    param_device_param_0: ParamDeviceParam0,
    _reserved47: [u8; 0x0c],
    param_device_param_1: ParamDeviceParam1,
    _reserved48: [u8; 0x0c],
    param_device_param_2: ParamDeviceParam2,
    _reserved49: [u8; 0x0c],
    param_logical_page_data_size: ParamLogicalPageDataSize,
    _reserved50: [u8; 0x0c],
    param_logical_page_spare_size: ParamLogicalPageSpareSize,
    _reserved51: [u8; 0x0c],
    param_revision: ParamRevision,
    _reserved52: [u8; 0x0c],
    param_onfi_device_features: ParamOnfiDeviceFeatures,
    _reserved53: [u8; 0x0c],
    param_onfi_optional_commands: ParamOnfiOptionalCommands,
    _reserved54: [u8; 0x0c],
    param_onfi_timing_mode: ParamOnfiTimingMode,
    _reserved55: [u8; 0x0c],
    param_onfi_pgm_cache_timing_mode: ParamOnfiPgmCacheTimingMode,
    _reserved56: [u8; 0x0c],
    param_onfi_device_no_of_luns: ParamOnfiDeviceNoOfLuns,
    _reserved57: [u8; 0x0c],
    param_onfi_device_no_of_blocks_per_lun_l: ParamOnfiDeviceNoOfBlocksPerLunL,
    _reserved58: [u8; 0x0c],
    param_onfi_device_no_of_blocks_per_lun_u: ParamOnfiDeviceNoOfBlocksPerLunU,
    _reserved59: [u8; 0x0c],
    param_features: ParamFeatures,
    _reserved60: [u8; 0x0c],
    status_transfer_mode: StatusTransferMode,
    _reserved61: [u8; 0x0c],
    status_intr_status0: StatusIntrStatus0,
    _reserved62: [u8; 0x0c],
    status_intr_en0: StatusIntrEn0,
    _reserved63: [u8; 0x0c],
    status_page_cnt0: StatusPageCnt0,
    _reserved64: [u8; 0x0c],
    status_err_page_addr0: StatusErrPageAddr0,
    _reserved65: [u8; 0x0c],
    status_err_block_addr0: StatusErrBlockAddr0,
    _reserved66: [u8; 0x0c],
    status_intr_status1: StatusIntrStatus1,
    _reserved67: [u8; 0x0c],
    status_intr_en1: StatusIntrEn1,
    _reserved68: [u8; 0x0c],
    status_page_cnt1: StatusPageCnt1,
    _reserved69: [u8; 0x0c],
    status_err_page_addr1: StatusErrPageAddr1,
    _reserved70: [u8; 0x0c],
    status_err_block_addr1: StatusErrBlockAddr1,
    _reserved71: [u8; 0x0c],
    status_intr_status2: StatusIntrStatus2,
    _reserved72: [u8; 0x0c],
    status_intr_en2: StatusIntrEn2,
    _reserved73: [u8; 0x0c],
    status_page_cnt2: StatusPageCnt2,
    _reserved74: [u8; 0x0c],
    status_err_page_addr2: StatusErrPageAddr2,
    _reserved75: [u8; 0x0c],
    status_err_block_addr2: StatusErrBlockAddr2,
    _reserved76: [u8; 0x0c],
    status_intr_status3: StatusIntrStatus3,
    _reserved77: [u8; 0x0c],
    status_intr_en3: StatusIntrEn3,
    _reserved78: [u8; 0x0c],
    status_page_cnt3: StatusPageCnt3,
    _reserved79: [u8; 0x0c],
    status_err_page_addr3: StatusErrPageAddr3,
    _reserved80: [u8; 0x0c],
    status_err_block_addr3: StatusErrBlockAddr3,
    _reserved81: [u8; 0x010c],
    ecc_ecccor_info_b01: EccEcccorInfoB01,
    _reserved82: [u8; 0x0c],
    ecc_ecccor_info_b23: EccEcccorInfoB23,
    _reserved83: [u8; 0x9c],
    dma_dma_enable: DmaDmaEnable,
    _reserved84: [u8; 0x1c],
    dma_dma_intr: DmaDmaIntr,
    _reserved85: [u8; 0x0c],
    dma_dma_intr_en: DmaDmaIntrEn,
    _reserved86: [u8; 0x0c],
    dma_target_err_addr_lo: DmaTargetErrAddrLo,
    _reserved87: [u8; 0x0c],
    dma_target_err_addr_hi: DmaTargetErrAddrHi,
    _reserved88: [u8; 0x1c],
    dma_flash_burst_length: DmaFlashBurstLength,
    _reserved89: [u8; 0x0c],
    dma_chip_interleave_enable_and_allow_int_reads: DmaChipInterleaveEnableAndAllowIntReads,
    _reserved90: [u8; 0x0c],
    dma_no_of_blocks_per_lun: DmaNoOfBlocksPerLun,
    _reserved91: [u8; 0x0c],
    dma_lun_status_cmd: DmaLunStatusCmd,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Device reset. Controller sends a RESET command to device. Controller resets bit after sending command to device"]
    #[inline(always)]
    pub const fn config_device_reset(&self) -> &ConfigDeviceReset {
        &self.config_device_reset
    }
    #[doc = "0x10 - Default data transfer mode. (Ignored during Spare only mode)"]
    #[inline(always)]
    pub const fn config_transfer_spare_reg(&self) -> &ConfigTransferSpareReg {
        &self.config_transfer_spare_reg
    }
    #[doc = "0x20 - Wait count value for Load operation"]
    #[inline(always)]
    pub const fn config_load_wait_cnt(&self) -> &ConfigLoadWaitCnt {
        &self.config_load_wait_cnt
    }
    #[doc = "0x30 - Wait count value for Program operation"]
    #[inline(always)]
    pub const fn config_program_wait_cnt(&self) -> &ConfigProgramWaitCnt {
        &self.config_program_wait_cnt
    }
    #[doc = "0x40 - Wait count value for Erase operation"]
    #[inline(always)]
    pub const fn config_erase_wait_cnt(&self) -> &ConfigEraseWaitCnt {
        &self.config_erase_wait_cnt
    }
    #[doc = "0x50 - Interrupt monitor cycle count value"]
    #[inline(always)]
    pub const fn config_int_mon_cyccnt(&self) -> &ConfigIntMonCyccnt {
        &self.config_int_mon_cyccnt
    }
    #[doc = "0x60 - Interrupt or polling mode. Ready/Busy pin is enabled from device."]
    #[inline(always)]
    pub const fn config_rb_pin_enabled(&self) -> &ConfigRbPinEnabled {
        &self.config_rb_pin_enabled
    }
    #[doc = "0x70 - Multiplane transfer mode. Pipelined read, copyback, erase and program commands are transfered in multiplane mode"]
    #[inline(always)]
    pub const fn config_multiplane_operation(&self) -> &ConfigMultiplaneOperation {
        &self.config_multiplane_operation
    }
    #[doc = "0x80 - Device supports multiplane read command sequence"]
    #[inline(always)]
    pub const fn config_multiplane_read_enable(&self) -> &ConfigMultiplaneReadEnable {
        &self.config_multiplane_read_enable
    }
    #[doc = "0x90 - Device does not support copyback command sequence"]
    #[inline(always)]
    pub const fn config_copyback_disable(&self) -> &ConfigCopybackDisable {
        &self.config_copyback_disable
    }
    #[doc = "0xa0 - Device supports cache write command sequence"]
    #[inline(always)]
    pub const fn config_cache_write_enable(&self) -> &ConfigCacheWriteEnable {
        &self.config_cache_write_enable
    }
    #[doc = "0xb0 - Device supports cache read command sequence"]
    #[inline(always)]
    pub const fn config_cache_read_enable(&self) -> &ConfigCacheReadEnable {
        &self.config_cache_read_enable
    }
    #[doc = "0xc0 - Enables read data prefetching to faster performance"]
    #[inline(always)]
    pub const fn config_prefetch_mode(&self) -> &ConfigPrefetchMode {
        &self.config_prefetch_mode
    }
    #[doc = "0xd0 - Device can work in the chip enable dont care mode"]
    #[inline(always)]
    pub const fn config_chip_enable_dont_care(&self) -> &ConfigChipEnableDontCare {
        &self.config_chip_enable_dont_care
    }
    #[doc = "0xe0 - Enable controller ECC check bit generation and correction"]
    #[inline(always)]
    pub const fn config_ecc_enable(&self) -> &ConfigEccEnable {
        &self.config_ecc_enable
    }
    #[doc = "0xf0 - Global Interrupt enable and Error/Timeout disable."]
    #[inline(always)]
    pub const fn config_global_int_enable(&self) -> &ConfigGlobalIntEnable {
        &self.config_global_int_enable
    }
    #[doc = "0x100 - "]
    #[inline(always)]
    pub const fn config_twhr2_and_we_2_re(&self) -> &ConfigTwhr2AndWe2Re {
        &self.config_twhr2_and_we_2_re
    }
    #[doc = "0x110 - "]
    #[inline(always)]
    pub const fn config_tcwaw_and_addr_2_data(&self) -> &ConfigTcwawAndAddr2Data {
        &self.config_tcwaw_and_addr_2_data
    }
    #[doc = "0x120 - Timing parameter between re high to we low (Trhw)"]
    #[inline(always)]
    pub const fn config_re_2_we(&self) -> &ConfigRe2We {
        &self.config_re_2_we
    }
    #[doc = "0x130 - Timing parameter from read enable going low to capture read data"]
    #[inline(always)]
    pub const fn config_acc_clks(&self) -> &ConfigAccClks {
        &self.config_acc_clks
    }
    #[doc = "0x140 - Number of planes in the device"]
    #[inline(always)]
    pub const fn config_number_of_planes(&self) -> &ConfigNumberOfPlanes {
        &self.config_number_of_planes
    }
    #[doc = "0x150 - Number of pages in a block"]
    #[inline(always)]
    pub const fn config_pages_per_block(&self) -> &ConfigPagesPerBlock {
        &self.config_pages_per_block
    }
    #[doc = "0x160 - I/O width of attached devices"]
    #[inline(always)]
    pub const fn config_device_width(&self) -> &ConfigDeviceWidth {
        &self.config_device_width
    }
    #[doc = "0x170 - Page main area size of device in bytes"]
    #[inline(always)]
    pub const fn config_device_main_area_size(&self) -> &ConfigDeviceMainAreaSize {
        &self.config_device_main_area_size
    }
    #[doc = "0x180 - Page spare area size of device in bytes"]
    #[inline(always)]
    pub const fn config_device_spare_area_size(&self) -> &ConfigDeviceSpareAreaSize {
        &self.config_device_spare_area_size
    }
    #[doc = "0x190 - Attached device has only 2 ROW address cycles"]
    #[inline(always)]
    pub const fn config_two_row_addr_cycles(&self) -> &ConfigTwoRowAddrCycles {
        &self.config_two_row_addr_cycles
    }
    #[doc = "0x1a0 - Address restriction for multiplane commands"]
    #[inline(always)]
    pub const fn config_multiplane_addr_restrict(&self) -> &ConfigMultiplaneAddrRestrict {
        &self.config_multiplane_addr_restrict
    }
    #[doc = "0x1b0 - Correction capability required"]
    #[inline(always)]
    pub const fn config_ecc_correction(&self) -> &ConfigEccCorrection {
        &self.config_ecc_correction
    }
    #[doc = "0x1c0 - The type of read sequence that the controller will follow for pipe read commands."]
    #[inline(always)]
    pub const fn config_read_mode(&self) -> &ConfigReadMode {
        &self.config_read_mode
    }
    #[doc = "0x1d0 - The type of write sequence that the controller will follow for pipe write commands."]
    #[inline(always)]
    pub const fn config_write_mode(&self) -> &ConfigWriteMode {
        &self.config_write_mode
    }
    #[doc = "0x1e0 - The type of copyback sequence that the controller will follow."]
    #[inline(always)]
    pub const fn config_copyback_mode(&self) -> &ConfigCopybackMode {
        &self.config_copyback_mode
    }
    #[doc = "0x1f0 - Read/Write Enable low pulse width"]
    #[inline(always)]
    pub const fn config_rdwr_en_lo_cnt(&self) -> &ConfigRdwrEnLoCnt {
        &self.config_rdwr_en_lo_cnt
    }
    #[doc = "0x200 - Read/Write Enable high pulse width"]
    #[inline(always)]
    pub const fn config_rdwr_en_hi_cnt(&self) -> &ConfigRdwrEnHiCnt {
        &self.config_rdwr_en_hi_cnt
    }
    #[doc = "0x210 - Max round trip read data delay for data capture"]
    #[inline(always)]
    pub const fn config_max_rd_delay(&self) -> &ConfigMaxRdDelay {
        &self.config_max_rd_delay
    }
    #[doc = "0x220 - Chip select setup time"]
    #[inline(always)]
    pub const fn config_cs_setup_cnt(&self) -> &ConfigCsSetupCnt {
        &self.config_cs_setup_cnt
    }
    #[doc = "0x230 - Spare area skip bytes"]
    #[inline(always)]
    pub const fn config_spare_area_skip_bytes(&self) -> &ConfigSpareAreaSkipBytes {
        &self.config_spare_area_skip_bytes
    }
    #[doc = "0x240 - Spare area marker value"]
    #[inline(always)]
    pub const fn config_spare_area_marker(&self) -> &ConfigSpareAreaMarker {
        &self.config_spare_area_marker
    }
    #[doc = "0x250 - Number of Devices connected on one bank"]
    #[inline(always)]
    pub const fn config_devices_connected(&self) -> &ConfigDevicesConnected {
        &self.config_devices_connected
    }
    #[doc = "0x260 - Indicates the die differentiator in case of NAND devices with stacked dies."]
    #[inline(always)]
    pub const fn config_die_mask(&self) -> &ConfigDieMask {
        &self.config_die_mask
    }
    #[doc = "0x270 - The starting block address of the next plane in a multi plane device."]
    #[inline(always)]
    pub const fn config_first_block_of_next_plane(&self) -> &ConfigFirstBlockOfNextPlane {
        &self.config_first_block_of_next_plane
    }
    #[doc = "0x280 - This register is used to control the assertion/de-assertion of the WP# pin to the device."]
    #[inline(always)]
    pub const fn config_write_protect(&self) -> &ConfigWriteProtect {
        &self.config_write_protect
    }
    #[doc = "0x290 - Timing parameter between re high to re low (Trhz) for the next bank"]
    #[inline(always)]
    pub const fn config_re_2_re(&self) -> &ConfigRe2Re {
        &self.config_re_2_re
    }
    #[doc = "0x2a0 - The number of cycles the controller waits after reset to issue the first RESET command to the device."]
    #[inline(always)]
    pub const fn config_por_reset_count(&self) -> &ConfigPorResetCount {
        &self.config_por_reset_count
    }
    #[doc = "0x2b0 - The number of cycles the controller waits before flagging a watchdog timeout interrupt."]
    #[inline(always)]
    pub const fn config_watchdog_reset_count(&self) -> &ConfigWatchdogResetCount {
        &self.config_watchdog_reset_count
    }
    #[doc = "0x300 - "]
    #[inline(always)]
    pub const fn param_manufacturer_id(&self) -> &ParamManufacturerId {
        &self.param_manufacturer_id
    }
    #[doc = "0x310 - "]
    #[inline(always)]
    pub const fn param_device_id(&self) -> &ParamDeviceId {
        &self.param_device_id
    }
    #[doc = "0x320 - "]
    #[inline(always)]
    pub const fn param_device_param_0(&self) -> &ParamDeviceParam0 {
        &self.param_device_param_0
    }
    #[doc = "0x330 - "]
    #[inline(always)]
    pub const fn param_device_param_1(&self) -> &ParamDeviceParam1 {
        &self.param_device_param_1
    }
    #[doc = "0x340 - "]
    #[inline(always)]
    pub const fn param_device_param_2(&self) -> &ParamDeviceParam2 {
        &self.param_device_param_2
    }
    #[doc = "0x350 - Logical page data area size in bytes"]
    #[inline(always)]
    pub const fn param_logical_page_data_size(&self) -> &ParamLogicalPageDataSize {
        &self.param_logical_page_data_size
    }
    #[doc = "0x360 - Logical page data area size in bytes"]
    #[inline(always)]
    pub const fn param_logical_page_spare_size(&self) -> &ParamLogicalPageSpareSize {
        &self.param_logical_page_spare_size
    }
    #[doc = "0x370 - Controller revision number"]
    #[inline(always)]
    pub const fn param_revision(&self) -> &ParamRevision {
        &self.param_revision
    }
    #[doc = "0x380 - Features supported by the connected ONFI device"]
    #[inline(always)]
    pub const fn param_onfi_device_features(&self) -> &ParamOnfiDeviceFeatures {
        &self.param_onfi_device_features
    }
    #[doc = "0x390 - Optional commands supported by the connected ONFI device"]
    #[inline(always)]
    pub const fn param_onfi_optional_commands(&self) -> &ParamOnfiOptionalCommands {
        &self.param_onfi_optional_commands
    }
    #[doc = "0x3a0 - Asynchronous Timing modes supported by the connected ONFI device"]
    #[inline(always)]
    pub const fn param_onfi_timing_mode(&self) -> &ParamOnfiTimingMode {
        &self.param_onfi_timing_mode
    }
    #[doc = "0x3b0 - Asynchronous Program Cache Timing modes supported by the connected ONFI device"]
    #[inline(always)]
    pub const fn param_onfi_pgm_cache_timing_mode(&self) -> &ParamOnfiPgmCacheTimingMode {
        &self.param_onfi_pgm_cache_timing_mode
    }
    #[doc = "0x3c0 - Indicates if the device is an ONFI compliant device and the number of LUNS present in the device"]
    #[inline(always)]
    pub const fn param_onfi_device_no_of_luns(&self) -> &ParamOnfiDeviceNoOfLuns {
        &self.param_onfi_device_no_of_luns
    }
    #[doc = "0x3d0 - Lower bits of number of blocks per LUN present in the ONFI complaint device."]
    #[inline(always)]
    pub const fn param_onfi_device_no_of_blocks_per_lun_l(
        &self,
    ) -> &ParamOnfiDeviceNoOfBlocksPerLunL {
        &self.param_onfi_device_no_of_blocks_per_lun_l
    }
    #[doc = "0x3e0 - Upper bits of number of blocks per LUN present in the ONFI complaint device."]
    #[inline(always)]
    pub const fn param_onfi_device_no_of_blocks_per_lun_u(
        &self,
    ) -> &ParamOnfiDeviceNoOfBlocksPerLunU {
        &self.param_onfi_device_no_of_blocks_per_lun_u
    }
    #[doc = "0x3f0 - Shows Available hardware features or attributes"]
    #[inline(always)]
    pub const fn param_features(&self) -> &ParamFeatures {
        &self.param_features
    }
    #[doc = "0x400 - Current data transfer mode is Main only, Spare only or Main+Spare. This information is per bank."]
    #[inline(always)]
    pub const fn status_transfer_mode(&self) -> &StatusTransferMode {
        &self.status_transfer_mode
    }
    #[doc = "0x410 - Interrupt status register for bank 0"]
    #[inline(always)]
    pub const fn status_intr_status0(&self) -> &StatusIntrStatus0 {
        &self.status_intr_status0
    }
    #[doc = "0x420 - Enables corresponding interrupt bit in interrupt register for bank 0"]
    #[inline(always)]
    pub const fn status_intr_en0(&self) -> &StatusIntrEn0 {
        &self.status_intr_en0
    }
    #[doc = "0x430 - Decrementing page count bank 0"]
    #[inline(always)]
    pub const fn status_page_cnt0(&self) -> &StatusPageCnt0 {
        &self.status_page_cnt0
    }
    #[doc = "0x440 - Erred page address bank 0"]
    #[inline(always)]
    pub const fn status_err_page_addr0(&self) -> &StatusErrPageAddr0 {
        &self.status_err_page_addr0
    }
    #[doc = "0x450 - Erred block address bank 0"]
    #[inline(always)]
    pub const fn status_err_block_addr0(&self) -> &StatusErrBlockAddr0 {
        &self.status_err_block_addr0
    }
    #[doc = "0x460 - Interrupt status register for bank 1"]
    #[inline(always)]
    pub const fn status_intr_status1(&self) -> &StatusIntrStatus1 {
        &self.status_intr_status1
    }
    #[doc = "0x470 - Enables corresponding interrupt bit in interrupt register for bank 1"]
    #[inline(always)]
    pub const fn status_intr_en1(&self) -> &StatusIntrEn1 {
        &self.status_intr_en1
    }
    #[doc = "0x480 - Decrementing page count bank 1"]
    #[inline(always)]
    pub const fn status_page_cnt1(&self) -> &StatusPageCnt1 {
        &self.status_page_cnt1
    }
    #[doc = "0x490 - Erred page address bank 1"]
    #[inline(always)]
    pub const fn status_err_page_addr1(&self) -> &StatusErrPageAddr1 {
        &self.status_err_page_addr1
    }
    #[doc = "0x4a0 - Erred block address bank 1"]
    #[inline(always)]
    pub const fn status_err_block_addr1(&self) -> &StatusErrBlockAddr1 {
        &self.status_err_block_addr1
    }
    #[doc = "0x4b0 - Interrupt status register for bank 2"]
    #[inline(always)]
    pub const fn status_intr_status2(&self) -> &StatusIntrStatus2 {
        &self.status_intr_status2
    }
    #[doc = "0x4c0 - Enables corresponding interrupt bit in interrupt register for bank 2"]
    #[inline(always)]
    pub const fn status_intr_en2(&self) -> &StatusIntrEn2 {
        &self.status_intr_en2
    }
    #[doc = "0x4d0 - Decrementing page count bank 2"]
    #[inline(always)]
    pub const fn status_page_cnt2(&self) -> &StatusPageCnt2 {
        &self.status_page_cnt2
    }
    #[doc = "0x4e0 - Erred page address bank 2"]
    #[inline(always)]
    pub const fn status_err_page_addr2(&self) -> &StatusErrPageAddr2 {
        &self.status_err_page_addr2
    }
    #[doc = "0x4f0 - Erred block address bank 2"]
    #[inline(always)]
    pub const fn status_err_block_addr2(&self) -> &StatusErrBlockAddr2 {
        &self.status_err_block_addr2
    }
    #[doc = "0x500 - Interrupt status register for bank 3"]
    #[inline(always)]
    pub const fn status_intr_status3(&self) -> &StatusIntrStatus3 {
        &self.status_intr_status3
    }
    #[doc = "0x510 - Enables corresponding interrupt bit in interrupt register for bank 3"]
    #[inline(always)]
    pub const fn status_intr_en3(&self) -> &StatusIntrEn3 {
        &self.status_intr_en3
    }
    #[doc = "0x520 - Decrementing page count bank 3"]
    #[inline(always)]
    pub const fn status_page_cnt3(&self) -> &StatusPageCnt3 {
        &self.status_page_cnt3
    }
    #[doc = "0x530 - Erred page address bank 3"]
    #[inline(always)]
    pub const fn status_err_page_addr3(&self) -> &StatusErrPageAddr3 {
        &self.status_err_page_addr3
    }
    #[doc = "0x540 - Erred block address bank 3"]
    #[inline(always)]
    pub const fn status_err_block_addr3(&self) -> &StatusErrBlockAddr3 {
        &self.status_err_block_addr3
    }
    #[doc = "0x650 - ECC Error correction Information register. Controller updates this register when it completes a transaction. The values are held in this register till a new transaction completes."]
    #[inline(always)]
    pub const fn ecc_ecccor_info_b01(&self) -> &EccEcccorInfoB01 {
        &self.ecc_ecccor_info_b01
    }
    #[doc = "0x660 - ECC Error correction Information register. Controller updates this register when it completes a transaction. The values are held in this register till a new transaction completes."]
    #[inline(always)]
    pub const fn ecc_ecccor_info_b23(&self) -> &EccEcccorInfoB23 {
        &self.ecc_ecccor_info_b23
    }
    #[doc = "0x700 - "]
    #[inline(always)]
    pub const fn dma_dma_enable(&self) -> &DmaDmaEnable {
        &self.dma_dma_enable
    }
    #[doc = "0x720 - DMA interrupt register"]
    #[inline(always)]
    pub const fn dma_dma_intr(&self) -> &DmaDmaIntr {
        &self.dma_dma_intr
    }
    #[doc = "0x730 - Enables corresponding interrupt bit in dma interrupt register"]
    #[inline(always)]
    pub const fn dma_dma_intr_en(&self) -> &DmaDmaIntrEn {
        &self.dma_dma_intr_en
    }
    #[doc = "0x740 - Transaction address for which controller initiator interface received an ERROR target response."]
    #[inline(always)]
    pub const fn dma_target_err_addr_lo(&self) -> &DmaTargetErrAddrLo {
        &self.dma_target_err_addr_lo
    }
    #[doc = "0x750 - Transaction address for which controller initiator interface received an ERROR target response."]
    #[inline(always)]
    pub const fn dma_target_err_addr_hi(&self) -> &DmaTargetErrAddrHi {
        &self.dma_target_err_addr_hi
    }
    #[doc = "0x770 - "]
    #[inline(always)]
    pub const fn dma_flash_burst_length(&self) -> &DmaFlashBurstLength {
        &self.dma_flash_burst_length
    }
    #[doc = "0x780 - "]
    #[inline(always)]
    pub const fn dma_chip_interleave_enable_and_allow_int_reads(
        &self,
    ) -> &DmaChipInterleaveEnableAndAllowIntReads {
        &self.dma_chip_interleave_enable_and_allow_int_reads
    }
    #[doc = "0x790 - "]
    #[inline(always)]
    pub const fn dma_no_of_blocks_per_lun(&self) -> &DmaNoOfBlocksPerLun {
        &self.dma_no_of_blocks_per_lun
    }
    #[doc = "0x7a0 - Indicates the command to be sent while checking status of the next LUN."]
    #[inline(always)]
    pub const fn dma_lun_status_cmd(&self) -> &DmaLunStatusCmd {
        &self.dma_lun_status_cmd
    }
}
#[doc = "config_device_reset (rw) register accessor: Device reset. Controller sends a RESET command to device. Controller resets bit after sending command to device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_device_reset::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_device_reset::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_device_reset`]
module"]
#[doc(alias = "config_device_reset")]
pub type ConfigDeviceReset = crate::Reg<config_device_reset::ConfigDeviceResetSpec>;
#[doc = "Device reset. Controller sends a RESET command to device. Controller resets bit after sending command to device"]
pub mod config_device_reset;
#[doc = "config_transfer_spare_reg (rw) register accessor: Default data transfer mode. (Ignored during Spare only mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_transfer_spare_reg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_transfer_spare_reg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_transfer_spare_reg`]
module"]
#[doc(alias = "config_transfer_spare_reg")]
pub type ConfigTransferSpareReg = crate::Reg<config_transfer_spare_reg::ConfigTransferSpareRegSpec>;
#[doc = "Default data transfer mode. (Ignored during Spare only mode)"]
pub mod config_transfer_spare_reg;
#[doc = "config_load_wait_cnt (rw) register accessor: Wait count value for Load operation\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_load_wait_cnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_load_wait_cnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_load_wait_cnt`]
module"]
#[doc(alias = "config_load_wait_cnt")]
pub type ConfigLoadWaitCnt = crate::Reg<config_load_wait_cnt::ConfigLoadWaitCntSpec>;
#[doc = "Wait count value for Load operation"]
pub mod config_load_wait_cnt;
#[doc = "config_program_wait_cnt (rw) register accessor: Wait count value for Program operation\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_program_wait_cnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_program_wait_cnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_program_wait_cnt`]
module"]
#[doc(alias = "config_program_wait_cnt")]
pub type ConfigProgramWaitCnt = crate::Reg<config_program_wait_cnt::ConfigProgramWaitCntSpec>;
#[doc = "Wait count value for Program operation"]
pub mod config_program_wait_cnt;
#[doc = "config_erase_wait_cnt (rw) register accessor: Wait count value for Erase operation\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_erase_wait_cnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_erase_wait_cnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_erase_wait_cnt`]
module"]
#[doc(alias = "config_erase_wait_cnt")]
pub type ConfigEraseWaitCnt = crate::Reg<config_erase_wait_cnt::ConfigEraseWaitCntSpec>;
#[doc = "Wait count value for Erase operation"]
pub mod config_erase_wait_cnt;
#[doc = "config_int_mon_cyccnt (rw) register accessor: Interrupt monitor cycle count value\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_int_mon_cyccnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_int_mon_cyccnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_int_mon_cyccnt`]
module"]
#[doc(alias = "config_int_mon_cyccnt")]
pub type ConfigIntMonCyccnt = crate::Reg<config_int_mon_cyccnt::ConfigIntMonCyccntSpec>;
#[doc = "Interrupt monitor cycle count value"]
pub mod config_int_mon_cyccnt;
#[doc = "config_rb_pin_enabled (rw) register accessor: Interrupt or polling mode. Ready/Busy pin is enabled from device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_rb_pin_enabled::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_rb_pin_enabled::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_rb_pin_enabled`]
module"]
#[doc(alias = "config_rb_pin_enabled")]
pub type ConfigRbPinEnabled = crate::Reg<config_rb_pin_enabled::ConfigRbPinEnabledSpec>;
#[doc = "Interrupt or polling mode. Ready/Busy pin is enabled from device."]
pub mod config_rb_pin_enabled;
#[doc = "config_multiplane_operation (rw) register accessor: Multiplane transfer mode. Pipelined read, copyback, erase and program commands are transfered in multiplane mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_multiplane_operation::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_multiplane_operation::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_multiplane_operation`]
module"]
#[doc(alias = "config_multiplane_operation")]
pub type ConfigMultiplaneOperation =
    crate::Reg<config_multiplane_operation::ConfigMultiplaneOperationSpec>;
#[doc = "Multiplane transfer mode. Pipelined read, copyback, erase and program commands are transfered in multiplane mode"]
pub mod config_multiplane_operation;
#[doc = "config_multiplane_read_enable (rw) register accessor: Device supports multiplane read command sequence\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_multiplane_read_enable::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_multiplane_read_enable::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_multiplane_read_enable`]
module"]
#[doc(alias = "config_multiplane_read_enable")]
pub type ConfigMultiplaneReadEnable =
    crate::Reg<config_multiplane_read_enable::ConfigMultiplaneReadEnableSpec>;
#[doc = "Device supports multiplane read command sequence"]
pub mod config_multiplane_read_enable;
#[doc = "config_copyback_disable (rw) register accessor: Device does not support copyback command sequence\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_copyback_disable::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_copyback_disable::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_copyback_disable`]
module"]
#[doc(alias = "config_copyback_disable")]
pub type ConfigCopybackDisable = crate::Reg<config_copyback_disable::ConfigCopybackDisableSpec>;
#[doc = "Device does not support copyback command sequence"]
pub mod config_copyback_disable;
#[doc = "config_cache_write_enable (rw) register accessor: Device supports cache write command sequence\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_cache_write_enable::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_cache_write_enable::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_cache_write_enable`]
module"]
#[doc(alias = "config_cache_write_enable")]
pub type ConfigCacheWriteEnable = crate::Reg<config_cache_write_enable::ConfigCacheWriteEnableSpec>;
#[doc = "Device supports cache write command sequence"]
pub mod config_cache_write_enable;
#[doc = "config_cache_read_enable (rw) register accessor: Device supports cache read command sequence\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_cache_read_enable::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_cache_read_enable::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_cache_read_enable`]
module"]
#[doc(alias = "config_cache_read_enable")]
pub type ConfigCacheReadEnable = crate::Reg<config_cache_read_enable::ConfigCacheReadEnableSpec>;
#[doc = "Device supports cache read command sequence"]
pub mod config_cache_read_enable;
#[doc = "config_prefetch_mode (rw) register accessor: Enables read data prefetching to faster performance\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_prefetch_mode::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_prefetch_mode::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_prefetch_mode`]
module"]
#[doc(alias = "config_prefetch_mode")]
pub type ConfigPrefetchMode = crate::Reg<config_prefetch_mode::ConfigPrefetchModeSpec>;
#[doc = "Enables read data prefetching to faster performance"]
pub mod config_prefetch_mode;
#[doc = "config_chip_enable_dont_care (rw) register accessor: Device can work in the chip enable dont care mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_chip_enable_dont_care::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_chip_enable_dont_care::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_chip_enable_dont_care`]
module"]
#[doc(alias = "config_chip_enable_dont_care")]
pub type ConfigChipEnableDontCare =
    crate::Reg<config_chip_enable_dont_care::ConfigChipEnableDontCareSpec>;
#[doc = "Device can work in the chip enable dont care mode"]
pub mod config_chip_enable_dont_care;
#[doc = "config_ecc_enable (rw) register accessor: Enable controller ECC check bit generation and correction\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_ecc_enable::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_ecc_enable::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_ecc_enable`]
module"]
#[doc(alias = "config_ecc_enable")]
pub type ConfigEccEnable = crate::Reg<config_ecc_enable::ConfigEccEnableSpec>;
#[doc = "Enable controller ECC check bit generation and correction"]
pub mod config_ecc_enable;
#[doc = "config_global_int_enable (rw) register accessor: Global Interrupt enable and Error/Timeout disable.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_global_int_enable::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_global_int_enable::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_global_int_enable`]
module"]
#[doc(alias = "config_global_int_enable")]
pub type ConfigGlobalIntEnable = crate::Reg<config_global_int_enable::ConfigGlobalIntEnableSpec>;
#[doc = "Global Interrupt enable and Error/Timeout disable."]
pub mod config_global_int_enable;
#[doc = "config_twhr2_and_we_2_re (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_twhr2_and_we_2_re::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_twhr2_and_we_2_re::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_twhr2_and_we_2_re`]
module"]
#[doc(alias = "config_twhr2_and_we_2_re")]
pub type ConfigTwhr2AndWe2Re = crate::Reg<config_twhr2_and_we_2_re::ConfigTwhr2AndWe2ReSpec>;
#[doc = ""]
pub mod config_twhr2_and_we_2_re;
#[doc = "config_tcwaw_and_addr_2_data (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_tcwaw_and_addr_2_data::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_tcwaw_and_addr_2_data::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_tcwaw_and_addr_2_data`]
module"]
#[doc(alias = "config_tcwaw_and_addr_2_data")]
pub type ConfigTcwawAndAddr2Data =
    crate::Reg<config_tcwaw_and_addr_2_data::ConfigTcwawAndAddr2DataSpec>;
#[doc = ""]
pub mod config_tcwaw_and_addr_2_data;
#[doc = "config_re_2_we (rw) register accessor: Timing parameter between re high to we low (Trhw)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_re_2_we::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_re_2_we::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_re_2_we`]
module"]
#[doc(alias = "config_re_2_we")]
pub type ConfigRe2We = crate::Reg<config_re_2_we::ConfigRe2WeSpec>;
#[doc = "Timing parameter between re high to we low (Trhw)"]
pub mod config_re_2_we;
#[doc = "config_acc_clks (rw) register accessor: Timing parameter from read enable going low to capture read data\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_acc_clks::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_acc_clks::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_acc_clks`]
module"]
#[doc(alias = "config_acc_clks")]
pub type ConfigAccClks = crate::Reg<config_acc_clks::ConfigAccClksSpec>;
#[doc = "Timing parameter from read enable going low to capture read data"]
pub mod config_acc_clks;
#[doc = "config_number_of_planes (rw) register accessor: Number of planes in the device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_number_of_planes::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_number_of_planes::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_number_of_planes`]
module"]
#[doc(alias = "config_number_of_planes")]
pub type ConfigNumberOfPlanes = crate::Reg<config_number_of_planes::ConfigNumberOfPlanesSpec>;
#[doc = "Number of planes in the device"]
pub mod config_number_of_planes;
#[doc = "config_pages_per_block (rw) register accessor: Number of pages in a block\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_pages_per_block::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_pages_per_block::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_pages_per_block`]
module"]
#[doc(alias = "config_pages_per_block")]
pub type ConfigPagesPerBlock = crate::Reg<config_pages_per_block::ConfigPagesPerBlockSpec>;
#[doc = "Number of pages in a block"]
pub mod config_pages_per_block;
#[doc = "config_device_width (rw) register accessor: I/O width of attached devices\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_device_width::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_device_width::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_device_width`]
module"]
#[doc(alias = "config_device_width")]
pub type ConfigDeviceWidth = crate::Reg<config_device_width::ConfigDeviceWidthSpec>;
#[doc = "I/O width of attached devices"]
pub mod config_device_width;
#[doc = "config_device_main_area_size (rw) register accessor: Page main area size of device in bytes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_device_main_area_size::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_device_main_area_size::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_device_main_area_size`]
module"]
#[doc(alias = "config_device_main_area_size")]
pub type ConfigDeviceMainAreaSize =
    crate::Reg<config_device_main_area_size::ConfigDeviceMainAreaSizeSpec>;
#[doc = "Page main area size of device in bytes"]
pub mod config_device_main_area_size;
#[doc = "config_device_spare_area_size (rw) register accessor: Page spare area size of device in bytes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_device_spare_area_size::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_device_spare_area_size::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_device_spare_area_size`]
module"]
#[doc(alias = "config_device_spare_area_size")]
pub type ConfigDeviceSpareAreaSize =
    crate::Reg<config_device_spare_area_size::ConfigDeviceSpareAreaSizeSpec>;
#[doc = "Page spare area size of device in bytes"]
pub mod config_device_spare_area_size;
#[doc = "config_two_row_addr_cycles (rw) register accessor: Attached device has only 2 ROW address cycles\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_two_row_addr_cycles::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_two_row_addr_cycles::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_two_row_addr_cycles`]
module"]
#[doc(alias = "config_two_row_addr_cycles")]
pub type ConfigTwoRowAddrCycles =
    crate::Reg<config_two_row_addr_cycles::ConfigTwoRowAddrCyclesSpec>;
#[doc = "Attached device has only 2 ROW address cycles"]
pub mod config_two_row_addr_cycles;
#[doc = "config_multiplane_addr_restrict (rw) register accessor: Address restriction for multiplane commands\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_multiplane_addr_restrict::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_multiplane_addr_restrict::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_multiplane_addr_restrict`]
module"]
#[doc(alias = "config_multiplane_addr_restrict")]
pub type ConfigMultiplaneAddrRestrict =
    crate::Reg<config_multiplane_addr_restrict::ConfigMultiplaneAddrRestrictSpec>;
#[doc = "Address restriction for multiplane commands"]
pub mod config_multiplane_addr_restrict;
#[doc = "config_ecc_correction (rw) register accessor: Correction capability required\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_ecc_correction::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_ecc_correction::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_ecc_correction`]
module"]
#[doc(alias = "config_ecc_correction")]
pub type ConfigEccCorrection = crate::Reg<config_ecc_correction::ConfigEccCorrectionSpec>;
#[doc = "Correction capability required"]
pub mod config_ecc_correction;
#[doc = "config_read_mode (rw) register accessor: The type of read sequence that the controller will follow for pipe read commands.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_read_mode::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_read_mode::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_read_mode`]
module"]
#[doc(alias = "config_read_mode")]
pub type ConfigReadMode = crate::Reg<config_read_mode::ConfigReadModeSpec>;
#[doc = "The type of read sequence that the controller will follow for pipe read commands."]
pub mod config_read_mode;
#[doc = "config_write_mode (rw) register accessor: The type of write sequence that the controller will follow for pipe write commands.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_write_mode::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_write_mode::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_write_mode`]
module"]
#[doc(alias = "config_write_mode")]
pub type ConfigWriteMode = crate::Reg<config_write_mode::ConfigWriteModeSpec>;
#[doc = "The type of write sequence that the controller will follow for pipe write commands."]
pub mod config_write_mode;
#[doc = "config_copyback_mode (rw) register accessor: The type of copyback sequence that the controller will follow.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_copyback_mode::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_copyback_mode::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_copyback_mode`]
module"]
#[doc(alias = "config_copyback_mode")]
pub type ConfigCopybackMode = crate::Reg<config_copyback_mode::ConfigCopybackModeSpec>;
#[doc = "The type of copyback sequence that the controller will follow."]
pub mod config_copyback_mode;
#[doc = "config_rdwr_en_lo_cnt (rw) register accessor: Read/Write Enable low pulse width\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_rdwr_en_lo_cnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_rdwr_en_lo_cnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_rdwr_en_lo_cnt`]
module"]
#[doc(alias = "config_rdwr_en_lo_cnt")]
pub type ConfigRdwrEnLoCnt = crate::Reg<config_rdwr_en_lo_cnt::ConfigRdwrEnLoCntSpec>;
#[doc = "Read/Write Enable low pulse width"]
pub mod config_rdwr_en_lo_cnt;
#[doc = "config_rdwr_en_hi_cnt (rw) register accessor: Read/Write Enable high pulse width\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_rdwr_en_hi_cnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_rdwr_en_hi_cnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_rdwr_en_hi_cnt`]
module"]
#[doc(alias = "config_rdwr_en_hi_cnt")]
pub type ConfigRdwrEnHiCnt = crate::Reg<config_rdwr_en_hi_cnt::ConfigRdwrEnHiCntSpec>;
#[doc = "Read/Write Enable high pulse width"]
pub mod config_rdwr_en_hi_cnt;
#[doc = "config_max_rd_delay (rw) register accessor: Max round trip read data delay for data capture\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_max_rd_delay::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_max_rd_delay::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_max_rd_delay`]
module"]
#[doc(alias = "config_max_rd_delay")]
pub type ConfigMaxRdDelay = crate::Reg<config_max_rd_delay::ConfigMaxRdDelaySpec>;
#[doc = "Max round trip read data delay for data capture"]
pub mod config_max_rd_delay;
#[doc = "config_cs_setup_cnt (rw) register accessor: Chip select setup time\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_cs_setup_cnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_cs_setup_cnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_cs_setup_cnt`]
module"]
#[doc(alias = "config_cs_setup_cnt")]
pub type ConfigCsSetupCnt = crate::Reg<config_cs_setup_cnt::ConfigCsSetupCntSpec>;
#[doc = "Chip select setup time"]
pub mod config_cs_setup_cnt;
#[doc = "config_spare_area_skip_bytes (rw) register accessor: Spare area skip bytes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_spare_area_skip_bytes::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_spare_area_skip_bytes::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_spare_area_skip_bytes`]
module"]
#[doc(alias = "config_spare_area_skip_bytes")]
pub type ConfigSpareAreaSkipBytes =
    crate::Reg<config_spare_area_skip_bytes::ConfigSpareAreaSkipBytesSpec>;
#[doc = "Spare area skip bytes"]
pub mod config_spare_area_skip_bytes;
#[doc = "config_spare_area_marker (rw) register accessor: Spare area marker value\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_spare_area_marker::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_spare_area_marker::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_spare_area_marker`]
module"]
#[doc(alias = "config_spare_area_marker")]
pub type ConfigSpareAreaMarker = crate::Reg<config_spare_area_marker::ConfigSpareAreaMarkerSpec>;
#[doc = "Spare area marker value"]
pub mod config_spare_area_marker;
#[doc = "config_devices_connected (rw) register accessor: Number of Devices connected on one bank\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_devices_connected::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_devices_connected::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_devices_connected`]
module"]
#[doc(alias = "config_devices_connected")]
pub type ConfigDevicesConnected = crate::Reg<config_devices_connected::ConfigDevicesConnectedSpec>;
#[doc = "Number of Devices connected on one bank"]
pub mod config_devices_connected;
#[doc = "config_die_mask (rw) register accessor: Indicates the die differentiator in case of NAND devices with stacked dies.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_die_mask::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_die_mask::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_die_mask`]
module"]
#[doc(alias = "config_die_mask")]
pub type ConfigDieMask = crate::Reg<config_die_mask::ConfigDieMaskSpec>;
#[doc = "Indicates the die differentiator in case of NAND devices with stacked dies."]
pub mod config_die_mask;
#[doc = "config_first_block_of_next_plane (rw) register accessor: The starting block address of the next plane in a multi plane device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_first_block_of_next_plane::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_first_block_of_next_plane::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_first_block_of_next_plane`]
module"]
#[doc(alias = "config_first_block_of_next_plane")]
pub type ConfigFirstBlockOfNextPlane =
    crate::Reg<config_first_block_of_next_plane::ConfigFirstBlockOfNextPlaneSpec>;
#[doc = "The starting block address of the next plane in a multi plane device."]
pub mod config_first_block_of_next_plane;
#[doc = "config_write_protect (rw) register accessor: This register is used to control the assertion/de-assertion of the WP# pin to the device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_write_protect::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_write_protect::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_write_protect`]
module"]
#[doc(alias = "config_write_protect")]
pub type ConfigWriteProtect = crate::Reg<config_write_protect::ConfigWriteProtectSpec>;
#[doc = "This register is used to control the assertion/de-assertion of the WP# pin to the device."]
pub mod config_write_protect;
#[doc = "config_re_2_re (rw) register accessor: Timing parameter between re high to re low (Trhz) for the next bank\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_re_2_re::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_re_2_re::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_re_2_re`]
module"]
#[doc(alias = "config_re_2_re")]
pub type ConfigRe2Re = crate::Reg<config_re_2_re::ConfigRe2ReSpec>;
#[doc = "Timing parameter between re high to re low (Trhz) for the next bank"]
pub mod config_re_2_re;
#[doc = "config_por_reset_count (rw) register accessor: The number of cycles the controller waits after reset to issue the first RESET command to the device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_por_reset_count::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_por_reset_count::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_por_reset_count`]
module"]
#[doc(alias = "config_por_reset_count")]
pub type ConfigPorResetCount = crate::Reg<config_por_reset_count::ConfigPorResetCountSpec>;
#[doc = "The number of cycles the controller waits after reset to issue the first RESET command to the device."]
pub mod config_por_reset_count;
#[doc = "config_watchdog_reset_count (rw) register accessor: The number of cycles the controller waits before flagging a watchdog timeout interrupt.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_watchdog_reset_count::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_watchdog_reset_count::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@config_watchdog_reset_count`]
module"]
#[doc(alias = "config_watchdog_reset_count")]
pub type ConfigWatchdogResetCount =
    crate::Reg<config_watchdog_reset_count::ConfigWatchdogResetCountSpec>;
#[doc = "The number of cycles the controller waits before flagging a watchdog timeout interrupt."]
pub mod config_watchdog_reset_count;
#[doc = "param_manufacturer_id (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_manufacturer_id::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`param_manufacturer_id::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_manufacturer_id`]
module"]
#[doc(alias = "param_manufacturer_id")]
pub type ParamManufacturerId = crate::Reg<param_manufacturer_id::ParamManufacturerIdSpec>;
#[doc = ""]
pub mod param_manufacturer_id;
#[doc = "param_device_id (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_device_id::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_device_id`]
module"]
#[doc(alias = "param_device_id")]
pub type ParamDeviceId = crate::Reg<param_device_id::ParamDeviceIdSpec>;
#[doc = ""]
pub mod param_device_id;
#[doc = "param_device_param_0 (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_device_param_0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_device_param_0`]
module"]
#[doc(alias = "param_device_param_0")]
pub type ParamDeviceParam0 = crate::Reg<param_device_param_0::ParamDeviceParam0Spec>;
#[doc = ""]
pub mod param_device_param_0;
#[doc = "param_device_param_1 (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_device_param_1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_device_param_1`]
module"]
#[doc(alias = "param_device_param_1")]
pub type ParamDeviceParam1 = crate::Reg<param_device_param_1::ParamDeviceParam1Spec>;
#[doc = ""]
pub mod param_device_param_1;
#[doc = "param_device_param_2 (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_device_param_2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_device_param_2`]
module"]
#[doc(alias = "param_device_param_2")]
pub type ParamDeviceParam2 = crate::Reg<param_device_param_2::ParamDeviceParam2Spec>;
#[doc = ""]
pub mod param_device_param_2;
#[doc = "param_logical_page_data_size (r) register accessor: Logical page data area size in bytes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_logical_page_data_size::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_logical_page_data_size`]
module"]
#[doc(alias = "param_logical_page_data_size")]
pub type ParamLogicalPageDataSize =
    crate::Reg<param_logical_page_data_size::ParamLogicalPageDataSizeSpec>;
#[doc = "Logical page data area size in bytes"]
pub mod param_logical_page_data_size;
#[doc = "param_logical_page_spare_size (r) register accessor: Logical page data area size in bytes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_logical_page_spare_size::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_logical_page_spare_size`]
module"]
#[doc(alias = "param_logical_page_spare_size")]
pub type ParamLogicalPageSpareSize =
    crate::Reg<param_logical_page_spare_size::ParamLogicalPageSpareSizeSpec>;
#[doc = "Logical page data area size in bytes"]
pub mod param_logical_page_spare_size;
#[doc = "param_revision (r) register accessor: Controller revision number\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_revision::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_revision`]
module"]
#[doc(alias = "param_revision")]
pub type ParamRevision = crate::Reg<param_revision::ParamRevisionSpec>;
#[doc = "Controller revision number"]
pub mod param_revision;
#[doc = "param_onfi_device_features (r) register accessor: Features supported by the connected ONFI device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_device_features::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_onfi_device_features`]
module"]
#[doc(alias = "param_onfi_device_features")]
pub type ParamOnfiDeviceFeatures =
    crate::Reg<param_onfi_device_features::ParamOnfiDeviceFeaturesSpec>;
#[doc = "Features supported by the connected ONFI device"]
pub mod param_onfi_device_features;
#[doc = "param_onfi_optional_commands (r) register accessor: Optional commands supported by the connected ONFI device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_optional_commands::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_onfi_optional_commands`]
module"]
#[doc(alias = "param_onfi_optional_commands")]
pub type ParamOnfiOptionalCommands =
    crate::Reg<param_onfi_optional_commands::ParamOnfiOptionalCommandsSpec>;
#[doc = "Optional commands supported by the connected ONFI device"]
pub mod param_onfi_optional_commands;
#[doc = "param_onfi_timing_mode (r) register accessor: Asynchronous Timing modes supported by the connected ONFI device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_timing_mode::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_onfi_timing_mode`]
module"]
#[doc(alias = "param_onfi_timing_mode")]
pub type ParamOnfiTimingMode = crate::Reg<param_onfi_timing_mode::ParamOnfiTimingModeSpec>;
#[doc = "Asynchronous Timing modes supported by the connected ONFI device"]
pub mod param_onfi_timing_mode;
#[doc = "param_onfi_pgm_cache_timing_mode (r) register accessor: Asynchronous Program Cache Timing modes supported by the connected ONFI device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_pgm_cache_timing_mode::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_onfi_pgm_cache_timing_mode`]
module"]
#[doc(alias = "param_onfi_pgm_cache_timing_mode")]
pub type ParamOnfiPgmCacheTimingMode =
    crate::Reg<param_onfi_pgm_cache_timing_mode::ParamOnfiPgmCacheTimingModeSpec>;
#[doc = "Asynchronous Program Cache Timing modes supported by the connected ONFI device"]
pub mod param_onfi_pgm_cache_timing_mode;
#[doc = "param_onfi_device_no_of_luns (rw) register accessor: Indicates if the device is an ONFI compliant device and the number of LUNS present in the device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_device_no_of_luns::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`param_onfi_device_no_of_luns::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_onfi_device_no_of_luns`]
module"]
#[doc(alias = "param_onfi_device_no_of_luns")]
pub type ParamOnfiDeviceNoOfLuns =
    crate::Reg<param_onfi_device_no_of_luns::ParamOnfiDeviceNoOfLunsSpec>;
#[doc = "Indicates if the device is an ONFI compliant device and the number of LUNS present in the device"]
pub mod param_onfi_device_no_of_luns;
#[doc = "param_onfi_device_no_of_blocks_per_lun_l (r) register accessor: Lower bits of number of blocks per LUN present in the ONFI complaint device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_device_no_of_blocks_per_lun_l::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_onfi_device_no_of_blocks_per_lun_l`]
module"]
#[doc(alias = "param_onfi_device_no_of_blocks_per_lun_l")]
pub type ParamOnfiDeviceNoOfBlocksPerLunL =
    crate::Reg<param_onfi_device_no_of_blocks_per_lun_l::ParamOnfiDeviceNoOfBlocksPerLunLSpec>;
#[doc = "Lower bits of number of blocks per LUN present in the ONFI complaint device."]
pub mod param_onfi_device_no_of_blocks_per_lun_l;
#[doc = "param_onfi_device_no_of_blocks_per_lun_u (r) register accessor: Upper bits of number of blocks per LUN present in the ONFI complaint device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_device_no_of_blocks_per_lun_u::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_onfi_device_no_of_blocks_per_lun_u`]
module"]
#[doc(alias = "param_onfi_device_no_of_blocks_per_lun_u")]
pub type ParamOnfiDeviceNoOfBlocksPerLunU =
    crate::Reg<param_onfi_device_no_of_blocks_per_lun_u::ParamOnfiDeviceNoOfBlocksPerLunUSpec>;
#[doc = "Upper bits of number of blocks per LUN present in the ONFI complaint device."]
pub mod param_onfi_device_no_of_blocks_per_lun_u;
#[doc = "param_features (r) register accessor: Shows Available hardware features or attributes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_features::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@param_features`]
module"]
#[doc(alias = "param_features")]
pub type ParamFeatures = crate::Reg<param_features::ParamFeaturesSpec>;
#[doc = "Shows Available hardware features or attributes"]
pub mod param_features;
#[doc = "status_transfer_mode (r) register accessor: Current data transfer mode is Main only, Spare only or Main+Spare. This information is per bank.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_transfer_mode::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_transfer_mode`]
module"]
#[doc(alias = "status_transfer_mode")]
pub type StatusTransferMode = crate::Reg<status_transfer_mode::StatusTransferModeSpec>;
#[doc = "Current data transfer mode is Main only, Spare only or Main+Spare. This information is per bank."]
pub mod status_transfer_mode;
#[doc = "status_intr_status0 (rw) register accessor: Interrupt status register for bank 0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_intr_status0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`status_intr_status0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_intr_status0`]
module"]
#[doc(alias = "status_intr_status0")]
pub type StatusIntrStatus0 = crate::Reg<status_intr_status0::StatusIntrStatus0Spec>;
#[doc = "Interrupt status register for bank 0"]
pub mod status_intr_status0;
#[doc = "status_intr_en0 (rw) register accessor: Enables corresponding interrupt bit in interrupt register for bank 0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_intr_en0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`status_intr_en0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_intr_en0`]
module"]
#[doc(alias = "status_intr_en0")]
pub type StatusIntrEn0 = crate::Reg<status_intr_en0::StatusIntrEn0Spec>;
#[doc = "Enables corresponding interrupt bit in interrupt register for bank 0"]
pub mod status_intr_en0;
#[doc = "status_page_cnt0 (r) register accessor: Decrementing page count bank 0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_page_cnt0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_page_cnt0`]
module"]
#[doc(alias = "status_page_cnt0")]
pub type StatusPageCnt0 = crate::Reg<status_page_cnt0::StatusPageCnt0Spec>;
#[doc = "Decrementing page count bank 0"]
pub mod status_page_cnt0;
#[doc = "status_err_page_addr0 (r) register accessor: Erred page address bank 0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_err_page_addr0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_err_page_addr0`]
module"]
#[doc(alias = "status_err_page_addr0")]
pub type StatusErrPageAddr0 = crate::Reg<status_err_page_addr0::StatusErrPageAddr0Spec>;
#[doc = "Erred page address bank 0"]
pub mod status_err_page_addr0;
#[doc = "status_err_block_addr0 (r) register accessor: Erred block address bank 0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_err_block_addr0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_err_block_addr0`]
module"]
#[doc(alias = "status_err_block_addr0")]
pub type StatusErrBlockAddr0 = crate::Reg<status_err_block_addr0::StatusErrBlockAddr0Spec>;
#[doc = "Erred block address bank 0"]
pub mod status_err_block_addr0;
#[doc = "status_intr_status1 (rw) register accessor: Interrupt status register for bank 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_intr_status1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`status_intr_status1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_intr_status1`]
module"]
#[doc(alias = "status_intr_status1")]
pub type StatusIntrStatus1 = crate::Reg<status_intr_status1::StatusIntrStatus1Spec>;
#[doc = "Interrupt status register for bank 1"]
pub mod status_intr_status1;
#[doc = "status_intr_en1 (rw) register accessor: Enables corresponding interrupt bit in interrupt register for bank 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_intr_en1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`status_intr_en1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_intr_en1`]
module"]
#[doc(alias = "status_intr_en1")]
pub type StatusIntrEn1 = crate::Reg<status_intr_en1::StatusIntrEn1Spec>;
#[doc = "Enables corresponding interrupt bit in interrupt register for bank 1"]
pub mod status_intr_en1;
#[doc = "status_page_cnt1 (r) register accessor: Decrementing page count bank 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_page_cnt1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_page_cnt1`]
module"]
#[doc(alias = "status_page_cnt1")]
pub type StatusPageCnt1 = crate::Reg<status_page_cnt1::StatusPageCnt1Spec>;
#[doc = "Decrementing page count bank 1"]
pub mod status_page_cnt1;
#[doc = "status_err_page_addr1 (r) register accessor: Erred page address bank 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_err_page_addr1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_err_page_addr1`]
module"]
#[doc(alias = "status_err_page_addr1")]
pub type StatusErrPageAddr1 = crate::Reg<status_err_page_addr1::StatusErrPageAddr1Spec>;
#[doc = "Erred page address bank 1"]
pub mod status_err_page_addr1;
#[doc = "status_err_block_addr1 (r) register accessor: Erred block address bank 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_err_block_addr1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_err_block_addr1`]
module"]
#[doc(alias = "status_err_block_addr1")]
pub type StatusErrBlockAddr1 = crate::Reg<status_err_block_addr1::StatusErrBlockAddr1Spec>;
#[doc = "Erred block address bank 1"]
pub mod status_err_block_addr1;
#[doc = "status_intr_status2 (rw) register accessor: Interrupt status register for bank 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_intr_status2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`status_intr_status2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_intr_status2`]
module"]
#[doc(alias = "status_intr_status2")]
pub type StatusIntrStatus2 = crate::Reg<status_intr_status2::StatusIntrStatus2Spec>;
#[doc = "Interrupt status register for bank 2"]
pub mod status_intr_status2;
#[doc = "status_intr_en2 (rw) register accessor: Enables corresponding interrupt bit in interrupt register for bank 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_intr_en2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`status_intr_en2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_intr_en2`]
module"]
#[doc(alias = "status_intr_en2")]
pub type StatusIntrEn2 = crate::Reg<status_intr_en2::StatusIntrEn2Spec>;
#[doc = "Enables corresponding interrupt bit in interrupt register for bank 2"]
pub mod status_intr_en2;
#[doc = "status_page_cnt2 (r) register accessor: Decrementing page count bank 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_page_cnt2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_page_cnt2`]
module"]
#[doc(alias = "status_page_cnt2")]
pub type StatusPageCnt2 = crate::Reg<status_page_cnt2::StatusPageCnt2Spec>;
#[doc = "Decrementing page count bank 2"]
pub mod status_page_cnt2;
#[doc = "status_err_page_addr2 (r) register accessor: Erred page address bank 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_err_page_addr2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_err_page_addr2`]
module"]
#[doc(alias = "status_err_page_addr2")]
pub type StatusErrPageAddr2 = crate::Reg<status_err_page_addr2::StatusErrPageAddr2Spec>;
#[doc = "Erred page address bank 2"]
pub mod status_err_page_addr2;
#[doc = "status_err_block_addr2 (r) register accessor: Erred block address bank 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_err_block_addr2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_err_block_addr2`]
module"]
#[doc(alias = "status_err_block_addr2")]
pub type StatusErrBlockAddr2 = crate::Reg<status_err_block_addr2::StatusErrBlockAddr2Spec>;
#[doc = "Erred block address bank 2"]
pub mod status_err_block_addr2;
#[doc = "status_intr_status3 (rw) register accessor: Interrupt status register for bank 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_intr_status3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`status_intr_status3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_intr_status3`]
module"]
#[doc(alias = "status_intr_status3")]
pub type StatusIntrStatus3 = crate::Reg<status_intr_status3::StatusIntrStatus3Spec>;
#[doc = "Interrupt status register for bank 3"]
pub mod status_intr_status3;
#[doc = "status_intr_en3 (rw) register accessor: Enables corresponding interrupt bit in interrupt register for bank 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_intr_en3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`status_intr_en3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_intr_en3`]
module"]
#[doc(alias = "status_intr_en3")]
pub type StatusIntrEn3 = crate::Reg<status_intr_en3::StatusIntrEn3Spec>;
#[doc = "Enables corresponding interrupt bit in interrupt register for bank 3"]
pub mod status_intr_en3;
#[doc = "status_page_cnt3 (r) register accessor: Decrementing page count bank 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_page_cnt3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_page_cnt3`]
module"]
#[doc(alias = "status_page_cnt3")]
pub type StatusPageCnt3 = crate::Reg<status_page_cnt3::StatusPageCnt3Spec>;
#[doc = "Decrementing page count bank 3"]
pub mod status_page_cnt3;
#[doc = "status_err_page_addr3 (r) register accessor: Erred page address bank 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_err_page_addr3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_err_page_addr3`]
module"]
#[doc(alias = "status_err_page_addr3")]
pub type StatusErrPageAddr3 = crate::Reg<status_err_page_addr3::StatusErrPageAddr3Spec>;
#[doc = "Erred page address bank 3"]
pub mod status_err_page_addr3;
#[doc = "status_err_block_addr3 (r) register accessor: Erred block address bank 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_err_block_addr3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status_err_block_addr3`]
module"]
#[doc(alias = "status_err_block_addr3")]
pub type StatusErrBlockAddr3 = crate::Reg<status_err_block_addr3::StatusErrBlockAddr3Spec>;
#[doc = "Erred block address bank 3"]
pub mod status_err_block_addr3;
#[doc = "ecc_ECCCorInfo_b01 (r) register accessor: ECC Error correction Information register. Controller updates this register when it completes a transaction. The values are held in this register till a new transaction completes.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ecc_ecccor_info_b01::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ecc_ecccor_info_b01`]
module"]
#[doc(alias = "ecc_ECCCorInfo_b01")]
pub type EccEcccorInfoB01 = crate::Reg<ecc_ecccor_info_b01::EccEcccorInfoB01Spec>;
#[doc = "ECC Error correction Information register. Controller updates this register when it completes a transaction. The values are held in this register till a new transaction completes."]
pub mod ecc_ecccor_info_b01;
#[doc = "ecc_ECCCorInfo_b23 (r) register accessor: ECC Error correction Information register. Controller updates this register when it completes a transaction. The values are held in this register till a new transaction completes.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ecc_ecccor_info_b23::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ecc_ecccor_info_b23`]
module"]
#[doc(alias = "ecc_ECCCorInfo_b23")]
pub type EccEcccorInfoB23 = crate::Reg<ecc_ecccor_info_b23::EccEcccorInfoB23Spec>;
#[doc = "ECC Error correction Information register. Controller updates this register when it completes a transaction. The values are held in this register till a new transaction completes."]
pub mod ecc_ecccor_info_b23;
#[doc = "dma_dma_enable (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_dma_enable::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_dma_enable::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dma_dma_enable`]
module"]
#[doc(alias = "dma_dma_enable")]
pub type DmaDmaEnable = crate::Reg<dma_dma_enable::DmaDmaEnableSpec>;
#[doc = ""]
pub mod dma_dma_enable;
#[doc = "dma_dma_intr (rw) register accessor: DMA interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_dma_intr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_dma_intr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dma_dma_intr`]
module"]
#[doc(alias = "dma_dma_intr")]
pub type DmaDmaIntr = crate::Reg<dma_dma_intr::DmaDmaIntrSpec>;
#[doc = "DMA interrupt register"]
pub mod dma_dma_intr;
#[doc = "dma_dma_intr_en (rw) register accessor: Enables corresponding interrupt bit in dma interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_dma_intr_en::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_dma_intr_en::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dma_dma_intr_en`]
module"]
#[doc(alias = "dma_dma_intr_en")]
pub type DmaDmaIntrEn = crate::Reg<dma_dma_intr_en::DmaDmaIntrEnSpec>;
#[doc = "Enables corresponding interrupt bit in dma interrupt register"]
pub mod dma_dma_intr_en;
#[doc = "dma_target_err_addr_lo (r) register accessor: Transaction address for which controller initiator interface received an ERROR target response.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_target_err_addr_lo::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dma_target_err_addr_lo`]
module"]
#[doc(alias = "dma_target_err_addr_lo")]
pub type DmaTargetErrAddrLo = crate::Reg<dma_target_err_addr_lo::DmaTargetErrAddrLoSpec>;
#[doc = "Transaction address for which controller initiator interface received an ERROR target response."]
pub mod dma_target_err_addr_lo;
#[doc = "dma_target_err_addr_hi (r) register accessor: Transaction address for which controller initiator interface received an ERROR target response.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_target_err_addr_hi::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dma_target_err_addr_hi`]
module"]
#[doc(alias = "dma_target_err_addr_hi")]
pub type DmaTargetErrAddrHi = crate::Reg<dma_target_err_addr_hi::DmaTargetErrAddrHiSpec>;
#[doc = "Transaction address for which controller initiator interface received an ERROR target response."]
pub mod dma_target_err_addr_hi;
#[doc = "dma_flash_burst_length (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_flash_burst_length::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_flash_burst_length::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dma_flash_burst_length`]
module"]
#[doc(alias = "dma_flash_burst_length")]
pub type DmaFlashBurstLength = crate::Reg<dma_flash_burst_length::DmaFlashBurstLengthSpec>;
#[doc = ""]
pub mod dma_flash_burst_length;
#[doc = "dma_chip_interleave_enable_and_allow_int_reads (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_chip_interleave_enable_and_allow_int_reads::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_chip_interleave_enable_and_allow_int_reads::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dma_chip_interleave_enable_and_allow_int_reads`]
module"]
#[doc(alias = "dma_chip_interleave_enable_and_allow_int_reads")]
pub type DmaChipInterleaveEnableAndAllowIntReads = crate::Reg<
    dma_chip_interleave_enable_and_allow_int_reads::DmaChipInterleaveEnableAndAllowIntReadsSpec,
>;
#[doc = ""]
pub mod dma_chip_interleave_enable_and_allow_int_reads;
#[doc = "dma_no_of_blocks_per_lun (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_no_of_blocks_per_lun::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_no_of_blocks_per_lun::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dma_no_of_blocks_per_lun`]
module"]
#[doc(alias = "dma_no_of_blocks_per_lun")]
pub type DmaNoOfBlocksPerLun = crate::Reg<dma_no_of_blocks_per_lun::DmaNoOfBlocksPerLunSpec>;
#[doc = ""]
pub mod dma_no_of_blocks_per_lun;
#[doc = "dma_lun_status_cmd (rw) register accessor: Indicates the command to be sent while checking status of the next LUN.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_lun_status_cmd::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_lun_status_cmd::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dma_lun_status_cmd`]
module"]
#[doc(alias = "dma_lun_status_cmd")]
pub type DmaLunStatusCmd = crate::Reg<dma_lun_status_cmd::DmaLunStatusCmdSpec>;
#[doc = "Indicates the command to be sent while checking status of the next LUN."]
pub mod dma_lun_status_cmd;
