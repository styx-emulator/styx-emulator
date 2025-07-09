// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    remap: Remap,
    _reserved1: [u8; 0x04],
    secgrp_l4main: SecgrpL4main,
    secgrp_l4sp: SecgrpL4sp,
    secgrp_l4mp: SecgrpL4mp,
    secgrp_l4osc1: SecgrpL4osc1,
    secgrp_l4spim: SecgrpL4spim,
    secgrp_stm: SecgrpStm,
    secgrp_lwhps2fpgaregs: SecgrpLwhps2fpgaregs,
    _reserved8: [u8; 0x04],
    secgrp_usb1: SecgrpUsb1,
    secgrp_nanddata: SecgrpNanddata,
    _reserved10: [u8; 0x50],
    secgrp_usb0: SecgrpUsb0,
    secgrp_nandregs: SecgrpNandregs,
    secgrp_qspidata: SecgrpQspidata,
    secgrp_fpgamgrdata: SecgrpFpgamgrdata,
    secgrp_hps2fpgaregs: SecgrpHps2fpgaregs,
    secgrp_acp: SecgrpAcp,
    secgrp_rom: SecgrpRom,
    secgrp_ocram: SecgrpOcram,
    secgrp_sdrdata: SecgrpSdrdata,
    _reserved19: [u8; 0x1f2c],
    idgrp_periph_id_4: IdgrpPeriphId4,
    _reserved20: [u8; 0x0c],
    idgrp_periph_id_0: IdgrpPeriphId0,
    idgrp_periph_id_1: IdgrpPeriphId1,
    idgrp_periph_id_2: IdgrpPeriphId2,
    idgrp_periph_id_3: IdgrpPeriphId3,
    idgrp_comp_id_0: IdgrpCompId0,
    idgrp_comp_id_1: IdgrpCompId1,
    idgrp_comp_id_2: IdgrpCompId2,
    idgrp_comp_id_3: IdgrpCompId3,
    _reserved28: [u8; 0x08],
    mastergrp_l4main_fn_mod_bm_iss: MastergrpL4mainFnModBmIss,
    _reserved29: [u8; 0x0ffc],
    mastergrp_l4sp_fn_mod_bm_iss: MastergrpL4spFnModBmIss,
    _reserved30: [u8; 0x0ffc],
    mastergrp_l4mp_fn_mod_bm_iss: MastergrpL4mpFnModBmIss,
    _reserved31: [u8; 0x0ffc],
    mastergrp_l4osc1_fn_mod_bm_iss: MastergrpL4osc1FnModBmIss,
    _reserved32: [u8; 0x0ffc],
    mastergrp_l4spim_fn_mod_bm_iss: MastergrpL4spimFnModBmIss,
    _reserved33: [u8; 0x0ffc],
    mastergrp_stm_fn_mod_bm_iss: MastergrpStmFnModBmIss,
    _reserved34: [u8; 0xfc],
    mastergrp_stm_fn_mod: MastergrpStmFnMod,
    _reserved35: [u8; 0x0efc],
    mastergrp_lwhps2fpga_fn_mod_bm_iss: MastergrpLwhps2fpgaFnModBmIss,
    _reserved36: [u8; 0xfc],
    mastergrp_lwhps2fpga_fn_mod: MastergrpLwhps2fpgaFnMod,
    _reserved37: [u8; 0x1efc],
    mastergrp_usb1_fn_mod_bm_iss: MastergrpUsb1FnModBmIss,
    _reserved38: [u8; 0x38],
    mastergrp_usb1_ahb_cntl: MastergrpUsb1AhbCntl,
    _reserved39: [u8; 0x0fc0],
    mastergrp_nanddata_fn_mod_bm_iss: MastergrpNanddataFnModBmIss,
    _reserved40: [u8; 0xfc],
    mastergrp_nanddata_fn_mod: MastergrpNanddataFnMod,
    _reserved41: [u8; 0x0001_4efc],
    mastergrp_usb0_fn_mod_bm_iss: MastergrpUsb0FnModBmIss,
    _reserved42: [u8; 0x38],
    mastergrp_usb0_ahb_cntl: MastergrpUsb0AhbCntl,
    _reserved43: [u8; 0x0fc0],
    mastergrp_nandregs_fn_mod_bm_iss: MastergrpNandregsFnModBmIss,
    _reserved44: [u8; 0xfc],
    mastergrp_nandregs_fn_mod: MastergrpNandregsFnMod,
    _reserved45: [u8; 0x0efc],
    mastergrp_qspidata_fn_mod_bm_iss: MastergrpQspidataFnModBmIss,
    _reserved46: [u8; 0x38],
    mastergrp_qspidata_ahb_cntl: MastergrpQspidataAhbCntl,
    _reserved47: [u8; 0x0fc0],
    mastergrp_fpgamgrdata_fn_mod_bm_iss: MastergrpFpgamgrdataFnModBmIss,
    _reserved48: [u8; 0x34],
    mastergrp_fpgamgrdata_wr_tidemark: MastergrpFpgamgrdataWrTidemark,
    _reserved49: [u8; 0xc4],
    mastergrp_fpgamgrdata_fn_mod: MastergrpFpgamgrdataFnMod,
    _reserved50: [u8; 0x0efc],
    mastergrp_hps2fpga_fn_mod_bm_iss: MastergrpHps2fpgaFnModBmIss,
    _reserved51: [u8; 0x34],
    mastergrp_hps2fpga_wr_tidemark: MastergrpHps2fpgaWrTidemark,
    _reserved52: [u8; 0xc4],
    mastergrp_hps2fpga_fn_mod: MastergrpHps2fpgaFnMod,
    _reserved53: [u8; 0x0efc],
    mastergrp_acp_fn_mod_bm_iss: MastergrpAcpFnModBmIss,
    _reserved54: [u8; 0xfc],
    mastergrp_acp_fn_mod: MastergrpAcpFnMod,
    _reserved55: [u8; 0x0efc],
    mastergrp_rom_fn_mod_bm_iss: MastergrpRomFnModBmIss,
    _reserved56: [u8; 0xfc],
    mastergrp_rom_fn_mod: MastergrpRomFnMod,
    _reserved57: [u8; 0x0efc],
    mastergrp_ocram_fn_mod_bm_iss: MastergrpOcramFnModBmIss,
    _reserved58: [u8; 0x34],
    mastergrp_ocram_wr_tidemark: MastergrpOcramWrTidemark,
    _reserved59: [u8; 0xc4],
    mastergrp_ocram_fn_mod: MastergrpOcramFnMod,
    _reserved60: [u8; 0x0001_af18],
    slavegrp_dap_fn_mod2: SlavegrpDapFnMod2,
    slavegrp_dap_fn_mod_ahb: SlavegrpDapFnModAhb,
    _reserved62: [u8; 0xd4],
    slavegrp_dap_read_qos: SlavegrpDapReadQos,
    slavegrp_dap_write_qos: SlavegrpDapWriteQos,
    slavegrp_dap_fn_mod: SlavegrpDapFnMod,
    _reserved65: [u8; 0x0ff4],
    slavegrp_mpu_read_qos: SlavegrpMpuReadQos,
    slavegrp_mpu_write_qos: SlavegrpMpuWriteQos,
    slavegrp_mpu_fn_mod: SlavegrpMpuFnMod,
    _reserved68: [u8; 0x0f1c],
    slavegrp_sdmmc_fn_mod_ahb: SlavegrpSdmmcFnModAhb,
    _reserved69: [u8; 0xd4],
    slavegrp_sdmmc_read_qos: SlavegrpSdmmcReadQos,
    slavegrp_sdmmc_write_qos: SlavegrpSdmmcWriteQos,
    slavegrp_sdmmc_fn_mod: SlavegrpSdmmcFnMod,
    _reserved72: [u8; 0x0ff4],
    slavegrp_dma_read_qos: SlavegrpDmaReadQos,
    slavegrp_dma_write_qos: SlavegrpDmaWriteQos,
    slavegrp_dma_fn_mod: SlavegrpDmaFnMod,
    _reserved75: [u8; 0x0f34],
    slavegrp_fpga2hps_wr_tidemark: SlavegrpFpga2hpsWrTidemark,
    _reserved76: [u8; 0xbc],
    slavegrp_fpga2hps_read_qos: SlavegrpFpga2hpsReadQos,
    slavegrp_fpga2hps_write_qos: SlavegrpFpga2hpsWriteQos,
    slavegrp_fpga2hps_fn_mod: SlavegrpFpga2hpsFnMod,
    _reserved79: [u8; 0x0ff4],
    slavegrp_etr_read_qos: SlavegrpEtrReadQos,
    slavegrp_etr_write_qos: SlavegrpEtrWriteQos,
    slavegrp_etr_fn_mod: SlavegrpEtrFnMod,
    _reserved82: [u8; 0x0ff4],
    slavegrp_emac0_read_qos: SlavegrpEmac0ReadQos,
    slavegrp_emac0_write_qos: SlavegrpEmac0WriteQos,
    slavegrp_emac0_fn_mod: SlavegrpEmac0FnMod,
    _reserved85: [u8; 0x0ff4],
    slavegrp_emac1_read_qos: SlavegrpEmac1ReadQos,
    slavegrp_emac1_write_qos: SlavegrpEmac1WriteQos,
    slavegrp_emac1_fn_mod: SlavegrpEmac1FnMod,
    _reserved88: [u8; 0x0f1c],
    slavegrp_usb0_fn_mod_ahb: SlavegrpUsb0FnModAhb,
    _reserved89: [u8; 0xd4],
    slavegrp_usb0_read_qos: SlavegrpUsb0ReadQos,
    slavegrp_usb0_write_qos: SlavegrpUsb0WriteQos,
    slavegrp_usb0_fn_mod: SlavegrpUsb0FnMod,
    _reserved92: [u8; 0x0ff4],
    slavegrp_nand_read_qos: SlavegrpNandReadQos,
    slavegrp_nand_write_qos: SlavegrpNandWriteQos,
    slavegrp_nand_fn_mod: SlavegrpNandFnMod,
    _reserved95: [u8; 0x0f1c],
    slavegrp_usb1_fn_mod_ahb: SlavegrpUsb1FnModAhb,
    _reserved96: [u8; 0xd4],
    slavegrp_usb1_read_qos: SlavegrpUsb1ReadQos,
    slavegrp_usb1_write_qos: SlavegrpUsb1WriteQos,
    slavegrp_usb1_fn_mod: SlavegrpUsb1FnMod,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - The L3 interconnect has separate address maps for the various L3 Masters. Generally, the addresses are the same for most masters. However, the sparse interconnect of the L3 switch causes some masters to have holes in their memory maps. The remap bits are not mutually exclusive. Each bit can be set independently and in combinations. Priority for the bits is determined by the bit offset: lower offset bits take precedence over higher offset bits."]
    #[inline(always)]
    pub const fn remap(&self) -> &Remap {
        &self.remap
    }
    #[doc = "0x08 - Controls security settings for L4 Main peripherals."]
    #[inline(always)]
    pub const fn secgrp_l4main(&self) -> &SecgrpL4main {
        &self.secgrp_l4main
    }
    #[doc = "0x0c - Controls security settings for L4 SP peripherals."]
    #[inline(always)]
    pub const fn secgrp_l4sp(&self) -> &SecgrpL4sp {
        &self.secgrp_l4sp
    }
    #[doc = "0x10 - Controls security settings for L4 MP peripherals."]
    #[inline(always)]
    pub const fn secgrp_l4mp(&self) -> &SecgrpL4mp {
        &self.secgrp_l4mp
    }
    #[doc = "0x14 - Controls security settings for L4 OSC1 peripherals."]
    #[inline(always)]
    pub const fn secgrp_l4osc1(&self) -> &SecgrpL4osc1 {
        &self.secgrp_l4osc1
    }
    #[doc = "0x18 - Controls security settings for L4 SPIM peripherals."]
    #[inline(always)]
    pub const fn secgrp_l4spim(&self) -> &SecgrpL4spim {
        &self.secgrp_l4spim
    }
    #[doc = "0x1c - Controls security settings for STM peripheral."]
    #[inline(always)]
    pub const fn secgrp_stm(&self) -> &SecgrpStm {
        &self.secgrp_stm
    }
    #[doc = "0x20 - Controls security settings for LWHPS2FPGA AXI Bridge Registers peripheral."]
    #[inline(always)]
    pub const fn secgrp_lwhps2fpgaregs(&self) -> &SecgrpLwhps2fpgaregs {
        &self.secgrp_lwhps2fpgaregs
    }
    #[doc = "0x28 - Controls security settings for USB1 Registers peripheral."]
    #[inline(always)]
    pub const fn secgrp_usb1(&self) -> &SecgrpUsb1 {
        &self.secgrp_usb1
    }
    #[doc = "0x2c - Controls security settings for NAND Flash Controller Data peripheral."]
    #[inline(always)]
    pub const fn secgrp_nanddata(&self) -> &SecgrpNanddata {
        &self.secgrp_nanddata
    }
    #[doc = "0x80 - Controls security settings for USB0 Registers peripheral."]
    #[inline(always)]
    pub const fn secgrp_usb0(&self) -> &SecgrpUsb0 {
        &self.secgrp_usb0
    }
    #[doc = "0x84 - Controls security settings for NAND Flash Controller Registers peripheral."]
    #[inline(always)]
    pub const fn secgrp_nandregs(&self) -> &SecgrpNandregs {
        &self.secgrp_nandregs
    }
    #[doc = "0x88 - Controls security settings for QSPI Flash Controller Data peripheral."]
    #[inline(always)]
    pub const fn secgrp_qspidata(&self) -> &SecgrpQspidata {
        &self.secgrp_qspidata
    }
    #[doc = "0x8c - Controls security settings for FPGA Manager Data peripheral."]
    #[inline(always)]
    pub const fn secgrp_fpgamgrdata(&self) -> &SecgrpFpgamgrdata {
        &self.secgrp_fpgamgrdata
    }
    #[doc = "0x90 - Controls security settings for HPS2FPGA AXI Bridge Registers peripheral."]
    #[inline(always)]
    pub const fn secgrp_hps2fpgaregs(&self) -> &SecgrpHps2fpgaregs {
        &self.secgrp_hps2fpgaregs
    }
    #[doc = "0x94 - Controls security settings for MPU ACP peripheral."]
    #[inline(always)]
    pub const fn secgrp_acp(&self) -> &SecgrpAcp {
        &self.secgrp_acp
    }
    #[doc = "0x98 - Controls security settings for ROM peripheral."]
    #[inline(always)]
    pub const fn secgrp_rom(&self) -> &SecgrpRom {
        &self.secgrp_rom
    }
    #[doc = "0x9c - Controls security settings for On-chip RAM peripheral."]
    #[inline(always)]
    pub const fn secgrp_ocram(&self) -> &SecgrpOcram {
        &self.secgrp_ocram
    }
    #[doc = "0xa0 - Controls security settings for SDRAM Data peripheral."]
    #[inline(always)]
    pub const fn secgrp_sdrdata(&self) -> &SecgrpSdrdata {
        &self.secgrp_sdrdata
    }
    #[doc = "0x1fd0 - JEP106 continuation code"]
    #[inline(always)]
    pub const fn idgrp_periph_id_4(&self) -> &IdgrpPeriphId4 {
        &self.idgrp_periph_id_4
    }
    #[doc = "0x1fe0 - Peripheral ID0"]
    #[inline(always)]
    pub const fn idgrp_periph_id_0(&self) -> &IdgrpPeriphId0 {
        &self.idgrp_periph_id_0
    }
    #[doc = "0x1fe4 - Peripheral ID1"]
    #[inline(always)]
    pub const fn idgrp_periph_id_1(&self) -> &IdgrpPeriphId1 {
        &self.idgrp_periph_id_1
    }
    #[doc = "0x1fe8 - Peripheral ID2"]
    #[inline(always)]
    pub const fn idgrp_periph_id_2(&self) -> &IdgrpPeriphId2 {
        &self.idgrp_periph_id_2
    }
    #[doc = "0x1fec - Peripheral ID3"]
    #[inline(always)]
    pub const fn idgrp_periph_id_3(&self) -> &IdgrpPeriphId3 {
        &self.idgrp_periph_id_3
    }
    #[doc = "0x1ff0 - Component ID0"]
    #[inline(always)]
    pub const fn idgrp_comp_id_0(&self) -> &IdgrpCompId0 {
        &self.idgrp_comp_id_0
    }
    #[doc = "0x1ff4 - Component ID1"]
    #[inline(always)]
    pub const fn idgrp_comp_id_1(&self) -> &IdgrpCompId1 {
        &self.idgrp_comp_id_1
    }
    #[doc = "0x1ff8 - Component ID2"]
    #[inline(always)]
    pub const fn idgrp_comp_id_2(&self) -> &IdgrpCompId2 {
        &self.idgrp_comp_id_2
    }
    #[doc = "0x1ffc - Component ID3"]
    #[inline(always)]
    pub const fn idgrp_comp_id_3(&self) -> &IdgrpCompId3 {
        &self.idgrp_comp_id_3
    }
    #[doc = "0x2008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_l4main_fn_mod_bm_iss(&self) -> &MastergrpL4mainFnModBmIss {
        &self.mastergrp_l4main_fn_mod_bm_iss
    }
    #[doc = "0x3008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_l4sp_fn_mod_bm_iss(&self) -> &MastergrpL4spFnModBmIss {
        &self.mastergrp_l4sp_fn_mod_bm_iss
    }
    #[doc = "0x4008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_l4mp_fn_mod_bm_iss(&self) -> &MastergrpL4mpFnModBmIss {
        &self.mastergrp_l4mp_fn_mod_bm_iss
    }
    #[doc = "0x5008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_l4osc1_fn_mod_bm_iss(&self) -> &MastergrpL4osc1FnModBmIss {
        &self.mastergrp_l4osc1_fn_mod_bm_iss
    }
    #[doc = "0x6008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_l4spim_fn_mod_bm_iss(&self) -> &MastergrpL4spimFnModBmIss {
        &self.mastergrp_l4spim_fn_mod_bm_iss
    }
    #[doc = "0x7008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_stm_fn_mod_bm_iss(&self) -> &MastergrpStmFnModBmIss {
        &self.mastergrp_stm_fn_mod_bm_iss
    }
    #[doc = "0x7108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_stm_fn_mod(&self) -> &MastergrpStmFnMod {
        &self.mastergrp_stm_fn_mod
    }
    #[doc = "0x8008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_lwhps2fpga_fn_mod_bm_iss(&self) -> &MastergrpLwhps2fpgaFnModBmIss {
        &self.mastergrp_lwhps2fpga_fn_mod_bm_iss
    }
    #[doc = "0x8108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_lwhps2fpga_fn_mod(&self) -> &MastergrpLwhps2fpgaFnMod {
        &self.mastergrp_lwhps2fpga_fn_mod
    }
    #[doc = "0xa008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_usb1_fn_mod_bm_iss(&self) -> &MastergrpUsb1FnModBmIss {
        &self.mastergrp_usb1_fn_mod_bm_iss
    }
    #[doc = "0xa044 - Sets the block issuing capability to one outstanding transaction."]
    #[inline(always)]
    pub const fn mastergrp_usb1_ahb_cntl(&self) -> &MastergrpUsb1AhbCntl {
        &self.mastergrp_usb1_ahb_cntl
    }
    #[doc = "0xb008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_nanddata_fn_mod_bm_iss(&self) -> &MastergrpNanddataFnModBmIss {
        &self.mastergrp_nanddata_fn_mod_bm_iss
    }
    #[doc = "0xb108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_nanddata_fn_mod(&self) -> &MastergrpNanddataFnMod {
        &self.mastergrp_nanddata_fn_mod
    }
    #[doc = "0x20008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_usb0_fn_mod_bm_iss(&self) -> &MastergrpUsb0FnModBmIss {
        &self.mastergrp_usb0_fn_mod_bm_iss
    }
    #[doc = "0x20044 - Sets the block issuing capability to one outstanding transaction."]
    #[inline(always)]
    pub const fn mastergrp_usb0_ahb_cntl(&self) -> &MastergrpUsb0AhbCntl {
        &self.mastergrp_usb0_ahb_cntl
    }
    #[doc = "0x21008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_nandregs_fn_mod_bm_iss(&self) -> &MastergrpNandregsFnModBmIss {
        &self.mastergrp_nandregs_fn_mod_bm_iss
    }
    #[doc = "0x21108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_nandregs_fn_mod(&self) -> &MastergrpNandregsFnMod {
        &self.mastergrp_nandregs_fn_mod
    }
    #[doc = "0x22008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_qspidata_fn_mod_bm_iss(&self) -> &MastergrpQspidataFnModBmIss {
        &self.mastergrp_qspidata_fn_mod_bm_iss
    }
    #[doc = "0x22044 - Sets the block issuing capability to one outstanding transaction."]
    #[inline(always)]
    pub const fn mastergrp_qspidata_ahb_cntl(&self) -> &MastergrpQspidataAhbCntl {
        &self.mastergrp_qspidata_ahb_cntl
    }
    #[doc = "0x23008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_fpgamgrdata_fn_mod_bm_iss(&self) -> &MastergrpFpgamgrdataFnModBmIss {
        &self.mastergrp_fpgamgrdata_fn_mod_bm_iss
    }
    #[doc = "0x23040 - Controls the release of the transaction in the write data FIFO."]
    #[inline(always)]
    pub const fn mastergrp_fpgamgrdata_wr_tidemark(&self) -> &MastergrpFpgamgrdataWrTidemark {
        &self.mastergrp_fpgamgrdata_wr_tidemark
    }
    #[doc = "0x23108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_fpgamgrdata_fn_mod(&self) -> &MastergrpFpgamgrdataFnMod {
        &self.mastergrp_fpgamgrdata_fn_mod
    }
    #[doc = "0x24008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_hps2fpga_fn_mod_bm_iss(&self) -> &MastergrpHps2fpgaFnModBmIss {
        &self.mastergrp_hps2fpga_fn_mod_bm_iss
    }
    #[doc = "0x24040 - Controls the release of the transaction in the write data FIFO."]
    #[inline(always)]
    pub const fn mastergrp_hps2fpga_wr_tidemark(&self) -> &MastergrpHps2fpgaWrTidemark {
        &self.mastergrp_hps2fpga_wr_tidemark
    }
    #[doc = "0x24108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_hps2fpga_fn_mod(&self) -> &MastergrpHps2fpgaFnMod {
        &self.mastergrp_hps2fpga_fn_mod
    }
    #[doc = "0x25008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_acp_fn_mod_bm_iss(&self) -> &MastergrpAcpFnModBmIss {
        &self.mastergrp_acp_fn_mod_bm_iss
    }
    #[doc = "0x25108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_acp_fn_mod(&self) -> &MastergrpAcpFnMod {
        &self.mastergrp_acp_fn_mod
    }
    #[doc = "0x26008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_rom_fn_mod_bm_iss(&self) -> &MastergrpRomFnModBmIss {
        &self.mastergrp_rom_fn_mod_bm_iss
    }
    #[doc = "0x26108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_rom_fn_mod(&self) -> &MastergrpRomFnMod {
        &self.mastergrp_rom_fn_mod
    }
    #[doc = "0x27008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_ocram_fn_mod_bm_iss(&self) -> &MastergrpOcramFnModBmIss {
        &self.mastergrp_ocram_fn_mod_bm_iss
    }
    #[doc = "0x27040 - Controls the release of the transaction in the write data FIFO."]
    #[inline(always)]
    pub const fn mastergrp_ocram_wr_tidemark(&self) -> &MastergrpOcramWrTidemark {
        &self.mastergrp_ocram_wr_tidemark
    }
    #[doc = "0x27108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_ocram_fn_mod(&self) -> &MastergrpOcramFnMod {
        &self.mastergrp_ocram_fn_mod
    }
    #[doc = "0x42024 - Controls bypass merge of upsizing/downsizing."]
    #[inline(always)]
    pub const fn slavegrp_dap_fn_mod2(&self) -> &SlavegrpDapFnMod2 {
        &self.slavegrp_dap_fn_mod2
    }
    #[doc = "0x42028 - Controls how AHB-lite burst transactions are converted to AXI tranactions."]
    #[inline(always)]
    pub const fn slavegrp_dap_fn_mod_ahb(&self) -> &SlavegrpDapFnModAhb {
        &self.slavegrp_dap_fn_mod_ahb
    }
    #[doc = "0x42100 - QoS (Quality of Service) value for the read channel."]
    #[inline(always)]
    pub const fn slavegrp_dap_read_qos(&self) -> &SlavegrpDapReadQos {
        &self.slavegrp_dap_read_qos
    }
    #[doc = "0x42104 - QoS (Quality of Service) value for the write channel."]
    #[inline(always)]
    pub const fn slavegrp_dap_write_qos(&self) -> &SlavegrpDapWriteQos {
        &self.slavegrp_dap_write_qos
    }
    #[doc = "0x42108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_dap_fn_mod(&self) -> &SlavegrpDapFnMod {
        &self.slavegrp_dap_fn_mod
    }
    #[doc = "0x43100 - QoS (Quality of Service) value for the read channel."]
    #[inline(always)]
    pub const fn slavegrp_mpu_read_qos(&self) -> &SlavegrpMpuReadQos {
        &self.slavegrp_mpu_read_qos
    }
    #[doc = "0x43104 - QoS (Quality of Service) value for the write channel."]
    #[inline(always)]
    pub const fn slavegrp_mpu_write_qos(&self) -> &SlavegrpMpuWriteQos {
        &self.slavegrp_mpu_write_qos
    }
    #[doc = "0x43108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_mpu_fn_mod(&self) -> &SlavegrpMpuFnMod {
        &self.slavegrp_mpu_fn_mod
    }
    #[doc = "0x44028 - Controls how AHB-lite burst transactions are converted to AXI tranactions."]
    #[inline(always)]
    pub const fn slavegrp_sdmmc_fn_mod_ahb(&self) -> &SlavegrpSdmmcFnModAhb {
        &self.slavegrp_sdmmc_fn_mod_ahb
    }
    #[doc = "0x44100 - QoS (Quality of Service) value for the read channel."]
    #[inline(always)]
    pub const fn slavegrp_sdmmc_read_qos(&self) -> &SlavegrpSdmmcReadQos {
        &self.slavegrp_sdmmc_read_qos
    }
    #[doc = "0x44104 - QoS (Quality of Service) value for the write channel."]
    #[inline(always)]
    pub const fn slavegrp_sdmmc_write_qos(&self) -> &SlavegrpSdmmcWriteQos {
        &self.slavegrp_sdmmc_write_qos
    }
    #[doc = "0x44108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_sdmmc_fn_mod(&self) -> &SlavegrpSdmmcFnMod {
        &self.slavegrp_sdmmc_fn_mod
    }
    #[doc = "0x45100 - QoS (Quality of Service) value for the read channel."]
    #[inline(always)]
    pub const fn slavegrp_dma_read_qos(&self) -> &SlavegrpDmaReadQos {
        &self.slavegrp_dma_read_qos
    }
    #[doc = "0x45104 - QoS (Quality of Service) value for the write channel."]
    #[inline(always)]
    pub const fn slavegrp_dma_write_qos(&self) -> &SlavegrpDmaWriteQos {
        &self.slavegrp_dma_write_qos
    }
    #[doc = "0x45108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_dma_fn_mod(&self) -> &SlavegrpDmaFnMod {
        &self.slavegrp_dma_fn_mod
    }
    #[doc = "0x46040 - Controls the release of the transaction in the write data FIFO."]
    #[inline(always)]
    pub const fn slavegrp_fpga2hps_wr_tidemark(&self) -> &SlavegrpFpga2hpsWrTidemark {
        &self.slavegrp_fpga2hps_wr_tidemark
    }
    #[doc = "0x46100 - QoS (Quality of Service) value for the read channel."]
    #[inline(always)]
    pub const fn slavegrp_fpga2hps_read_qos(&self) -> &SlavegrpFpga2hpsReadQos {
        &self.slavegrp_fpga2hps_read_qos
    }
    #[doc = "0x46104 - QoS (Quality of Service) value for the write channel."]
    #[inline(always)]
    pub const fn slavegrp_fpga2hps_write_qos(&self) -> &SlavegrpFpga2hpsWriteQos {
        &self.slavegrp_fpga2hps_write_qos
    }
    #[doc = "0x46108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_fpga2hps_fn_mod(&self) -> &SlavegrpFpga2hpsFnMod {
        &self.slavegrp_fpga2hps_fn_mod
    }
    #[doc = "0x47100 - QoS (Quality of Service) value for the read channel."]
    #[inline(always)]
    pub const fn slavegrp_etr_read_qos(&self) -> &SlavegrpEtrReadQos {
        &self.slavegrp_etr_read_qos
    }
    #[doc = "0x47104 - QoS (Quality of Service) value for the write channel."]
    #[inline(always)]
    pub const fn slavegrp_etr_write_qos(&self) -> &SlavegrpEtrWriteQos {
        &self.slavegrp_etr_write_qos
    }
    #[doc = "0x47108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_etr_fn_mod(&self) -> &SlavegrpEtrFnMod {
        &self.slavegrp_etr_fn_mod
    }
    #[doc = "0x48100 - QoS (Quality of Service) value for the read channel."]
    #[inline(always)]
    pub const fn slavegrp_emac0_read_qos(&self) -> &SlavegrpEmac0ReadQos {
        &self.slavegrp_emac0_read_qos
    }
    #[doc = "0x48104 - QoS (Quality of Service) value for the write channel."]
    #[inline(always)]
    pub const fn slavegrp_emac0_write_qos(&self) -> &SlavegrpEmac0WriteQos {
        &self.slavegrp_emac0_write_qos
    }
    #[doc = "0x48108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_emac0_fn_mod(&self) -> &SlavegrpEmac0FnMod {
        &self.slavegrp_emac0_fn_mod
    }
    #[doc = "0x49100 - QoS (Quality of Service) value for the read channel."]
    #[inline(always)]
    pub const fn slavegrp_emac1_read_qos(&self) -> &SlavegrpEmac1ReadQos {
        &self.slavegrp_emac1_read_qos
    }
    #[doc = "0x49104 - QoS (Quality of Service) value for the write channel."]
    #[inline(always)]
    pub const fn slavegrp_emac1_write_qos(&self) -> &SlavegrpEmac1WriteQos {
        &self.slavegrp_emac1_write_qos
    }
    #[doc = "0x49108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_emac1_fn_mod(&self) -> &SlavegrpEmac1FnMod {
        &self.slavegrp_emac1_fn_mod
    }
    #[doc = "0x4a028 - Controls how AHB-lite burst transactions are converted to AXI tranactions."]
    #[inline(always)]
    pub const fn slavegrp_usb0_fn_mod_ahb(&self) -> &SlavegrpUsb0FnModAhb {
        &self.slavegrp_usb0_fn_mod_ahb
    }
    #[doc = "0x4a100 - QoS (Quality of Service) value for the read channel."]
    #[inline(always)]
    pub const fn slavegrp_usb0_read_qos(&self) -> &SlavegrpUsb0ReadQos {
        &self.slavegrp_usb0_read_qos
    }
    #[doc = "0x4a104 - QoS (Quality of Service) value for the write channel."]
    #[inline(always)]
    pub const fn slavegrp_usb0_write_qos(&self) -> &SlavegrpUsb0WriteQos {
        &self.slavegrp_usb0_write_qos
    }
    #[doc = "0x4a108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_usb0_fn_mod(&self) -> &SlavegrpUsb0FnMod {
        &self.slavegrp_usb0_fn_mod
    }
    #[doc = "0x4b100 - QoS (Quality of Service) value for the read channel."]
    #[inline(always)]
    pub const fn slavegrp_nand_read_qos(&self) -> &SlavegrpNandReadQos {
        &self.slavegrp_nand_read_qos
    }
    #[doc = "0x4b104 - QoS (Quality of Service) value for the write channel."]
    #[inline(always)]
    pub const fn slavegrp_nand_write_qos(&self) -> &SlavegrpNandWriteQos {
        &self.slavegrp_nand_write_qos
    }
    #[doc = "0x4b108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_nand_fn_mod(&self) -> &SlavegrpNandFnMod {
        &self.slavegrp_nand_fn_mod
    }
    #[doc = "0x4c028 - Controls how AHB-lite burst transactions are converted to AXI tranactions."]
    #[inline(always)]
    pub const fn slavegrp_usb1_fn_mod_ahb(&self) -> &SlavegrpUsb1FnModAhb {
        &self.slavegrp_usb1_fn_mod_ahb
    }
    #[doc = "0x4c100 - QoS (Quality of Service) value for the read channel."]
    #[inline(always)]
    pub const fn slavegrp_usb1_read_qos(&self) -> &SlavegrpUsb1ReadQos {
        &self.slavegrp_usb1_read_qos
    }
    #[doc = "0x4c104 - QoS (Quality of Service) value for the write channel."]
    #[inline(always)]
    pub const fn slavegrp_usb1_write_qos(&self) -> &SlavegrpUsb1WriteQos {
        &self.slavegrp_usb1_write_qos
    }
    #[doc = "0x4c108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_usb1_fn_mod(&self) -> &SlavegrpUsb1FnMod {
        &self.slavegrp_usb1_fn_mod
    }
}
#[doc = "remap (w) register accessor: The L3 interconnect has separate address maps for the various L3 Masters. Generally, the addresses are the same for most masters. However, the sparse interconnect of the L3 switch causes some masters to have holes in their memory maps. The remap bits are not mutually exclusive. Each bit can be set independently and in combinations. Priority for the bits is determined by the bit offset: lower offset bits take precedence over higher offset bits.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`remap::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@remap`]
module"]
#[doc(alias = "remap")]
pub type Remap = crate::Reg<remap::RemapSpec>;
#[doc = "The L3 interconnect has separate address maps for the various L3 Masters. Generally, the addresses are the same for most masters. However, the sparse interconnect of the L3 switch causes some masters to have holes in their memory maps. The remap bits are not mutually exclusive. Each bit can be set independently and in combinations. Priority for the bits is determined by the bit offset: lower offset bits take precedence over higher offset bits."]
pub mod remap;
#[doc = "secgrp_l4main (w) register accessor: Controls security settings for L4 Main peripherals.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_l4main::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_l4main`]
module"]
#[doc(alias = "secgrp_l4main")]
pub type SecgrpL4main = crate::Reg<secgrp_l4main::SecgrpL4mainSpec>;
#[doc = "Controls security settings for L4 Main peripherals."]
pub mod secgrp_l4main;
#[doc = "secgrp_l4sp (w) register accessor: Controls security settings for L4 SP peripherals.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_l4sp::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_l4sp`]
module"]
#[doc(alias = "secgrp_l4sp")]
pub type SecgrpL4sp = crate::Reg<secgrp_l4sp::SecgrpL4spSpec>;
#[doc = "Controls security settings for L4 SP peripherals."]
pub mod secgrp_l4sp;
#[doc = "secgrp_l4mp (w) register accessor: Controls security settings for L4 MP peripherals.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_l4mp::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_l4mp`]
module"]
#[doc(alias = "secgrp_l4mp")]
pub type SecgrpL4mp = crate::Reg<secgrp_l4mp::SecgrpL4mpSpec>;
#[doc = "Controls security settings for L4 MP peripherals."]
pub mod secgrp_l4mp;
#[doc = "secgrp_l4osc1 (w) register accessor: Controls security settings for L4 OSC1 peripherals.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_l4osc1::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_l4osc1`]
module"]
#[doc(alias = "secgrp_l4osc1")]
pub type SecgrpL4osc1 = crate::Reg<secgrp_l4osc1::SecgrpL4osc1Spec>;
#[doc = "Controls security settings for L4 OSC1 peripherals."]
pub mod secgrp_l4osc1;
#[doc = "secgrp_l4spim (w) register accessor: Controls security settings for L4 SPIM peripherals.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_l4spim::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_l4spim`]
module"]
#[doc(alias = "secgrp_l4spim")]
pub type SecgrpL4spim = crate::Reg<secgrp_l4spim::SecgrpL4spimSpec>;
#[doc = "Controls security settings for L4 SPIM peripherals."]
pub mod secgrp_l4spim;
#[doc = "secgrp_stm (w) register accessor: Controls security settings for STM peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_stm::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_stm`]
module"]
#[doc(alias = "secgrp_stm")]
pub type SecgrpStm = crate::Reg<secgrp_stm::SecgrpStmSpec>;
#[doc = "Controls security settings for STM peripheral."]
pub mod secgrp_stm;
#[doc = "secgrp_lwhps2fpgaregs (w) register accessor: Controls security settings for LWHPS2FPGA AXI Bridge Registers peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_lwhps2fpgaregs::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_lwhps2fpgaregs`]
module"]
#[doc(alias = "secgrp_lwhps2fpgaregs")]
pub type SecgrpLwhps2fpgaregs = crate::Reg<secgrp_lwhps2fpgaregs::SecgrpLwhps2fpgaregsSpec>;
#[doc = "Controls security settings for LWHPS2FPGA AXI Bridge Registers peripheral."]
pub mod secgrp_lwhps2fpgaregs;
#[doc = "secgrp_usb1 (w) register accessor: Controls security settings for USB1 Registers peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_usb1::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_usb1`]
module"]
#[doc(alias = "secgrp_usb1")]
pub type SecgrpUsb1 = crate::Reg<secgrp_usb1::SecgrpUsb1Spec>;
#[doc = "Controls security settings for USB1 Registers peripheral."]
pub mod secgrp_usb1;
#[doc = "secgrp_nanddata (w) register accessor: Controls security settings for NAND Flash Controller Data peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_nanddata::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_nanddata`]
module"]
#[doc(alias = "secgrp_nanddata")]
pub type SecgrpNanddata = crate::Reg<secgrp_nanddata::SecgrpNanddataSpec>;
#[doc = "Controls security settings for NAND Flash Controller Data peripheral."]
pub mod secgrp_nanddata;
#[doc = "secgrp_usb0 (w) register accessor: Controls security settings for USB0 Registers peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_usb0::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_usb0`]
module"]
#[doc(alias = "secgrp_usb0")]
pub type SecgrpUsb0 = crate::Reg<secgrp_usb0::SecgrpUsb0Spec>;
#[doc = "Controls security settings for USB0 Registers peripheral."]
pub mod secgrp_usb0;
#[doc = "secgrp_nandregs (w) register accessor: Controls security settings for NAND Flash Controller Registers peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_nandregs::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_nandregs`]
module"]
#[doc(alias = "secgrp_nandregs")]
pub type SecgrpNandregs = crate::Reg<secgrp_nandregs::SecgrpNandregsSpec>;
#[doc = "Controls security settings for NAND Flash Controller Registers peripheral."]
pub mod secgrp_nandregs;
#[doc = "secgrp_qspidata (w) register accessor: Controls security settings for QSPI Flash Controller Data peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_qspidata::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_qspidata`]
module"]
#[doc(alias = "secgrp_qspidata")]
pub type SecgrpQspidata = crate::Reg<secgrp_qspidata::SecgrpQspidataSpec>;
#[doc = "Controls security settings for QSPI Flash Controller Data peripheral."]
pub mod secgrp_qspidata;
#[doc = "secgrp_fpgamgrdata (w) register accessor: Controls security settings for FPGA Manager Data peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_fpgamgrdata::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_fpgamgrdata`]
module"]
#[doc(alias = "secgrp_fpgamgrdata")]
pub type SecgrpFpgamgrdata = crate::Reg<secgrp_fpgamgrdata::SecgrpFpgamgrdataSpec>;
#[doc = "Controls security settings for FPGA Manager Data peripheral."]
pub mod secgrp_fpgamgrdata;
#[doc = "secgrp_hps2fpgaregs (w) register accessor: Controls security settings for HPS2FPGA AXI Bridge Registers peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_hps2fpgaregs::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_hps2fpgaregs`]
module"]
#[doc(alias = "secgrp_hps2fpgaregs")]
pub type SecgrpHps2fpgaregs = crate::Reg<secgrp_hps2fpgaregs::SecgrpHps2fpgaregsSpec>;
#[doc = "Controls security settings for HPS2FPGA AXI Bridge Registers peripheral."]
pub mod secgrp_hps2fpgaregs;
#[doc = "secgrp_acp (w) register accessor: Controls security settings for MPU ACP peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_acp::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_acp`]
module"]
#[doc(alias = "secgrp_acp")]
pub type SecgrpAcp = crate::Reg<secgrp_acp::SecgrpAcpSpec>;
#[doc = "Controls security settings for MPU ACP peripheral."]
pub mod secgrp_acp;
#[doc = "secgrp_rom (w) register accessor: Controls security settings for ROM peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_rom::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_rom`]
module"]
#[doc(alias = "secgrp_rom")]
pub type SecgrpRom = crate::Reg<secgrp_rom::SecgrpRomSpec>;
#[doc = "Controls security settings for ROM peripheral."]
pub mod secgrp_rom;
#[doc = "secgrp_ocram (w) register accessor: Controls security settings for On-chip RAM peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_ocram::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_ocram`]
module"]
#[doc(alias = "secgrp_ocram")]
pub type SecgrpOcram = crate::Reg<secgrp_ocram::SecgrpOcramSpec>;
#[doc = "Controls security settings for On-chip RAM peripheral."]
pub mod secgrp_ocram;
#[doc = "secgrp_sdrdata (w) register accessor: Controls security settings for SDRAM Data peripheral.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`secgrp_sdrdata::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@secgrp_sdrdata`]
module"]
#[doc(alias = "secgrp_sdrdata")]
pub type SecgrpSdrdata = crate::Reg<secgrp_sdrdata::SecgrpSdrdataSpec>;
#[doc = "Controls security settings for SDRAM Data peripheral."]
pub mod secgrp_sdrdata;
#[doc = "idgrp_periph_id_4 (r) register accessor: JEP106 continuation code\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_periph_id_4`]
module"]
#[doc(alias = "idgrp_periph_id_4")]
pub type IdgrpPeriphId4 = crate::Reg<idgrp_periph_id_4::IdgrpPeriphId4Spec>;
#[doc = "JEP106 continuation code"]
pub mod idgrp_periph_id_4;
#[doc = "idgrp_periph_id_0 (r) register accessor: Peripheral ID0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_periph_id_0`]
module"]
#[doc(alias = "idgrp_periph_id_0")]
pub type IdgrpPeriphId0 = crate::Reg<idgrp_periph_id_0::IdgrpPeriphId0Spec>;
#[doc = "Peripheral ID0"]
pub mod idgrp_periph_id_0;
#[doc = "idgrp_periph_id_1 (r) register accessor: Peripheral ID1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_periph_id_1`]
module"]
#[doc(alias = "idgrp_periph_id_1")]
pub type IdgrpPeriphId1 = crate::Reg<idgrp_periph_id_1::IdgrpPeriphId1Spec>;
#[doc = "Peripheral ID1"]
pub mod idgrp_periph_id_1;
#[doc = "idgrp_periph_id_2 (r) register accessor: Peripheral ID2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_periph_id_2`]
module"]
#[doc(alias = "idgrp_periph_id_2")]
pub type IdgrpPeriphId2 = crate::Reg<idgrp_periph_id_2::IdgrpPeriphId2Spec>;
#[doc = "Peripheral ID2"]
pub mod idgrp_periph_id_2;
#[doc = "idgrp_periph_id_3 (r) register accessor: Peripheral ID3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_periph_id_3`]
module"]
#[doc(alias = "idgrp_periph_id_3")]
pub type IdgrpPeriphId3 = crate::Reg<idgrp_periph_id_3::IdgrpPeriphId3Spec>;
#[doc = "Peripheral ID3"]
pub mod idgrp_periph_id_3;
#[doc = "idgrp_comp_id_0 (r) register accessor: Component ID0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_comp_id_0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_comp_id_0`]
module"]
#[doc(alias = "idgrp_comp_id_0")]
pub type IdgrpCompId0 = crate::Reg<idgrp_comp_id_0::IdgrpCompId0Spec>;
#[doc = "Component ID0"]
pub mod idgrp_comp_id_0;
#[doc = "idgrp_comp_id_1 (r) register accessor: Component ID1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_comp_id_1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_comp_id_1`]
module"]
#[doc(alias = "idgrp_comp_id_1")]
pub type IdgrpCompId1 = crate::Reg<idgrp_comp_id_1::IdgrpCompId1Spec>;
#[doc = "Component ID1"]
pub mod idgrp_comp_id_1;
#[doc = "idgrp_comp_id_2 (r) register accessor: Component ID2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_comp_id_2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_comp_id_2`]
module"]
#[doc(alias = "idgrp_comp_id_2")]
pub type IdgrpCompId2 = crate::Reg<idgrp_comp_id_2::IdgrpCompId2Spec>;
#[doc = "Component ID2"]
pub mod idgrp_comp_id_2;
#[doc = "idgrp_comp_id_3 (r) register accessor: Component ID3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_comp_id_3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_comp_id_3`]
module"]
#[doc(alias = "idgrp_comp_id_3")]
pub type IdgrpCompId3 = crate::Reg<idgrp_comp_id_3::IdgrpCompId3Spec>;
#[doc = "Component ID3"]
pub mod idgrp_comp_id_3;
#[doc = "mastergrp_l4main_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_l4main_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_l4main_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_l4main_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_l4main_fn_mod_bm_iss")]
pub type MastergrpL4mainFnModBmIss =
    crate::Reg<mastergrp_l4main_fn_mod_bm_iss::MastergrpL4mainFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_l4main_fn_mod_bm_iss;
#[doc = "mastergrp_l4sp_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_l4sp_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_l4sp_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_l4sp_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_l4sp_fn_mod_bm_iss")]
pub type MastergrpL4spFnModBmIss =
    crate::Reg<mastergrp_l4sp_fn_mod_bm_iss::MastergrpL4spFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_l4sp_fn_mod_bm_iss;
#[doc = "mastergrp_l4mp_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_l4mp_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_l4mp_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_l4mp_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_l4mp_fn_mod_bm_iss")]
pub type MastergrpL4mpFnModBmIss =
    crate::Reg<mastergrp_l4mp_fn_mod_bm_iss::MastergrpL4mpFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_l4mp_fn_mod_bm_iss;
#[doc = "mastergrp_l4osc1_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_l4osc1_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_l4osc1_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_l4osc1_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_l4osc1_fn_mod_bm_iss")]
pub type MastergrpL4osc1FnModBmIss =
    crate::Reg<mastergrp_l4osc1_fn_mod_bm_iss::MastergrpL4osc1FnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_l4osc1_fn_mod_bm_iss;
#[doc = "mastergrp_l4spim_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_l4spim_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_l4spim_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_l4spim_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_l4spim_fn_mod_bm_iss")]
pub type MastergrpL4spimFnModBmIss =
    crate::Reg<mastergrp_l4spim_fn_mod_bm_iss::MastergrpL4spimFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_l4spim_fn_mod_bm_iss;
#[doc = "mastergrp_stm_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_stm_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_stm_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_stm_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_stm_fn_mod_bm_iss")]
pub type MastergrpStmFnModBmIss =
    crate::Reg<mastergrp_stm_fn_mod_bm_iss::MastergrpStmFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_stm_fn_mod_bm_iss;
#[doc = "mastergrp_stm_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_stm_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_stm_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_stm_fn_mod`]
module"]
#[doc(alias = "mastergrp_stm_fn_mod")]
pub type MastergrpStmFnMod = crate::Reg<mastergrp_stm_fn_mod::MastergrpStmFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod mastergrp_stm_fn_mod;
#[doc = "mastergrp_lwhps2fpga_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_lwhps2fpga_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_lwhps2fpga_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_lwhps2fpga_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_lwhps2fpga_fn_mod_bm_iss")]
pub type MastergrpLwhps2fpgaFnModBmIss =
    crate::Reg<mastergrp_lwhps2fpga_fn_mod_bm_iss::MastergrpLwhps2fpgaFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_lwhps2fpga_fn_mod_bm_iss;
#[doc = "mastergrp_lwhps2fpga_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_lwhps2fpga_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_lwhps2fpga_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_lwhps2fpga_fn_mod`]
module"]
#[doc(alias = "mastergrp_lwhps2fpga_fn_mod")]
pub type MastergrpLwhps2fpgaFnMod =
    crate::Reg<mastergrp_lwhps2fpga_fn_mod::MastergrpLwhps2fpgaFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod mastergrp_lwhps2fpga_fn_mod;
#[doc = "mastergrp_usb1_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_usb1_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_usb1_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_usb1_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_usb1_fn_mod_bm_iss")]
pub type MastergrpUsb1FnModBmIss =
    crate::Reg<mastergrp_usb1_fn_mod_bm_iss::MastergrpUsb1FnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_usb1_fn_mod_bm_iss;
#[doc = "mastergrp_usb1_ahb_cntl (rw) register accessor: Sets the block issuing capability to one outstanding transaction.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_usb1_ahb_cntl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_usb1_ahb_cntl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_usb1_ahb_cntl`]
module"]
#[doc(alias = "mastergrp_usb1_ahb_cntl")]
pub type MastergrpUsb1AhbCntl = crate::Reg<mastergrp_usb1_ahb_cntl::MastergrpUsb1AhbCntlSpec>;
#[doc = "Sets the block issuing capability to one outstanding transaction."]
pub mod mastergrp_usb1_ahb_cntl;
#[doc = "mastergrp_nanddata_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_nanddata_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_nanddata_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_nanddata_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_nanddata_fn_mod_bm_iss")]
pub type MastergrpNanddataFnModBmIss =
    crate::Reg<mastergrp_nanddata_fn_mod_bm_iss::MastergrpNanddataFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_nanddata_fn_mod_bm_iss;
#[doc = "mastergrp_nanddata_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_nanddata_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_nanddata_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_nanddata_fn_mod`]
module"]
#[doc(alias = "mastergrp_nanddata_fn_mod")]
pub type MastergrpNanddataFnMod = crate::Reg<mastergrp_nanddata_fn_mod::MastergrpNanddataFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod mastergrp_nanddata_fn_mod;
#[doc = "mastergrp_usb0_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_usb0_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_usb0_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_usb0_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_usb0_fn_mod_bm_iss")]
pub type MastergrpUsb0FnModBmIss =
    crate::Reg<mastergrp_usb0_fn_mod_bm_iss::MastergrpUsb0FnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_usb0_fn_mod_bm_iss;
#[doc = "mastergrp_usb0_ahb_cntl (rw) register accessor: Sets the block issuing capability to one outstanding transaction.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_usb0_ahb_cntl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_usb0_ahb_cntl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_usb0_ahb_cntl`]
module"]
#[doc(alias = "mastergrp_usb0_ahb_cntl")]
pub type MastergrpUsb0AhbCntl = crate::Reg<mastergrp_usb0_ahb_cntl::MastergrpUsb0AhbCntlSpec>;
#[doc = "Sets the block issuing capability to one outstanding transaction."]
pub mod mastergrp_usb0_ahb_cntl;
#[doc = "mastergrp_nandregs_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_nandregs_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_nandregs_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_nandregs_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_nandregs_fn_mod_bm_iss")]
pub type MastergrpNandregsFnModBmIss =
    crate::Reg<mastergrp_nandregs_fn_mod_bm_iss::MastergrpNandregsFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_nandregs_fn_mod_bm_iss;
#[doc = "mastergrp_nandregs_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_nandregs_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_nandregs_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_nandregs_fn_mod`]
module"]
#[doc(alias = "mastergrp_nandregs_fn_mod")]
pub type MastergrpNandregsFnMod = crate::Reg<mastergrp_nandregs_fn_mod::MastergrpNandregsFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod mastergrp_nandregs_fn_mod;
#[doc = "mastergrp_qspidata_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_qspidata_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_qspidata_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_qspidata_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_qspidata_fn_mod_bm_iss")]
pub type MastergrpQspidataFnModBmIss =
    crate::Reg<mastergrp_qspidata_fn_mod_bm_iss::MastergrpQspidataFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_qspidata_fn_mod_bm_iss;
#[doc = "mastergrp_qspidata_ahb_cntl (rw) register accessor: Sets the block issuing capability to one outstanding transaction.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_qspidata_ahb_cntl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_qspidata_ahb_cntl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_qspidata_ahb_cntl`]
module"]
#[doc(alias = "mastergrp_qspidata_ahb_cntl")]
pub type MastergrpQspidataAhbCntl =
    crate::Reg<mastergrp_qspidata_ahb_cntl::MastergrpQspidataAhbCntlSpec>;
#[doc = "Sets the block issuing capability to one outstanding transaction."]
pub mod mastergrp_qspidata_ahb_cntl;
#[doc = "mastergrp_fpgamgrdata_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_fpgamgrdata_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_fpgamgrdata_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_fpgamgrdata_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_fpgamgrdata_fn_mod_bm_iss")]
pub type MastergrpFpgamgrdataFnModBmIss =
    crate::Reg<mastergrp_fpgamgrdata_fn_mod_bm_iss::MastergrpFpgamgrdataFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_fpgamgrdata_fn_mod_bm_iss;
#[doc = "mastergrp_fpgamgrdata_wr_tidemark (rw) register accessor: Controls the release of the transaction in the write data FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_fpgamgrdata_wr_tidemark::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_fpgamgrdata_wr_tidemark::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_fpgamgrdata_wr_tidemark`]
module"]
#[doc(alias = "mastergrp_fpgamgrdata_wr_tidemark")]
pub type MastergrpFpgamgrdataWrTidemark =
    crate::Reg<mastergrp_fpgamgrdata_wr_tidemark::MastergrpFpgamgrdataWrTidemarkSpec>;
#[doc = "Controls the release of the transaction in the write data FIFO."]
pub mod mastergrp_fpgamgrdata_wr_tidemark;
#[doc = "mastergrp_fpgamgrdata_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_fpgamgrdata_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_fpgamgrdata_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_fpgamgrdata_fn_mod`]
module"]
#[doc(alias = "mastergrp_fpgamgrdata_fn_mod")]
pub type MastergrpFpgamgrdataFnMod =
    crate::Reg<mastergrp_fpgamgrdata_fn_mod::MastergrpFpgamgrdataFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod mastergrp_fpgamgrdata_fn_mod;
#[doc = "mastergrp_hps2fpga_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_hps2fpga_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_hps2fpga_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_hps2fpga_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_hps2fpga_fn_mod_bm_iss")]
pub type MastergrpHps2fpgaFnModBmIss =
    crate::Reg<mastergrp_hps2fpga_fn_mod_bm_iss::MastergrpHps2fpgaFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_hps2fpga_fn_mod_bm_iss;
#[doc = "mastergrp_hps2fpga_wr_tidemark (rw) register accessor: Controls the release of the transaction in the write data FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_hps2fpga_wr_tidemark::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_hps2fpga_wr_tidemark::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_hps2fpga_wr_tidemark`]
module"]
#[doc(alias = "mastergrp_hps2fpga_wr_tidemark")]
pub type MastergrpHps2fpgaWrTidemark =
    crate::Reg<mastergrp_hps2fpga_wr_tidemark::MastergrpHps2fpgaWrTidemarkSpec>;
#[doc = "Controls the release of the transaction in the write data FIFO."]
pub mod mastergrp_hps2fpga_wr_tidemark;
#[doc = "mastergrp_hps2fpga_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_hps2fpga_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_hps2fpga_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_hps2fpga_fn_mod`]
module"]
#[doc(alias = "mastergrp_hps2fpga_fn_mod")]
pub type MastergrpHps2fpgaFnMod = crate::Reg<mastergrp_hps2fpga_fn_mod::MastergrpHps2fpgaFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod mastergrp_hps2fpga_fn_mod;
#[doc = "mastergrp_acp_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_acp_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_acp_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_acp_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_acp_fn_mod_bm_iss")]
pub type MastergrpAcpFnModBmIss =
    crate::Reg<mastergrp_acp_fn_mod_bm_iss::MastergrpAcpFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_acp_fn_mod_bm_iss;
#[doc = "mastergrp_acp_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_acp_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_acp_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_acp_fn_mod`]
module"]
#[doc(alias = "mastergrp_acp_fn_mod")]
pub type MastergrpAcpFnMod = crate::Reg<mastergrp_acp_fn_mod::MastergrpAcpFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod mastergrp_acp_fn_mod;
#[doc = "mastergrp_rom_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_rom_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_rom_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_rom_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_rom_fn_mod_bm_iss")]
pub type MastergrpRomFnModBmIss =
    crate::Reg<mastergrp_rom_fn_mod_bm_iss::MastergrpRomFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_rom_fn_mod_bm_iss;
#[doc = "mastergrp_rom_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_rom_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_rom_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_rom_fn_mod`]
module"]
#[doc(alias = "mastergrp_rom_fn_mod")]
pub type MastergrpRomFnMod = crate::Reg<mastergrp_rom_fn_mod::MastergrpRomFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod mastergrp_rom_fn_mod;
#[doc = "mastergrp_ocram_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_ocram_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_ocram_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_ocram_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_ocram_fn_mod_bm_iss")]
pub type MastergrpOcramFnModBmIss =
    crate::Reg<mastergrp_ocram_fn_mod_bm_iss::MastergrpOcramFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_ocram_fn_mod_bm_iss;
#[doc = "mastergrp_ocram_wr_tidemark (rw) register accessor: Controls the release of the transaction in the write data FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_ocram_wr_tidemark::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_ocram_wr_tidemark::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_ocram_wr_tidemark`]
module"]
#[doc(alias = "mastergrp_ocram_wr_tidemark")]
pub type MastergrpOcramWrTidemark =
    crate::Reg<mastergrp_ocram_wr_tidemark::MastergrpOcramWrTidemarkSpec>;
#[doc = "Controls the release of the transaction in the write data FIFO."]
pub mod mastergrp_ocram_wr_tidemark;
#[doc = "mastergrp_ocram_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_ocram_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_ocram_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_ocram_fn_mod`]
module"]
#[doc(alias = "mastergrp_ocram_fn_mod")]
pub type MastergrpOcramFnMod = crate::Reg<mastergrp_ocram_fn_mod::MastergrpOcramFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod mastergrp_ocram_fn_mod;
#[doc = "slavegrp_dap_fn_mod2 (rw) register accessor: Controls bypass merge of upsizing/downsizing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_dap_fn_mod2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_dap_fn_mod2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_dap_fn_mod2`]
module"]
#[doc(alias = "slavegrp_dap_fn_mod2")]
pub type SlavegrpDapFnMod2 = crate::Reg<slavegrp_dap_fn_mod2::SlavegrpDapFnMod2Spec>;
#[doc = "Controls bypass merge of upsizing/downsizing."]
pub mod slavegrp_dap_fn_mod2;
#[doc = "slavegrp_dap_fn_mod_ahb (rw) register accessor: Controls how AHB-lite burst transactions are converted to AXI tranactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_dap_fn_mod_ahb::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_dap_fn_mod_ahb::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_dap_fn_mod_ahb`]
module"]
#[doc(alias = "slavegrp_dap_fn_mod_ahb")]
pub type SlavegrpDapFnModAhb = crate::Reg<slavegrp_dap_fn_mod_ahb::SlavegrpDapFnModAhbSpec>;
#[doc = "Controls how AHB-lite burst transactions are converted to AXI tranactions."]
pub mod slavegrp_dap_fn_mod_ahb;
#[doc = "slavegrp_dap_read_qos (rw) register accessor: QoS (Quality of Service) value for the read channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_dap_read_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_dap_read_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_dap_read_qos`]
module"]
#[doc(alias = "slavegrp_dap_read_qos")]
pub type SlavegrpDapReadQos = crate::Reg<slavegrp_dap_read_qos::SlavegrpDapReadQosSpec>;
#[doc = "QoS (Quality of Service) value for the read channel."]
pub mod slavegrp_dap_read_qos;
#[doc = "slavegrp_dap_write_qos (rw) register accessor: QoS (Quality of Service) value for the write channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_dap_write_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_dap_write_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_dap_write_qos`]
module"]
#[doc(alias = "slavegrp_dap_write_qos")]
pub type SlavegrpDapWriteQos = crate::Reg<slavegrp_dap_write_qos::SlavegrpDapWriteQosSpec>;
#[doc = "QoS (Quality of Service) value for the write channel."]
pub mod slavegrp_dap_write_qos;
#[doc = "slavegrp_dap_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_dap_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_dap_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_dap_fn_mod`]
module"]
#[doc(alias = "slavegrp_dap_fn_mod")]
pub type SlavegrpDapFnMod = crate::Reg<slavegrp_dap_fn_mod::SlavegrpDapFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_dap_fn_mod;
#[doc = "slavegrp_mpu_read_qos (rw) register accessor: QoS (Quality of Service) value for the read channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_mpu_read_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_mpu_read_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_mpu_read_qos`]
module"]
#[doc(alias = "slavegrp_mpu_read_qos")]
pub type SlavegrpMpuReadQos = crate::Reg<slavegrp_mpu_read_qos::SlavegrpMpuReadQosSpec>;
#[doc = "QoS (Quality of Service) value for the read channel."]
pub mod slavegrp_mpu_read_qos;
#[doc = "slavegrp_mpu_write_qos (rw) register accessor: QoS (Quality of Service) value for the write channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_mpu_write_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_mpu_write_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_mpu_write_qos`]
module"]
#[doc(alias = "slavegrp_mpu_write_qos")]
pub type SlavegrpMpuWriteQos = crate::Reg<slavegrp_mpu_write_qos::SlavegrpMpuWriteQosSpec>;
#[doc = "QoS (Quality of Service) value for the write channel."]
pub mod slavegrp_mpu_write_qos;
#[doc = "slavegrp_mpu_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_mpu_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_mpu_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_mpu_fn_mod`]
module"]
#[doc(alias = "slavegrp_mpu_fn_mod")]
pub type SlavegrpMpuFnMod = crate::Reg<slavegrp_mpu_fn_mod::SlavegrpMpuFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_mpu_fn_mod;
#[doc = "slavegrp_sdmmc_fn_mod_ahb (rw) register accessor: Controls how AHB-lite burst transactions are converted to AXI tranactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_sdmmc_fn_mod_ahb::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_sdmmc_fn_mod_ahb::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_sdmmc_fn_mod_ahb`]
module"]
#[doc(alias = "slavegrp_sdmmc_fn_mod_ahb")]
pub type SlavegrpSdmmcFnModAhb = crate::Reg<slavegrp_sdmmc_fn_mod_ahb::SlavegrpSdmmcFnModAhbSpec>;
#[doc = "Controls how AHB-lite burst transactions are converted to AXI tranactions."]
pub mod slavegrp_sdmmc_fn_mod_ahb;
#[doc = "slavegrp_sdmmc_read_qos (rw) register accessor: QoS (Quality of Service) value for the read channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_sdmmc_read_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_sdmmc_read_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_sdmmc_read_qos`]
module"]
#[doc(alias = "slavegrp_sdmmc_read_qos")]
pub type SlavegrpSdmmcReadQos = crate::Reg<slavegrp_sdmmc_read_qos::SlavegrpSdmmcReadQosSpec>;
#[doc = "QoS (Quality of Service) value for the read channel."]
pub mod slavegrp_sdmmc_read_qos;
#[doc = "slavegrp_sdmmc_write_qos (rw) register accessor: QoS (Quality of Service) value for the write channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_sdmmc_write_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_sdmmc_write_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_sdmmc_write_qos`]
module"]
#[doc(alias = "slavegrp_sdmmc_write_qos")]
pub type SlavegrpSdmmcWriteQos = crate::Reg<slavegrp_sdmmc_write_qos::SlavegrpSdmmcWriteQosSpec>;
#[doc = "QoS (Quality of Service) value for the write channel."]
pub mod slavegrp_sdmmc_write_qos;
#[doc = "slavegrp_sdmmc_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_sdmmc_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_sdmmc_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_sdmmc_fn_mod`]
module"]
#[doc(alias = "slavegrp_sdmmc_fn_mod")]
pub type SlavegrpSdmmcFnMod = crate::Reg<slavegrp_sdmmc_fn_mod::SlavegrpSdmmcFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_sdmmc_fn_mod;
#[doc = "slavegrp_dma_read_qos (rw) register accessor: QoS (Quality of Service) value for the read channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_dma_read_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_dma_read_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_dma_read_qos`]
module"]
#[doc(alias = "slavegrp_dma_read_qos")]
pub type SlavegrpDmaReadQos = crate::Reg<slavegrp_dma_read_qos::SlavegrpDmaReadQosSpec>;
#[doc = "QoS (Quality of Service) value for the read channel."]
pub mod slavegrp_dma_read_qos;
#[doc = "slavegrp_dma_write_qos (rw) register accessor: QoS (Quality of Service) value for the write channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_dma_write_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_dma_write_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_dma_write_qos`]
module"]
#[doc(alias = "slavegrp_dma_write_qos")]
pub type SlavegrpDmaWriteQos = crate::Reg<slavegrp_dma_write_qos::SlavegrpDmaWriteQosSpec>;
#[doc = "QoS (Quality of Service) value for the write channel."]
pub mod slavegrp_dma_write_qos;
#[doc = "slavegrp_dma_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_dma_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_dma_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_dma_fn_mod`]
module"]
#[doc(alias = "slavegrp_dma_fn_mod")]
pub type SlavegrpDmaFnMod = crate::Reg<slavegrp_dma_fn_mod::SlavegrpDmaFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_dma_fn_mod;
#[doc = "slavegrp_fpga2hps_wr_tidemark (rw) register accessor: Controls the release of the transaction in the write data FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_fpga2hps_wr_tidemark::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_fpga2hps_wr_tidemark::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_fpga2hps_wr_tidemark`]
module"]
#[doc(alias = "slavegrp_fpga2hps_wr_tidemark")]
pub type SlavegrpFpga2hpsWrTidemark =
    crate::Reg<slavegrp_fpga2hps_wr_tidemark::SlavegrpFpga2hpsWrTidemarkSpec>;
#[doc = "Controls the release of the transaction in the write data FIFO."]
pub mod slavegrp_fpga2hps_wr_tidemark;
#[doc = "slavegrp_fpga2hps_read_qos (rw) register accessor: QoS (Quality of Service) value for the read channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_fpga2hps_read_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_fpga2hps_read_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_fpga2hps_read_qos`]
module"]
#[doc(alias = "slavegrp_fpga2hps_read_qos")]
pub type SlavegrpFpga2hpsReadQos =
    crate::Reg<slavegrp_fpga2hps_read_qos::SlavegrpFpga2hpsReadQosSpec>;
#[doc = "QoS (Quality of Service) value for the read channel."]
pub mod slavegrp_fpga2hps_read_qos;
#[doc = "slavegrp_fpga2hps_write_qos (rw) register accessor: QoS (Quality of Service) value for the write channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_fpga2hps_write_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_fpga2hps_write_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_fpga2hps_write_qos`]
module"]
#[doc(alias = "slavegrp_fpga2hps_write_qos")]
pub type SlavegrpFpga2hpsWriteQos =
    crate::Reg<slavegrp_fpga2hps_write_qos::SlavegrpFpga2hpsWriteQosSpec>;
#[doc = "QoS (Quality of Service) value for the write channel."]
pub mod slavegrp_fpga2hps_write_qos;
#[doc = "slavegrp_fpga2hps_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_fpga2hps_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_fpga2hps_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_fpga2hps_fn_mod`]
module"]
#[doc(alias = "slavegrp_fpga2hps_fn_mod")]
pub type SlavegrpFpga2hpsFnMod = crate::Reg<slavegrp_fpga2hps_fn_mod::SlavegrpFpga2hpsFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_fpga2hps_fn_mod;
#[doc = "slavegrp_etr_read_qos (rw) register accessor: QoS (Quality of Service) value for the read channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_etr_read_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_etr_read_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_etr_read_qos`]
module"]
#[doc(alias = "slavegrp_etr_read_qos")]
pub type SlavegrpEtrReadQos = crate::Reg<slavegrp_etr_read_qos::SlavegrpEtrReadQosSpec>;
#[doc = "QoS (Quality of Service) value for the read channel."]
pub mod slavegrp_etr_read_qos;
#[doc = "slavegrp_etr_write_qos (rw) register accessor: QoS (Quality of Service) value for the write channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_etr_write_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_etr_write_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_etr_write_qos`]
module"]
#[doc(alias = "slavegrp_etr_write_qos")]
pub type SlavegrpEtrWriteQos = crate::Reg<slavegrp_etr_write_qos::SlavegrpEtrWriteQosSpec>;
#[doc = "QoS (Quality of Service) value for the write channel."]
pub mod slavegrp_etr_write_qos;
#[doc = "slavegrp_etr_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_etr_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_etr_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_etr_fn_mod`]
module"]
#[doc(alias = "slavegrp_etr_fn_mod")]
pub type SlavegrpEtrFnMod = crate::Reg<slavegrp_etr_fn_mod::SlavegrpEtrFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_etr_fn_mod;
#[doc = "slavegrp_emac0_read_qos (rw) register accessor: QoS (Quality of Service) value for the read channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_emac0_read_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_emac0_read_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_emac0_read_qos`]
module"]
#[doc(alias = "slavegrp_emac0_read_qos")]
pub type SlavegrpEmac0ReadQos = crate::Reg<slavegrp_emac0_read_qos::SlavegrpEmac0ReadQosSpec>;
#[doc = "QoS (Quality of Service) value for the read channel."]
pub mod slavegrp_emac0_read_qos;
#[doc = "slavegrp_emac0_write_qos (rw) register accessor: QoS (Quality of Service) value for the write channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_emac0_write_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_emac0_write_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_emac0_write_qos`]
module"]
#[doc(alias = "slavegrp_emac0_write_qos")]
pub type SlavegrpEmac0WriteQos = crate::Reg<slavegrp_emac0_write_qos::SlavegrpEmac0WriteQosSpec>;
#[doc = "QoS (Quality of Service) value for the write channel."]
pub mod slavegrp_emac0_write_qos;
#[doc = "slavegrp_emac0_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_emac0_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_emac0_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_emac0_fn_mod`]
module"]
#[doc(alias = "slavegrp_emac0_fn_mod")]
pub type SlavegrpEmac0FnMod = crate::Reg<slavegrp_emac0_fn_mod::SlavegrpEmac0FnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_emac0_fn_mod;
#[doc = "slavegrp_emac1_read_qos (rw) register accessor: QoS (Quality of Service) value for the read channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_emac1_read_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_emac1_read_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_emac1_read_qos`]
module"]
#[doc(alias = "slavegrp_emac1_read_qos")]
pub type SlavegrpEmac1ReadQos = crate::Reg<slavegrp_emac1_read_qos::SlavegrpEmac1ReadQosSpec>;
#[doc = "QoS (Quality of Service) value for the read channel."]
pub mod slavegrp_emac1_read_qos;
#[doc = "slavegrp_emac1_write_qos (rw) register accessor: QoS (Quality of Service) value for the write channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_emac1_write_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_emac1_write_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_emac1_write_qos`]
module"]
#[doc(alias = "slavegrp_emac1_write_qos")]
pub type SlavegrpEmac1WriteQos = crate::Reg<slavegrp_emac1_write_qos::SlavegrpEmac1WriteQosSpec>;
#[doc = "QoS (Quality of Service) value for the write channel."]
pub mod slavegrp_emac1_write_qos;
#[doc = "slavegrp_emac1_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_emac1_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_emac1_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_emac1_fn_mod`]
module"]
#[doc(alias = "slavegrp_emac1_fn_mod")]
pub type SlavegrpEmac1FnMod = crate::Reg<slavegrp_emac1_fn_mod::SlavegrpEmac1FnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_emac1_fn_mod;
#[doc = "slavegrp_usb0_fn_mod_ahb (rw) register accessor: Controls how AHB-lite burst transactions are converted to AXI tranactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_usb0_fn_mod_ahb::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_usb0_fn_mod_ahb::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_usb0_fn_mod_ahb`]
module"]
#[doc(alias = "slavegrp_usb0_fn_mod_ahb")]
pub type SlavegrpUsb0FnModAhb = crate::Reg<slavegrp_usb0_fn_mod_ahb::SlavegrpUsb0FnModAhbSpec>;
#[doc = "Controls how AHB-lite burst transactions are converted to AXI tranactions."]
pub mod slavegrp_usb0_fn_mod_ahb;
#[doc = "slavegrp_usb0_read_qos (rw) register accessor: QoS (Quality of Service) value for the read channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_usb0_read_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_usb0_read_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_usb0_read_qos`]
module"]
#[doc(alias = "slavegrp_usb0_read_qos")]
pub type SlavegrpUsb0ReadQos = crate::Reg<slavegrp_usb0_read_qos::SlavegrpUsb0ReadQosSpec>;
#[doc = "QoS (Quality of Service) value for the read channel."]
pub mod slavegrp_usb0_read_qos;
#[doc = "slavegrp_usb0_write_qos (rw) register accessor: QoS (Quality of Service) value for the write channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_usb0_write_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_usb0_write_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_usb0_write_qos`]
module"]
#[doc(alias = "slavegrp_usb0_write_qos")]
pub type SlavegrpUsb0WriteQos = crate::Reg<slavegrp_usb0_write_qos::SlavegrpUsb0WriteQosSpec>;
#[doc = "QoS (Quality of Service) value for the write channel."]
pub mod slavegrp_usb0_write_qos;
#[doc = "slavegrp_usb0_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_usb0_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_usb0_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_usb0_fn_mod`]
module"]
#[doc(alias = "slavegrp_usb0_fn_mod")]
pub type SlavegrpUsb0FnMod = crate::Reg<slavegrp_usb0_fn_mod::SlavegrpUsb0FnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_usb0_fn_mod;
#[doc = "slavegrp_nand_read_qos (rw) register accessor: QoS (Quality of Service) value for the read channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_nand_read_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_nand_read_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_nand_read_qos`]
module"]
#[doc(alias = "slavegrp_nand_read_qos")]
pub type SlavegrpNandReadQos = crate::Reg<slavegrp_nand_read_qos::SlavegrpNandReadQosSpec>;
#[doc = "QoS (Quality of Service) value for the read channel."]
pub mod slavegrp_nand_read_qos;
#[doc = "slavegrp_nand_write_qos (rw) register accessor: QoS (Quality of Service) value for the write channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_nand_write_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_nand_write_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_nand_write_qos`]
module"]
#[doc(alias = "slavegrp_nand_write_qos")]
pub type SlavegrpNandWriteQos = crate::Reg<slavegrp_nand_write_qos::SlavegrpNandWriteQosSpec>;
#[doc = "QoS (Quality of Service) value for the write channel."]
pub mod slavegrp_nand_write_qos;
#[doc = "slavegrp_nand_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_nand_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_nand_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_nand_fn_mod`]
module"]
#[doc(alias = "slavegrp_nand_fn_mod")]
pub type SlavegrpNandFnMod = crate::Reg<slavegrp_nand_fn_mod::SlavegrpNandFnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_nand_fn_mod;
#[doc = "slavegrp_usb1_fn_mod_ahb (rw) register accessor: Controls how AHB-lite burst transactions are converted to AXI tranactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_usb1_fn_mod_ahb::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_usb1_fn_mod_ahb::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_usb1_fn_mod_ahb`]
module"]
#[doc(alias = "slavegrp_usb1_fn_mod_ahb")]
pub type SlavegrpUsb1FnModAhb = crate::Reg<slavegrp_usb1_fn_mod_ahb::SlavegrpUsb1FnModAhbSpec>;
#[doc = "Controls how AHB-lite burst transactions are converted to AXI tranactions."]
pub mod slavegrp_usb1_fn_mod_ahb;
#[doc = "slavegrp_usb1_read_qos (rw) register accessor: QoS (Quality of Service) value for the read channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_usb1_read_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_usb1_read_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_usb1_read_qos`]
module"]
#[doc(alias = "slavegrp_usb1_read_qos")]
pub type SlavegrpUsb1ReadQos = crate::Reg<slavegrp_usb1_read_qos::SlavegrpUsb1ReadQosSpec>;
#[doc = "QoS (Quality of Service) value for the read channel."]
pub mod slavegrp_usb1_read_qos;
#[doc = "slavegrp_usb1_write_qos (rw) register accessor: QoS (Quality of Service) value for the write channel.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_usb1_write_qos::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_usb1_write_qos::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_usb1_write_qos`]
module"]
#[doc(alias = "slavegrp_usb1_write_qos")]
pub type SlavegrpUsb1WriteQos = crate::Reg<slavegrp_usb1_write_qos::SlavegrpUsb1WriteQosSpec>;
#[doc = "QoS (Quality of Service) value for the write channel."]
pub mod slavegrp_usb1_write_qos;
#[doc = "slavegrp_usb1_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_usb1_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_usb1_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_usb1_fn_mod`]
module"]
#[doc(alias = "slavegrp_usb1_fn_mod")]
pub type SlavegrpUsb1FnMod = crate::Reg<slavegrp_usb1_fn_mod::SlavegrpUsb1FnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_usb1_fn_mod;
