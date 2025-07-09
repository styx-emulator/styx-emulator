// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    gmacgrp_mac_configuration: GmacgrpMacConfiguration,
    gmacgrp_mac_frame_filter: GmacgrpMacFrameFilter,
    _reserved2: [u8; 0x08],
    gmacgrp_gmii_address: GmacgrpGmiiAddress,
    gmacgrp_gmii_data: GmacgrpGmiiData,
    gmacgrp_flow_control: GmacgrpFlowControl,
    gmacgrp_vlan_tag: GmacgrpVlanTag,
    gmacgrp_version: GmacgrpVersion,
    gmacgrp_debug: GmacgrpDebug,
    _reserved8: [u8; 0x08],
    gmacgrp_lpi_control_status: GmacgrpLpiControlStatus,
    gmacgrp_lpi_timers_control: GmacgrpLpiTimersControl,
    gmacgrp_interrupt_status: GmacgrpInterruptStatus,
    gmacgrp_interrupt_mask: GmacgrpInterruptMask,
    gmacgrp_mac_address0_high: GmacgrpMacAddress0High,
    gmacgrp_mac_address0_low: GmacgrpMacAddress0Low,
    gmacgrp_mac_address1_high: GmacgrpMacAddress1High,
    gmacgrp_mac_address1_low: GmacgrpMacAddress1Low,
    gmacgrp_mac_address2_high: GmacgrpMacAddress2High,
    gmacgrp_mac_address2_low: GmacgrpMacAddress2Low,
    gmacgrp_mac_address3_high: GmacgrpMacAddress3High,
    gmacgrp_mac_address3_low: GmacgrpMacAddress3Low,
    gmacgrp_mac_address4_high: GmacgrpMacAddress4High,
    gmacgrp_mac_address4_low: GmacgrpMacAddress4Low,
    gmacgrp_mac_address5_high: GmacgrpMacAddress5High,
    gmacgrp_mac_address5_low: GmacgrpMacAddress5Low,
    gmacgrp_mac_address6_high: GmacgrpMacAddress6High,
    gmacgrp_mac_address6_low: GmacgrpMacAddress6Low,
    gmacgrp_mac_address7_high: GmacgrpMacAddress7High,
    gmacgrp_mac_address7_low: GmacgrpMacAddress7Low,
    gmacgrp_mac_address8_high: GmacgrpMacAddress8High,
    gmacgrp_mac_address8_low: GmacgrpMacAddress8Low,
    gmacgrp_mac_address9_high: GmacgrpMacAddress9High,
    gmacgrp_mac_address9_low: GmacgrpMacAddress9Low,
    gmacgrp_mac_address10_high: GmacgrpMacAddress10High,
    gmacgrp_mac_address10_low: GmacgrpMacAddress10Low,
    gmacgrp_mac_address11_high: GmacgrpMacAddress11High,
    gmacgrp_mac_address11_low: GmacgrpMacAddress11Low,
    gmacgrp_mac_address12_high: GmacgrpMacAddress12High,
    gmacgrp_mac_address12_low: GmacgrpMacAddress12Low,
    gmacgrp_mac_address13_high: GmacgrpMacAddress13High,
    gmacgrp_mac_address13_low: GmacgrpMacAddress13Low,
    gmacgrp_mac_address14_high: GmacgrpMacAddress14High,
    gmacgrp_mac_address14_low: GmacgrpMacAddress14Low,
    gmacgrp_mac_address15_high: GmacgrpMacAddress15High,
    gmacgrp_mac_address15_low: GmacgrpMacAddress15Low,
    _reserved44: [u8; 0x18],
    gmacgrp_sgmii_rgmii_smii_control_status: GmacgrpSgmiiRgmiiSmiiControlStatus,
    _reserved45: [u8; 0x24],
    gmacgrp_mmc_control: GmacgrpMmcControl,
    gmacgrp_mmc_receive_interrupt: GmacgrpMmcReceiveInterrupt,
    gmacgrp_mmc_transmit_interrupt: GmacgrpMmcTransmitInterrupt,
    gmacgrp_mmc_receive_interrupt_mask: GmacgrpMmcReceiveInterruptMask,
    gmacgrp_mmc_transmit_interrupt_mask: GmacgrpMmcTransmitInterruptMask,
    gmacgrp_txoctetcount_gb: GmacgrpTxoctetcountGb,
    gmacgrp_txframecount_gb: GmacgrpTxframecountGb,
    gmacgrp_txbroadcastframes_g: GmacgrpTxbroadcastframesG,
    gmacgrp_txmulticastframes_g: GmacgrpTxmulticastframesG,
    gmacgrp_tx64octets_gb: GmacgrpTx64octetsGb,
    gmacgrp_tx65to127octets_gb: GmacgrpTx65to127octetsGb,
    gmacgrp_tx128to255octets_gb: GmacgrpTx128to255octetsGb,
    gmacgrp_tx256to511octets_gb: GmacgrpTx256to511octetsGb,
    gmacgrp_tx512to1023octets_gb: GmacgrpTx512to1023octetsGb,
    gmacgrp_tx1024tomaxoctets_gb: GmacgrpTx1024tomaxoctetsGb,
    gmacgrp_txunicastframes_gb: GmacgrpTxunicastframesGb,
    gmacgrp_txmulticastframes_gb: GmacgrpTxmulticastframesGb,
    gmacgrp_txbroadcastframes_gb: GmacgrpTxbroadcastframesGb,
    gmacgrp_txunderflowerror: GmacgrpTxunderflowerror,
    gmacgrp_txsinglecol_g: GmacgrpTxsinglecolG,
    gmacgrp_txmulticol_g: GmacgrpTxmulticolG,
    gmacgrp_txdeferred: GmacgrpTxdeferred,
    gmacgrp_txlatecol: GmacgrpTxlatecol,
    gmacgrp_txexesscol: GmacgrpTxexesscol,
    gmacgrp_txcarriererr: GmacgrpTxcarriererr,
    gmacgrp_txoctetcnt: GmacgrpTxoctetcnt,
    gmacgrp_txframecount_g: GmacgrpTxframecountG,
    gmacgrp_txexcessdef: GmacgrpTxexcessdef,
    gmacgrp_txpauseframes: GmacgrpTxpauseframes,
    gmacgrp_txvlanframes_g: GmacgrpTxvlanframesG,
    gmacgrp_txoversize_g: GmacgrpTxoversizeG,
    _reserved76: [u8; 0x04],
    gmacgrp_rxframecount_gb: GmacgrpRxframecountGb,
    gmacgrp_rxoctetcount_gb: GmacgrpRxoctetcountGb,
    gmacgrp_rxoctetcount_g: GmacgrpRxoctetcountG,
    gmacgrp_rxbroadcastframes_g: GmacgrpRxbroadcastframesG,
    gmacgrp_rxmulticastframes_g: GmacgrpRxmulticastframesG,
    gmacgrp_rxcrcerror: GmacgrpRxcrcerror,
    gmacgrp_rxalignmenterror: GmacgrpRxalignmenterror,
    gmacgrp_rxrunterror: GmacgrpRxrunterror,
    gmacgrp_rxjabbererror: GmacgrpRxjabbererror,
    gmacgrp_rxundersize_g: GmacgrpRxundersizeG,
    gmacgrp_rxoversize_g: GmacgrpRxoversizeG,
    gmacgrp_rx64octets_gb: GmacgrpRx64octetsGb,
    gmacgrp_rx65to127octets_gb: GmacgrpRx65to127octetsGb,
    gmacgrp_rx128to255octets_gb: GmacgrpRx128to255octetsGb,
    gmacgrp_rx256to511octets_gb: GmacgrpRx256to511octetsGb,
    gmacgrp_rx512to1023octets_gb: GmacgrpRx512to1023octetsGb,
    gmacgrp_rx1024tomaxoctets_gb: GmacgrpRx1024tomaxoctetsGb,
    gmacgrp_rxunicastframes_g: GmacgrpRxunicastframesG,
    gmacgrp_rxlengtherror: GmacgrpRxlengtherror,
    gmacgrp_rxoutofrangetype: GmacgrpRxoutofrangetype,
    gmacgrp_rxpauseframes: GmacgrpRxpauseframes,
    gmacgrp_rxfifooverflow: GmacgrpRxfifooverflow,
    gmacgrp_rxvlanframes_gb: GmacgrpRxvlanframesGb,
    gmacgrp_rxwatchdogerror: GmacgrpRxwatchdogerror,
    gmacgrp_rxrcverror: GmacgrpRxrcverror,
    gmacgrp_rxctrlframes_g: GmacgrpRxctrlframesG,
    _reserved102: [u8; 0x18],
    gmacgrp_mmc_ipc_receive_interrupt_mask: GmacgrpMmcIpcReceiveInterruptMask,
    _reserved103: [u8; 0x04],
    gmacgrp_mmc_ipc_receive_interrupt: GmacgrpMmcIpcReceiveInterrupt,
    _reserved104: [u8; 0x04],
    gmacgrp_rxipv4_gd_frms: GmacgrpRxipv4GdFrms,
    gmacgrp_rxipv4_hdrerr_frms: GmacgrpRxipv4HdrerrFrms,
    gmacgrp_rxipv4_nopay_frms: GmacgrpRxipv4NopayFrms,
    gmacgrp_rxipv4_frag_frms: GmacgrpRxipv4FragFrms,
    gmacgrp_rxipv4_udsbl_frms: GmacgrpRxipv4UdsblFrms,
    gmacgrp_rxipv6_gd_frms: GmacgrpRxipv6GdFrms,
    gmacgrp_rxipv6_hdrerr_frms: GmacgrpRxipv6HdrerrFrms,
    gmacgrp_rxipv6_nopay_frms: GmacgrpRxipv6NopayFrms,
    gmacgrp_rxudp_gd_frms: GmacgrpRxudpGdFrms,
    gmacgrp_rxudp_err_frms: GmacgrpRxudpErrFrms,
    gmacgrp_rxtcp_gd_frms: GmacgrpRxtcpGdFrms,
    gmacgrp_rxtcp_err_frms: GmacgrpRxtcpErrFrms,
    gmacgrp_rxicmp_gd_frms: GmacgrpRxicmpGdFrms,
    gmacgrp_rxicmp_err_frms: GmacgrpRxicmpErrFrms,
    _reserved118: [u8; 0x08],
    gmacgrp_rxipv4_gd_octets: GmacgrpRxipv4GdOctets,
    gmacgrp_rxipv4_hdrerr_octets: GmacgrpRxipv4HdrerrOctets,
    gmacgrp_rxipv4_nopay_octets: GmacgrpRxipv4NopayOctets,
    gmacgrp_rxipv4_frag_octets: GmacgrpRxipv4FragOctets,
    gmacgrp_rxipv4_udsbl_octets: GmacgrpRxipv4UdsblOctets,
    gmacgrp_rxipv6_gd_octets: GmacgrpRxipv6GdOctets,
    gmacgrp_rxipv6_hdrerr_octets: GmacgrpRxipv6HdrerrOctets,
    gmacgrp_rxipv6_nopay_octets: GmacgrpRxipv6NopayOctets,
    gmacgrp_rxudp_gd_octets: GmacgrpRxudpGdOctets,
    gmacgrp_rxudp_err_octets: GmacgrpRxudpErrOctets,
    gmacgrp_rxtcp_gd_octets: GmacgrpRxtcpGdOctets,
    gmacgrp_rxtcperroctets: GmacgrpRxtcperroctets,
    gmacgrp_rxicmp_gd_octets: GmacgrpRxicmpGdOctets,
    gmacgrp_rxicmp_err_octets: GmacgrpRxicmpErrOctets,
    _reserved132: [u8; 0x0178],
    gmacgrp_l3_l4_control0: GmacgrpL3L4Control0,
    gmacgrp_layer4_address0: GmacgrpLayer4Address0,
    _reserved134: [u8; 0x08],
    gmacgrp_layer3_addr0_reg0: GmacgrpLayer3Addr0Reg0,
    gmacgrp_layer3_addr1_reg0: GmacgrpLayer3Addr1Reg0,
    gmacgrp_layer3_addr2_reg0: GmacgrpLayer3Addr2Reg0,
    gmacgrp_layer3_addr3_reg0: GmacgrpLayer3Addr3Reg0,
    _reserved138: [u8; 0x10],
    gmacgrp_l3_l4_control1: GmacgrpL3L4Control1,
    gmacgrp_layer4_address1: GmacgrpLayer4Address1,
    _reserved140: [u8; 0x08],
    gmacgrp_layer3_addr0_reg1: GmacgrpLayer3Addr0Reg1,
    gmacgrp_layer3_addr1_reg1: GmacgrpLayer3Addr1Reg1,
    gmacgrp_layer3_addr2_reg1: GmacgrpLayer3Addr2Reg1,
    gmacgrp_layer3_addr3_reg1: GmacgrpLayer3Addr3Reg1,
    _reserved144: [u8; 0x10],
    gmacgrp_l3_l4_control2: GmacgrpL3L4Control2,
    gmacgrp_layer4_address2: GmacgrpLayer4Address2,
    _reserved146: [u8; 0x08],
    gmacgrp_layer3_addr0_reg2: GmacgrpLayer3Addr0Reg2,
    gmacgrp_layer3_addr1_reg2: GmacgrpLayer3Addr1Reg2,
    gmacgrp_layer3_addr2_reg2: GmacgrpLayer3Addr2Reg2,
    gmacgrp_layer3_addr3_reg2: GmacgrpLayer3Addr3Reg2,
    _reserved150: [u8; 0x10],
    gmacgrp_l3_l4_control3: GmacgrpL3L4Control3,
    gmacgrp_layer4_address3: GmacgrpLayer4Address3,
    _reserved152: [u8; 0x08],
    gmacgrp_layer3_addr0_reg3: GmacgrpLayer3Addr0Reg3,
    gmacgrp_layer3_addr1_reg3: GmacgrpLayer3Addr1Reg3,
    gmacgrp_layer3_addr2_reg3: GmacgrpLayer3Addr2Reg3,
    gmacgrp_layer3_addr3_reg3: GmacgrpLayer3Addr3Reg3,
    _reserved156: [u8; 0x50],
    gmacgrp_hash_table_reg0: GmacgrpHashTableReg0,
    gmacgrp_hash_table_reg1: GmacgrpHashTableReg1,
    gmacgrp_hash_table_reg2: GmacgrpHashTableReg2,
    gmacgrp_hash_table_reg3: GmacgrpHashTableReg3,
    gmacgrp_hash_table_reg4: GmacgrpHashTableReg4,
    gmacgrp_hash_table_reg5: GmacgrpHashTableReg5,
    gmacgrp_hash_table_reg6: GmacgrpHashTableReg6,
    gmacgrp_hash_table_reg7: GmacgrpHashTableReg7,
    _reserved164: [u8; 0x64],
    gmacgrp_vlan_incl_reg: GmacgrpVlanInclReg,
    gmacgrp_vlan_hash_table_reg: GmacgrpVlanHashTableReg,
    _reserved166: [u8; 0x0174],
    gmacgrp_timestamp_control: GmacgrpTimestampControl,
    gmacgrp_sub_second_increment: GmacgrpSubSecondIncrement,
    gmacgrp_system_time_seconds: GmacgrpSystemTimeSeconds,
    gmacgrp_system_time_nanoseconds: GmacgrpSystemTimeNanoseconds,
    gmacgrp_system_time_seconds_update: GmacgrpSystemTimeSecondsUpdate,
    gmacgrp_system_time_nanoseconds_update: GmacgrpSystemTimeNanosecondsUpdate,
    gmacgrp_timestamp_addend: GmacgrpTimestampAddend,
    gmacgrp_target_time_seconds: GmacgrpTargetTimeSeconds,
    gmacgrp_target_time_nanoseconds: GmacgrpTargetTimeNanoseconds,
    gmacgrp_system_time_higher_word_seconds: GmacgrpSystemTimeHigherWordSeconds,
    gmacgrp_timestamp_status: GmacgrpTimestampStatus,
    gmacgrp_pps_control: GmacgrpPpsControl,
    gmacgrp_auxiliary_timestamp_nanoseconds: GmacgrpAuxiliaryTimestampNanoseconds,
    gmacgrp_auxiliary_timestamp_seconds: GmacgrpAuxiliaryTimestampSeconds,
    _reserved180: [u8; 0x28],
    gmacgrp_pps0_interval: GmacgrpPps0Interval,
    gmacgrp_pps0_width: GmacgrpPps0Width,
    _reserved182: [u8; 0x98],
    gmacgrp_mac_address16_high: GmacgrpMacAddress16High,
    gmacgrp_mac_address16_low: GmacgrpMacAddress16Low,
    gmacgrp_mac_address17_high: GmacgrpMacAddress17High,
    gmacgrp_mac_address17_low: GmacgrpMacAddress17Low,
    gmacgrp_mac_address18_high: GmacgrpMacAddress18High,
    gmacgrp_mac_address18_low: GmacgrpMacAddress18Low,
    gmacgrp_mac_address19_high: GmacgrpMacAddress19High,
    gmacgrp_mac_address19_low: GmacgrpMacAddress19Low,
    gmacgrp_mac_address20_high: GmacgrpMacAddress20High,
    gmacgrp_mac_address20_low: GmacgrpMacAddress20Low,
    gmacgrp_mac_address21_high: GmacgrpMacAddress21High,
    gmacgrp_mac_address21_low: GmacgrpMacAddress21Low,
    gmacgrp_mac_address22_high: GmacgrpMacAddress22High,
    gmacgrp_mac_address22_low: GmacgrpMacAddress22Low,
    gmacgrp_mac_address23_high: GmacgrpMacAddress23High,
    gmacgrp_mac_address23_low: GmacgrpMacAddress23Low,
    gmacgrp_mac_address24_high: GmacgrpMacAddress24High,
    gmacgrp_mac_address24_low: GmacgrpMacAddress24Low,
    gmacgrp_mac_address25_high: GmacgrpMacAddress25High,
    gmacgrp_mac_address25_low: GmacgrpMacAddress25Low,
    gmacgrp_mac_address26_high: GmacgrpMacAddress26High,
    gmacgrp_mac_address26_low: GmacgrpMacAddress26Low,
    gmacgrp_mac_address27_high: GmacgrpMacAddress27High,
    gmacgrp_mac_address27_low: GmacgrpMacAddress27Low,
    gmacgrp_mac_address28_high: GmacgrpMacAddress28High,
    gmacgrp_mac_address28_low: GmacgrpMacAddress28Low,
    gmacgrp_mac_address29_high: GmacgrpMacAddress29High,
    gmacgrp_mac_address29_low: GmacgrpMacAddress29Low,
    gmacgrp_mac_address30_high: GmacgrpMacAddress30High,
    gmacgrp_mac_address30_low: GmacgrpMacAddress30Low,
    gmacgrp_mac_address31_high: GmacgrpMacAddress31High,
    gmacgrp_mac_address31_low: GmacgrpMacAddress31Low,
    gmacgrp_mac_address32_high: GmacgrpMacAddress32High,
    gmacgrp_mac_address32_low: GmacgrpMacAddress32Low,
    gmacgrp_mac_address33_high: GmacgrpMacAddress33High,
    gmacgrp_mac_address33_low: GmacgrpMacAddress33Low,
    gmacgrp_mac_address34_high: GmacgrpMacAddress34High,
    gmacgrp_mac_address34_low: GmacgrpMacAddress34Low,
    gmacgrp_mac_address35_high: GmacgrpMacAddress35High,
    gmacgrp_mac_address35_low: GmacgrpMacAddress35Low,
    gmacgrp_mac_address36_high: GmacgrpMacAddress36High,
    gmacgrp_mac_address36_low: GmacgrpMacAddress36Low,
    gmacgrp_mac_address37_high: GmacgrpMacAddress37High,
    gmacgrp_mac_address37_low: GmacgrpMacAddress37Low,
    gmacgrp_mac_address38_high: GmacgrpMacAddress38High,
    gmacgrp_mac_address38_low: GmacgrpMacAddress38Low,
    gmacgrp_mac_address39_high: GmacgrpMacAddress39High,
    gmacgrp_mac_address39_low: GmacgrpMacAddress39Low,
    gmacgrp_mac_address40_high: GmacgrpMacAddress40High,
    gmacgrp_mac_address40_low: GmacgrpMacAddress40Low,
    gmacgrp_mac_address41_high: GmacgrpMacAddress41High,
    gmacgrp_mac_address41_low: GmacgrpMacAddress41Low,
    gmacgrp_mac_address42_high: GmacgrpMacAddress42High,
    gmacgrp_mac_address42_low: GmacgrpMacAddress42Low,
    gmacgrp_mac_address43_high: GmacgrpMacAddress43High,
    gmacgrp_mac_address43_low: GmacgrpMacAddress43Low,
    gmacgrp_mac_address44_high: GmacgrpMacAddress44High,
    gmacgrp_mac_address44_low: GmacgrpMacAddress44Low,
    gmacgrp_mac_address45_high: GmacgrpMacAddress45High,
    gmacgrp_mac_address45_low: GmacgrpMacAddress45Low,
    gmacgrp_mac_address46_high: GmacgrpMacAddress46High,
    gmacgrp_mac_address46_low: GmacgrpMacAddress46Low,
    gmacgrp_mac_address47_high: GmacgrpMacAddress47High,
    gmacgrp_mac_address47_low: GmacgrpMacAddress47Low,
    gmacgrp_mac_address48_high: GmacgrpMacAddress48High,
    gmacgrp_mac_address48_low: GmacgrpMacAddress48Low,
    gmacgrp_mac_address49_high: GmacgrpMacAddress49High,
    gmacgrp_mac_address49_low: GmacgrpMacAddress49Low,
    gmacgrp_mac_address50_high: GmacgrpMacAddress50High,
    gmacgrp_mac_address50_low: GmacgrpMacAddress50Low,
    gmacgrp_mac_address51_high: GmacgrpMacAddress51High,
    gmacgrp_mac_address51_low: GmacgrpMacAddress51Low,
    gmacgrp_mac_address52_high: GmacgrpMacAddress52High,
    gmacgrp_mac_address52_low: GmacgrpMacAddress52Low,
    gmacgrp_mac_address53_high: GmacgrpMacAddress53High,
    gmacgrp_mac_address53_low: GmacgrpMacAddress53Low,
    gmacgrp_mac_address54_high: GmacgrpMacAddress54High,
    gmacgrp_mac_address54_low: GmacgrpMacAddress54Low,
    gmacgrp_mac_address55_high: GmacgrpMacAddress55High,
    gmacgrp_mac_address55_low: GmacgrpMacAddress55Low,
    gmacgrp_mac_address56_high: GmacgrpMacAddress56High,
    gmacgrp_mac_address56_low: GmacgrpMacAddress56Low,
    gmacgrp_mac_address57_high: GmacgrpMacAddress57High,
    gmacgrp_mac_address57_low: GmacgrpMacAddress57Low,
    gmacgrp_mac_address58_high: GmacgrpMacAddress58High,
    gmacgrp_mac_address58_low: GmacgrpMacAddress58Low,
    gmacgrp_mac_address59_high: GmacgrpMacAddress59High,
    gmacgrp_mac_address59_low: GmacgrpMacAddress59Low,
    gmacgrp_mac_address60_high: GmacgrpMacAddress60High,
    gmacgrp_mac_address60_low: GmacgrpMacAddress60Low,
    gmacgrp_mac_address61_high: GmacgrpMacAddress61High,
    gmacgrp_mac_address61_low: GmacgrpMacAddress61Low,
    gmacgrp_mac_address62_high: GmacgrpMacAddress62High,
    gmacgrp_mac_address62_low: GmacgrpMacAddress62Low,
    gmacgrp_mac_address63_high: GmacgrpMacAddress63High,
    gmacgrp_mac_address63_low: GmacgrpMacAddress63Low,
    gmacgrp_mac_address64_high: GmacgrpMacAddress64High,
    gmacgrp_mac_address64_low: GmacgrpMacAddress64Low,
    gmacgrp_mac_address65_high: GmacgrpMacAddress65High,
    gmacgrp_mac_address65_low: GmacgrpMacAddress65Low,
    gmacgrp_mac_address66_high: GmacgrpMacAddress66High,
    gmacgrp_mac_address66_low: GmacgrpMacAddress66Low,
    gmacgrp_mac_address67_high: GmacgrpMacAddress67High,
    gmacgrp_mac_address67_low: GmacgrpMacAddress67Low,
    gmacgrp_mac_address68_high: GmacgrpMacAddress68High,
    gmacgrp_mac_address68_low: GmacgrpMacAddress68Low,
    gmacgrp_mac_address69_high: GmacgrpMacAddress69High,
    gmacgrp_mac_address69_low: GmacgrpMacAddress69Low,
    gmacgrp_mac_address70_high: GmacgrpMacAddress70High,
    gmacgrp_mac_address70_low: GmacgrpMacAddress70Low,
    gmacgrp_mac_address71_high: GmacgrpMacAddress71High,
    gmacgrp_mac_address71_low: GmacgrpMacAddress71Low,
    gmacgrp_mac_address72_high: GmacgrpMacAddress72High,
    gmacgrp_mac_address72_low: GmacgrpMacAddress72Low,
    gmacgrp_mac_address73_high: GmacgrpMacAddress73High,
    gmacgrp_mac_address73_low: GmacgrpMacAddress73Low,
    gmacgrp_mac_address74_high: GmacgrpMacAddress74High,
    gmacgrp_mac_address74_low: GmacgrpMacAddress74Low,
    gmacgrp_mac_address75_high: GmacgrpMacAddress75High,
    gmacgrp_mac_address75_low: GmacgrpMacAddress75Low,
    gmacgrp_mac_address76_high: GmacgrpMacAddress76High,
    gmacgrp_mac_address76_low: GmacgrpMacAddress76Low,
    gmacgrp_mac_address77_high: GmacgrpMacAddress77High,
    gmacgrp_mac_address77_low: GmacgrpMacAddress77Low,
    gmacgrp_mac_address78_high: GmacgrpMacAddress78High,
    gmacgrp_mac_address78_low: GmacgrpMacAddress78Low,
    gmacgrp_mac_address79_high: GmacgrpMacAddress79High,
    gmacgrp_mac_address79_low: GmacgrpMacAddress79Low,
    gmacgrp_mac_address80_high: GmacgrpMacAddress80High,
    gmacgrp_mac_address80_low: GmacgrpMacAddress80Low,
    gmacgrp_mac_address81_high: GmacgrpMacAddress81High,
    gmacgrp_mac_address81_low: GmacgrpMacAddress81Low,
    gmacgrp_mac_address82_high: GmacgrpMacAddress82High,
    gmacgrp_mac_address82_low: GmacgrpMacAddress82Low,
    gmacgrp_mac_address83_high: GmacgrpMacAddress83High,
    gmacgrp_mac_address83_low: GmacgrpMacAddress83Low,
    gmacgrp_mac_address84_high: GmacgrpMacAddress84High,
    gmacgrp_mac_address84_low: GmacgrpMacAddress84Low,
    gmacgrp_mac_address85_high: GmacgrpMacAddress85High,
    gmacgrp_mac_address85_low: GmacgrpMacAddress85Low,
    gmacgrp_mac_address86_high: GmacgrpMacAddress86High,
    gmacgrp_mac_address86_low: GmacgrpMacAddress86Low,
    gmacgrp_mac_address87_high: GmacgrpMacAddress87High,
    gmacgrp_mac_address87_low: GmacgrpMacAddress87Low,
    gmacgrp_mac_address88_high: GmacgrpMacAddress88High,
    gmacgrp_mac_address88_low: GmacgrpMacAddress88Low,
    gmacgrp_mac_address89_high: GmacgrpMacAddress89High,
    gmacgrp_mac_address89_low: GmacgrpMacAddress89Low,
    gmacgrp_mac_address90_high: GmacgrpMacAddress90High,
    gmacgrp_mac_address90_low: GmacgrpMacAddress90Low,
    gmacgrp_mac_address91_high: GmacgrpMacAddress91High,
    gmacgrp_mac_address91_low: GmacgrpMacAddress91Low,
    gmacgrp_mac_address92_high: GmacgrpMacAddress92High,
    gmacgrp_mac_address92_low: GmacgrpMacAddress92Low,
    gmacgrp_mac_address93_high: GmacgrpMacAddress93High,
    gmacgrp_mac_address93_low: GmacgrpMacAddress93Low,
    gmacgrp_mac_address94_high: GmacgrpMacAddress94High,
    gmacgrp_mac_address94_low: GmacgrpMacAddress94Low,
    gmacgrp_mac_address95_high: GmacgrpMacAddress95High,
    gmacgrp_mac_address95_low: GmacgrpMacAddress95Low,
    gmacgrp_mac_address96_high: GmacgrpMacAddress96High,
    gmacgrp_mac_address96_low: GmacgrpMacAddress96Low,
    gmacgrp_mac_address97_high: GmacgrpMacAddress97High,
    gmacgrp_mac_address97_low: GmacgrpMacAddress97Low,
    gmacgrp_mac_address98_high: GmacgrpMacAddress98High,
    gmacgrp_mac_address98_low: GmacgrpMacAddress98Low,
    gmacgrp_mac_address99_high: GmacgrpMacAddress99High,
    gmacgrp_mac_address99_low: GmacgrpMacAddress99Low,
    gmacgrp_mac_address100_high: GmacgrpMacAddress100High,
    gmacgrp_mac_address100_low: GmacgrpMacAddress100Low,
    gmacgrp_mac_address101_high: GmacgrpMacAddress101High,
    gmacgrp_mac_address101_low: GmacgrpMacAddress101Low,
    gmacgrp_mac_address102_high: GmacgrpMacAddress102High,
    gmacgrp_mac_address102_low: GmacgrpMacAddress102Low,
    gmacgrp_mac_address103_high: GmacgrpMacAddress103High,
    gmacgrp_mac_address103_low: GmacgrpMacAddress103Low,
    gmacgrp_mac_address104_high: GmacgrpMacAddress104High,
    gmacgrp_mac_address104_low: GmacgrpMacAddress104Low,
    gmacgrp_mac_address105_high: GmacgrpMacAddress105High,
    gmacgrp_mac_address105_low: GmacgrpMacAddress105Low,
    gmacgrp_mac_address106_high: GmacgrpMacAddress106High,
    gmacgrp_mac_address106_low: GmacgrpMacAddress106Low,
    gmacgrp_mac_address107_high: GmacgrpMacAddress107High,
    gmacgrp_mac_address107_low: GmacgrpMacAddress107Low,
    gmacgrp_mac_address108_high: GmacgrpMacAddress108High,
    gmacgrp_mac_address108_low: GmacgrpMacAddress108Low,
    gmacgrp_mac_address109_high: GmacgrpMacAddress109High,
    gmacgrp_mac_address109_low: GmacgrpMacAddress109Low,
    gmacgrp_mac_address110_high: GmacgrpMacAddress110High,
    gmacgrp_mac_address110_low: GmacgrpMacAddress110Low,
    gmacgrp_mac_address111_high: GmacgrpMacAddress111High,
    gmacgrp_mac_address111_low: GmacgrpMacAddress111Low,
    gmacgrp_mac_address112_high: GmacgrpMacAddress112High,
    gmacgrp_mac_address112_low: GmacgrpMacAddress112Low,
    gmacgrp_mac_address113_high: GmacgrpMacAddress113High,
    gmacgrp_mac_address113_low: GmacgrpMacAddress113Low,
    gmacgrp_mac_address114_high: GmacgrpMacAddress114High,
    gmacgrp_mac_address114_low: GmacgrpMacAddress114Low,
    gmacgrp_mac_address115_high: GmacgrpMacAddress115High,
    gmacgrp_mac_address115_low: GmacgrpMacAddress115Low,
    gmacgrp_mac_address116_high: GmacgrpMacAddress116High,
    gmacgrp_mac_address116_low: GmacgrpMacAddress116Low,
    gmacgrp_mac_address117_high: GmacgrpMacAddress117High,
    gmacgrp_mac_address117_low: GmacgrpMacAddress117Low,
    gmacgrp_mac_address118_high: GmacgrpMacAddress118High,
    gmacgrp_mac_address118_low: GmacgrpMacAddress118Low,
    gmacgrp_mac_address119_high: GmacgrpMacAddress119High,
    gmacgrp_mac_address119_low: GmacgrpMacAddress119Low,
    gmacgrp_mac_address120_high: GmacgrpMacAddress120High,
    gmacgrp_mac_address120_low: GmacgrpMacAddress120Low,
    gmacgrp_mac_address121_high: GmacgrpMacAddress121High,
    gmacgrp_mac_address121_low: GmacgrpMacAddress121Low,
    gmacgrp_mac_address122_high: GmacgrpMacAddress122High,
    gmacgrp_mac_address122_low: GmacgrpMacAddress122Low,
    gmacgrp_mac_address123_high: GmacgrpMacAddress123High,
    gmacgrp_mac_address123_low: GmacgrpMacAddress123Low,
    gmacgrp_mac_address124_high: GmacgrpMacAddress124High,
    gmacgrp_mac_address124_low: GmacgrpMacAddress124Low,
    gmacgrp_mac_address125_high: GmacgrpMacAddress125High,
    gmacgrp_mac_address125_low: GmacgrpMacAddress125Low,
    gmacgrp_mac_address126_high: GmacgrpMacAddress126High,
    gmacgrp_mac_address126_low: GmacgrpMacAddress126Low,
    gmacgrp_mac_address127_high: GmacgrpMacAddress127High,
    gmacgrp_mac_address127_low: GmacgrpMacAddress127Low,
    _reserved406: [u8; 0x0480],
    dmagrp_bus_mode: DmagrpBusMode,
    dmagrp_transmit_poll_demand: DmagrpTransmitPollDemand,
    dmagrp_receive_poll_demand: DmagrpReceivePollDemand,
    dmagrp_receive_descriptor_list_address: DmagrpReceiveDescriptorListAddress,
    dmagrp_transmit_descriptor_list_address: DmagrpTransmitDescriptorListAddress,
    dmagrp_status: DmagrpStatus,
    dmagrp_operation_mode: DmagrpOperationMode,
    dmagrp_interrupt_enable: DmagrpInterruptEnable,
    dmagrp_missed_frame_and_buffer_overflow_counter: DmagrpMissedFrameAndBufferOverflowCounter,
    dmagrp_receive_interrupt_watchdog_timer: DmagrpReceiveInterruptWatchdogTimer,
    dmagrp_axi_bus_mode: DmagrpAxiBusMode,
    dmagrp_ahb_or_axi_status: DmagrpAhbOrAxiStatus,
    _reserved418: [u8; 0x18],
    dmagrp_current_host_transmit_descriptor: DmagrpCurrentHostTransmitDescriptor,
    dmagrp_current_host_receive_descriptor: DmagrpCurrentHostReceiveDescriptor,
    dmagrp_current_host_transmit_buffer_address: DmagrpCurrentHostTransmitBufferAddress,
    dmagrp_current_host_receive_buffer_address: DmagrpCurrentHostReceiveBufferAddress,
    dmagrp_hw_feature: DmagrpHwFeature,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - The MAC Configuration register establishes receive and transmit operating modes."]
    #[inline(always)]
    pub const fn gmacgrp_mac_configuration(&self) -> &GmacgrpMacConfiguration {
        &self.gmacgrp_mac_configuration
    }
    #[doc = "0x04 - The MAC Frame Filter register contains the filter controls for receiving frames. Some of the controls from this register go to the address check block of the MAC, which performs the first level of address filtering. The second level of filtering is performed on the incoming frame, based on other controls such as Pass Bad Frames and Pass Control Frames."]
    #[inline(always)]
    pub const fn gmacgrp_mac_frame_filter(&self) -> &GmacgrpMacFrameFilter {
        &self.gmacgrp_mac_frame_filter
    }
    #[doc = "0x10 - The GMII Address register controls the management cycles to the external PHY through the management interface."]
    #[inline(always)]
    pub const fn gmacgrp_gmii_address(&self) -> &GmacgrpGmiiAddress {
        &self.gmacgrp_gmii_address
    }
    #[doc = "0x14 - The GMII Data register stores Write data to be written to the PHY register located at the address specified in Register 4 (GMII Address Register). This register also stores the Read data from the PHY register located at the address specified by Register 4."]
    #[inline(always)]
    pub const fn gmacgrp_gmii_data(&self) -> &GmacgrpGmiiData {
        &self.gmacgrp_gmii_data
    }
    #[doc = "0x18 - The Flow Control register controls the generation and reception of the Control (Pause Command) frames by the MAC's Flow control block. A Write to a register with the Busy bit set to '1' triggers the Flow Control block to generate a Pause Control frame. The fields of the control frame are selected as specified in the 802.3x specification, and the Pause Time value from this register is used in the Pause Time field of the control frame. The Busy bit remains set until the control frame is transferred onto the cable. The Host must make sure that the Busy bit is cleared before writing to the register."]
    #[inline(always)]
    pub const fn gmacgrp_flow_control(&self) -> &GmacgrpFlowControl {
        &self.gmacgrp_flow_control
    }
    #[doc = "0x1c - The VLAN Tag register contains the IEEE 802.1Q VLAN Tag to identify the VLAN frames. The MAC compares the 13th and 14th bytes of the receiving frame (Length/Type) with 16'h8100, and the following two bytes are compared with the VLAN tag. If a match occurs, the MAC sets the received VLAN bit in the receive frame status. The legal length of the frame is increased from 1,518 bytes to 1,522 bytes. Because the VLAN Tag register is double-synchronized to the (G)MII clock domain, then consecutive writes to these register should be performed only after at least four clock cycles in the destination clock domain."]
    #[inline(always)]
    pub const fn gmacgrp_vlan_tag(&self) -> &GmacgrpVlanTag {
        &self.gmacgrp_vlan_tag
    }
    #[doc = "0x20 - The Version registers identifies the version of the EMAC. This register contains two bytes: one specified by Synopsys to identify the core release number, and the other specified by Altera."]
    #[inline(always)]
    pub const fn gmacgrp_version(&self) -> &GmacgrpVersion {
        &self.gmacgrp_version
    }
    #[doc = "0x24 - The Debug register gives the status of all main blocks of the transmit and receive data-paths and the FIFOs. An all-zero status indicates that the MAC is in idle state (and FIFOs are empty) and no activity is going on in the data-paths."]
    #[inline(always)]
    pub const fn gmacgrp_debug(&self) -> &GmacgrpDebug {
        &self.gmacgrp_debug
    }
    #[doc = "0x30 - The LPI Control and Status Register controls the LPI functions and provides the LPI interrupt status. The status bits are cleared when this register is read."]
    #[inline(always)]
    pub const fn gmacgrp_lpi_control_status(&self) -> &GmacgrpLpiControlStatus {
        &self.gmacgrp_lpi_control_status
    }
    #[doc = "0x34 - The LPI Timers Control register controls the timeout values in the LPI states. It specifies the time for which the MAC transmits the LPI pattern and also the time for which the MAC waits before resuming the normal transmission."]
    #[inline(always)]
    pub const fn gmacgrp_lpi_timers_control(&self) -> &GmacgrpLpiTimersControl {
        &self.gmacgrp_lpi_timers_control
    }
    #[doc = "0x38 - The Interrupt Status register identifies the events in the MAC that can generate interrupt. All interrupt events are generated only when the corresponding optional feature is enabled."]
    #[inline(always)]
    pub const fn gmacgrp_interrupt_status(&self) -> &GmacgrpInterruptStatus {
        &self.gmacgrp_interrupt_status
    }
    #[doc = "0x3c - The Interrupt Mask Register bits enable you to mask the interrupt signal because of the corresponding event in the Interrupt Status Register. The interrupt signal is sbd_intr_o."]
    #[inline(always)]
    pub const fn gmacgrp_interrupt_mask(&self) -> &GmacgrpInterruptMask {
        &self.gmacgrp_interrupt_mask
    }
    #[doc = "0x40 - The MAC Address0 High register holds the upper 16 bits of the first 6-byte MAC address of the station. The first DA byte that is received on the (G)MII interface corresponds to the LS byte (Bits \\[7:0\\]) of the MAC Address Low register. For example, if 0x112233445566 is received (0x11 in lane 0 of the first column) on the (G)MII as the destination address, then the MacAddress0 Register \\[47:0\\]
is compared with 0x665544332211. Because the MAC address registers are double-synchronized to the (G)MII clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address0 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address0_high(&self) -> &GmacgrpMacAddress0High {
        &self.gmacgrp_mac_address0_high
    }
    #[doc = "0x44 - The MAC Address0 Low register holds the lower 32 bits of the first 6-byte MAC address of the station."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address0_low(&self) -> &GmacgrpMacAddress0Low {
        &self.gmacgrp_mac_address0_low
    }
    #[doc = "0x48 - The MAC Address1 High register holds the upper 16 bits of the 2nd 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address1 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address1_high(&self) -> &GmacgrpMacAddress1High {
        &self.gmacgrp_mac_address1_high
    }
    #[doc = "0x4c - The MAC Address1 Low register holds the lower 32 bits of the 2nd 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address1_low(&self) -> &GmacgrpMacAddress1Low {
        &self.gmacgrp_mac_address1_low
    }
    #[doc = "0x50 - The MAC Address2 High register holds the upper 16 bits of the 3rd 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address2 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address2_high(&self) -> &GmacgrpMacAddress2High {
        &self.gmacgrp_mac_address2_high
    }
    #[doc = "0x54 - The MAC Address2 Low register holds the lower 32 bits of the 3rd 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address2_low(&self) -> &GmacgrpMacAddress2Low {
        &self.gmacgrp_mac_address2_low
    }
    #[doc = "0x58 - The MAC Address3 High register holds the upper 16 bits of the 4th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address3 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address3_high(&self) -> &GmacgrpMacAddress3High {
        &self.gmacgrp_mac_address3_high
    }
    #[doc = "0x5c - The MAC Address3 Low register holds the lower 32 bits of the 4th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address3_low(&self) -> &GmacgrpMacAddress3Low {
        &self.gmacgrp_mac_address3_low
    }
    #[doc = "0x60 - The MAC Address4 High register holds the upper 16 bits of the 5th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address4 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address4_high(&self) -> &GmacgrpMacAddress4High {
        &self.gmacgrp_mac_address4_high
    }
    #[doc = "0x64 - The MAC Address4 Low register holds the lower 32 bits of the 5th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address4_low(&self) -> &GmacgrpMacAddress4Low {
        &self.gmacgrp_mac_address4_low
    }
    #[doc = "0x68 - The MAC Address5 High register holds the upper 16 bits of the 6th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address5 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address5_high(&self) -> &GmacgrpMacAddress5High {
        &self.gmacgrp_mac_address5_high
    }
    #[doc = "0x6c - The MAC Address5 Low register holds the lower 32 bits of the 6th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address5_low(&self) -> &GmacgrpMacAddress5Low {
        &self.gmacgrp_mac_address5_low
    }
    #[doc = "0x70 - The MAC Address6 High register holds the upper 16 bits of the 7th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address6 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address6_high(&self) -> &GmacgrpMacAddress6High {
        &self.gmacgrp_mac_address6_high
    }
    #[doc = "0x74 - The MAC Address6 Low register holds the lower 32 bits of the 7th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address6_low(&self) -> &GmacgrpMacAddress6Low {
        &self.gmacgrp_mac_address6_low
    }
    #[doc = "0x78 - The MAC Address7 High register holds the upper 16 bits of the 8th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address7 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address7_high(&self) -> &GmacgrpMacAddress7High {
        &self.gmacgrp_mac_address7_high
    }
    #[doc = "0x7c - The MAC Address7 Low register holds the lower 32 bits of the 8th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address7_low(&self) -> &GmacgrpMacAddress7Low {
        &self.gmacgrp_mac_address7_low
    }
    #[doc = "0x80 - The MAC Address8 High register holds the upper 16 bits of the 9th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address8 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address8_high(&self) -> &GmacgrpMacAddress8High {
        &self.gmacgrp_mac_address8_high
    }
    #[doc = "0x84 - The MAC Address8 Low register holds the lower 32 bits of the 9th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address8_low(&self) -> &GmacgrpMacAddress8Low {
        &self.gmacgrp_mac_address8_low
    }
    #[doc = "0x88 - The MAC Address9 High register holds the upper 16 bits of the 10th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address9 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address9_high(&self) -> &GmacgrpMacAddress9High {
        &self.gmacgrp_mac_address9_high
    }
    #[doc = "0x8c - The MAC Address9 Low register holds the lower 32 bits of the 10th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address9_low(&self) -> &GmacgrpMacAddress9Low {
        &self.gmacgrp_mac_address9_low
    }
    #[doc = "0x90 - The MAC Address10 High register holds the upper 16 bits of the 11th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address10 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address10_high(&self) -> &GmacgrpMacAddress10High {
        &self.gmacgrp_mac_address10_high
    }
    #[doc = "0x94 - The MAC Address10 Low register holds the lower 32 bits of the 11th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address10_low(&self) -> &GmacgrpMacAddress10Low {
        &self.gmacgrp_mac_address10_low
    }
    #[doc = "0x98 - The MAC Address11 High register holds the upper 16 bits of the 12th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address11 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address11_high(&self) -> &GmacgrpMacAddress11High {
        &self.gmacgrp_mac_address11_high
    }
    #[doc = "0x9c - The MAC Address11 Low register holds the lower 32 bits of the 12th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address11_low(&self) -> &GmacgrpMacAddress11Low {
        &self.gmacgrp_mac_address11_low
    }
    #[doc = "0xa0 - The MAC Address12 High register holds the upper 16 bits of the 13th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address12 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address12_high(&self) -> &GmacgrpMacAddress12High {
        &self.gmacgrp_mac_address12_high
    }
    #[doc = "0xa4 - The MAC Address12 Low register holds the lower 32 bits of the 13th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address12_low(&self) -> &GmacgrpMacAddress12Low {
        &self.gmacgrp_mac_address12_low
    }
    #[doc = "0xa8 - The MAC Address13 High register holds the upper 16 bits of the 14th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address13 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address13_high(&self) -> &GmacgrpMacAddress13High {
        &self.gmacgrp_mac_address13_high
    }
    #[doc = "0xac - The MAC Address13 Low register holds the lower 32 bits of the 14th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address13_low(&self) -> &GmacgrpMacAddress13Low {
        &self.gmacgrp_mac_address13_low
    }
    #[doc = "0xb0 - The MAC Address14 High register holds the upper 16 bits of the 15th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address14 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address14_high(&self) -> &GmacgrpMacAddress14High {
        &self.gmacgrp_mac_address14_high
    }
    #[doc = "0xb4 - The MAC Address14 Low register holds the lower 32 bits of the 15th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address14_low(&self) -> &GmacgrpMacAddress14Low {
        &self.gmacgrp_mac_address14_low
    }
    #[doc = "0xb8 - The MAC Address15 High register holds the upper 16 bits of the 16th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address15 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address15_high(&self) -> &GmacgrpMacAddress15High {
        &self.gmacgrp_mac_address15_high
    }
    #[doc = "0xbc - The MAC Address15 Low register holds the lower 32 bits of the 16th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address15_low(&self) -> &GmacgrpMacAddress15Low {
        &self.gmacgrp_mac_address15_low
    }
    #[doc = "0xd8 - The SGMII/RGMII/SMII Status register indicates the status signals received by the RGMII interface (selected at reset) from the PHY."]
    #[inline(always)]
    pub const fn gmacgrp_sgmii_rgmii_smii_control_status(
        &self,
    ) -> &GmacgrpSgmiiRgmiiSmiiControlStatus {
        &self.gmacgrp_sgmii_rgmii_smii_control_status
    }
    #[doc = "0x100 - The MMC Control register establishes the operating mode of the management counters. Note: The bit 0 (Counters Reset) has higher priority than bit 4 (Counter Preset). Therefore, when the Software tries to set both bits in the same write cycle, all counters are cleared and the bit 4 is not set."]
    #[inline(always)]
    pub const fn gmacgrp_mmc_control(&self) -> &GmacgrpMmcControl {
        &self.gmacgrp_mmc_control
    }
    #[doc = "0x104 - The MMC Receive Interrupt register maintains the interrupts that are generated when the following happens: * Receive statistic counters reach half of their maximum values (0x8000_0000 for 32-bit counter and 0x8000 for 16-bit counter). * Receive statistic counters cross their maximum values (0xFFFF_FFFF for 32-bit counter and 0xFFFF for 16-bit counter). When the Counter Stop Rollover is set, then interrupts are set but the counter remains at all-ones. The MMC Receive Interrupt register is a 32-bit wide register. An interrupt bit is cleared when the respective MMC counter that caused the interrupt is read. The least significant byte lane (Bits\\[7:0\\]) of the respective counter must be read in order to clear the interrupt bit."]
    #[inline(always)]
    pub const fn gmacgrp_mmc_receive_interrupt(&self) -> &GmacgrpMmcReceiveInterrupt {
        &self.gmacgrp_mmc_receive_interrupt
    }
    #[doc = "0x108 - The MMC Transmit Interrupt register maintains the interrupts generated when transmit statistic counters reach half of their maximum values (0x8000_0000 for 32-bit counter and 0x8000 for 16-bit counter), and the maximum values (0xFFFF_FFFF for 32-bit counter and 0xFFFF for 16-bit counter). When Counter Stop Rollover is set, then interrupts are set but the counter remains at all-ones. The MMC Transmit Interrupt register is a 32-bit wide register. An interrupt bit is cleared when the respective MMC counter that caused the interrupt is read. The least significant byte lane (Bits\\[7:0\\]) of the respective counter must be read in order to clear the interrupt bit."]
    #[inline(always)]
    pub const fn gmacgrp_mmc_transmit_interrupt(&self) -> &GmacgrpMmcTransmitInterrupt {
        &self.gmacgrp_mmc_transmit_interrupt
    }
    #[doc = "0x10c - The MMC Receive Interrupt Mask register maintains the masks for the interrupts generated when the receive statistic counters reach half of their maximum value, or maximum value. This register is 32-bits wide."]
    #[inline(always)]
    pub const fn gmacgrp_mmc_receive_interrupt_mask(&self) -> &GmacgrpMmcReceiveInterruptMask {
        &self.gmacgrp_mmc_receive_interrupt_mask
    }
    #[doc = "0x110 - The MMC Transmit Interrupt Mask register maintains the masks for the interrupts generated when the transmit statistic counters reach half of their maximum value or maximum value. This register is 32-bits wide."]
    #[inline(always)]
    pub const fn gmacgrp_mmc_transmit_interrupt_mask(&self) -> &GmacgrpMmcTransmitInterruptMask {
        &self.gmacgrp_mmc_transmit_interrupt_mask
    }
    #[doc = "0x114 - Number of bytes transmitted, exclusive of preamble and retried bytes, in good and bad frames"]
    #[inline(always)]
    pub const fn gmacgrp_txoctetcount_gb(&self) -> &GmacgrpTxoctetcountGb {
        &self.gmacgrp_txoctetcount_gb
    }
    #[doc = "0x118 - Number of good and bad frames transmitted, exclusive of retried frames"]
    #[inline(always)]
    pub const fn gmacgrp_txframecount_gb(&self) -> &GmacgrpTxframecountGb {
        &self.gmacgrp_txframecount_gb
    }
    #[doc = "0x11c - Number of good broadcast frames transmitted"]
    #[inline(always)]
    pub const fn gmacgrp_txbroadcastframes_g(&self) -> &GmacgrpTxbroadcastframesG {
        &self.gmacgrp_txbroadcastframes_g
    }
    #[doc = "0x120 - Number of good multicast frames transmitted"]
    #[inline(always)]
    pub const fn gmacgrp_txmulticastframes_g(&self) -> &GmacgrpTxmulticastframesG {
        &self.gmacgrp_txmulticastframes_g
    }
    #[doc = "0x124 - Number of good and bad frames transmitted with length 64 bytes, exclusive of preamble and retried frames"]
    #[inline(always)]
    pub const fn gmacgrp_tx64octets_gb(&self) -> &GmacgrpTx64octetsGb {
        &self.gmacgrp_tx64octets_gb
    }
    #[doc = "0x128 - Number of good and bad frames transmitted with length between 65 and 127 (inclusive) bytes, exclusive of preamble and retried frames"]
    #[inline(always)]
    pub const fn gmacgrp_tx65to127octets_gb(&self) -> &GmacgrpTx65to127octetsGb {
        &self.gmacgrp_tx65to127octets_gb
    }
    #[doc = "0x12c - Number of good and bad frames transmitted with length between 128 and 255 (inclusive) bytes, exclusive of preamble and retried frames"]
    #[inline(always)]
    pub const fn gmacgrp_tx128to255octets_gb(&self) -> &GmacgrpTx128to255octetsGb {
        &self.gmacgrp_tx128to255octets_gb
    }
    #[doc = "0x130 - Number of good and bad frames transmitted with length between 256 and 511 (inclusive) bytes, exclusive of preamble and retried frames"]
    #[inline(always)]
    pub const fn gmacgrp_tx256to511octets_gb(&self) -> &GmacgrpTx256to511octetsGb {
        &self.gmacgrp_tx256to511octets_gb
    }
    #[doc = "0x134 - Number of good and bad frames transmitted with length between 512 and 1,023 (inclusive) bytes, exclusive of preamble and retried frames"]
    #[inline(always)]
    pub const fn gmacgrp_tx512to1023octets_gb(&self) -> &GmacgrpTx512to1023octetsGb {
        &self.gmacgrp_tx512to1023octets_gb
    }
    #[doc = "0x138 - Number of good and bad frames transmitted with length between 1,024 and maxsize (inclusive) bytes, exclusive of preamble and retried frames"]
    #[inline(always)]
    pub const fn gmacgrp_tx1024tomaxoctets_gb(&self) -> &GmacgrpTx1024tomaxoctetsGb {
        &self.gmacgrp_tx1024tomaxoctets_gb
    }
    #[doc = "0x13c - Number of good and bad unicast frames transmitted"]
    #[inline(always)]
    pub const fn gmacgrp_txunicastframes_gb(&self) -> &GmacgrpTxunicastframesGb {
        &self.gmacgrp_txunicastframes_gb
    }
    #[doc = "0x140 - Number of good and bad multicast frames transmitted"]
    #[inline(always)]
    pub const fn gmacgrp_txmulticastframes_gb(&self) -> &GmacgrpTxmulticastframesGb {
        &self.gmacgrp_txmulticastframes_gb
    }
    #[doc = "0x144 - Number of good and bad broadcast frames transmitted"]
    #[inline(always)]
    pub const fn gmacgrp_txbroadcastframes_gb(&self) -> &GmacgrpTxbroadcastframesGb {
        &self.gmacgrp_txbroadcastframes_gb
    }
    #[doc = "0x148 - Number of frames aborted due to frame underflow error"]
    #[inline(always)]
    pub const fn gmacgrp_txunderflowerror(&self) -> &GmacgrpTxunderflowerror {
        &self.gmacgrp_txunderflowerror
    }
    #[doc = "0x14c - Number of successfully transmitted frames after a single collision in Half-duplex mode"]
    #[inline(always)]
    pub const fn gmacgrp_txsinglecol_g(&self) -> &GmacgrpTxsinglecolG {
        &self.gmacgrp_txsinglecol_g
    }
    #[doc = "0x150 - Number of successfully transmitted frames after more than a single collision in Half-duplex mode"]
    #[inline(always)]
    pub const fn gmacgrp_txmulticol_g(&self) -> &GmacgrpTxmulticolG {
        &self.gmacgrp_txmulticol_g
    }
    #[doc = "0x154 - Number of successfully transmitted frames after a deferral in Halfduplex mode"]
    #[inline(always)]
    pub const fn gmacgrp_txdeferred(&self) -> &GmacgrpTxdeferred {
        &self.gmacgrp_txdeferred
    }
    #[doc = "0x158 - Number of frames aborted due to late collision error"]
    #[inline(always)]
    pub const fn gmacgrp_txlatecol(&self) -> &GmacgrpTxlatecol {
        &self.gmacgrp_txlatecol
    }
    #[doc = "0x15c - Number of frames aborted due to excessive (16) collision errors"]
    #[inline(always)]
    pub const fn gmacgrp_txexesscol(&self) -> &GmacgrpTxexesscol {
        &self.gmacgrp_txexesscol
    }
    #[doc = "0x160 - Number of frames aborted due to carrier sense error (no carrier or loss of carrier)"]
    #[inline(always)]
    pub const fn gmacgrp_txcarriererr(&self) -> &GmacgrpTxcarriererr {
        &self.gmacgrp_txcarriererr
    }
    #[doc = "0x164 - Number of bytes transmitted, exclusive of preamble, in good frames only"]
    #[inline(always)]
    pub const fn gmacgrp_txoctetcnt(&self) -> &GmacgrpTxoctetcnt {
        &self.gmacgrp_txoctetcnt
    }
    #[doc = "0x168 - Number of good frames transmitted"]
    #[inline(always)]
    pub const fn gmacgrp_txframecount_g(&self) -> &GmacgrpTxframecountG {
        &self.gmacgrp_txframecount_g
    }
    #[doc = "0x16c - Number of frames aborted due to excessive deferral error (deferred for more than two max-sized frame times)"]
    #[inline(always)]
    pub const fn gmacgrp_txexcessdef(&self) -> &GmacgrpTxexcessdef {
        &self.gmacgrp_txexcessdef
    }
    #[doc = "0x170 - Number of good PAUSE frames transmitted"]
    #[inline(always)]
    pub const fn gmacgrp_txpauseframes(&self) -> &GmacgrpTxpauseframes {
        &self.gmacgrp_txpauseframes
    }
    #[doc = "0x174 - Number of good VLAN frames transmitted, exclusive of retried frames"]
    #[inline(always)]
    pub const fn gmacgrp_txvlanframes_g(&self) -> &GmacgrpTxvlanframesG {
        &self.gmacgrp_txvlanframes_g
    }
    #[doc = "0x178 - Number of good and bad frames received"]
    #[inline(always)]
    pub const fn gmacgrp_txoversize_g(&self) -> &GmacgrpTxoversizeG {
        &self.gmacgrp_txoversize_g
    }
    #[doc = "0x180 - Number of good and bad frames received"]
    #[inline(always)]
    pub const fn gmacgrp_rxframecount_gb(&self) -> &GmacgrpRxframecountGb {
        &self.gmacgrp_rxframecount_gb
    }
    #[doc = "0x184 - Number of bytes received, exclusive of preamble, in good and bad frames"]
    #[inline(always)]
    pub const fn gmacgrp_rxoctetcount_gb(&self) -> &GmacgrpRxoctetcountGb {
        &self.gmacgrp_rxoctetcount_gb
    }
    #[doc = "0x188 - Number of bytes received, exclusive of preamble, only in good frames"]
    #[inline(always)]
    pub const fn gmacgrp_rxoctetcount_g(&self) -> &GmacgrpRxoctetcountG {
        &self.gmacgrp_rxoctetcount_g
    }
    #[doc = "0x18c - Number of good broadcast frames received"]
    #[inline(always)]
    pub const fn gmacgrp_rxbroadcastframes_g(&self) -> &GmacgrpRxbroadcastframesG {
        &self.gmacgrp_rxbroadcastframes_g
    }
    #[doc = "0x190 - Number of good multicast frames received"]
    #[inline(always)]
    pub const fn gmacgrp_rxmulticastframes_g(&self) -> &GmacgrpRxmulticastframesG {
        &self.gmacgrp_rxmulticastframes_g
    }
    #[doc = "0x194 - Number of frames received with CRC error"]
    #[inline(always)]
    pub const fn gmacgrp_rxcrcerror(&self) -> &GmacgrpRxcrcerror {
        &self.gmacgrp_rxcrcerror
    }
    #[doc = "0x198 - Number of frames received with alignment (dribble) error. Valid only in 10/100 mode"]
    #[inline(always)]
    pub const fn gmacgrp_rxalignmenterror(&self) -> &GmacgrpRxalignmenterror {
        &self.gmacgrp_rxalignmenterror
    }
    #[doc = "0x19c - Number of frames received with runt (&lt;64 bytes and CRC error) error"]
    #[inline(always)]
    pub const fn gmacgrp_rxrunterror(&self) -> &GmacgrpRxrunterror {
        &self.gmacgrp_rxrunterror
    }
    #[doc = "0x1a0 - Number of giant frames received with length (including CRC) greater than 1,518 bytes (1,522 bytes for VLAN tagged) and with CRC error. If Jumbo Frame mode is enabled, then frames of length greater than 9,018 bytes (9,022 for VLAN tagged) are considered as giant frames"]
    #[inline(always)]
    pub const fn gmacgrp_rxjabbererror(&self) -> &GmacgrpRxjabbererror {
        &self.gmacgrp_rxjabbererror
    }
    #[doc = "0x1a4 - Number of frames received with length less than 64 bytes, without any errors"]
    #[inline(always)]
    pub const fn gmacgrp_rxundersize_g(&self) -> &GmacgrpRxundersizeG {
        &self.gmacgrp_rxundersize_g
    }
    #[doc = "0x1a8 - Number of frames received with length greater than the maxsize (1,518 or 1,522 for VLAN tagged frames), without errors"]
    #[inline(always)]
    pub const fn gmacgrp_rxoversize_g(&self) -> &GmacgrpRxoversizeG {
        &self.gmacgrp_rxoversize_g
    }
    #[doc = "0x1ac - Number of good and bad frames received with length 64 bytes, exclusive of preamble"]
    #[inline(always)]
    pub const fn gmacgrp_rx64octets_gb(&self) -> &GmacgrpRx64octetsGb {
        &self.gmacgrp_rx64octets_gb
    }
    #[doc = "0x1b0 - Number of good and bad frames received with length between 65 and 127 (inclusive) bytes, exclusive of preamble"]
    #[inline(always)]
    pub const fn gmacgrp_rx65to127octets_gb(&self) -> &GmacgrpRx65to127octetsGb {
        &self.gmacgrp_rx65to127octets_gb
    }
    #[doc = "0x1b4 - Number of good and bad frames received with length between 128 and 255 (inclusive) bytes, exclusive of preamble"]
    #[inline(always)]
    pub const fn gmacgrp_rx128to255octets_gb(&self) -> &GmacgrpRx128to255octetsGb {
        &self.gmacgrp_rx128to255octets_gb
    }
    #[doc = "0x1b8 - Number of good and bad frames received with length between 256 and 511 (inclusive) bytes, exclusive of preamble"]
    #[inline(always)]
    pub const fn gmacgrp_rx256to511octets_gb(&self) -> &GmacgrpRx256to511octetsGb {
        &self.gmacgrp_rx256to511octets_gb
    }
    #[doc = "0x1bc - Number of good and bad frames received with length between 512 and 1,023 (inclusive) bytes, exclusive of preamble"]
    #[inline(always)]
    pub const fn gmacgrp_rx512to1023octets_gb(&self) -> &GmacgrpRx512to1023octetsGb {
        &self.gmacgrp_rx512to1023octets_gb
    }
    #[doc = "0x1c0 - Number of good and bad frames received with length between 1,024 and maxsize (inclusive) bytes, exclusive of preamble and retried frames"]
    #[inline(always)]
    pub const fn gmacgrp_rx1024tomaxoctets_gb(&self) -> &GmacgrpRx1024tomaxoctetsGb {
        &self.gmacgrp_rx1024tomaxoctets_gb
    }
    #[doc = "0x1c4 - Number of good unicast frames received"]
    #[inline(always)]
    pub const fn gmacgrp_rxunicastframes_g(&self) -> &GmacgrpRxunicastframesG {
        &self.gmacgrp_rxunicastframes_g
    }
    #[doc = "0x1c8 - Number of frames received with length error (length type field not equal to frame size), for all frames with valid length field"]
    #[inline(always)]
    pub const fn gmacgrp_rxlengtherror(&self) -> &GmacgrpRxlengtherror {
        &self.gmacgrp_rxlengtherror
    }
    #[doc = "0x1cc - Number of frames received with length field not equal to the valid frame size (greater than 1,500 but less than 1,536)"]
    #[inline(always)]
    pub const fn gmacgrp_rxoutofrangetype(&self) -> &GmacgrpRxoutofrangetype {
        &self.gmacgrp_rxoutofrangetype
    }
    #[doc = "0x1d0 - Number of good and valid PAUSE frames received"]
    #[inline(always)]
    pub const fn gmacgrp_rxpauseframes(&self) -> &GmacgrpRxpauseframes {
        &self.gmacgrp_rxpauseframes
    }
    #[doc = "0x1d4 - Number of missed received frames due to FIFO overflow"]
    #[inline(always)]
    pub const fn gmacgrp_rxfifooverflow(&self) -> &GmacgrpRxfifooverflow {
        &self.gmacgrp_rxfifooverflow
    }
    #[doc = "0x1d8 - Number of good and bad VLAN frames received"]
    #[inline(always)]
    pub const fn gmacgrp_rxvlanframes_gb(&self) -> &GmacgrpRxvlanframesGb {
        &self.gmacgrp_rxvlanframes_gb
    }
    #[doc = "0x1dc - Number of frames received with error due to watchdog timeout error (frames with a data load larger than 2,048 bytes)"]
    #[inline(always)]
    pub const fn gmacgrp_rxwatchdogerror(&self) -> &GmacgrpRxwatchdogerror {
        &self.gmacgrp_rxwatchdogerror
    }
    #[doc = "0x1e0 - Number of frames received with Receive error or Frame Extension error on the GMII or MII interface."]
    #[inline(always)]
    pub const fn gmacgrp_rxrcverror(&self) -> &GmacgrpRxrcverror {
        &self.gmacgrp_rxrcverror
    }
    #[doc = "0x1e4 - Number of received good control frames."]
    #[inline(always)]
    pub const fn gmacgrp_rxctrlframes_g(&self) -> &GmacgrpRxctrlframesG {
        &self.gmacgrp_rxctrlframes_g
    }
    #[doc = "0x200 - This register maintains the mask for the interrupt generated from the receive IPC statistic counters."]
    #[inline(always)]
    pub const fn gmacgrp_mmc_ipc_receive_interrupt_mask(
        &self,
    ) -> &GmacgrpMmcIpcReceiveInterruptMask {
        &self.gmacgrp_mmc_ipc_receive_interrupt_mask
    }
    #[doc = "0x208 - This register maintains the interrupts generated when receive IPC statistic counters reach half their maximum values (0x8000_0000 for 32-bit counter and 0x8000 for 16-bit counter), and when they cross their maximum values (0xFFFF_FFFF for 32-bit counter and 0xFFFF for 16-bit counter). When Counter Stop Rollover is set, then interrupts are set but the counter remains at all-ones. The MMC Receive Checksum Offload Interrupt register is 32-bits wide. When the MMC IPC counter that caused the interrupt is read, its corresponding interrupt bit is cleared. The counter's least-significant byte lane (bits\\[7:0\\]) must be read to clear the interrupt bit."]
    #[inline(always)]
    pub const fn gmacgrp_mmc_ipc_receive_interrupt(&self) -> &GmacgrpMmcIpcReceiveInterrupt {
        &self.gmacgrp_mmc_ipc_receive_interrupt
    }
    #[doc = "0x210 - Number of good IPv4 datagrams received with the TCP, UDP, or ICMP payload"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv4_gd_frms(&self) -> &GmacgrpRxipv4GdFrms {
        &self.gmacgrp_rxipv4_gd_frms
    }
    #[doc = "0x214 - Number of IPv4 datagrams received with header (checksum, length, or version mismatch) errors"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv4_hdrerr_frms(&self) -> &GmacgrpRxipv4HdrerrFrms {
        &self.gmacgrp_rxipv4_hdrerr_frms
    }
    #[doc = "0x218 - Number of IPv4 datagram frames received that did not have a TCP, UDP, or ICMP payload processed by the Checksum engine"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv4_nopay_frms(&self) -> &GmacgrpRxipv4NopayFrms {
        &self.gmacgrp_rxipv4_nopay_frms
    }
    #[doc = "0x21c - Number of good IPv4 datagrams with fragmentation"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv4_frag_frms(&self) -> &GmacgrpRxipv4FragFrms {
        &self.gmacgrp_rxipv4_frag_frms
    }
    #[doc = "0x220 - Number of good IPv4 datagrams received that had a UDP payload with checksum disabled"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv4_udsbl_frms(&self) -> &GmacgrpRxipv4UdsblFrms {
        &self.gmacgrp_rxipv4_udsbl_frms
    }
    #[doc = "0x224 - Number of good IPv6 datagrams received with TCP, UDP, or ICMP payloads"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv6_gd_frms(&self) -> &GmacgrpRxipv6GdFrms {
        &self.gmacgrp_rxipv6_gd_frms
    }
    #[doc = "0x228 - Number of IPv6 datagrams received with header errors (length or version mismatch)"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv6_hdrerr_frms(&self) -> &GmacgrpRxipv6HdrerrFrms {
        &self.gmacgrp_rxipv6_hdrerr_frms
    }
    #[doc = "0x22c - Number of IPv6 datagram frames received that did not have a TCP, UDP, or ICMP payload. This includes all IPv6 datagrams with fragmentation or security extension headers"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv6_nopay_frms(&self) -> &GmacgrpRxipv6NopayFrms {
        &self.gmacgrp_rxipv6_nopay_frms
    }
    #[doc = "0x230 - Number of good IP datagrams with a good UDP payload. This counter is not updated when the counter is incremented"]
    #[inline(always)]
    pub const fn gmacgrp_rxudp_gd_frms(&self) -> &GmacgrpRxudpGdFrms {
        &self.gmacgrp_rxudp_gd_frms
    }
    #[doc = "0x234 - Number of good IP datagrams whose UDP payload has a checksum error"]
    #[inline(always)]
    pub const fn gmacgrp_rxudp_err_frms(&self) -> &GmacgrpRxudpErrFrms {
        &self.gmacgrp_rxudp_err_frms
    }
    #[doc = "0x238 - Number of good IP datagrams with a good TCP payload"]
    #[inline(always)]
    pub const fn gmacgrp_rxtcp_gd_frms(&self) -> &GmacgrpRxtcpGdFrms {
        &self.gmacgrp_rxtcp_gd_frms
    }
    #[doc = "0x23c - Number of good IP datagrams whose TCP payload has a checksum error"]
    #[inline(always)]
    pub const fn gmacgrp_rxtcp_err_frms(&self) -> &GmacgrpRxtcpErrFrms {
        &self.gmacgrp_rxtcp_err_frms
    }
    #[doc = "0x240 - Number of good IP datagrams with a good ICMP payload"]
    #[inline(always)]
    pub const fn gmacgrp_rxicmp_gd_frms(&self) -> &GmacgrpRxicmpGdFrms {
        &self.gmacgrp_rxicmp_gd_frms
    }
    #[doc = "0x244 - Number of good IP datagrams whose ICMP payload has a checksum error"]
    #[inline(always)]
    pub const fn gmacgrp_rxicmp_err_frms(&self) -> &GmacgrpRxicmpErrFrms {
        &self.gmacgrp_rxicmp_err_frms
    }
    #[doc = "0x250 - Number of bytes received in good IPv4 datagrams encapsulating TCP, UDP, or ICMP data"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv4_gd_octets(&self) -> &GmacgrpRxipv4GdOctets {
        &self.gmacgrp_rxipv4_gd_octets
    }
    #[doc = "0x254 - Number of bytes received in IPv4 datagrams with header errors (checksum, length, version mismatch). The value in the Length field of IPv4 header is used to update this counter"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv4_hdrerr_octets(&self) -> &GmacgrpRxipv4HdrerrOctets {
        &self.gmacgrp_rxipv4_hdrerr_octets
    }
    #[doc = "0x258 - Number of bytes received in IPv4 datagrams that did not have a TCP, UDP, or ICMP payload. The value in the IPv4 headers Length field is used to update this counter"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv4_nopay_octets(&self) -> &GmacgrpRxipv4NopayOctets {
        &self.gmacgrp_rxipv4_nopay_octets
    }
    #[doc = "0x25c - Number of bytes received in fragmented IPv4 datagrams. The value in the IPv4 headers Length field is used to update this counter"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv4_frag_octets(&self) -> &GmacgrpRxipv4FragOctets {
        &self.gmacgrp_rxipv4_frag_octets
    }
    #[doc = "0x260 - Number of bytes received in a UDP segment that had the UDP checksum disabled. This counter does not count IP Header bytes"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv4_udsbl_octets(&self) -> &GmacgrpRxipv4UdsblOctets {
        &self.gmacgrp_rxipv4_udsbl_octets
    }
    #[doc = "0x264 - Number of bytes received in good IPv6 datagrams encapsulating TCP, UDP or ICMPv6 data"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv6_gd_octets(&self) -> &GmacgrpRxipv6GdOctets {
        &self.gmacgrp_rxipv6_gd_octets
    }
    #[doc = "0x268 - Number of bytes received in IPv6 datagrams with header errors (length, version mismatch). The value in the IPv6 headers Length field is used to update this counter"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv6_hdrerr_octets(&self) -> &GmacgrpRxipv6HdrerrOctets {
        &self.gmacgrp_rxipv6_hdrerr_octets
    }
    #[doc = "0x26c - Number of bytes received in IPv6 datagrams that did not have a TCP, UDP, or ICMP payload. The value in the IPv6 headers Length field is used to update this counter"]
    #[inline(always)]
    pub const fn gmacgrp_rxipv6_nopay_octets(&self) -> &GmacgrpRxipv6NopayOctets {
        &self.gmacgrp_rxipv6_nopay_octets
    }
    #[doc = "0x270 - Number of bytes received in a good UDP segment. This counter does not count IP header bytes"]
    #[inline(always)]
    pub const fn gmacgrp_rxudp_gd_octets(&self) -> &GmacgrpRxudpGdOctets {
        &self.gmacgrp_rxudp_gd_octets
    }
    #[doc = "0x274 - Number of bytes received in a UDP segment that had checksum errors"]
    #[inline(always)]
    pub const fn gmacgrp_rxudp_err_octets(&self) -> &GmacgrpRxudpErrOctets {
        &self.gmacgrp_rxudp_err_octets
    }
    #[doc = "0x278 - Number of bytes received in a good TCP segment"]
    #[inline(always)]
    pub const fn gmacgrp_rxtcp_gd_octets(&self) -> &GmacgrpRxtcpGdOctets {
        &self.gmacgrp_rxtcp_gd_octets
    }
    #[doc = "0x27c - Number of bytes received in a TCP segment with checksum errors"]
    #[inline(always)]
    pub const fn gmacgrp_rxtcperroctets(&self) -> &GmacgrpRxtcperroctets {
        &self.gmacgrp_rxtcperroctets
    }
    #[doc = "0x280 - Number of bytes received in a good ICMP segment"]
    #[inline(always)]
    pub const fn gmacgrp_rxicmp_gd_octets(&self) -> &GmacgrpRxicmpGdOctets {
        &self.gmacgrp_rxicmp_gd_octets
    }
    #[doc = "0x284 - Number of bytes received in an ICMP segment with checksum errors"]
    #[inline(always)]
    pub const fn gmacgrp_rxicmp_err_octets(&self) -> &GmacgrpRxicmpErrOctets {
        &self.gmacgrp_rxicmp_err_octets
    }
    #[doc = "0x400 - This register controls the operations of the filter 0 of Layer 3 and Layer 4."]
    #[inline(always)]
    pub const fn gmacgrp_l3_l4_control0(&self) -> &GmacgrpL3L4Control0 {
        &self.gmacgrp_l3_l4_control0
    }
    #[doc = "0x404 - Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock."]
    #[inline(always)]
    pub const fn gmacgrp_layer4_address0(&self) -> &GmacgrpLayer4Address0 {
        &self.gmacgrp_layer4_address0
    }
    #[doc = "0x410 - For IPv4 frames, the Layer 3 Address 0 Register 0 contains the 32-bit IP Source Address field. For IPv6 frames, it contains Bits\\[31:0\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr0_reg0(&self) -> &GmacgrpLayer3Addr0Reg0 {
        &self.gmacgrp_layer3_addr0_reg0
    }
    #[doc = "0x414 - For IPv4 frames, the Layer 3 Address 1 Register 0 contains the 32-bit IP Destination Address field. For IPv6 frames, it contains Bits\\[63:32\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr1_reg0(&self) -> &GmacgrpLayer3Addr1Reg0 {
        &self.gmacgrp_layer3_addr1_reg0
    }
    #[doc = "0x418 - For IPv4 frames, the Layer 3 Address 2 Register 0 is reserved. For IPv6 frames, it contains Bits \\[95:64\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr2_reg0(&self) -> &GmacgrpLayer3Addr2Reg0 {
        &self.gmacgrp_layer3_addr2_reg0
    }
    #[doc = "0x41c - For IPv4 frames, the Layer 3 Address 3 Register 0 is reserved. For IPv6 frames, it contains Bits \\[127:96\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr3_reg0(&self) -> &GmacgrpLayer3Addr3Reg0 {
        &self.gmacgrp_layer3_addr3_reg0
    }
    #[doc = "0x430 - This register controls the operations of the filter 0 of Layer 3 and Layer 4."]
    #[inline(always)]
    pub const fn gmacgrp_l3_l4_control1(&self) -> &GmacgrpL3L4Control1 {
        &self.gmacgrp_l3_l4_control1
    }
    #[doc = "0x434 - Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock."]
    #[inline(always)]
    pub const fn gmacgrp_layer4_address1(&self) -> &GmacgrpLayer4Address1 {
        &self.gmacgrp_layer4_address1
    }
    #[doc = "0x440 - For IPv4 frames, the Layer 3 Address 0 Register 1 contains the 32-bit IP Source Address field. For IPv6 frames, it contains Bits\\[31:0\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr0_reg1(&self) -> &GmacgrpLayer3Addr0Reg1 {
        &self.gmacgrp_layer3_addr0_reg1
    }
    #[doc = "0x444 - For IPv4 frames, the Layer 3 Address 1 Register 1 contains the 32-bit IP Destination Address field. For IPv6 frames, it contains Bits\\[63:32\\]
of the 128-bit IP Source Address or Destination Address field"]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr1_reg1(&self) -> &GmacgrpLayer3Addr1Reg1 {
        &self.gmacgrp_layer3_addr1_reg1
    }
    #[doc = "0x448 - For IPv4 frames, the Layer 3 Address 2 Register 1 is reserved. For IPv6 frames, it contains Bits \\[95:64\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr2_reg1(&self) -> &GmacgrpLayer3Addr2Reg1 {
        &self.gmacgrp_layer3_addr2_reg1
    }
    #[doc = "0x44c - For IPv4 frames, the Layer 3 Address 3 Register 1 is reserved. For IPv6 frames, it contains Bits \\[127:96\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr3_reg1(&self) -> &GmacgrpLayer3Addr3Reg1 {
        &self.gmacgrp_layer3_addr3_reg1
    }
    #[doc = "0x460 - This register controls the operations of the filter 2 of Layer 3 and Layer 4."]
    #[inline(always)]
    pub const fn gmacgrp_l3_l4_control2(&self) -> &GmacgrpL3L4Control2 {
        &self.gmacgrp_l3_l4_control2
    }
    #[doc = "0x464 - Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock."]
    #[inline(always)]
    pub const fn gmacgrp_layer4_address2(&self) -> &GmacgrpLayer4Address2 {
        &self.gmacgrp_layer4_address2
    }
    #[doc = "0x470 - For IPv4 frames, the Layer 3 Address 0 Register 2 contains the 32-bit IP Source Address field. For IPv6 frames, it contains Bits \\[31:0\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr0_reg2(&self) -> &GmacgrpLayer3Addr0Reg2 {
        &self.gmacgrp_layer3_addr0_reg2
    }
    #[doc = "0x474 - For IPv4 frames, the Layer 3 Address 1 Register 2 contains the 32-bit IP Destination Address field. For IPv6 frames, it contains Bits \\[63:32\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr1_reg2(&self) -> &GmacgrpLayer3Addr1Reg2 {
        &self.gmacgrp_layer3_addr1_reg2
    }
    #[doc = "0x478 - For IPv4 frames, the Layer 3 Address 2 Register 2 is reserved. For IPv6 frames, it contains Bits \\[95:64\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr2_reg2(&self) -> &GmacgrpLayer3Addr2Reg2 {
        &self.gmacgrp_layer3_addr2_reg2
    }
    #[doc = "0x47c - For IPv4 frames, the Layer 3 Address 3 Register 2 is reserved. For IPv6 frames, it contains Bits \\[127:96\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr3_reg2(&self) -> &GmacgrpLayer3Addr3Reg2 {
        &self.gmacgrp_layer3_addr3_reg2
    }
    #[doc = "0x490 - This register controls the operations of the filter 0 of Layer 3 and Layer 4."]
    #[inline(always)]
    pub const fn gmacgrp_l3_l4_control3(&self) -> &GmacgrpL3L4Control3 {
        &self.gmacgrp_l3_l4_control3
    }
    #[doc = "0x494 - Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock."]
    #[inline(always)]
    pub const fn gmacgrp_layer4_address3(&self) -> &GmacgrpLayer4Address3 {
        &self.gmacgrp_layer4_address3
    }
    #[doc = "0x4a0 - For IPv4 frames, the Layer 3 Address 0 Register 3 contains the 32-bit IP Source Address field. For IPv6 frames, it contains Bits \\[31:0\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr0_reg3(&self) -> &GmacgrpLayer3Addr0Reg3 {
        &self.gmacgrp_layer3_addr0_reg3
    }
    #[doc = "0x4a4 - For IPv4 frames, the Layer 3 Address 1 Register 3 contains the 32-bit IP Destination Address field. For IPv6 frames, it contains Bits \\[63:32\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr1_reg3(&self) -> &GmacgrpLayer3Addr1Reg3 {
        &self.gmacgrp_layer3_addr1_reg3
    }
    #[doc = "0x4a8 - For IPv4 frames, the Layer 3 Address 2 Register 3 is reserved. For IPv6 frames, it contains Bits \\[95:64\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr2_reg3(&self) -> &GmacgrpLayer3Addr2Reg3 {
        &self.gmacgrp_layer3_addr2_reg3
    }
    #[doc = "0x4ac - For IPv4 frames, the Layer 3 Address 3 Register 3 is reserved. For IPv6 frames, it contains Bits \\[127:96\\]
of the 128-bit IP Source Address or Destination Address field."]
    #[inline(always)]
    pub const fn gmacgrp_layer3_addr3_reg3(&self) -> &GmacgrpLayer3Addr3Reg3 {
        &self.gmacgrp_layer3_addr3_reg3
    }
    #[doc = "0x500 - This register contains the first 32 bits of the hash table. The 256-bit Hash table is used for group address filtering. For hash filtering, the content of the destination address in the incoming frame is passed through the CRC logic and the upper eight bits of the CRC register are used to index the content of the Hash table. The most significant bits determines the register to be used (Hash Table Register X), and the least significant five bits determine the bit within the register. For example, a hash value of 8b'10111111 selects Bit 31 of the Hash Table Register 5. The hash value of the destination address is calculated in the following way: 1. Calculate the 32-bit CRC for the DA (See IEEE 802.3, Section 3.2.8 for the steps to calculate CRC32). 2. Perform bitwise reversal for the value obtained in Step 1. 3. Take the upper 8 bits from the value obtained in Step 2. If the corresponding bit value of the register is 1'b1, the frame is accepted. Otherwise, it is rejected. If the Bit 1 (Pass All Multicast) is set in Register 1 (MAC Frame Filter), then all multicast frames are accepted regardless of the multicast hash values. Because the Hash Table register is double-synchronized to the (G)MII clock domain, the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Hash Table Register X registers are written. Note: Because of double-synchronization, consecutive writes to this register should be performed after at least four clock cycles in the destination clock domain."]
    #[inline(always)]
    pub const fn gmacgrp_hash_table_reg0(&self) -> &GmacgrpHashTableReg0 {
        &self.gmacgrp_hash_table_reg0
    }
    #[doc = "0x504 - This register contains the second 32 bits of the hash table."]
    #[inline(always)]
    pub const fn gmacgrp_hash_table_reg1(&self) -> &GmacgrpHashTableReg1 {
        &self.gmacgrp_hash_table_reg1
    }
    #[doc = "0x508 - This register contains the third 32 bits of the hash table."]
    #[inline(always)]
    pub const fn gmacgrp_hash_table_reg2(&self) -> &GmacgrpHashTableReg2 {
        &self.gmacgrp_hash_table_reg2
    }
    #[doc = "0x50c - This register contains the fourth 32 bits of the hash table."]
    #[inline(always)]
    pub const fn gmacgrp_hash_table_reg3(&self) -> &GmacgrpHashTableReg3 {
        &self.gmacgrp_hash_table_reg3
    }
    #[doc = "0x510 - This register contains the fifth 32 bits of the hash table."]
    #[inline(always)]
    pub const fn gmacgrp_hash_table_reg4(&self) -> &GmacgrpHashTableReg4 {
        &self.gmacgrp_hash_table_reg4
    }
    #[doc = "0x514 - This register contains the sixth 32 bits of the hash table."]
    #[inline(always)]
    pub const fn gmacgrp_hash_table_reg5(&self) -> &GmacgrpHashTableReg5 {
        &self.gmacgrp_hash_table_reg5
    }
    #[doc = "0x518 - This register contains the seventh 32 bits of the hash table."]
    #[inline(always)]
    pub const fn gmacgrp_hash_table_reg6(&self) -> &GmacgrpHashTableReg6 {
        &self.gmacgrp_hash_table_reg6
    }
    #[doc = "0x51c - This register contains the eighth 32 bits of the hash table."]
    #[inline(always)]
    pub const fn gmacgrp_hash_table_reg7(&self) -> &GmacgrpHashTableReg7 {
        &self.gmacgrp_hash_table_reg7
    }
    #[doc = "0x584 - The VLAN Tag Inclusion or Replacement register contains the VLAN tag for insertion or replacement in the transmit frames."]
    #[inline(always)]
    pub const fn gmacgrp_vlan_incl_reg(&self) -> &GmacgrpVlanInclReg {
        &self.gmacgrp_vlan_incl_reg
    }
    #[doc = "0x588 - The 16-bit Hash table is used for group address filtering based on VLAN tag when Bit 18 (VTHM) of Register 7 (VLAN Tag Register) is set. For hash filtering, the content of the 16-bit VLAN tag or 12-bit VLAN ID (based on Bit 16 (ETV) of VLAN Tag Register) in the incoming frame is passed through the CRC logic and the upper four bits of the calculated CRC are used to index the contents of the VLAN Hash table. For example, a hash value of 4b'1000 selects Bit 8 of the VLAN Hash table. The hash value of the destination address is calculated in the following way: 1. Calculate the 32-bit CRC for the VLAN tag or ID (See IEEE 802.3, Section 3.2.8 for the steps to calculate CRC32). 2. Perform bitwise reversal for the value obtained in Step 1. 3. Take the upper four bits from the value obtained in Step 2. If the corresponding bit value of the register is 1'b1, the frame is accepted. Otherwise, it is rejected. Because the Hash Table register is double-synchronized to the (G)MII clock domain, the synchronization is triggered only when Bits\\[15:8\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of this register are written. Notes: * Because of double-synchronization, consecutive writes to this register should be performed after at least four clock cycles in the destination clock domain."]
    #[inline(always)]
    pub const fn gmacgrp_vlan_hash_table_reg(&self) -> &GmacgrpVlanHashTableReg {
        &self.gmacgrp_vlan_hash_table_reg
    }
    #[doc = "0x700 - This register controls the operation of the System Time generator and the processing of PTP packets for timestamping in the Receiver."]
    #[inline(always)]
    pub const fn gmacgrp_timestamp_control(&self) -> &GmacgrpTimestampControl {
        &self.gmacgrp_timestamp_control
    }
    #[doc = "0x704 - In the Coarse Update mode (TSCFUPDT bit in Register 448), the value in this register is added to the system time every clock cycle of clk_ptp_ref_i. In the Fine Update mode, the value in this register is added to the system time whenever the Accumulator gets an overflow."]
    #[inline(always)]
    pub const fn gmacgrp_sub_second_increment(&self) -> &GmacgrpSubSecondIncrement {
        &self.gmacgrp_sub_second_increment
    }
    #[doc = "0x708 - The System Time -Seconds register, along with System-TimeNanoseconds register, indicates the current value of the system time maintained by the MAC. Though it is updated on a continuous basis, there is some delay from the actual time because of clock domain transfer latencies (from clk_ptp_ref_i to l3_sp_clk)."]
    #[inline(always)]
    pub const fn gmacgrp_system_time_seconds(&self) -> &GmacgrpSystemTimeSeconds {
        &self.gmacgrp_system_time_seconds
    }
    #[doc = "0x70c - The value in this field has the sub second representation of time, with an accuracy of 0.46 ns. When TSCTRLSSR is set, each bit represents 1 ns and the maximum value is 0x3B9A_C9FF, after which it rolls-over to zero."]
    #[inline(always)]
    pub const fn gmacgrp_system_time_nanoseconds(&self) -> &GmacgrpSystemTimeNanoseconds {
        &self.gmacgrp_system_time_nanoseconds
    }
    #[doc = "0x710 - The System Time - Seconds Update register, along with the System Time - Nanoseconds Update register, initializes or updates the system time maintained by the MAC. You must write both of these registers before setting the TSINIT or TSUPDT bits in the Timestamp Control register."]
    #[inline(always)]
    pub const fn gmacgrp_system_time_seconds_update(&self) -> &GmacgrpSystemTimeSecondsUpdate {
        &self.gmacgrp_system_time_seconds_update
    }
    #[doc = "0x714 - Update system time"]
    #[inline(always)]
    pub const fn gmacgrp_system_time_nanoseconds_update(
        &self,
    ) -> &GmacgrpSystemTimeNanosecondsUpdate {
        &self.gmacgrp_system_time_nanoseconds_update
    }
    #[doc = "0x718 - This register value is used only when the system time is configured for Fine Update mode (TSCFUPDT bit in Register 448). This register content is added to a 32-bit accumulator in every clock cycle (of clk_ptp_ref_i) and the system time is updated whenever the accumulator overflows."]
    #[inline(always)]
    pub const fn gmacgrp_timestamp_addend(&self) -> &GmacgrpTimestampAddend {
        &self.gmacgrp_timestamp_addend
    }
    #[doc = "0x71c - The Target Time Seconds register, along with Target Time Nanoseconds register, is used to schedule an interrupt event (Register 458\\[1\\]
when Advanced Timestamping is enabled; otherwise, TS interrupt bit in Register14\\[9\\]) when the system time exceeds the value programmed in these registers."]
    #[inline(always)]
    pub const fn gmacgrp_target_time_seconds(&self) -> &GmacgrpTargetTimeSeconds {
        &self.gmacgrp_target_time_seconds
    }
    #[doc = "0x720 - Target time"]
    #[inline(always)]
    pub const fn gmacgrp_target_time_nanoseconds(&self) -> &GmacgrpTargetTimeNanoseconds {
        &self.gmacgrp_target_time_nanoseconds
    }
    #[doc = "0x724 - System time higher word"]
    #[inline(always)]
    pub const fn gmacgrp_system_time_higher_word_seconds(
        &self,
    ) -> &GmacgrpSystemTimeHigherWordSeconds {
        &self.gmacgrp_system_time_higher_word_seconds
    }
    #[doc = "0x728 - Timestamp status. All bits except Bits\\[27:25\\]
get cleared when the host reads this register."]
    #[inline(always)]
    pub const fn gmacgrp_timestamp_status(&self) -> &GmacgrpTimestampStatus {
        &self.gmacgrp_timestamp_status
    }
    #[doc = "0x72c - Controls timestamp Pulse-Per-Second output"]
    #[inline(always)]
    pub const fn gmacgrp_pps_control(&self) -> &GmacgrpPpsControl {
        &self.gmacgrp_pps_control
    }
    #[doc = "0x730 - This register, along with Register 461 (Auxiliary Timestamp Seconds Register), gives the 64-bit timestamp stored as auxiliary snapshot. The two registers together form the read port of a 64-bit wide FIFO with a depth of 16. Multiple snapshots can be stored in this FIFO. The ATSNS bits in the Timestamp Status register indicate the fill-level of this FIFO. The top of the FIFO is removed only when the last byte of Register 461 (Auxiliary Timestamp - Seconds Register) is read. In the little-endian mode, this means when Bits\\[31:24\\]
are read. In big-endian mode, it corresponds to the reading of Bits\\[7:0\\]
of Register 461 (Auxiliary Timestamp - Seconds Register)."]
    #[inline(always)]
    pub const fn gmacgrp_auxiliary_timestamp_nanoseconds(
        &self,
    ) -> &GmacgrpAuxiliaryTimestampNanoseconds {
        &self.gmacgrp_auxiliary_timestamp_nanoseconds
    }
    #[doc = "0x734 - Contains the higher 32 bits (Seconds field) of the auxiliary timestamp."]
    #[inline(always)]
    pub const fn gmacgrp_auxiliary_timestamp_seconds(&self) -> &GmacgrpAuxiliaryTimestampSeconds {
        &self.gmacgrp_auxiliary_timestamp_seconds
    }
    #[doc = "0x760 - The PPS0 Interval register contains the number of units of sub-second increment value between the rising edges of PPS0 signal output (ptp_pps_o\\[0\\])."]
    #[inline(always)]
    pub const fn gmacgrp_pps0_interval(&self) -> &GmacgrpPps0Interval {
        &self.gmacgrp_pps0_interval
    }
    #[doc = "0x764 - The PPS0 Width register contains the number of units of sub-second increment value between the rising and corresponding falling edges of the PPS0 signal output (ptp_pps_o\\[0\\])."]
    #[inline(always)]
    pub const fn gmacgrp_pps0_width(&self) -> &GmacgrpPps0Width {
        &self.gmacgrp_pps0_width
    }
    #[doc = "0x800 - The MAC Address16 High register holds the upper 16 bits of the 17th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address16 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address16_high(&self) -> &GmacgrpMacAddress16High {
        &self.gmacgrp_mac_address16_high
    }
    #[doc = "0x804 - The MAC Address16 Low register holds the lower 32 bits of the 17th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address16_low(&self) -> &GmacgrpMacAddress16Low {
        &self.gmacgrp_mac_address16_low
    }
    #[doc = "0x808 - The MAC Address17 High register holds the upper 16 bits of the 18th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address17 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address17_high(&self) -> &GmacgrpMacAddress17High {
        &self.gmacgrp_mac_address17_high
    }
    #[doc = "0x80c - The MAC Address17 Low register holds the lower 32 bits of the 18th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address17_low(&self) -> &GmacgrpMacAddress17Low {
        &self.gmacgrp_mac_address17_low
    }
    #[doc = "0x810 - The MAC Address18 High register holds the upper 16 bits of the 19th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address18 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address18_high(&self) -> &GmacgrpMacAddress18High {
        &self.gmacgrp_mac_address18_high
    }
    #[doc = "0x814 - The MAC Address18 Low register holds the lower 32 bits of the 19th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address18_low(&self) -> &GmacgrpMacAddress18Low {
        &self.gmacgrp_mac_address18_low
    }
    #[doc = "0x818 - The MAC Address19 High register holds the upper 16 bits of the 20th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address19 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address19_high(&self) -> &GmacgrpMacAddress19High {
        &self.gmacgrp_mac_address19_high
    }
    #[doc = "0x81c - The MAC Address19 Low register holds the lower 32 bits of the 20th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address19_low(&self) -> &GmacgrpMacAddress19Low {
        &self.gmacgrp_mac_address19_low
    }
    #[doc = "0x820 - The MAC Address20 High register holds the upper 16 bits of the 21th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address20 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address20_high(&self) -> &GmacgrpMacAddress20High {
        &self.gmacgrp_mac_address20_high
    }
    #[doc = "0x824 - The MAC Address20 Low register holds the lower 32 bits of the 21th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address20_low(&self) -> &GmacgrpMacAddress20Low {
        &self.gmacgrp_mac_address20_low
    }
    #[doc = "0x828 - The MAC Address21 High register holds the upper 16 bits of the 22th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address21 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address21_high(&self) -> &GmacgrpMacAddress21High {
        &self.gmacgrp_mac_address21_high
    }
    #[doc = "0x82c - The MAC Address21 Low register holds the lower 32 bits of the 22th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address21_low(&self) -> &GmacgrpMacAddress21Low {
        &self.gmacgrp_mac_address21_low
    }
    #[doc = "0x830 - The MAC Address22 High register holds the upper 16 bits of the 23th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address22 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address22_high(&self) -> &GmacgrpMacAddress22High {
        &self.gmacgrp_mac_address22_high
    }
    #[doc = "0x834 - The MAC Address22 Low register holds the lower 32 bits of the 23th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address22_low(&self) -> &GmacgrpMacAddress22Low {
        &self.gmacgrp_mac_address22_low
    }
    #[doc = "0x838 - The MAC Address23 High register holds the upper 16 bits of the 24th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address23 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address23_high(&self) -> &GmacgrpMacAddress23High {
        &self.gmacgrp_mac_address23_high
    }
    #[doc = "0x83c - The MAC Address23 Low register holds the lower 32 bits of the 24th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address23_low(&self) -> &GmacgrpMacAddress23Low {
        &self.gmacgrp_mac_address23_low
    }
    #[doc = "0x840 - The MAC Address24 High register holds the upper 16 bits of the 25th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address24 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address24_high(&self) -> &GmacgrpMacAddress24High {
        &self.gmacgrp_mac_address24_high
    }
    #[doc = "0x844 - The MAC Address24 Low register holds the lower 32 bits of the 25th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address24_low(&self) -> &GmacgrpMacAddress24Low {
        &self.gmacgrp_mac_address24_low
    }
    #[doc = "0x848 - The MAC Address25 High register holds the upper 16 bits of the 26th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address25 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address25_high(&self) -> &GmacgrpMacAddress25High {
        &self.gmacgrp_mac_address25_high
    }
    #[doc = "0x84c - The MAC Address25 Low register holds the lower 32 bits of the 26th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address25_low(&self) -> &GmacgrpMacAddress25Low {
        &self.gmacgrp_mac_address25_low
    }
    #[doc = "0x850 - The MAC Address26 High register holds the upper 16 bits of the 27th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address26 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address26_high(&self) -> &GmacgrpMacAddress26High {
        &self.gmacgrp_mac_address26_high
    }
    #[doc = "0x854 - The MAC Address26 Low register holds the lower 32 bits of the 27th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address26_low(&self) -> &GmacgrpMacAddress26Low {
        &self.gmacgrp_mac_address26_low
    }
    #[doc = "0x858 - The MAC Address27 High register holds the upper 16 bits of the 28th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address27 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address27_high(&self) -> &GmacgrpMacAddress27High {
        &self.gmacgrp_mac_address27_high
    }
    #[doc = "0x85c - The MAC Address27 Low register holds the lower 32 bits of the 28th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address27_low(&self) -> &GmacgrpMacAddress27Low {
        &self.gmacgrp_mac_address27_low
    }
    #[doc = "0x860 - The MAC Address28 High register holds the upper 16 bits of the 29th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address28 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address28_high(&self) -> &GmacgrpMacAddress28High {
        &self.gmacgrp_mac_address28_high
    }
    #[doc = "0x864 - The MAC Address28 Low register holds the lower 32 bits of the 29th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address28_low(&self) -> &GmacgrpMacAddress28Low {
        &self.gmacgrp_mac_address28_low
    }
    #[doc = "0x868 - The MAC Address29 High register holds the upper 16 bits of the 30th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address29 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address29_high(&self) -> &GmacgrpMacAddress29High {
        &self.gmacgrp_mac_address29_high
    }
    #[doc = "0x86c - The MAC Address29 Low register holds the lower 32 bits of the 30th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address29_low(&self) -> &GmacgrpMacAddress29Low {
        &self.gmacgrp_mac_address29_low
    }
    #[doc = "0x870 - The MAC Address30 High register holds the upper 16 bits of the 31th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address30 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address30_high(&self) -> &GmacgrpMacAddress30High {
        &self.gmacgrp_mac_address30_high
    }
    #[doc = "0x874 - The MAC Address30 Low register holds the lower 32 bits of the 31th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address30_low(&self) -> &GmacgrpMacAddress30Low {
        &self.gmacgrp_mac_address30_low
    }
    #[doc = "0x878 - The MAC Address31 High register holds the upper 16 bits of the 32th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address31 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address31_high(&self) -> &GmacgrpMacAddress31High {
        &self.gmacgrp_mac_address31_high
    }
    #[doc = "0x87c - The MAC Address31 Low register holds the lower 32 bits of the 32th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address31_low(&self) -> &GmacgrpMacAddress31Low {
        &self.gmacgrp_mac_address31_low
    }
    #[doc = "0x880 - The MAC Address32 High register holds the upper 16 bits of the 33th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address32 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address32_high(&self) -> &GmacgrpMacAddress32High {
        &self.gmacgrp_mac_address32_high
    }
    #[doc = "0x884 - The MAC Address32 Low register holds the lower 32 bits of the 33th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address32_low(&self) -> &GmacgrpMacAddress32Low {
        &self.gmacgrp_mac_address32_low
    }
    #[doc = "0x888 - The MAC Address33 High register holds the upper 16 bits of the 34th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address33 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address33_high(&self) -> &GmacgrpMacAddress33High {
        &self.gmacgrp_mac_address33_high
    }
    #[doc = "0x88c - The MAC Address33 Low register holds the lower 32 bits of the 34th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address33_low(&self) -> &GmacgrpMacAddress33Low {
        &self.gmacgrp_mac_address33_low
    }
    #[doc = "0x890 - The MAC Address34 High register holds the upper 16 bits of the 35th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address34 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address34_high(&self) -> &GmacgrpMacAddress34High {
        &self.gmacgrp_mac_address34_high
    }
    #[doc = "0x894 - The MAC Address34 Low register holds the lower 32 bits of the 35th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address34_low(&self) -> &GmacgrpMacAddress34Low {
        &self.gmacgrp_mac_address34_low
    }
    #[doc = "0x898 - The MAC Address35 High register holds the upper 16 bits of the 36th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address35 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address35_high(&self) -> &GmacgrpMacAddress35High {
        &self.gmacgrp_mac_address35_high
    }
    #[doc = "0x89c - The MAC Address35 Low register holds the lower 32 bits of the 36th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address35_low(&self) -> &GmacgrpMacAddress35Low {
        &self.gmacgrp_mac_address35_low
    }
    #[doc = "0x8a0 - The MAC Address36 High register holds the upper 16 bits of the 37th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address36 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address36_high(&self) -> &GmacgrpMacAddress36High {
        &self.gmacgrp_mac_address36_high
    }
    #[doc = "0x8a4 - The MAC Address36 Low register holds the lower 32 bits of the 37th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address36_low(&self) -> &GmacgrpMacAddress36Low {
        &self.gmacgrp_mac_address36_low
    }
    #[doc = "0x8a8 - The MAC Address37 High register holds the upper 16 bits of the 38th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address37 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address37_high(&self) -> &GmacgrpMacAddress37High {
        &self.gmacgrp_mac_address37_high
    }
    #[doc = "0x8ac - The MAC Address37 Low register holds the lower 32 bits of the 38th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address37_low(&self) -> &GmacgrpMacAddress37Low {
        &self.gmacgrp_mac_address37_low
    }
    #[doc = "0x8b0 - The MAC Address38 High register holds the upper 16 bits of the 39th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address38 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address38_high(&self) -> &GmacgrpMacAddress38High {
        &self.gmacgrp_mac_address38_high
    }
    #[doc = "0x8b4 - The MAC Address38 Low register holds the lower 32 bits of the 39th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address38_low(&self) -> &GmacgrpMacAddress38Low {
        &self.gmacgrp_mac_address38_low
    }
    #[doc = "0x8b8 - The MAC Address39 High register holds the upper 16 bits of the 40th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address39 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address39_high(&self) -> &GmacgrpMacAddress39High {
        &self.gmacgrp_mac_address39_high
    }
    #[doc = "0x8bc - The MAC Address39 Low register holds the lower 32 bits of the 40th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address39_low(&self) -> &GmacgrpMacAddress39Low {
        &self.gmacgrp_mac_address39_low
    }
    #[doc = "0x8c0 - The MAC Address40 High register holds the upper 16 bits of the 41th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address40 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address40_high(&self) -> &GmacgrpMacAddress40High {
        &self.gmacgrp_mac_address40_high
    }
    #[doc = "0x8c4 - The MAC Address40 Low register holds the lower 32 bits of the 41th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address40_low(&self) -> &GmacgrpMacAddress40Low {
        &self.gmacgrp_mac_address40_low
    }
    #[doc = "0x8c8 - The MAC Address41 High register holds the upper 16 bits of the 42th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address41 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address41_high(&self) -> &GmacgrpMacAddress41High {
        &self.gmacgrp_mac_address41_high
    }
    #[doc = "0x8cc - The MAC Address41 Low register holds the lower 32 bits of the 42th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address41_low(&self) -> &GmacgrpMacAddress41Low {
        &self.gmacgrp_mac_address41_low
    }
    #[doc = "0x8d0 - The MAC Address42 High register holds the upper 16 bits of the 43th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address42 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address42_high(&self) -> &GmacgrpMacAddress42High {
        &self.gmacgrp_mac_address42_high
    }
    #[doc = "0x8d4 - The MAC Address42 Low register holds the lower 32 bits of the 43th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address42_low(&self) -> &GmacgrpMacAddress42Low {
        &self.gmacgrp_mac_address42_low
    }
    #[doc = "0x8d8 - The MAC Address43 High register holds the upper 16 bits of the 44th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address43 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address43_high(&self) -> &GmacgrpMacAddress43High {
        &self.gmacgrp_mac_address43_high
    }
    #[doc = "0x8dc - The MAC Address43 Low register holds the lower 32 bits of the 44th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address43_low(&self) -> &GmacgrpMacAddress43Low {
        &self.gmacgrp_mac_address43_low
    }
    #[doc = "0x8e0 - The MAC Address44 High register holds the upper 16 bits of the 45th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address44 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address44_high(&self) -> &GmacgrpMacAddress44High {
        &self.gmacgrp_mac_address44_high
    }
    #[doc = "0x8e4 - The MAC Address44 Low register holds the lower 32 bits of the 45th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address44_low(&self) -> &GmacgrpMacAddress44Low {
        &self.gmacgrp_mac_address44_low
    }
    #[doc = "0x8e8 - The MAC Address45 High register holds the upper 16 bits of the 46th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address45 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address45_high(&self) -> &GmacgrpMacAddress45High {
        &self.gmacgrp_mac_address45_high
    }
    #[doc = "0x8ec - The MAC Address45 Low register holds the lower 32 bits of the 46th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address45_low(&self) -> &GmacgrpMacAddress45Low {
        &self.gmacgrp_mac_address45_low
    }
    #[doc = "0x8f0 - The MAC Address46 High register holds the upper 16 bits of the 47th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address46 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address46_high(&self) -> &GmacgrpMacAddress46High {
        &self.gmacgrp_mac_address46_high
    }
    #[doc = "0x8f4 - The MAC Address46 Low register holds the lower 32 bits of the 47th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address46_low(&self) -> &GmacgrpMacAddress46Low {
        &self.gmacgrp_mac_address46_low
    }
    #[doc = "0x8f8 - The MAC Address47 High register holds the upper 16 bits of the 48th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address47 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address47_high(&self) -> &GmacgrpMacAddress47High {
        &self.gmacgrp_mac_address47_high
    }
    #[doc = "0x8fc - The MAC Address47 Low register holds the lower 32 bits of the 48th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address47_low(&self) -> &GmacgrpMacAddress47Low {
        &self.gmacgrp_mac_address47_low
    }
    #[doc = "0x900 - The MAC Address48 High register holds the upper 16 bits of the 49th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address48 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address48_high(&self) -> &GmacgrpMacAddress48High {
        &self.gmacgrp_mac_address48_high
    }
    #[doc = "0x904 - The MAC Address48 Low register holds the lower 32 bits of the 49th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address48_low(&self) -> &GmacgrpMacAddress48Low {
        &self.gmacgrp_mac_address48_low
    }
    #[doc = "0x908 - The MAC Address49 High register holds the upper 16 bits of the 50th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address49 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address49_high(&self) -> &GmacgrpMacAddress49High {
        &self.gmacgrp_mac_address49_high
    }
    #[doc = "0x90c - The MAC Address49 Low register holds the lower 32 bits of the 50th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address49_low(&self) -> &GmacgrpMacAddress49Low {
        &self.gmacgrp_mac_address49_low
    }
    #[doc = "0x910 - The MAC Address50 High register holds the upper 16 bits of the 51th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address50 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address50_high(&self) -> &GmacgrpMacAddress50High {
        &self.gmacgrp_mac_address50_high
    }
    #[doc = "0x914 - The MAC Address50 Low register holds the lower 32 bits of the 51th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address50_low(&self) -> &GmacgrpMacAddress50Low {
        &self.gmacgrp_mac_address50_low
    }
    #[doc = "0x918 - The MAC Address51 High register holds the upper 16 bits of the 52th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address51 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address51_high(&self) -> &GmacgrpMacAddress51High {
        &self.gmacgrp_mac_address51_high
    }
    #[doc = "0x91c - The MAC Address51 Low register holds the lower 32 bits of the 52th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address51_low(&self) -> &GmacgrpMacAddress51Low {
        &self.gmacgrp_mac_address51_low
    }
    #[doc = "0x920 - The MAC Address52 High register holds the upper 16 bits of the 53th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address52 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address52_high(&self) -> &GmacgrpMacAddress52High {
        &self.gmacgrp_mac_address52_high
    }
    #[doc = "0x924 - The MAC Address52 Low register holds the lower 32 bits of the 53th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address52_low(&self) -> &GmacgrpMacAddress52Low {
        &self.gmacgrp_mac_address52_low
    }
    #[doc = "0x928 - The MAC Address53 High register holds the upper 16 bits of the 54th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address53 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address53_high(&self) -> &GmacgrpMacAddress53High {
        &self.gmacgrp_mac_address53_high
    }
    #[doc = "0x92c - The MAC Address53 Low register holds the lower 32 bits of the 54th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address53_low(&self) -> &GmacgrpMacAddress53Low {
        &self.gmacgrp_mac_address53_low
    }
    #[doc = "0x930 - The MAC Address54 High register holds the upper 16 bits of the 55th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address54 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address54_high(&self) -> &GmacgrpMacAddress54High {
        &self.gmacgrp_mac_address54_high
    }
    #[doc = "0x934 - The MAC Address54 Low register holds the lower 32 bits of the 55th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address54_low(&self) -> &GmacgrpMacAddress54Low {
        &self.gmacgrp_mac_address54_low
    }
    #[doc = "0x938 - The MAC Address55 High register holds the upper 16 bits of the 56th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address55 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address55_high(&self) -> &GmacgrpMacAddress55High {
        &self.gmacgrp_mac_address55_high
    }
    #[doc = "0x93c - The MAC Address55 Low register holds the lower 32 bits of the 56th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address55_low(&self) -> &GmacgrpMacAddress55Low {
        &self.gmacgrp_mac_address55_low
    }
    #[doc = "0x940 - The MAC Address56 High register holds the upper 16 bits of the 57th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address56 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address56_high(&self) -> &GmacgrpMacAddress56High {
        &self.gmacgrp_mac_address56_high
    }
    #[doc = "0x944 - The MAC Address56 Low register holds the lower 32 bits of the 57th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address56_low(&self) -> &GmacgrpMacAddress56Low {
        &self.gmacgrp_mac_address56_low
    }
    #[doc = "0x948 - The MAC Address57 High register holds the upper 16 bits of the 58th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address57 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address57_high(&self) -> &GmacgrpMacAddress57High {
        &self.gmacgrp_mac_address57_high
    }
    #[doc = "0x94c - The MAC Address57 Low register holds the lower 32 bits of the 58th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address57_low(&self) -> &GmacgrpMacAddress57Low {
        &self.gmacgrp_mac_address57_low
    }
    #[doc = "0x950 - The MAC Address58 High register holds the upper 16 bits of the 59th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address58 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address58_high(&self) -> &GmacgrpMacAddress58High {
        &self.gmacgrp_mac_address58_high
    }
    #[doc = "0x954 - The MAC Address58 Low register holds the lower 32 bits of the 59th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address58_low(&self) -> &GmacgrpMacAddress58Low {
        &self.gmacgrp_mac_address58_low
    }
    #[doc = "0x958 - The MAC Address59 High register holds the upper 16 bits of the 60th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address59 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address59_high(&self) -> &GmacgrpMacAddress59High {
        &self.gmacgrp_mac_address59_high
    }
    #[doc = "0x95c - The MAC Address59 Low register holds the lower 32 bits of the 60th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address59_low(&self) -> &GmacgrpMacAddress59Low {
        &self.gmacgrp_mac_address59_low
    }
    #[doc = "0x960 - The MAC Address60 High register holds the upper 16 bits of the 61th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address60 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address60_high(&self) -> &GmacgrpMacAddress60High {
        &self.gmacgrp_mac_address60_high
    }
    #[doc = "0x964 - The MAC Address60 Low register holds the lower 32 bits of the 61th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address60_low(&self) -> &GmacgrpMacAddress60Low {
        &self.gmacgrp_mac_address60_low
    }
    #[doc = "0x968 - The MAC Address61 High register holds the upper 16 bits of the 62th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address61 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address61_high(&self) -> &GmacgrpMacAddress61High {
        &self.gmacgrp_mac_address61_high
    }
    #[doc = "0x96c - The MAC Address61 Low register holds the lower 32 bits of the 62th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address61_low(&self) -> &GmacgrpMacAddress61Low {
        &self.gmacgrp_mac_address61_low
    }
    #[doc = "0x970 - The MAC Address62 High register holds the upper 16 bits of the 63th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address62 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address62_high(&self) -> &GmacgrpMacAddress62High {
        &self.gmacgrp_mac_address62_high
    }
    #[doc = "0x974 - The MAC Address62 Low register holds the lower 32 bits of the 63th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address62_low(&self) -> &GmacgrpMacAddress62Low {
        &self.gmacgrp_mac_address62_low
    }
    #[doc = "0x978 - The MAC Address63 High register holds the upper 16 bits of the 64th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address63 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address63_high(&self) -> &GmacgrpMacAddress63High {
        &self.gmacgrp_mac_address63_high
    }
    #[doc = "0x97c - The MAC Address63 Low register holds the lower 32 bits of the 64th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address63_low(&self) -> &GmacgrpMacAddress63Low {
        &self.gmacgrp_mac_address63_low
    }
    #[doc = "0x980 - The MAC Address64 High register holds the upper 16 bits of the 65th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address64 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address64_high(&self) -> &GmacgrpMacAddress64High {
        &self.gmacgrp_mac_address64_high
    }
    #[doc = "0x984 - The MAC Address64 Low register holds the lower 32 bits of the 65th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address64_low(&self) -> &GmacgrpMacAddress64Low {
        &self.gmacgrp_mac_address64_low
    }
    #[doc = "0x988 - The MAC Address65 High register holds the upper 16 bits of the 66th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address65 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address65_high(&self) -> &GmacgrpMacAddress65High {
        &self.gmacgrp_mac_address65_high
    }
    #[doc = "0x98c - The MAC Address65 Low register holds the lower 32 bits of the 66th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address65_low(&self) -> &GmacgrpMacAddress65Low {
        &self.gmacgrp_mac_address65_low
    }
    #[doc = "0x990 - The MAC Address66 High register holds the upper 16 bits of the 67th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address66 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address66_high(&self) -> &GmacgrpMacAddress66High {
        &self.gmacgrp_mac_address66_high
    }
    #[doc = "0x994 - The MAC Address66 Low register holds the lower 32 bits of the 67th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address66_low(&self) -> &GmacgrpMacAddress66Low {
        &self.gmacgrp_mac_address66_low
    }
    #[doc = "0x998 - The MAC Address67 High register holds the upper 16 bits of the 68th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address67 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address67_high(&self) -> &GmacgrpMacAddress67High {
        &self.gmacgrp_mac_address67_high
    }
    #[doc = "0x99c - The MAC Address67 Low register holds the lower 32 bits of the 68th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address67_low(&self) -> &GmacgrpMacAddress67Low {
        &self.gmacgrp_mac_address67_low
    }
    #[doc = "0x9a0 - The MAC Address68 High register holds the upper 16 bits of the 69th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address68 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address68_high(&self) -> &GmacgrpMacAddress68High {
        &self.gmacgrp_mac_address68_high
    }
    #[doc = "0x9a4 - The MAC Address68 Low register holds the lower 32 bits of the 69th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address68_low(&self) -> &GmacgrpMacAddress68Low {
        &self.gmacgrp_mac_address68_low
    }
    #[doc = "0x9a8 - The MAC Address69 High register holds the upper 16 bits of the 70th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address69 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address69_high(&self) -> &GmacgrpMacAddress69High {
        &self.gmacgrp_mac_address69_high
    }
    #[doc = "0x9ac - The MAC Address69 Low register holds the lower 32 bits of the 70th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address69_low(&self) -> &GmacgrpMacAddress69Low {
        &self.gmacgrp_mac_address69_low
    }
    #[doc = "0x9b0 - The MAC Address70 High register holds the upper 16 bits of the 71th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address70 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address70_high(&self) -> &GmacgrpMacAddress70High {
        &self.gmacgrp_mac_address70_high
    }
    #[doc = "0x9b4 - The MAC Address70 Low register holds the lower 32 bits of the 71th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address70_low(&self) -> &GmacgrpMacAddress70Low {
        &self.gmacgrp_mac_address70_low
    }
    #[doc = "0x9b8 - The MAC Address71 High register holds the upper 16 bits of the 72th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address71 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address71_high(&self) -> &GmacgrpMacAddress71High {
        &self.gmacgrp_mac_address71_high
    }
    #[doc = "0x9bc - The MAC Address71 Low register holds the lower 32 bits of the 72th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address71_low(&self) -> &GmacgrpMacAddress71Low {
        &self.gmacgrp_mac_address71_low
    }
    #[doc = "0x9c0 - The MAC Address72 High register holds the upper 16 bits of the 73th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address72 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address72_high(&self) -> &GmacgrpMacAddress72High {
        &self.gmacgrp_mac_address72_high
    }
    #[doc = "0x9c4 - The MAC Address72 Low register holds the lower 32 bits of the 73th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address72_low(&self) -> &GmacgrpMacAddress72Low {
        &self.gmacgrp_mac_address72_low
    }
    #[doc = "0x9c8 - The MAC Address73 High register holds the upper 16 bits of the 74th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address73 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address73_high(&self) -> &GmacgrpMacAddress73High {
        &self.gmacgrp_mac_address73_high
    }
    #[doc = "0x9cc - The MAC Address73 Low register holds the lower 32 bits of the 74th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address73_low(&self) -> &GmacgrpMacAddress73Low {
        &self.gmacgrp_mac_address73_low
    }
    #[doc = "0x9d0 - The MAC Address74 High register holds the upper 16 bits of the 75th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address74 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address74_high(&self) -> &GmacgrpMacAddress74High {
        &self.gmacgrp_mac_address74_high
    }
    #[doc = "0x9d4 - The MAC Address74 Low register holds the lower 32 bits of the 75th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address74_low(&self) -> &GmacgrpMacAddress74Low {
        &self.gmacgrp_mac_address74_low
    }
    #[doc = "0x9d8 - The MAC Address75 High register holds the upper 16 bits of the 76th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address75 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address75_high(&self) -> &GmacgrpMacAddress75High {
        &self.gmacgrp_mac_address75_high
    }
    #[doc = "0x9dc - The MAC Address75 Low register holds the lower 32 bits of the 76th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address75_low(&self) -> &GmacgrpMacAddress75Low {
        &self.gmacgrp_mac_address75_low
    }
    #[doc = "0x9e0 - The MAC Address76 High register holds the upper 16 bits of the 77th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address76 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address76_high(&self) -> &GmacgrpMacAddress76High {
        &self.gmacgrp_mac_address76_high
    }
    #[doc = "0x9e4 - The MAC Address76 Low register holds the lower 32 bits of the 77th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address76_low(&self) -> &GmacgrpMacAddress76Low {
        &self.gmacgrp_mac_address76_low
    }
    #[doc = "0x9e8 - The MAC Address77 High register holds the upper 16 bits of the 78th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address77 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address77_high(&self) -> &GmacgrpMacAddress77High {
        &self.gmacgrp_mac_address77_high
    }
    #[doc = "0x9ec - The MAC Address77 Low register holds the lower 32 bits of the 78th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address77_low(&self) -> &GmacgrpMacAddress77Low {
        &self.gmacgrp_mac_address77_low
    }
    #[doc = "0x9f0 - The MAC Address78 High register holds the upper 16 bits of the 79th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address78 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address78_high(&self) -> &GmacgrpMacAddress78High {
        &self.gmacgrp_mac_address78_high
    }
    #[doc = "0x9f4 - The MAC Address78 Low register holds the lower 32 bits of the 79th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address78_low(&self) -> &GmacgrpMacAddress78Low {
        &self.gmacgrp_mac_address78_low
    }
    #[doc = "0x9f8 - The MAC Address79 High register holds the upper 16 bits of the 80th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address79 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address79_high(&self) -> &GmacgrpMacAddress79High {
        &self.gmacgrp_mac_address79_high
    }
    #[doc = "0x9fc - The MAC Address79 Low register holds the lower 32 bits of the 80th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address79_low(&self) -> &GmacgrpMacAddress79Low {
        &self.gmacgrp_mac_address79_low
    }
    #[doc = "0xa00 - The MAC Address80 High register holds the upper 16 bits of the 81th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address80 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address80_high(&self) -> &GmacgrpMacAddress80High {
        &self.gmacgrp_mac_address80_high
    }
    #[doc = "0xa04 - The MAC Address80 Low register holds the lower 32 bits of the 81th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address80_low(&self) -> &GmacgrpMacAddress80Low {
        &self.gmacgrp_mac_address80_low
    }
    #[doc = "0xa08 - The MAC Address81 High register holds the upper 16 bits of the 82th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address81 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address81_high(&self) -> &GmacgrpMacAddress81High {
        &self.gmacgrp_mac_address81_high
    }
    #[doc = "0xa0c - The MAC Address81 Low register holds the lower 32 bits of the 82th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address81_low(&self) -> &GmacgrpMacAddress81Low {
        &self.gmacgrp_mac_address81_low
    }
    #[doc = "0xa10 - The MAC Address82 High register holds the upper 16 bits of the 83th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address82 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address82_high(&self) -> &GmacgrpMacAddress82High {
        &self.gmacgrp_mac_address82_high
    }
    #[doc = "0xa14 - The MAC Address82 Low register holds the lower 32 bits of the 83th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address82_low(&self) -> &GmacgrpMacAddress82Low {
        &self.gmacgrp_mac_address82_low
    }
    #[doc = "0xa18 - The MAC Address83 High register holds the upper 16 bits of the 84th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address83 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address83_high(&self) -> &GmacgrpMacAddress83High {
        &self.gmacgrp_mac_address83_high
    }
    #[doc = "0xa1c - The MAC Address83 Low register holds the lower 32 bits of the 84th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address83_low(&self) -> &GmacgrpMacAddress83Low {
        &self.gmacgrp_mac_address83_low
    }
    #[doc = "0xa20 - The MAC Address84 High register holds the upper 16 bits of the 85th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address84 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address84_high(&self) -> &GmacgrpMacAddress84High {
        &self.gmacgrp_mac_address84_high
    }
    #[doc = "0xa24 - The MAC Address84 Low register holds the lower 32 bits of the 85th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address84_low(&self) -> &GmacgrpMacAddress84Low {
        &self.gmacgrp_mac_address84_low
    }
    #[doc = "0xa28 - The MAC Address85 High register holds the upper 16 bits of the 86th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address85 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address85_high(&self) -> &GmacgrpMacAddress85High {
        &self.gmacgrp_mac_address85_high
    }
    #[doc = "0xa2c - The MAC Address85 Low register holds the lower 32 bits of the 86th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address85_low(&self) -> &GmacgrpMacAddress85Low {
        &self.gmacgrp_mac_address85_low
    }
    #[doc = "0xa30 - The MAC Address86 High register holds the upper 16 bits of the 87th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address86 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address86_high(&self) -> &GmacgrpMacAddress86High {
        &self.gmacgrp_mac_address86_high
    }
    #[doc = "0xa34 - The MAC Address86 Low register holds the lower 32 bits of the 87th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address86_low(&self) -> &GmacgrpMacAddress86Low {
        &self.gmacgrp_mac_address86_low
    }
    #[doc = "0xa38 - The MAC Address87 High register holds the upper 16 bits of the 88th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address87 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address87_high(&self) -> &GmacgrpMacAddress87High {
        &self.gmacgrp_mac_address87_high
    }
    #[doc = "0xa3c - The MAC Address87 Low register holds the lower 32 bits of the 88th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address87_low(&self) -> &GmacgrpMacAddress87Low {
        &self.gmacgrp_mac_address87_low
    }
    #[doc = "0xa40 - The MAC Address88 High register holds the upper 16 bits of the 89th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address88 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address88_high(&self) -> &GmacgrpMacAddress88High {
        &self.gmacgrp_mac_address88_high
    }
    #[doc = "0xa44 - The MAC Address88 Low register holds the lower 32 bits of the 89th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address88_low(&self) -> &GmacgrpMacAddress88Low {
        &self.gmacgrp_mac_address88_low
    }
    #[doc = "0xa48 - The MAC Address89 High register holds the upper 16 bits of the 90th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address89 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address89_high(&self) -> &GmacgrpMacAddress89High {
        &self.gmacgrp_mac_address89_high
    }
    #[doc = "0xa4c - The MAC Address89 Low register holds the lower 32 bits of the 90th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address89_low(&self) -> &GmacgrpMacAddress89Low {
        &self.gmacgrp_mac_address89_low
    }
    #[doc = "0xa50 - The MAC Address90 High register holds the upper 16 bits of the 91th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address90 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address90_high(&self) -> &GmacgrpMacAddress90High {
        &self.gmacgrp_mac_address90_high
    }
    #[doc = "0xa54 - The MAC Address90 Low register holds the lower 32 bits of the 91th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address90_low(&self) -> &GmacgrpMacAddress90Low {
        &self.gmacgrp_mac_address90_low
    }
    #[doc = "0xa58 - The MAC Address91 High register holds the upper 16 bits of the 92th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address91 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address91_high(&self) -> &GmacgrpMacAddress91High {
        &self.gmacgrp_mac_address91_high
    }
    #[doc = "0xa5c - The MAC Address91 Low register holds the lower 32 bits of the 92th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address91_low(&self) -> &GmacgrpMacAddress91Low {
        &self.gmacgrp_mac_address91_low
    }
    #[doc = "0xa60 - The MAC Address92 High register holds the upper 16 bits of the 93th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address92 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address92_high(&self) -> &GmacgrpMacAddress92High {
        &self.gmacgrp_mac_address92_high
    }
    #[doc = "0xa64 - The MAC Address92 Low register holds the lower 32 bits of the 93th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address92_low(&self) -> &GmacgrpMacAddress92Low {
        &self.gmacgrp_mac_address92_low
    }
    #[doc = "0xa68 - The MAC Address93 High register holds the upper 16 bits of the 94th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address93 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address93_high(&self) -> &GmacgrpMacAddress93High {
        &self.gmacgrp_mac_address93_high
    }
    #[doc = "0xa6c - The MAC Address93 Low register holds the lower 32 bits of the 94th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address93_low(&self) -> &GmacgrpMacAddress93Low {
        &self.gmacgrp_mac_address93_low
    }
    #[doc = "0xa70 - The MAC Address94 High register holds the upper 16 bits of the 95th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address94 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address94_high(&self) -> &GmacgrpMacAddress94High {
        &self.gmacgrp_mac_address94_high
    }
    #[doc = "0xa74 - The MAC Address94 Low register holds the lower 32 bits of the 95th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address94_low(&self) -> &GmacgrpMacAddress94Low {
        &self.gmacgrp_mac_address94_low
    }
    #[doc = "0xa78 - The MAC Address95 High register holds the upper 16 bits of the 96th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address95 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address95_high(&self) -> &GmacgrpMacAddress95High {
        &self.gmacgrp_mac_address95_high
    }
    #[doc = "0xa7c - The MAC Address95 Low register holds the lower 32 bits of the 96th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address95_low(&self) -> &GmacgrpMacAddress95Low {
        &self.gmacgrp_mac_address95_low
    }
    #[doc = "0xa80 - The MAC Address96 High register holds the upper 16 bits of the 97th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address96 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address96_high(&self) -> &GmacgrpMacAddress96High {
        &self.gmacgrp_mac_address96_high
    }
    #[doc = "0xa84 - The MAC Address96 Low register holds the lower 32 bits of the 97th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address96_low(&self) -> &GmacgrpMacAddress96Low {
        &self.gmacgrp_mac_address96_low
    }
    #[doc = "0xa88 - The MAC Address97 High register holds the upper 16 bits of the 98th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address97 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address97_high(&self) -> &GmacgrpMacAddress97High {
        &self.gmacgrp_mac_address97_high
    }
    #[doc = "0xa8c - The MAC Address97 Low register holds the lower 32 bits of the 98th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address97_low(&self) -> &GmacgrpMacAddress97Low {
        &self.gmacgrp_mac_address97_low
    }
    #[doc = "0xa90 - The MAC Address98 High register holds the upper 16 bits of the 99th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address98 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address98_high(&self) -> &GmacgrpMacAddress98High {
        &self.gmacgrp_mac_address98_high
    }
    #[doc = "0xa94 - The MAC Address98 Low register holds the lower 32 bits of the 99th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address98_low(&self) -> &GmacgrpMacAddress98Low {
        &self.gmacgrp_mac_address98_low
    }
    #[doc = "0xa98 - The MAC Address99 High register holds the upper 16 bits of the 100th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address99 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address99_high(&self) -> &GmacgrpMacAddress99High {
        &self.gmacgrp_mac_address99_high
    }
    #[doc = "0xa9c - The MAC Address99 Low register holds the lower 32 bits of the 100th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address99_low(&self) -> &GmacgrpMacAddress99Low {
        &self.gmacgrp_mac_address99_low
    }
    #[doc = "0xaa0 - The MAC Address100 High register holds the upper 16 bits of the 101th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address100 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address100_high(&self) -> &GmacgrpMacAddress100High {
        &self.gmacgrp_mac_address100_high
    }
    #[doc = "0xaa4 - The MAC Address100 Low register holds the lower 32 bits of the 101th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address100_low(&self) -> &GmacgrpMacAddress100Low {
        &self.gmacgrp_mac_address100_low
    }
    #[doc = "0xaa8 - The MAC Address101 High register holds the upper 16 bits of the 102th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address101 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address101_high(&self) -> &GmacgrpMacAddress101High {
        &self.gmacgrp_mac_address101_high
    }
    #[doc = "0xaac - The MAC Address101 Low register holds the lower 32 bits of the 102th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address101_low(&self) -> &GmacgrpMacAddress101Low {
        &self.gmacgrp_mac_address101_low
    }
    #[doc = "0xab0 - The MAC Address102 High register holds the upper 16 bits of the 103th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address102 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address102_high(&self) -> &GmacgrpMacAddress102High {
        &self.gmacgrp_mac_address102_high
    }
    #[doc = "0xab4 - The MAC Address102 Low register holds the lower 32 bits of the 103th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address102_low(&self) -> &GmacgrpMacAddress102Low {
        &self.gmacgrp_mac_address102_low
    }
    #[doc = "0xab8 - The MAC Address103 High register holds the upper 16 bits of the 104th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address103 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address103_high(&self) -> &GmacgrpMacAddress103High {
        &self.gmacgrp_mac_address103_high
    }
    #[doc = "0xabc - The MAC Address103 Low register holds the lower 32 bits of the 104th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address103_low(&self) -> &GmacgrpMacAddress103Low {
        &self.gmacgrp_mac_address103_low
    }
    #[doc = "0xac0 - The MAC Address104 High register holds the upper 16 bits of the 105th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address104 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address104_high(&self) -> &GmacgrpMacAddress104High {
        &self.gmacgrp_mac_address104_high
    }
    #[doc = "0xac4 - The MAC Address104 Low register holds the lower 32 bits of the 105th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address104_low(&self) -> &GmacgrpMacAddress104Low {
        &self.gmacgrp_mac_address104_low
    }
    #[doc = "0xac8 - The MAC Address105 High register holds the upper 16 bits of the 106th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address105 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address105_high(&self) -> &GmacgrpMacAddress105High {
        &self.gmacgrp_mac_address105_high
    }
    #[doc = "0xacc - The MAC Address105 Low register holds the lower 32 bits of the 106th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address105_low(&self) -> &GmacgrpMacAddress105Low {
        &self.gmacgrp_mac_address105_low
    }
    #[doc = "0xad0 - The MAC Address106 High register holds the upper 16 bits of the 107th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address106 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address106_high(&self) -> &GmacgrpMacAddress106High {
        &self.gmacgrp_mac_address106_high
    }
    #[doc = "0xad4 - The MAC Address106 Low register holds the lower 32 bits of the 107th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address106_low(&self) -> &GmacgrpMacAddress106Low {
        &self.gmacgrp_mac_address106_low
    }
    #[doc = "0xad8 - The MAC Address107 High register holds the upper 16 bits of the 108th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address107 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address107_high(&self) -> &GmacgrpMacAddress107High {
        &self.gmacgrp_mac_address107_high
    }
    #[doc = "0xadc - The MAC Address107 Low register holds the lower 32 bits of the 108th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address107_low(&self) -> &GmacgrpMacAddress107Low {
        &self.gmacgrp_mac_address107_low
    }
    #[doc = "0xae0 - The MAC Address108 High register holds the upper 16 bits of the 109th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address108 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address108_high(&self) -> &GmacgrpMacAddress108High {
        &self.gmacgrp_mac_address108_high
    }
    #[doc = "0xae4 - The MAC Address108 Low register holds the lower 32 bits of the 109th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address108_low(&self) -> &GmacgrpMacAddress108Low {
        &self.gmacgrp_mac_address108_low
    }
    #[doc = "0xae8 - The MAC Address109 High register holds the upper 16 bits of the 110th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address109 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address109_high(&self) -> &GmacgrpMacAddress109High {
        &self.gmacgrp_mac_address109_high
    }
    #[doc = "0xaec - The MAC Address109 Low register holds the lower 32 bits of the 110th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address109_low(&self) -> &GmacgrpMacAddress109Low {
        &self.gmacgrp_mac_address109_low
    }
    #[doc = "0xaf0 - The MAC Address110 High register holds the upper 16 bits of the 111th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address110 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address110_high(&self) -> &GmacgrpMacAddress110High {
        &self.gmacgrp_mac_address110_high
    }
    #[doc = "0xaf4 - The MAC Address110 Low register holds the lower 32 bits of the 111th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address110_low(&self) -> &GmacgrpMacAddress110Low {
        &self.gmacgrp_mac_address110_low
    }
    #[doc = "0xaf8 - The MAC Address111 High register holds the upper 16 bits of the 112th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address111 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address111_high(&self) -> &GmacgrpMacAddress111High {
        &self.gmacgrp_mac_address111_high
    }
    #[doc = "0xafc - The MAC Address111 Low register holds the lower 32 bits of the 112th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address111_low(&self) -> &GmacgrpMacAddress111Low {
        &self.gmacgrp_mac_address111_low
    }
    #[doc = "0xb00 - The MAC Address112 High register holds the upper 16 bits of the 113th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address112 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address112_high(&self) -> &GmacgrpMacAddress112High {
        &self.gmacgrp_mac_address112_high
    }
    #[doc = "0xb04 - The MAC Address112 Low register holds the lower 32 bits of the 113th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address112_low(&self) -> &GmacgrpMacAddress112Low {
        &self.gmacgrp_mac_address112_low
    }
    #[doc = "0xb08 - The MAC Address113 High register holds the upper 16 bits of the 114th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address113 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address113_high(&self) -> &GmacgrpMacAddress113High {
        &self.gmacgrp_mac_address113_high
    }
    #[doc = "0xb0c - The MAC Address113 Low register holds the lower 32 bits of the 114th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address113_low(&self) -> &GmacgrpMacAddress113Low {
        &self.gmacgrp_mac_address113_low
    }
    #[doc = "0xb10 - The MAC Address114 High register holds the upper 16 bits of the 115th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address114 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address114_high(&self) -> &GmacgrpMacAddress114High {
        &self.gmacgrp_mac_address114_high
    }
    #[doc = "0xb14 - The MAC Address114 Low register holds the lower 32 bits of the 115th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address114_low(&self) -> &GmacgrpMacAddress114Low {
        &self.gmacgrp_mac_address114_low
    }
    #[doc = "0xb18 - The MAC Address115 High register holds the upper 16 bits of the 116th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address115 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address115_high(&self) -> &GmacgrpMacAddress115High {
        &self.gmacgrp_mac_address115_high
    }
    #[doc = "0xb1c - The MAC Address115 Low register holds the lower 32 bits of the 116th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address115_low(&self) -> &GmacgrpMacAddress115Low {
        &self.gmacgrp_mac_address115_low
    }
    #[doc = "0xb20 - The MAC Address116 High register holds the upper 16 bits of the 117th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address116 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address116_high(&self) -> &GmacgrpMacAddress116High {
        &self.gmacgrp_mac_address116_high
    }
    #[doc = "0xb24 - The MAC Address116 Low register holds the lower 32 bits of the 117th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address116_low(&self) -> &GmacgrpMacAddress116Low {
        &self.gmacgrp_mac_address116_low
    }
    #[doc = "0xb28 - The MAC Address117 High register holds the upper 16 bits of the 118th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address117 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address117_high(&self) -> &GmacgrpMacAddress117High {
        &self.gmacgrp_mac_address117_high
    }
    #[doc = "0xb2c - The MAC Address117 Low register holds the lower 32 bits of the 118th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address117_low(&self) -> &GmacgrpMacAddress117Low {
        &self.gmacgrp_mac_address117_low
    }
    #[doc = "0xb30 - The MAC Address118 High register holds the upper 16 bits of the 119th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address118 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address118_high(&self) -> &GmacgrpMacAddress118High {
        &self.gmacgrp_mac_address118_high
    }
    #[doc = "0xb34 - The MAC Address118 Low register holds the lower 32 bits of the 119th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address118_low(&self) -> &GmacgrpMacAddress118Low {
        &self.gmacgrp_mac_address118_low
    }
    #[doc = "0xb38 - The MAC Address119 High register holds the upper 16 bits of the 120th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address119 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address119_high(&self) -> &GmacgrpMacAddress119High {
        &self.gmacgrp_mac_address119_high
    }
    #[doc = "0xb3c - The MAC Address119 Low register holds the lower 32 bits of the 120th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address119_low(&self) -> &GmacgrpMacAddress119Low {
        &self.gmacgrp_mac_address119_low
    }
    #[doc = "0xb40 - The MAC Address120 High register holds the upper 16 bits of the 121th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address120 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address120_high(&self) -> &GmacgrpMacAddress120High {
        &self.gmacgrp_mac_address120_high
    }
    #[doc = "0xb44 - The MAC Address120 Low register holds the lower 32 bits of the 121th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address120_low(&self) -> &GmacgrpMacAddress120Low {
        &self.gmacgrp_mac_address120_low
    }
    #[doc = "0xb48 - The MAC Address121 High register holds the upper 16 bits of the 122th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address121 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address121_high(&self) -> &GmacgrpMacAddress121High {
        &self.gmacgrp_mac_address121_high
    }
    #[doc = "0xb4c - The MAC Address121 Low register holds the lower 32 bits of the 122th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address121_low(&self) -> &GmacgrpMacAddress121Low {
        &self.gmacgrp_mac_address121_low
    }
    #[doc = "0xb50 - The MAC Address122 High register holds the upper 16 bits of the 123th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address122 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address122_high(&self) -> &GmacgrpMacAddress122High {
        &self.gmacgrp_mac_address122_high
    }
    #[doc = "0xb54 - The MAC Address122 Low register holds the lower 32 bits of the 123th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address122_low(&self) -> &GmacgrpMacAddress122Low {
        &self.gmacgrp_mac_address122_low
    }
    #[doc = "0xb58 - The MAC Address123 High register holds the upper 16 bits of the 124th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address123 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address123_high(&self) -> &GmacgrpMacAddress123High {
        &self.gmacgrp_mac_address123_high
    }
    #[doc = "0xb5c - The MAC Address123 Low register holds the lower 32 bits of the 124th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address123_low(&self) -> &GmacgrpMacAddress123Low {
        &self.gmacgrp_mac_address123_low
    }
    #[doc = "0xb60 - The MAC Address124 High register holds the upper 16 bits of the 125th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address124 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address124_high(&self) -> &GmacgrpMacAddress124High {
        &self.gmacgrp_mac_address124_high
    }
    #[doc = "0xb64 - The MAC Address124 Low register holds the lower 32 bits of the 125th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address124_low(&self) -> &GmacgrpMacAddress124Low {
        &self.gmacgrp_mac_address124_low
    }
    #[doc = "0xb68 - The MAC Address125 High register holds the upper 16 bits of the 126th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address125 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address125_high(&self) -> &GmacgrpMacAddress125High {
        &self.gmacgrp_mac_address125_high
    }
    #[doc = "0xb6c - The MAC Address125 Low register holds the lower 32 bits of the 126th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address125_low(&self) -> &GmacgrpMacAddress125Low {
        &self.gmacgrp_mac_address125_low
    }
    #[doc = "0xb70 - The MAC Address126 High register holds the upper 16 bits of the 127th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address126 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address126_high(&self) -> &GmacgrpMacAddress126High {
        &self.gmacgrp_mac_address126_high
    }
    #[doc = "0xb74 - The MAC Address126 Low register holds the lower 32 bits of the 127th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address126_low(&self) -> &GmacgrpMacAddress126Low {
        &self.gmacgrp_mac_address126_low
    }
    #[doc = "0xb78 - The MAC Address127 High register holds the upper 16 bits of the 128th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address127 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address127_high(&self) -> &GmacgrpMacAddress127High {
        &self.gmacgrp_mac_address127_high
    }
    #[doc = "0xb7c - The MAC Address127 Low register holds the lower 32 bits of the 128th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
    #[inline(always)]
    pub const fn gmacgrp_mac_address127_low(&self) -> &GmacgrpMacAddress127Low {
        &self.gmacgrp_mac_address127_low
    }
    #[doc = "0x1000 - The Bus Mode register establishes the bus operating modes for the DMA."]
    #[inline(always)]
    pub const fn dmagrp_bus_mode(&self) -> &DmagrpBusMode {
        &self.dmagrp_bus_mode
    }
    #[doc = "0x1004 - The Transmit Poll Demand register enables the Tx DMA to check whether or not the DMA owns the current descriptor. The Transmit Poll Demand command is given to wake up the Tx DMA if it is in the Suspend mode. The Tx DMA can go into the Suspend mode because of an Underflow error in a transmitted frame or the unavailability of descriptors owned by it. You can give this command anytime and the Tx DMA resets this command when it again starts fetching the current descriptor from host memory."]
    #[inline(always)]
    pub const fn dmagrp_transmit_poll_demand(&self) -> &DmagrpTransmitPollDemand {
        &self.dmagrp_transmit_poll_demand
    }
    #[doc = "0x1008 - The Receive Poll Demand register enables the receive DMA to check for new descriptors. This command is used to wake up the Rx DMA from the SUSPEND state. The RxDMA can go into the SUSPEND state only because of the unavailability of descriptors it owns."]
    #[inline(always)]
    pub const fn dmagrp_receive_poll_demand(&self) -> &DmagrpReceivePollDemand {
        &self.dmagrp_receive_poll_demand
    }
    #[doc = "0x100c - The Receive Descriptor List Address register points to the start of the Receive Descriptor List. The descriptor lists reside in the host's physical memory space and must be Word, Dword, or Lword-aligned (for 32-bit, 64-bit, or 128-bit data bus). The DMA internally converts it to bus width aligned address by making the corresponding LS bits low. Writing to this register is permitted only when reception is stopped. When stopped, this register must be written to before the receive Start command is given. You can write to this register only when Rx DMA has stopped, that is, Bit 1 (SR) is set to zero in Register 6 (Operation Mode Register). When stopped, this register can be written with a new descriptor list address. When you set the SR bit to 1, the DMA takes the newly programmed descriptor base address. If this register is not changed when the SR bit is set to 0, then the DMA takes the descriptor address where it was stopped earlier."]
    #[inline(always)]
    pub const fn dmagrp_receive_descriptor_list_address(
        &self,
    ) -> &DmagrpReceiveDescriptorListAddress {
        &self.dmagrp_receive_descriptor_list_address
    }
    #[doc = "0x1010 - The Transmit Descriptor List Address register points to the start of the Transmit Descriptor List. The descriptor lists reside in the host's physical memory space and must be Word, Dword, or Lword-aligned (for 32-bit, 64-bit, or 128-bit data bus). The DMA internally converts it to bus width aligned address by making the corresponding LSB to low. You can write to this register only when the Tx DMA has stopped, that is, Bit 13 (ST) is set to zero in Register 6 (Operation Mode Register). When stopped, this register can be written with a new descriptor list address. When you set the ST bit to 1, the DMA takes the newly programmed descriptor base address. If this register is not changed when the ST bit is set to 0, then the DMA takes the descriptor address where it was stopped earlier."]
    #[inline(always)]
    pub const fn dmagrp_transmit_descriptor_list_address(
        &self,
    ) -> &DmagrpTransmitDescriptorListAddress {
        &self.dmagrp_transmit_descriptor_list_address
    }
    #[doc = "0x1014 - The Status register contains all status bits that the DMA reports to the host. The software driver reads this register during an interrupt service routine or polling. Most of the fields in this register cause the host to be interrupted. The bits of this register are not cleared when read. Writing 1'b1 to (unreserved) Bits\\[16:0\\]
of this register clears these bits and writing 1'b0 has no effect. Each field (Bits\\[16:0\\]) can be masked by masking the appropriate bit in Register 7 (Interrupt Enable Register)."]
    #[inline(always)]
    pub const fn dmagrp_status(&self) -> &DmagrpStatus {
        &self.dmagrp_status
    }
    #[doc = "0x1018 - The Operation Mode register establishes the Transmit and Receive operating modes and commands. This register should be the last CSR to be written as part of the DMA initialization."]
    #[inline(always)]
    pub const fn dmagrp_operation_mode(&self) -> &DmagrpOperationMode {
        &self.dmagrp_operation_mode
    }
    #[doc = "0x101c - The Interrupt Enable register enables the interrupts reported by Register 5 (Status Register). Setting a bit to 1'b1 enables a corresponding interrupt. After a hardware or software reset, all interrupts are disabled."]
    #[inline(always)]
    pub const fn dmagrp_interrupt_enable(&self) -> &DmagrpInterruptEnable {
        &self.dmagrp_interrupt_enable
    }
    #[doc = "0x1020 - The DMA maintains two counters to track the number of frames missed during reception. This register reports the current value of the counter. The counter is used for diagnostic purposes. Bits\\[15:0\\]
indicate missed frames because of the host buffer being unavailable. Bits\\[27:17\\]
indicate missed frames because of buffer overflow conditions (MTL and MAC) and runt frames (good frames of less than 64 bytes) dropped by the MTL."]
    #[inline(always)]
    pub const fn dmagrp_missed_frame_and_buffer_overflow_counter(
        &self,
    ) -> &DmagrpMissedFrameAndBufferOverflowCounter {
        &self.dmagrp_missed_frame_and_buffer_overflow_counter
    }
    #[doc = "0x1024 - This register, when written with non-zero value, enables the watchdog timer for the Receive Interrupt (Bit 6) of Register 5 (Status Register)"]
    #[inline(always)]
    pub const fn dmagrp_receive_interrupt_watchdog_timer(
        &self,
    ) -> &DmagrpReceiveInterruptWatchdogTimer {
        &self.dmagrp_receive_interrupt_watchdog_timer
    }
    #[doc = "0x1028 - The AXI Bus Mode Register controls the behavior of the AXI master. It is mainly used to control the burst splitting and the number of outstanding requests."]
    #[inline(always)]
    pub const fn dmagrp_axi_bus_mode(&self) -> &DmagrpAxiBusMode {
        &self.dmagrp_axi_bus_mode
    }
    #[doc = "0x102c - This register provides the active status of the AXI interface's read and write channels. This register is useful for debugging purposes. In addition, this register is valid only in the Channel 0 DMA when multiple channels are present in the AV mode."]
    #[inline(always)]
    pub const fn dmagrp_ahb_or_axi_status(&self) -> &DmagrpAhbOrAxiStatus {
        &self.dmagrp_ahb_or_axi_status
    }
    #[doc = "0x1048 - The Current Host Transmit Descriptor register points to the start address of the current Transmit Descriptor read by the DMA."]
    #[inline(always)]
    pub const fn dmagrp_current_host_transmit_descriptor(
        &self,
    ) -> &DmagrpCurrentHostTransmitDescriptor {
        &self.dmagrp_current_host_transmit_descriptor
    }
    #[doc = "0x104c - The Current Host Receive Descriptor register points to the start address of the current Receive Descriptor read by the DMA."]
    #[inline(always)]
    pub const fn dmagrp_current_host_receive_descriptor(
        &self,
    ) -> &DmagrpCurrentHostReceiveDescriptor {
        &self.dmagrp_current_host_receive_descriptor
    }
    #[doc = "0x1050 - The Current Host Transmit Buffer Address register points to the current Transmit Buffer Address being read by the DMA."]
    #[inline(always)]
    pub const fn dmagrp_current_host_transmit_buffer_address(
        &self,
    ) -> &DmagrpCurrentHostTransmitBufferAddress {
        &self.dmagrp_current_host_transmit_buffer_address
    }
    #[doc = "0x1054 - The Current Host Receive Buffer Address register points to the current Receive Buffer address being read by the DMA."]
    #[inline(always)]
    pub const fn dmagrp_current_host_receive_buffer_address(
        &self,
    ) -> &DmagrpCurrentHostReceiveBufferAddress {
        &self.dmagrp_current_host_receive_buffer_address
    }
    #[doc = "0x1058 - This register indicates the presence of the optional features or functions of the gmac. The software driver can use this register to dynamically enable or disable the programs related to the optional blocks."]
    #[inline(always)]
    pub const fn dmagrp_hw_feature(&self) -> &DmagrpHwFeature {
        &self.dmagrp_hw_feature
    }
}
#[doc = "gmacgrp_MAC_Configuration (rw) register accessor: The MAC Configuration register establishes receive and transmit operating modes.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_configuration::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_configuration::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_configuration`]
module"]
#[doc(alias = "gmacgrp_MAC_Configuration")]
pub type GmacgrpMacConfiguration =
    crate::Reg<gmacgrp_mac_configuration::GmacgrpMacConfigurationSpec>;
#[doc = "The MAC Configuration register establishes receive and transmit operating modes."]
pub mod gmacgrp_mac_configuration;
#[doc = "gmacgrp_MAC_Frame_Filter (rw) register accessor: The MAC Frame Filter register contains the filter controls for receiving frames. Some of the controls from this register go to the address check block of the MAC, which performs the first level of address filtering. The second level of filtering is performed on the incoming frame, based on other controls such as Pass Bad Frames and Pass Control Frames.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_frame_filter::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_frame_filter::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_frame_filter`]
module"]
#[doc(alias = "gmacgrp_MAC_Frame_Filter")]
pub type GmacgrpMacFrameFilter = crate::Reg<gmacgrp_mac_frame_filter::GmacgrpMacFrameFilterSpec>;
#[doc = "The MAC Frame Filter register contains the filter controls for receiving frames. Some of the controls from this register go to the address check block of the MAC, which performs the first level of address filtering. The second level of filtering is performed on the incoming frame, based on other controls such as Pass Bad Frames and Pass Control Frames."]
pub mod gmacgrp_mac_frame_filter;
#[doc = "gmacgrp_GMII_Address (rw) register accessor: The GMII Address register controls the management cycles to the external PHY through the management interface.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_gmii_address::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_gmii_address::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_gmii_address`]
module"]
#[doc(alias = "gmacgrp_GMII_Address")]
pub type GmacgrpGmiiAddress = crate::Reg<gmacgrp_gmii_address::GmacgrpGmiiAddressSpec>;
#[doc = "The GMII Address register controls the management cycles to the external PHY through the management interface."]
pub mod gmacgrp_gmii_address;
#[doc = "gmacgrp_GMII_Data (rw) register accessor: The GMII Data register stores Write data to be written to the PHY register located at the address specified in Register 4 (GMII Address Register). This register also stores the Read data from the PHY register located at the address specified by Register 4.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_gmii_data::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_gmii_data::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_gmii_data`]
module"]
#[doc(alias = "gmacgrp_GMII_Data")]
pub type GmacgrpGmiiData = crate::Reg<gmacgrp_gmii_data::GmacgrpGmiiDataSpec>;
#[doc = "The GMII Data register stores Write data to be written to the PHY register located at the address specified in Register 4 (GMII Address Register). This register also stores the Read data from the PHY register located at the address specified by Register 4."]
pub mod gmacgrp_gmii_data;
#[doc = "gmacgrp_Flow_Control (rw) register accessor: The Flow Control register controls the generation and reception of the Control (Pause Command) frames by the MAC's Flow control block. A Write to a register with the Busy bit set to '1' triggers the Flow Control block to generate a Pause Control frame. The fields of the control frame are selected as specified in the 802.3x specification, and the Pause Time value from this register is used in the Pause Time field of the control frame. The Busy bit remains set until the control frame is transferred onto the cable. The Host must make sure that the Busy bit is cleared before writing to the register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_flow_control::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_flow_control::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_flow_control`]
module"]
#[doc(alias = "gmacgrp_Flow_Control")]
pub type GmacgrpFlowControl = crate::Reg<gmacgrp_flow_control::GmacgrpFlowControlSpec>;
#[doc = "The Flow Control register controls the generation and reception of the Control (Pause Command) frames by the MAC's Flow control block. A Write to a register with the Busy bit set to '1' triggers the Flow Control block to generate a Pause Control frame. The fields of the control frame are selected as specified in the 802.3x specification, and the Pause Time value from this register is used in the Pause Time field of the control frame. The Busy bit remains set until the control frame is transferred onto the cable. The Host must make sure that the Busy bit is cleared before writing to the register."]
pub mod gmacgrp_flow_control;
#[doc = "gmacgrp_VLAN_Tag (rw) register accessor: The VLAN Tag register contains the IEEE 802.1Q VLAN Tag to identify the VLAN frames. The MAC compares the 13th and 14th bytes of the receiving frame (Length/Type) with 16'h8100, and the following two bytes are compared with the VLAN tag. If a match occurs, the MAC sets the received VLAN bit in the receive frame status. The legal length of the frame is increased from 1,518 bytes to 1,522 bytes. Because the VLAN Tag register is double-synchronized to the (G)MII clock domain, then consecutive writes to these register should be performed only after at least four clock cycles in the destination clock domain.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_vlan_tag::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_vlan_tag::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_vlan_tag`]
module"]
#[doc(alias = "gmacgrp_VLAN_Tag")]
pub type GmacgrpVlanTag = crate::Reg<gmacgrp_vlan_tag::GmacgrpVlanTagSpec>;
#[doc = "The VLAN Tag register contains the IEEE 802.1Q VLAN Tag to identify the VLAN frames. The MAC compares the 13th and 14th bytes of the receiving frame (Length/Type) with 16'h8100, and the following two bytes are compared with the VLAN tag. If a match occurs, the MAC sets the received VLAN bit in the receive frame status. The legal length of the frame is increased from 1,518 bytes to 1,522 bytes. Because the VLAN Tag register is double-synchronized to the (G)MII clock domain, then consecutive writes to these register should be performed only after at least four clock cycles in the destination clock domain."]
pub mod gmacgrp_vlan_tag;
#[doc = "gmacgrp_Version (r) register accessor: The Version registers identifies the version of the EMAC. This register contains two bytes: one specified by Synopsys to identify the core release number, and the other specified by Altera.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_version::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_version`]
module"]
#[doc(alias = "gmacgrp_Version")]
pub type GmacgrpVersion = crate::Reg<gmacgrp_version::GmacgrpVersionSpec>;
#[doc = "The Version registers identifies the version of the EMAC. This register contains two bytes: one specified by Synopsys to identify the core release number, and the other specified by Altera."]
pub mod gmacgrp_version;
#[doc = "gmacgrp_Debug (r) register accessor: The Debug register gives the status of all main blocks of the transmit and receive data-paths and the FIFOs. An all-zero status indicates that the MAC is in idle state (and FIFOs are empty) and no activity is going on in the data-paths.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_debug::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_debug`]
module"]
#[doc(alias = "gmacgrp_Debug")]
pub type GmacgrpDebug = crate::Reg<gmacgrp_debug::GmacgrpDebugSpec>;
#[doc = "The Debug register gives the status of all main blocks of the transmit and receive data-paths and the FIFOs. An all-zero status indicates that the MAC is in idle state (and FIFOs are empty) and no activity is going on in the data-paths."]
pub mod gmacgrp_debug;
#[doc = "gmacgrp_LPI_Control_Status (rw) register accessor: The LPI Control and Status Register controls the LPI functions and provides the LPI interrupt status. The status bits are cleared when this register is read.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_lpi_control_status::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_lpi_control_status::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_lpi_control_status`]
module"]
#[doc(alias = "gmacgrp_LPI_Control_Status")]
pub type GmacgrpLpiControlStatus =
    crate::Reg<gmacgrp_lpi_control_status::GmacgrpLpiControlStatusSpec>;
#[doc = "The LPI Control and Status Register controls the LPI functions and provides the LPI interrupt status. The status bits are cleared when this register is read."]
pub mod gmacgrp_lpi_control_status;
#[doc = "gmacgrp_LPI_Timers_Control (rw) register accessor: The LPI Timers Control register controls the timeout values in the LPI states. It specifies the time for which the MAC transmits the LPI pattern and also the time for which the MAC waits before resuming the normal transmission.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_lpi_timers_control::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_lpi_timers_control::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_lpi_timers_control`]
module"]
#[doc(alias = "gmacgrp_LPI_Timers_Control")]
pub type GmacgrpLpiTimersControl =
    crate::Reg<gmacgrp_lpi_timers_control::GmacgrpLpiTimersControlSpec>;
#[doc = "The LPI Timers Control register controls the timeout values in the LPI states. It specifies the time for which the MAC transmits the LPI pattern and also the time for which the MAC waits before resuming the normal transmission."]
pub mod gmacgrp_lpi_timers_control;
#[doc = "gmacgrp_Interrupt_Status (r) register accessor: The Interrupt Status register identifies the events in the MAC that can generate interrupt. All interrupt events are generated only when the corresponding optional feature is enabled.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_interrupt_status::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_interrupt_status`]
module"]
#[doc(alias = "gmacgrp_Interrupt_Status")]
pub type GmacgrpInterruptStatus = crate::Reg<gmacgrp_interrupt_status::GmacgrpInterruptStatusSpec>;
#[doc = "The Interrupt Status register identifies the events in the MAC that can generate interrupt. All interrupt events are generated only when the corresponding optional feature is enabled."]
pub mod gmacgrp_interrupt_status;
#[doc = "gmacgrp_Interrupt_Mask (rw) register accessor: The Interrupt Mask Register bits enable you to mask the interrupt signal because of the corresponding event in the Interrupt Status Register. The interrupt signal is sbd_intr_o.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_interrupt_mask::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_interrupt_mask::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_interrupt_mask`]
module"]
#[doc(alias = "gmacgrp_Interrupt_Mask")]
pub type GmacgrpInterruptMask = crate::Reg<gmacgrp_interrupt_mask::GmacgrpInterruptMaskSpec>;
#[doc = "The Interrupt Mask Register bits enable you to mask the interrupt signal because of the corresponding event in the Interrupt Status Register. The interrupt signal is sbd_intr_o."]
pub mod gmacgrp_interrupt_mask;
#[doc = "gmacgrp_MAC_Address0_High (rw) register accessor: The MAC Address0 High register holds the upper 16 bits of the first 6-byte MAC address of the station. The first DA byte that is received on the (G)MII interface corresponds to the LS byte (Bits \\[7:0\\]) of the MAC Address Low register. For example, if 0x112233445566 is received (0x11 in lane 0 of the first column) on the (G)MII as the destination address, then the MacAddress0 Register \\[47:0\\]
is compared with 0x665544332211. Because the MAC address registers are double-synchronized to the (G)MII clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address0 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address0_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address0_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address0_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address0_High")]
pub type GmacgrpMacAddress0High = crate::Reg<gmacgrp_mac_address0_high::GmacgrpMacAddress0HighSpec>;
#[doc = "The MAC Address0 High register holds the upper 16 bits of the first 6-byte MAC address of the station. The first DA byte that is received on the (G)MII interface corresponds to the LS byte (Bits \\[7:0\\]) of the MAC Address Low register. For example, if 0x112233445566 is received (0x11 in lane 0 of the first column) on the (G)MII as the destination address, then the MacAddress0 Register \\[47:0\\]
is compared with 0x665544332211. Because the MAC address registers are double-synchronized to the (G)MII clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address0 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain."]
pub mod gmacgrp_mac_address0_high;
#[doc = "gmacgrp_MAC_Address0_Low (rw) register accessor: The MAC Address0 Low register holds the lower 32 bits of the first 6-byte MAC address of the station.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address0_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address0_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address0_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address0_Low")]
pub type GmacgrpMacAddress0Low = crate::Reg<gmacgrp_mac_address0_low::GmacgrpMacAddress0LowSpec>;
#[doc = "The MAC Address0 Low register holds the lower 32 bits of the first 6-byte MAC address of the station."]
pub mod gmacgrp_mac_address0_low;
#[doc = "gmacgrp_MAC_Address1_High (rw) register accessor: The MAC Address1 High register holds the upper 16 bits of the 2nd 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address1 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address1_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address1_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address1_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address1_High")]
pub type GmacgrpMacAddress1High = crate::Reg<gmacgrp_mac_address1_high::GmacgrpMacAddress1HighSpec>;
#[doc = "The MAC Address1 High register holds the upper 16 bits of the 2nd 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address1 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address1_high;
#[doc = "gmacgrp_MAC_Address1_Low (rw) register accessor: The MAC Address1 Low register holds the lower 32 bits of the 2nd 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address1_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address1_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address1_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address1_Low")]
pub type GmacgrpMacAddress1Low = crate::Reg<gmacgrp_mac_address1_low::GmacgrpMacAddress1LowSpec>;
#[doc = "The MAC Address1 Low register holds the lower 32 bits of the 2nd 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address1_low;
#[doc = "gmacgrp_MAC_Address2_High (rw) register accessor: The MAC Address2 High register holds the upper 16 bits of the 3rd 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address2 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address2_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address2_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address2_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address2_High")]
pub type GmacgrpMacAddress2High = crate::Reg<gmacgrp_mac_address2_high::GmacgrpMacAddress2HighSpec>;
#[doc = "The MAC Address2 High register holds the upper 16 bits of the 3rd 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address2 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address2_high;
#[doc = "gmacgrp_MAC_Address2_Low (rw) register accessor: The MAC Address2 Low register holds the lower 32 bits of the 3rd 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address2_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address2_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address2_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address2_Low")]
pub type GmacgrpMacAddress2Low = crate::Reg<gmacgrp_mac_address2_low::GmacgrpMacAddress2LowSpec>;
#[doc = "The MAC Address2 Low register holds the lower 32 bits of the 3rd 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address2_low;
#[doc = "gmacgrp_MAC_Address3_High (rw) register accessor: The MAC Address3 High register holds the upper 16 bits of the 4th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address3 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address3_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address3_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address3_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address3_High")]
pub type GmacgrpMacAddress3High = crate::Reg<gmacgrp_mac_address3_high::GmacgrpMacAddress3HighSpec>;
#[doc = "The MAC Address3 High register holds the upper 16 bits of the 4th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address3 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address3_high;
#[doc = "gmacgrp_MAC_Address3_Low (rw) register accessor: The MAC Address3 Low register holds the lower 32 bits of the 4th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address3_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address3_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address3_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address3_Low")]
pub type GmacgrpMacAddress3Low = crate::Reg<gmacgrp_mac_address3_low::GmacgrpMacAddress3LowSpec>;
#[doc = "The MAC Address3 Low register holds the lower 32 bits of the 4th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address3_low;
#[doc = "gmacgrp_MAC_Address4_High (rw) register accessor: The MAC Address4 High register holds the upper 16 bits of the 5th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address4 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address4_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address4_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address4_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address4_High")]
pub type GmacgrpMacAddress4High = crate::Reg<gmacgrp_mac_address4_high::GmacgrpMacAddress4HighSpec>;
#[doc = "The MAC Address4 High register holds the upper 16 bits of the 5th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address4 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address4_high;
#[doc = "gmacgrp_MAC_Address4_Low (rw) register accessor: The MAC Address4 Low register holds the lower 32 bits of the 5th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address4_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address4_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address4_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address4_Low")]
pub type GmacgrpMacAddress4Low = crate::Reg<gmacgrp_mac_address4_low::GmacgrpMacAddress4LowSpec>;
#[doc = "The MAC Address4 Low register holds the lower 32 bits of the 5th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address4_low;
#[doc = "gmacgrp_MAC_Address5_High (rw) register accessor: The MAC Address5 High register holds the upper 16 bits of the 6th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address5 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address5_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address5_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address5_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address5_High")]
pub type GmacgrpMacAddress5High = crate::Reg<gmacgrp_mac_address5_high::GmacgrpMacAddress5HighSpec>;
#[doc = "The MAC Address5 High register holds the upper 16 bits of the 6th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address5 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address5_high;
#[doc = "gmacgrp_MAC_Address5_Low (rw) register accessor: The MAC Address5 Low register holds the lower 32 bits of the 6th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address5_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address5_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address5_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address5_Low")]
pub type GmacgrpMacAddress5Low = crate::Reg<gmacgrp_mac_address5_low::GmacgrpMacAddress5LowSpec>;
#[doc = "The MAC Address5 Low register holds the lower 32 bits of the 6th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address5_low;
#[doc = "gmacgrp_MAC_Address6_High (rw) register accessor: The MAC Address6 High register holds the upper 16 bits of the 7th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address6 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address6_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address6_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address6_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address6_High")]
pub type GmacgrpMacAddress6High = crate::Reg<gmacgrp_mac_address6_high::GmacgrpMacAddress6HighSpec>;
#[doc = "The MAC Address6 High register holds the upper 16 bits of the 7th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address6 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address6_high;
#[doc = "gmacgrp_MAC_Address6_Low (rw) register accessor: The MAC Address6 Low register holds the lower 32 bits of the 7th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address6_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address6_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address6_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address6_Low")]
pub type GmacgrpMacAddress6Low = crate::Reg<gmacgrp_mac_address6_low::GmacgrpMacAddress6LowSpec>;
#[doc = "The MAC Address6 Low register holds the lower 32 bits of the 7th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address6_low;
#[doc = "gmacgrp_MAC_Address7_High (rw) register accessor: The MAC Address7 High register holds the upper 16 bits of the 8th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address7 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address7_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address7_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address7_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address7_High")]
pub type GmacgrpMacAddress7High = crate::Reg<gmacgrp_mac_address7_high::GmacgrpMacAddress7HighSpec>;
#[doc = "The MAC Address7 High register holds the upper 16 bits of the 8th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address7 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address7_high;
#[doc = "gmacgrp_MAC_Address7_Low (rw) register accessor: The MAC Address7 Low register holds the lower 32 bits of the 8th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address7_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address7_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address7_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address7_Low")]
pub type GmacgrpMacAddress7Low = crate::Reg<gmacgrp_mac_address7_low::GmacgrpMacAddress7LowSpec>;
#[doc = "The MAC Address7 Low register holds the lower 32 bits of the 8th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address7_low;
#[doc = "gmacgrp_MAC_Address8_High (rw) register accessor: The MAC Address8 High register holds the upper 16 bits of the 9th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address8 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address8_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address8_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address8_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address8_High")]
pub type GmacgrpMacAddress8High = crate::Reg<gmacgrp_mac_address8_high::GmacgrpMacAddress8HighSpec>;
#[doc = "The MAC Address8 High register holds the upper 16 bits of the 9th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address8 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address8_high;
#[doc = "gmacgrp_MAC_Address8_Low (rw) register accessor: The MAC Address8 Low register holds the lower 32 bits of the 9th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address8_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address8_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address8_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address8_Low")]
pub type GmacgrpMacAddress8Low = crate::Reg<gmacgrp_mac_address8_low::GmacgrpMacAddress8LowSpec>;
#[doc = "The MAC Address8 Low register holds the lower 32 bits of the 9th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address8_low;
#[doc = "gmacgrp_MAC_Address9_High (rw) register accessor: The MAC Address9 High register holds the upper 16 bits of the 10th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address9 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address9_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address9_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address9_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address9_High")]
pub type GmacgrpMacAddress9High = crate::Reg<gmacgrp_mac_address9_high::GmacgrpMacAddress9HighSpec>;
#[doc = "The MAC Address9 High register holds the upper 16 bits of the 10th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address9 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address9_high;
#[doc = "gmacgrp_MAC_Address9_Low (rw) register accessor: The MAC Address9 Low register holds the lower 32 bits of the 10th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address9_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address9_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address9_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address9_Low")]
pub type GmacgrpMacAddress9Low = crate::Reg<gmacgrp_mac_address9_low::GmacgrpMacAddress9LowSpec>;
#[doc = "The MAC Address9 Low register holds the lower 32 bits of the 10th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address9_low;
#[doc = "gmacgrp_MAC_Address10_High (rw) register accessor: The MAC Address10 High register holds the upper 16 bits of the 11th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address10 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address10_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address10_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address10_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address10_High")]
pub type GmacgrpMacAddress10High =
    crate::Reg<gmacgrp_mac_address10_high::GmacgrpMacAddress10HighSpec>;
#[doc = "The MAC Address10 High register holds the upper 16 bits of the 11th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address10 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address10_high;
#[doc = "gmacgrp_MAC_Address10_Low (rw) register accessor: The MAC Address10 Low register holds the lower 32 bits of the 11th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address10_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address10_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address10_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address10_Low")]
pub type GmacgrpMacAddress10Low = crate::Reg<gmacgrp_mac_address10_low::GmacgrpMacAddress10LowSpec>;
#[doc = "The MAC Address10 Low register holds the lower 32 bits of the 11th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address10_low;
#[doc = "gmacgrp_MAC_Address11_High (rw) register accessor: The MAC Address11 High register holds the upper 16 bits of the 12th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address11 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address11_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address11_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address11_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address11_High")]
pub type GmacgrpMacAddress11High =
    crate::Reg<gmacgrp_mac_address11_high::GmacgrpMacAddress11HighSpec>;
#[doc = "The MAC Address11 High register holds the upper 16 bits of the 12th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address11 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address11_high;
#[doc = "gmacgrp_MAC_Address11_Low (rw) register accessor: The MAC Address11 Low register holds the lower 32 bits of the 12th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address11_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address11_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address11_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address11_Low")]
pub type GmacgrpMacAddress11Low = crate::Reg<gmacgrp_mac_address11_low::GmacgrpMacAddress11LowSpec>;
#[doc = "The MAC Address11 Low register holds the lower 32 bits of the 12th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address11_low;
#[doc = "gmacgrp_MAC_Address12_High (rw) register accessor: The MAC Address12 High register holds the upper 16 bits of the 13th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address12 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address12_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address12_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address12_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address12_High")]
pub type GmacgrpMacAddress12High =
    crate::Reg<gmacgrp_mac_address12_high::GmacgrpMacAddress12HighSpec>;
#[doc = "The MAC Address12 High register holds the upper 16 bits of the 13th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address12 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address12_high;
#[doc = "gmacgrp_MAC_Address12_Low (rw) register accessor: The MAC Address12 Low register holds the lower 32 bits of the 13th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address12_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address12_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address12_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address12_Low")]
pub type GmacgrpMacAddress12Low = crate::Reg<gmacgrp_mac_address12_low::GmacgrpMacAddress12LowSpec>;
#[doc = "The MAC Address12 Low register holds the lower 32 bits of the 13th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address12_low;
#[doc = "gmacgrp_MAC_Address13_High (rw) register accessor: The MAC Address13 High register holds the upper 16 bits of the 14th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address13 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address13_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address13_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address13_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address13_High")]
pub type GmacgrpMacAddress13High =
    crate::Reg<gmacgrp_mac_address13_high::GmacgrpMacAddress13HighSpec>;
#[doc = "The MAC Address13 High register holds the upper 16 bits of the 14th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address13 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address13_high;
#[doc = "gmacgrp_MAC_Address13_Low (rw) register accessor: The MAC Address13 Low register holds the lower 32 bits of the 14th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address13_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address13_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address13_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address13_Low")]
pub type GmacgrpMacAddress13Low = crate::Reg<gmacgrp_mac_address13_low::GmacgrpMacAddress13LowSpec>;
#[doc = "The MAC Address13 Low register holds the lower 32 bits of the 14th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address13_low;
#[doc = "gmacgrp_MAC_Address14_High (rw) register accessor: The MAC Address14 High register holds the upper 16 bits of the 15th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address14 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address14_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address14_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address14_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address14_High")]
pub type GmacgrpMacAddress14High =
    crate::Reg<gmacgrp_mac_address14_high::GmacgrpMacAddress14HighSpec>;
#[doc = "The MAC Address14 High register holds the upper 16 bits of the 15th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address14 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address14_high;
#[doc = "gmacgrp_MAC_Address14_Low (rw) register accessor: The MAC Address14 Low register holds the lower 32 bits of the 15th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address14_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address14_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address14_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address14_Low")]
pub type GmacgrpMacAddress14Low = crate::Reg<gmacgrp_mac_address14_low::GmacgrpMacAddress14LowSpec>;
#[doc = "The MAC Address14 Low register holds the lower 32 bits of the 15th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address14_low;
#[doc = "gmacgrp_MAC_Address15_High (rw) register accessor: The MAC Address15 High register holds the upper 16 bits of the 16th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address15 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address15_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address15_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address15_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address15_High")]
pub type GmacgrpMacAddress15High =
    crate::Reg<gmacgrp_mac_address15_high::GmacgrpMacAddress15HighSpec>;
#[doc = "The MAC Address15 High register holds the upper 16 bits of the 16th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address15 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address15_high;
#[doc = "gmacgrp_MAC_Address15_Low (rw) register accessor: The MAC Address15 Low register holds the lower 32 bits of the 16th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address15_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address15_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address15_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address15_Low")]
pub type GmacgrpMacAddress15Low = crate::Reg<gmacgrp_mac_address15_low::GmacgrpMacAddress15LowSpec>;
#[doc = "The MAC Address15 Low register holds the lower 32 bits of the 16th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address15_low;
#[doc = "gmacgrp_SGMII_RGMII_SMII_Control_Status (r) register accessor: The SGMII/RGMII/SMII Status register indicates the status signals received by the RGMII interface (selected at reset) from the PHY.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_sgmii_rgmii_smii_control_status::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_sgmii_rgmii_smii_control_status`]
module"]
#[doc(alias = "gmacgrp_SGMII_RGMII_SMII_Control_Status")]
pub type GmacgrpSgmiiRgmiiSmiiControlStatus =
    crate::Reg<gmacgrp_sgmii_rgmii_smii_control_status::GmacgrpSgmiiRgmiiSmiiControlStatusSpec>;
#[doc = "The SGMII/RGMII/SMII Status register indicates the status signals received by the RGMII interface (selected at reset) from the PHY."]
pub mod gmacgrp_sgmii_rgmii_smii_control_status;
#[doc = "gmacgrp_MMC_Control (rw) register accessor: The MMC Control register establishes the operating mode of the management counters. Note: The bit 0 (Counters Reset) has higher priority than bit 4 (Counter Preset). Therefore, when the Software tries to set both bits in the same write cycle, all counters are cleared and the bit 4 is not set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_control::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mmc_control::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mmc_control`]
module"]
#[doc(alias = "gmacgrp_MMC_Control")]
pub type GmacgrpMmcControl = crate::Reg<gmacgrp_mmc_control::GmacgrpMmcControlSpec>;
#[doc = "The MMC Control register establishes the operating mode of the management counters. Note: The bit 0 (Counters Reset) has higher priority than bit 4 (Counter Preset). Therefore, when the Software tries to set both bits in the same write cycle, all counters are cleared and the bit 4 is not set."]
pub mod gmacgrp_mmc_control;
#[doc = "gmacgrp_MMC_Receive_Interrupt (r) register accessor: The MMC Receive Interrupt register maintains the interrupts that are generated when the following happens: * Receive statistic counters reach half of their maximum values (0x8000_0000 for 32-bit counter and 0x8000 for 16-bit counter). * Receive statistic counters cross their maximum values (0xFFFF_FFFF for 32-bit counter and 0xFFFF for 16-bit counter). When the Counter Stop Rollover is set, then interrupts are set but the counter remains at all-ones. The MMC Receive Interrupt register is a 32-bit wide register. An interrupt bit is cleared when the respective MMC counter that caused the interrupt is read. The least significant byte lane (Bits\\[7:0\\]) of the respective counter must be read in order to clear the interrupt bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_receive_interrupt::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mmc_receive_interrupt`]
module"]
#[doc(alias = "gmacgrp_MMC_Receive_Interrupt")]
pub type GmacgrpMmcReceiveInterrupt =
    crate::Reg<gmacgrp_mmc_receive_interrupt::GmacgrpMmcReceiveInterruptSpec>;
#[doc = "The MMC Receive Interrupt register maintains the interrupts that are generated when the following happens: * Receive statistic counters reach half of their maximum values (0x8000_0000 for 32-bit counter and 0x8000 for 16-bit counter). * Receive statistic counters cross their maximum values (0xFFFF_FFFF for 32-bit counter and 0xFFFF for 16-bit counter). When the Counter Stop Rollover is set, then interrupts are set but the counter remains at all-ones. The MMC Receive Interrupt register is a 32-bit wide register. An interrupt bit is cleared when the respective MMC counter that caused the interrupt is read. The least significant byte lane (Bits\\[7:0\\]) of the respective counter must be read in order to clear the interrupt bit."]
pub mod gmacgrp_mmc_receive_interrupt;
#[doc = "gmacgrp_MMC_Transmit_Interrupt (r) register accessor: The MMC Transmit Interrupt register maintains the interrupts generated when transmit statistic counters reach half of their maximum values (0x8000_0000 for 32-bit counter and 0x8000 for 16-bit counter), and the maximum values (0xFFFF_FFFF for 32-bit counter and 0xFFFF for 16-bit counter). When Counter Stop Rollover is set, then interrupts are set but the counter remains at all-ones. The MMC Transmit Interrupt register is a 32-bit wide register. An interrupt bit is cleared when the respective MMC counter that caused the interrupt is read. The least significant byte lane (Bits\\[7:0\\]) of the respective counter must be read in order to clear the interrupt bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_transmit_interrupt::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mmc_transmit_interrupt`]
module"]
#[doc(alias = "gmacgrp_MMC_Transmit_Interrupt")]
pub type GmacgrpMmcTransmitInterrupt =
    crate::Reg<gmacgrp_mmc_transmit_interrupt::GmacgrpMmcTransmitInterruptSpec>;
#[doc = "The MMC Transmit Interrupt register maintains the interrupts generated when transmit statistic counters reach half of their maximum values (0x8000_0000 for 32-bit counter and 0x8000 for 16-bit counter), and the maximum values (0xFFFF_FFFF for 32-bit counter and 0xFFFF for 16-bit counter). When Counter Stop Rollover is set, then interrupts are set but the counter remains at all-ones. The MMC Transmit Interrupt register is a 32-bit wide register. An interrupt bit is cleared when the respective MMC counter that caused the interrupt is read. The least significant byte lane (Bits\\[7:0\\]) of the respective counter must be read in order to clear the interrupt bit."]
pub mod gmacgrp_mmc_transmit_interrupt;
#[doc = "gmacgrp_MMC_Receive_Interrupt_Mask (rw) register accessor: The MMC Receive Interrupt Mask register maintains the masks for the interrupts generated when the receive statistic counters reach half of their maximum value, or maximum value. This register is 32-bits wide.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_receive_interrupt_mask::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mmc_receive_interrupt_mask::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mmc_receive_interrupt_mask`]
module"]
#[doc(alias = "gmacgrp_MMC_Receive_Interrupt_Mask")]
pub type GmacgrpMmcReceiveInterruptMask =
    crate::Reg<gmacgrp_mmc_receive_interrupt_mask::GmacgrpMmcReceiveInterruptMaskSpec>;
#[doc = "The MMC Receive Interrupt Mask register maintains the masks for the interrupts generated when the receive statistic counters reach half of their maximum value, or maximum value. This register is 32-bits wide."]
pub mod gmacgrp_mmc_receive_interrupt_mask;
#[doc = "gmacgrp_MMC_Transmit_Interrupt_Mask (rw) register accessor: The MMC Transmit Interrupt Mask register maintains the masks for the interrupts generated when the transmit statistic counters reach half of their maximum value or maximum value. This register is 32-bits wide.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_transmit_interrupt_mask::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mmc_transmit_interrupt_mask::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mmc_transmit_interrupt_mask`]
module"]
#[doc(alias = "gmacgrp_MMC_Transmit_Interrupt_Mask")]
pub type GmacgrpMmcTransmitInterruptMask =
    crate::Reg<gmacgrp_mmc_transmit_interrupt_mask::GmacgrpMmcTransmitInterruptMaskSpec>;
#[doc = "The MMC Transmit Interrupt Mask register maintains the masks for the interrupts generated when the transmit statistic counters reach half of their maximum value or maximum value. This register is 32-bits wide."]
pub mod gmacgrp_mmc_transmit_interrupt_mask;
#[doc = "gmacgrp_txoctetcount_gb (r) register accessor: Number of bytes transmitted, exclusive of preamble and retried bytes, in good and bad frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txoctetcount_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txoctetcount_gb`]
module"]
#[doc(alias = "gmacgrp_txoctetcount_gb")]
pub type GmacgrpTxoctetcountGb = crate::Reg<gmacgrp_txoctetcount_gb::GmacgrpTxoctetcountGbSpec>;
#[doc = "Number of bytes transmitted, exclusive of preamble and retried bytes, in good and bad frames"]
pub mod gmacgrp_txoctetcount_gb;
#[doc = "gmacgrp_txframecount_gb (r) register accessor: Number of good and bad frames transmitted, exclusive of retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txframecount_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txframecount_gb`]
module"]
#[doc(alias = "gmacgrp_txframecount_gb")]
pub type GmacgrpTxframecountGb = crate::Reg<gmacgrp_txframecount_gb::GmacgrpTxframecountGbSpec>;
#[doc = "Number of good and bad frames transmitted, exclusive of retried frames"]
pub mod gmacgrp_txframecount_gb;
#[doc = "gmacgrp_txbroadcastframes_g (r) register accessor: Number of good broadcast frames transmitted\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txbroadcastframes_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txbroadcastframes_g`]
module"]
#[doc(alias = "gmacgrp_txbroadcastframes_g")]
pub type GmacgrpTxbroadcastframesG =
    crate::Reg<gmacgrp_txbroadcastframes_g::GmacgrpTxbroadcastframesGSpec>;
#[doc = "Number of good broadcast frames transmitted"]
pub mod gmacgrp_txbroadcastframes_g;
#[doc = "gmacgrp_txmulticastframes_g (r) register accessor: Number of good multicast frames transmitted\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txmulticastframes_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txmulticastframes_g`]
module"]
#[doc(alias = "gmacgrp_txmulticastframes_g")]
pub type GmacgrpTxmulticastframesG =
    crate::Reg<gmacgrp_txmulticastframes_g::GmacgrpTxmulticastframesGSpec>;
#[doc = "Number of good multicast frames transmitted"]
pub mod gmacgrp_txmulticastframes_g;
#[doc = "gmacgrp_tx64octets_gb (r) register accessor: Number of good and bad frames transmitted with length 64 bytes, exclusive of preamble and retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_tx64octets_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_tx64octets_gb`]
module"]
#[doc(alias = "gmacgrp_tx64octets_gb")]
pub type GmacgrpTx64octetsGb = crate::Reg<gmacgrp_tx64octets_gb::GmacgrpTx64octetsGbSpec>;
#[doc = "Number of good and bad frames transmitted with length 64 bytes, exclusive of preamble and retried frames"]
pub mod gmacgrp_tx64octets_gb;
#[doc = "gmacgrp_tx65to127octets_gb (r) register accessor: Number of good and bad frames transmitted with length between 65 and 127 (inclusive) bytes, exclusive of preamble and retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_tx65to127octets_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_tx65to127octets_gb`]
module"]
#[doc(alias = "gmacgrp_tx65to127octets_gb")]
pub type GmacgrpTx65to127octetsGb =
    crate::Reg<gmacgrp_tx65to127octets_gb::GmacgrpTx65to127octetsGbSpec>;
#[doc = "Number of good and bad frames transmitted with length between 65 and 127 (inclusive) bytes, exclusive of preamble and retried frames"]
pub mod gmacgrp_tx65to127octets_gb;
#[doc = "gmacgrp_tx128to255octets_gb (r) register accessor: Number of good and bad frames transmitted with length between 128 and 255 (inclusive) bytes, exclusive of preamble and retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_tx128to255octets_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_tx128to255octets_gb`]
module"]
#[doc(alias = "gmacgrp_tx128to255octets_gb")]
pub type GmacgrpTx128to255octetsGb =
    crate::Reg<gmacgrp_tx128to255octets_gb::GmacgrpTx128to255octetsGbSpec>;
#[doc = "Number of good and bad frames transmitted with length between 128 and 255 (inclusive) bytes, exclusive of preamble and retried frames"]
pub mod gmacgrp_tx128to255octets_gb;
#[doc = "gmacgrp_tx256to511octets_gb (r) register accessor: Number of good and bad frames transmitted with length between 256 and 511 (inclusive) bytes, exclusive of preamble and retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_tx256to511octets_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_tx256to511octets_gb`]
module"]
#[doc(alias = "gmacgrp_tx256to511octets_gb")]
pub type GmacgrpTx256to511octetsGb =
    crate::Reg<gmacgrp_tx256to511octets_gb::GmacgrpTx256to511octetsGbSpec>;
#[doc = "Number of good and bad frames transmitted with length between 256 and 511 (inclusive) bytes, exclusive of preamble and retried frames"]
pub mod gmacgrp_tx256to511octets_gb;
#[doc = "gmacgrp_tx512to1023octets_gb (r) register accessor: Number of good and bad frames transmitted with length between 512 and 1,023 (inclusive) bytes, exclusive of preamble and retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_tx512to1023octets_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_tx512to1023octets_gb`]
module"]
#[doc(alias = "gmacgrp_tx512to1023octets_gb")]
pub type GmacgrpTx512to1023octetsGb =
    crate::Reg<gmacgrp_tx512to1023octets_gb::GmacgrpTx512to1023octetsGbSpec>;
#[doc = "Number of good and bad frames transmitted with length between 512 and 1,023 (inclusive) bytes, exclusive of preamble and retried frames"]
pub mod gmacgrp_tx512to1023octets_gb;
#[doc = "gmacgrp_tx1024tomaxoctets_gb (r) register accessor: Number of good and bad frames transmitted with length between 1,024 and maxsize (inclusive) bytes, exclusive of preamble and retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_tx1024tomaxoctets_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_tx1024tomaxoctets_gb`]
module"]
#[doc(alias = "gmacgrp_tx1024tomaxoctets_gb")]
pub type GmacgrpTx1024tomaxoctetsGb =
    crate::Reg<gmacgrp_tx1024tomaxoctets_gb::GmacgrpTx1024tomaxoctetsGbSpec>;
#[doc = "Number of good and bad frames transmitted with length between 1,024 and maxsize (inclusive) bytes, exclusive of preamble and retried frames"]
pub mod gmacgrp_tx1024tomaxoctets_gb;
#[doc = "gmacgrp_txunicastframes_gb (r) register accessor: Number of good and bad unicast frames transmitted\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txunicastframes_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txunicastframes_gb`]
module"]
#[doc(alias = "gmacgrp_txunicastframes_gb")]
pub type GmacgrpTxunicastframesGb =
    crate::Reg<gmacgrp_txunicastframes_gb::GmacgrpTxunicastframesGbSpec>;
#[doc = "Number of good and bad unicast frames transmitted"]
pub mod gmacgrp_txunicastframes_gb;
#[doc = "gmacgrp_txmulticastframes_gb (r) register accessor: Number of good and bad multicast frames transmitted\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txmulticastframes_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txmulticastframes_gb`]
module"]
#[doc(alias = "gmacgrp_txmulticastframes_gb")]
pub type GmacgrpTxmulticastframesGb =
    crate::Reg<gmacgrp_txmulticastframes_gb::GmacgrpTxmulticastframesGbSpec>;
#[doc = "Number of good and bad multicast frames transmitted"]
pub mod gmacgrp_txmulticastframes_gb;
#[doc = "gmacgrp_txbroadcastframes_gb (r) register accessor: Number of good and bad broadcast frames transmitted\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txbroadcastframes_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txbroadcastframes_gb`]
module"]
#[doc(alias = "gmacgrp_txbroadcastframes_gb")]
pub type GmacgrpTxbroadcastframesGb =
    crate::Reg<gmacgrp_txbroadcastframes_gb::GmacgrpTxbroadcastframesGbSpec>;
#[doc = "Number of good and bad broadcast frames transmitted"]
pub mod gmacgrp_txbroadcastframes_gb;
#[doc = "gmacgrp_txunderflowerror (r) register accessor: Number of frames aborted due to frame underflow error\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txunderflowerror::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txunderflowerror`]
module"]
#[doc(alias = "gmacgrp_txunderflowerror")]
pub type GmacgrpTxunderflowerror =
    crate::Reg<gmacgrp_txunderflowerror::GmacgrpTxunderflowerrorSpec>;
#[doc = "Number of frames aborted due to frame underflow error"]
pub mod gmacgrp_txunderflowerror;
#[doc = "gmacgrp_txsinglecol_g (r) register accessor: Number of successfully transmitted frames after a single collision in Half-duplex mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txsinglecol_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txsinglecol_g`]
module"]
#[doc(alias = "gmacgrp_txsinglecol_g")]
pub type GmacgrpTxsinglecolG = crate::Reg<gmacgrp_txsinglecol_g::GmacgrpTxsinglecolGSpec>;
#[doc = "Number of successfully transmitted frames after a single collision in Half-duplex mode"]
pub mod gmacgrp_txsinglecol_g;
#[doc = "gmacgrp_txmulticol_g (r) register accessor: Number of successfully transmitted frames after more than a single collision in Half-duplex mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txmulticol_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txmulticol_g`]
module"]
#[doc(alias = "gmacgrp_txmulticol_g")]
pub type GmacgrpTxmulticolG = crate::Reg<gmacgrp_txmulticol_g::GmacgrpTxmulticolGSpec>;
#[doc = "Number of successfully transmitted frames after more than a single collision in Half-duplex mode"]
pub mod gmacgrp_txmulticol_g;
#[doc = "gmacgrp_txdeferred (r) register accessor: Number of successfully transmitted frames after a deferral in Halfduplex mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txdeferred::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txdeferred`]
module"]
#[doc(alias = "gmacgrp_txdeferred")]
pub type GmacgrpTxdeferred = crate::Reg<gmacgrp_txdeferred::GmacgrpTxdeferredSpec>;
#[doc = "Number of successfully transmitted frames after a deferral in Halfduplex mode"]
pub mod gmacgrp_txdeferred;
#[doc = "gmacgrp_txlatecol (r) register accessor: Number of frames aborted due to late collision error\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txlatecol::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txlatecol`]
module"]
#[doc(alias = "gmacgrp_txlatecol")]
pub type GmacgrpTxlatecol = crate::Reg<gmacgrp_txlatecol::GmacgrpTxlatecolSpec>;
#[doc = "Number of frames aborted due to late collision error"]
pub mod gmacgrp_txlatecol;
#[doc = "gmacgrp_txexesscol (r) register accessor: Number of frames aborted due to excessive (16) collision errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txexesscol::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txexesscol`]
module"]
#[doc(alias = "gmacgrp_txexesscol")]
pub type GmacgrpTxexesscol = crate::Reg<gmacgrp_txexesscol::GmacgrpTxexesscolSpec>;
#[doc = "Number of frames aborted due to excessive (16) collision errors"]
pub mod gmacgrp_txexesscol;
#[doc = "gmacgrp_txcarriererr (r) register accessor: Number of frames aborted due to carrier sense error (no carrier or loss of carrier)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txcarriererr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txcarriererr`]
module"]
#[doc(alias = "gmacgrp_txcarriererr")]
pub type GmacgrpTxcarriererr = crate::Reg<gmacgrp_txcarriererr::GmacgrpTxcarriererrSpec>;
#[doc = "Number of frames aborted due to carrier sense error (no carrier or loss of carrier)"]
pub mod gmacgrp_txcarriererr;
#[doc = "gmacgrp_txoctetcnt (r) register accessor: Number of bytes transmitted, exclusive of preamble, in good frames only\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txoctetcnt::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txoctetcnt`]
module"]
#[doc(alias = "gmacgrp_txoctetcnt")]
pub type GmacgrpTxoctetcnt = crate::Reg<gmacgrp_txoctetcnt::GmacgrpTxoctetcntSpec>;
#[doc = "Number of bytes transmitted, exclusive of preamble, in good frames only"]
pub mod gmacgrp_txoctetcnt;
#[doc = "gmacgrp_txframecount_g (r) register accessor: Number of good frames transmitted\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txframecount_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txframecount_g`]
module"]
#[doc(alias = "gmacgrp_txframecount_g")]
pub type GmacgrpTxframecountG = crate::Reg<gmacgrp_txframecount_g::GmacgrpTxframecountGSpec>;
#[doc = "Number of good frames transmitted"]
pub mod gmacgrp_txframecount_g;
#[doc = "gmacgrp_txexcessdef (r) register accessor: Number of frames aborted due to excessive deferral error (deferred for more than two max-sized frame times)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txexcessdef::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txexcessdef`]
module"]
#[doc(alias = "gmacgrp_txexcessdef")]
pub type GmacgrpTxexcessdef = crate::Reg<gmacgrp_txexcessdef::GmacgrpTxexcessdefSpec>;
#[doc = "Number of frames aborted due to excessive deferral error (deferred for more than two max-sized frame times)"]
pub mod gmacgrp_txexcessdef;
#[doc = "gmacgrp_txpauseframes (r) register accessor: Number of good PAUSE frames transmitted\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txpauseframes::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txpauseframes`]
module"]
#[doc(alias = "gmacgrp_txpauseframes")]
pub type GmacgrpTxpauseframes = crate::Reg<gmacgrp_txpauseframes::GmacgrpTxpauseframesSpec>;
#[doc = "Number of good PAUSE frames transmitted"]
pub mod gmacgrp_txpauseframes;
#[doc = "gmacgrp_txvlanframes_g (r) register accessor: Number of good VLAN frames transmitted, exclusive of retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txvlanframes_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txvlanframes_g`]
module"]
#[doc(alias = "gmacgrp_txvlanframes_g")]
pub type GmacgrpTxvlanframesG = crate::Reg<gmacgrp_txvlanframes_g::GmacgrpTxvlanframesGSpec>;
#[doc = "Number of good VLAN frames transmitted, exclusive of retried frames"]
pub mod gmacgrp_txvlanframes_g;
#[doc = "gmacgrp_txoversize_g (r) register accessor: Number of good and bad frames received\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txoversize_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_txoversize_g`]
module"]
#[doc(alias = "gmacgrp_txoversize_g")]
pub type GmacgrpTxoversizeG = crate::Reg<gmacgrp_txoversize_g::GmacgrpTxoversizeGSpec>;
#[doc = "Number of good and bad frames received"]
pub mod gmacgrp_txoversize_g;
#[doc = "gmacgrp_rxframecount_gb (r) register accessor: Number of good and bad frames received\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxframecount_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxframecount_gb`]
module"]
#[doc(alias = "gmacgrp_rxframecount_gb")]
pub type GmacgrpRxframecountGb = crate::Reg<gmacgrp_rxframecount_gb::GmacgrpRxframecountGbSpec>;
#[doc = "Number of good and bad frames received"]
pub mod gmacgrp_rxframecount_gb;
#[doc = "gmacgrp_rxoctetcount_gb (r) register accessor: Number of bytes received, exclusive of preamble, in good and bad frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxoctetcount_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxoctetcount_gb`]
module"]
#[doc(alias = "gmacgrp_rxoctetcount_gb")]
pub type GmacgrpRxoctetcountGb = crate::Reg<gmacgrp_rxoctetcount_gb::GmacgrpRxoctetcountGbSpec>;
#[doc = "Number of bytes received, exclusive of preamble, in good and bad frames"]
pub mod gmacgrp_rxoctetcount_gb;
#[doc = "gmacgrp_rxoctetcount_g (r) register accessor: Number of bytes received, exclusive of preamble, only in good frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxoctetcount_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxoctetcount_g`]
module"]
#[doc(alias = "gmacgrp_rxoctetcount_g")]
pub type GmacgrpRxoctetcountG = crate::Reg<gmacgrp_rxoctetcount_g::GmacgrpRxoctetcountGSpec>;
#[doc = "Number of bytes received, exclusive of preamble, only in good frames"]
pub mod gmacgrp_rxoctetcount_g;
#[doc = "gmacgrp_rxbroadcastframes_g (r) register accessor: Number of good broadcast frames received\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxbroadcastframes_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxbroadcastframes_g`]
module"]
#[doc(alias = "gmacgrp_rxbroadcastframes_g")]
pub type GmacgrpRxbroadcastframesG =
    crate::Reg<gmacgrp_rxbroadcastframes_g::GmacgrpRxbroadcastframesGSpec>;
#[doc = "Number of good broadcast frames received"]
pub mod gmacgrp_rxbroadcastframes_g;
#[doc = "gmacgrp_rxmulticastframes_g (r) register accessor: Number of good multicast frames received\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxmulticastframes_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxmulticastframes_g`]
module"]
#[doc(alias = "gmacgrp_rxmulticastframes_g")]
pub type GmacgrpRxmulticastframesG =
    crate::Reg<gmacgrp_rxmulticastframes_g::GmacgrpRxmulticastframesGSpec>;
#[doc = "Number of good multicast frames received"]
pub mod gmacgrp_rxmulticastframes_g;
#[doc = "gmacgrp_rxcrcerror (r) register accessor: Number of frames received with CRC error\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxcrcerror::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxcrcerror`]
module"]
#[doc(alias = "gmacgrp_rxcrcerror")]
pub type GmacgrpRxcrcerror = crate::Reg<gmacgrp_rxcrcerror::GmacgrpRxcrcerrorSpec>;
#[doc = "Number of frames received with CRC error"]
pub mod gmacgrp_rxcrcerror;
#[doc = "gmacgrp_rxalignmenterror (r) register accessor: Number of frames received with alignment (dribble) error. Valid only in 10/100 mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxalignmenterror::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxalignmenterror`]
module"]
#[doc(alias = "gmacgrp_rxalignmenterror")]
pub type GmacgrpRxalignmenterror =
    crate::Reg<gmacgrp_rxalignmenterror::GmacgrpRxalignmenterrorSpec>;
#[doc = "Number of frames received with alignment (dribble) error. Valid only in 10/100 mode"]
pub mod gmacgrp_rxalignmenterror;
#[doc = "gmacgrp_rxrunterror (r) register accessor: Number of frames received with runt (&lt;64 bytes and CRC error) error\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxrunterror::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxrunterror`]
module"]
#[doc(alias = "gmacgrp_rxrunterror")]
pub type GmacgrpRxrunterror = crate::Reg<gmacgrp_rxrunterror::GmacgrpRxrunterrorSpec>;
#[doc = "Number of frames received with runt (&lt;64 bytes and CRC error) error"]
pub mod gmacgrp_rxrunterror;
#[doc = "gmacgrp_rxjabbererror (r) register accessor: Number of giant frames received with length (including CRC) greater than 1,518 bytes (1,522 bytes for VLAN tagged) and with CRC error. If Jumbo Frame mode is enabled, then frames of length greater than 9,018 bytes (9,022 for VLAN tagged) are considered as giant frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxjabbererror::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxjabbererror`]
module"]
#[doc(alias = "gmacgrp_rxjabbererror")]
pub type GmacgrpRxjabbererror = crate::Reg<gmacgrp_rxjabbererror::GmacgrpRxjabbererrorSpec>;
#[doc = "Number of giant frames received with length (including CRC) greater than 1,518 bytes (1,522 bytes for VLAN tagged) and with CRC error. If Jumbo Frame mode is enabled, then frames of length greater than 9,018 bytes (9,022 for VLAN tagged) are considered as giant frames"]
pub mod gmacgrp_rxjabbererror;
#[doc = "gmacgrp_rxundersize_g (r) register accessor: Number of frames received with length less than 64 bytes, without any errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxundersize_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxundersize_g`]
module"]
#[doc(alias = "gmacgrp_rxundersize_g")]
pub type GmacgrpRxundersizeG = crate::Reg<gmacgrp_rxundersize_g::GmacgrpRxundersizeGSpec>;
#[doc = "Number of frames received with length less than 64 bytes, without any errors"]
pub mod gmacgrp_rxundersize_g;
#[doc = "gmacgrp_rxoversize_g (r) register accessor: Number of frames received with length greater than the maxsize (1,518 or 1,522 for VLAN tagged frames), without errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxoversize_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxoversize_g`]
module"]
#[doc(alias = "gmacgrp_rxoversize_g")]
pub type GmacgrpRxoversizeG = crate::Reg<gmacgrp_rxoversize_g::GmacgrpRxoversizeGSpec>;
#[doc = "Number of frames received with length greater than the maxsize (1,518 or 1,522 for VLAN tagged frames), without errors"]
pub mod gmacgrp_rxoversize_g;
#[doc = "gmacgrp_rx64octets_gb (r) register accessor: Number of good and bad frames received with length 64 bytes, exclusive of preamble\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rx64octets_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rx64octets_gb`]
module"]
#[doc(alias = "gmacgrp_rx64octets_gb")]
pub type GmacgrpRx64octetsGb = crate::Reg<gmacgrp_rx64octets_gb::GmacgrpRx64octetsGbSpec>;
#[doc = "Number of good and bad frames received with length 64 bytes, exclusive of preamble"]
pub mod gmacgrp_rx64octets_gb;
#[doc = "gmacgrp_rx65to127octets_gb (r) register accessor: Number of good and bad frames received with length between 65 and 127 (inclusive) bytes, exclusive of preamble\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rx65to127octets_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rx65to127octets_gb`]
module"]
#[doc(alias = "gmacgrp_rx65to127octets_gb")]
pub type GmacgrpRx65to127octetsGb =
    crate::Reg<gmacgrp_rx65to127octets_gb::GmacgrpRx65to127octetsGbSpec>;
#[doc = "Number of good and bad frames received with length between 65 and 127 (inclusive) bytes, exclusive of preamble"]
pub mod gmacgrp_rx65to127octets_gb;
#[doc = "gmacgrp_rx128to255octets_gb (r) register accessor: Number of good and bad frames received with length between 128 and 255 (inclusive) bytes, exclusive of preamble\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rx128to255octets_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rx128to255octets_gb`]
module"]
#[doc(alias = "gmacgrp_rx128to255octets_gb")]
pub type GmacgrpRx128to255octetsGb =
    crate::Reg<gmacgrp_rx128to255octets_gb::GmacgrpRx128to255octetsGbSpec>;
#[doc = "Number of good and bad frames received with length between 128 and 255 (inclusive) bytes, exclusive of preamble"]
pub mod gmacgrp_rx128to255octets_gb;
#[doc = "gmacgrp_rx256to511octets_gb (r) register accessor: Number of good and bad frames received with length between 256 and 511 (inclusive) bytes, exclusive of preamble\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rx256to511octets_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rx256to511octets_gb`]
module"]
#[doc(alias = "gmacgrp_rx256to511octets_gb")]
pub type GmacgrpRx256to511octetsGb =
    crate::Reg<gmacgrp_rx256to511octets_gb::GmacgrpRx256to511octetsGbSpec>;
#[doc = "Number of good and bad frames received with length between 256 and 511 (inclusive) bytes, exclusive of preamble"]
pub mod gmacgrp_rx256to511octets_gb;
#[doc = "gmacgrp_rx512to1023octets_gb (r) register accessor: Number of good and bad frames received with length between 512 and 1,023 (inclusive) bytes, exclusive of preamble\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rx512to1023octets_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rx512to1023octets_gb`]
module"]
#[doc(alias = "gmacgrp_rx512to1023octets_gb")]
pub type GmacgrpRx512to1023octetsGb =
    crate::Reg<gmacgrp_rx512to1023octets_gb::GmacgrpRx512to1023octetsGbSpec>;
#[doc = "Number of good and bad frames received with length between 512 and 1,023 (inclusive) bytes, exclusive of preamble"]
pub mod gmacgrp_rx512to1023octets_gb;
#[doc = "gmacgrp_rx1024tomaxoctets_gb (r) register accessor: Number of good and bad frames received with length between 1,024 and maxsize (inclusive) bytes, exclusive of preamble and retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rx1024tomaxoctets_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rx1024tomaxoctets_gb`]
module"]
#[doc(alias = "gmacgrp_rx1024tomaxoctets_gb")]
pub type GmacgrpRx1024tomaxoctetsGb =
    crate::Reg<gmacgrp_rx1024tomaxoctets_gb::GmacgrpRx1024tomaxoctetsGbSpec>;
#[doc = "Number of good and bad frames received with length between 1,024 and maxsize (inclusive) bytes, exclusive of preamble and retried frames"]
pub mod gmacgrp_rx1024tomaxoctets_gb;
#[doc = "gmacgrp_rxunicastframes_g (r) register accessor: Number of good unicast frames received\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxunicastframes_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxunicastframes_g`]
module"]
#[doc(alias = "gmacgrp_rxunicastframes_g")]
pub type GmacgrpRxunicastframesG =
    crate::Reg<gmacgrp_rxunicastframes_g::GmacgrpRxunicastframesGSpec>;
#[doc = "Number of good unicast frames received"]
pub mod gmacgrp_rxunicastframes_g;
#[doc = "gmacgrp_rxlengtherror (r) register accessor: Number of frames received with length error (length type field not equal to frame size), for all frames with valid length field\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxlengtherror::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxlengtherror`]
module"]
#[doc(alias = "gmacgrp_rxlengtherror")]
pub type GmacgrpRxlengtherror = crate::Reg<gmacgrp_rxlengtherror::GmacgrpRxlengtherrorSpec>;
#[doc = "Number of frames received with length error (length type field not equal to frame size), for all frames with valid length field"]
pub mod gmacgrp_rxlengtherror;
#[doc = "gmacgrp_rxoutofrangetype (r) register accessor: Number of frames received with length field not equal to the valid frame size (greater than 1,500 but less than 1,536)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxoutofrangetype::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxoutofrangetype`]
module"]
#[doc(alias = "gmacgrp_rxoutofrangetype")]
pub type GmacgrpRxoutofrangetype =
    crate::Reg<gmacgrp_rxoutofrangetype::GmacgrpRxoutofrangetypeSpec>;
#[doc = "Number of frames received with length field not equal to the valid frame size (greater than 1,500 but less than 1,536)"]
pub mod gmacgrp_rxoutofrangetype;
#[doc = "gmacgrp_rxpauseframes (r) register accessor: Number of good and valid PAUSE frames received\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxpauseframes::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxpauseframes`]
module"]
#[doc(alias = "gmacgrp_rxpauseframes")]
pub type GmacgrpRxpauseframes = crate::Reg<gmacgrp_rxpauseframes::GmacgrpRxpauseframesSpec>;
#[doc = "Number of good and valid PAUSE frames received"]
pub mod gmacgrp_rxpauseframes;
#[doc = "gmacgrp_rxfifooverflow (r) register accessor: Number of missed received frames due to FIFO overflow\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxfifooverflow::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxfifooverflow`]
module"]
#[doc(alias = "gmacgrp_rxfifooverflow")]
pub type GmacgrpRxfifooverflow = crate::Reg<gmacgrp_rxfifooverflow::GmacgrpRxfifooverflowSpec>;
#[doc = "Number of missed received frames due to FIFO overflow"]
pub mod gmacgrp_rxfifooverflow;
#[doc = "gmacgrp_rxvlanframes_gb (r) register accessor: Number of good and bad VLAN frames received\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxvlanframes_gb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxvlanframes_gb`]
module"]
#[doc(alias = "gmacgrp_rxvlanframes_gb")]
pub type GmacgrpRxvlanframesGb = crate::Reg<gmacgrp_rxvlanframes_gb::GmacgrpRxvlanframesGbSpec>;
#[doc = "Number of good and bad VLAN frames received"]
pub mod gmacgrp_rxvlanframes_gb;
#[doc = "gmacgrp_rxwatchdogerror (r) register accessor: Number of frames received with error due to watchdog timeout error (frames with a data load larger than 2,048 bytes)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxwatchdogerror::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxwatchdogerror`]
module"]
#[doc(alias = "gmacgrp_rxwatchdogerror")]
pub type GmacgrpRxwatchdogerror = crate::Reg<gmacgrp_rxwatchdogerror::GmacgrpRxwatchdogerrorSpec>;
#[doc = "Number of frames received with error due to watchdog timeout error (frames with a data load larger than 2,048 bytes)"]
pub mod gmacgrp_rxwatchdogerror;
#[doc = "gmacgrp_rxrcverror (r) register accessor: Number of frames received with Receive error or Frame Extension error on the GMII or MII interface.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxrcverror::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxrcverror`]
module"]
#[doc(alias = "gmacgrp_rxrcverror")]
pub type GmacgrpRxrcverror = crate::Reg<gmacgrp_rxrcverror::GmacgrpRxrcverrorSpec>;
#[doc = "Number of frames received with Receive error or Frame Extension error on the GMII or MII interface."]
pub mod gmacgrp_rxrcverror;
#[doc = "gmacgrp_rxctrlframes_g (r) register accessor: Number of received good control frames.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxctrlframes_g::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxctrlframes_g`]
module"]
#[doc(alias = "gmacgrp_rxctrlframes_g")]
pub type GmacgrpRxctrlframesG = crate::Reg<gmacgrp_rxctrlframes_g::GmacgrpRxctrlframesGSpec>;
#[doc = "Number of received good control frames."]
pub mod gmacgrp_rxctrlframes_g;
#[doc = "gmacgrp_MMC_IPC_Receive_Interrupt_Mask (rw) register accessor: This register maintains the mask for the interrupt generated from the receive IPC statistic counters.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_ipc_receive_interrupt_mask::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mmc_ipc_receive_interrupt_mask::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mmc_ipc_receive_interrupt_mask`]
module"]
#[doc(alias = "gmacgrp_MMC_IPC_Receive_Interrupt_Mask")]
pub type GmacgrpMmcIpcReceiveInterruptMask =
    crate::Reg<gmacgrp_mmc_ipc_receive_interrupt_mask::GmacgrpMmcIpcReceiveInterruptMaskSpec>;
#[doc = "This register maintains the mask for the interrupt generated from the receive IPC statistic counters."]
pub mod gmacgrp_mmc_ipc_receive_interrupt_mask;
#[doc = "gmacgrp_MMC_IPC_Receive_Interrupt (r) register accessor: This register maintains the interrupts generated when receive IPC statistic counters reach half their maximum values (0x8000_0000 for 32-bit counter and 0x8000 for 16-bit counter), and when they cross their maximum values (0xFFFF_FFFF for 32-bit counter and 0xFFFF for 16-bit counter). When Counter Stop Rollover is set, then interrupts are set but the counter remains at all-ones. The MMC Receive Checksum Offload Interrupt register is 32-bits wide. When the MMC IPC counter that caused the interrupt is read, its corresponding interrupt bit is cleared. The counter's least-significant byte lane (bits\\[7:0\\]) must be read to clear the interrupt bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_ipc_receive_interrupt::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mmc_ipc_receive_interrupt`]
module"]
#[doc(alias = "gmacgrp_MMC_IPC_Receive_Interrupt")]
pub type GmacgrpMmcIpcReceiveInterrupt =
    crate::Reg<gmacgrp_mmc_ipc_receive_interrupt::GmacgrpMmcIpcReceiveInterruptSpec>;
#[doc = "This register maintains the interrupts generated when receive IPC statistic counters reach half their maximum values (0x8000_0000 for 32-bit counter and 0x8000 for 16-bit counter), and when they cross their maximum values (0xFFFF_FFFF for 32-bit counter and 0xFFFF for 16-bit counter). When Counter Stop Rollover is set, then interrupts are set but the counter remains at all-ones. The MMC Receive Checksum Offload Interrupt register is 32-bits wide. When the MMC IPC counter that caused the interrupt is read, its corresponding interrupt bit is cleared. The counter's least-significant byte lane (bits\\[7:0\\]) must be read to clear the interrupt bit."]
pub mod gmacgrp_mmc_ipc_receive_interrupt;
#[doc = "gmacgrp_rxipv4_gd_frms (r) register accessor: Number of good IPv4 datagrams received with the TCP, UDP, or ICMP payload\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_gd_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv4_gd_frms`]
module"]
#[doc(alias = "gmacgrp_rxipv4_gd_frms")]
pub type GmacgrpRxipv4GdFrms = crate::Reg<gmacgrp_rxipv4_gd_frms::GmacgrpRxipv4GdFrmsSpec>;
#[doc = "Number of good IPv4 datagrams received with the TCP, UDP, or ICMP payload"]
pub mod gmacgrp_rxipv4_gd_frms;
#[doc = "gmacgrp_rxipv4_hdrerr_frms (r) register accessor: Number of IPv4 datagrams received with header (checksum, length, or version mismatch) errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_hdrerr_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv4_hdrerr_frms`]
module"]
#[doc(alias = "gmacgrp_rxipv4_hdrerr_frms")]
pub type GmacgrpRxipv4HdrerrFrms =
    crate::Reg<gmacgrp_rxipv4_hdrerr_frms::GmacgrpRxipv4HdrerrFrmsSpec>;
#[doc = "Number of IPv4 datagrams received with header (checksum, length, or version mismatch) errors"]
pub mod gmacgrp_rxipv4_hdrerr_frms;
#[doc = "gmacgrp_rxipv4_nopay_frms (r) register accessor: Number of IPv4 datagram frames received that did not have a TCP, UDP, or ICMP payload processed by the Checksum engine\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_nopay_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv4_nopay_frms`]
module"]
#[doc(alias = "gmacgrp_rxipv4_nopay_frms")]
pub type GmacgrpRxipv4NopayFrms = crate::Reg<gmacgrp_rxipv4_nopay_frms::GmacgrpRxipv4NopayFrmsSpec>;
#[doc = "Number of IPv4 datagram frames received that did not have a TCP, UDP, or ICMP payload processed by the Checksum engine"]
pub mod gmacgrp_rxipv4_nopay_frms;
#[doc = "gmacgrp_rxipv4_frag_frms (r) register accessor: Number of good IPv4 datagrams with fragmentation\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_frag_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv4_frag_frms`]
module"]
#[doc(alias = "gmacgrp_rxipv4_frag_frms")]
pub type GmacgrpRxipv4FragFrms = crate::Reg<gmacgrp_rxipv4_frag_frms::GmacgrpRxipv4FragFrmsSpec>;
#[doc = "Number of good IPv4 datagrams with fragmentation"]
pub mod gmacgrp_rxipv4_frag_frms;
#[doc = "gmacgrp_rxipv4_udsbl_frms (r) register accessor: Number of good IPv4 datagrams received that had a UDP payload with checksum disabled\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_udsbl_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv4_udsbl_frms`]
module"]
#[doc(alias = "gmacgrp_rxipv4_udsbl_frms")]
pub type GmacgrpRxipv4UdsblFrms = crate::Reg<gmacgrp_rxipv4_udsbl_frms::GmacgrpRxipv4UdsblFrmsSpec>;
#[doc = "Number of good IPv4 datagrams received that had a UDP payload with checksum disabled"]
pub mod gmacgrp_rxipv4_udsbl_frms;
#[doc = "gmacgrp_rxipv6_gd_frms (r) register accessor: Number of good IPv6 datagrams received with TCP, UDP, or ICMP payloads\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv6_gd_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv6_gd_frms`]
module"]
#[doc(alias = "gmacgrp_rxipv6_gd_frms")]
pub type GmacgrpRxipv6GdFrms = crate::Reg<gmacgrp_rxipv6_gd_frms::GmacgrpRxipv6GdFrmsSpec>;
#[doc = "Number of good IPv6 datagrams received with TCP, UDP, or ICMP payloads"]
pub mod gmacgrp_rxipv6_gd_frms;
#[doc = "gmacgrp_rxipv6_hdrerr_frms (r) register accessor: Number of IPv6 datagrams received with header errors (length or version mismatch)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv6_hdrerr_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv6_hdrerr_frms`]
module"]
#[doc(alias = "gmacgrp_rxipv6_hdrerr_frms")]
pub type GmacgrpRxipv6HdrerrFrms =
    crate::Reg<gmacgrp_rxipv6_hdrerr_frms::GmacgrpRxipv6HdrerrFrmsSpec>;
#[doc = "Number of IPv6 datagrams received with header errors (length or version mismatch)"]
pub mod gmacgrp_rxipv6_hdrerr_frms;
#[doc = "gmacgrp_rxipv6_nopay_frms (r) register accessor: Number of IPv6 datagram frames received that did not have a TCP, UDP, or ICMP payload. This includes all IPv6 datagrams with fragmentation or security extension headers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv6_nopay_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv6_nopay_frms`]
module"]
#[doc(alias = "gmacgrp_rxipv6_nopay_frms")]
pub type GmacgrpRxipv6NopayFrms = crate::Reg<gmacgrp_rxipv6_nopay_frms::GmacgrpRxipv6NopayFrmsSpec>;
#[doc = "Number of IPv6 datagram frames received that did not have a TCP, UDP, or ICMP payload. This includes all IPv6 datagrams with fragmentation or security extension headers"]
pub mod gmacgrp_rxipv6_nopay_frms;
#[doc = "gmacgrp_rxudp_gd_frms (r) register accessor: Number of good IP datagrams with a good UDP payload. This counter is not updated when the counter is incremented\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxudp_gd_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxudp_gd_frms`]
module"]
#[doc(alias = "gmacgrp_rxudp_gd_frms")]
pub type GmacgrpRxudpGdFrms = crate::Reg<gmacgrp_rxudp_gd_frms::GmacgrpRxudpGdFrmsSpec>;
#[doc = "Number of good IP datagrams with a good UDP payload. This counter is not updated when the counter is incremented"]
pub mod gmacgrp_rxudp_gd_frms;
#[doc = "gmacgrp_rxudp_err_frms (r) register accessor: Number of good IP datagrams whose UDP payload has a checksum error\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxudp_err_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxudp_err_frms`]
module"]
#[doc(alias = "gmacgrp_rxudp_err_frms")]
pub type GmacgrpRxudpErrFrms = crate::Reg<gmacgrp_rxudp_err_frms::GmacgrpRxudpErrFrmsSpec>;
#[doc = "Number of good IP datagrams whose UDP payload has a checksum error"]
pub mod gmacgrp_rxudp_err_frms;
#[doc = "gmacgrp_rxtcp_gd_frms (r) register accessor: Number of good IP datagrams with a good TCP payload\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxtcp_gd_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxtcp_gd_frms`]
module"]
#[doc(alias = "gmacgrp_rxtcp_gd_frms")]
pub type GmacgrpRxtcpGdFrms = crate::Reg<gmacgrp_rxtcp_gd_frms::GmacgrpRxtcpGdFrmsSpec>;
#[doc = "Number of good IP datagrams with a good TCP payload"]
pub mod gmacgrp_rxtcp_gd_frms;
#[doc = "gmacgrp_rxtcp_err_frms (r) register accessor: Number of good IP datagrams whose TCP payload has a checksum error\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxtcp_err_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxtcp_err_frms`]
module"]
#[doc(alias = "gmacgrp_rxtcp_err_frms")]
pub type GmacgrpRxtcpErrFrms = crate::Reg<gmacgrp_rxtcp_err_frms::GmacgrpRxtcpErrFrmsSpec>;
#[doc = "Number of good IP datagrams whose TCP payload has a checksum error"]
pub mod gmacgrp_rxtcp_err_frms;
#[doc = "gmacgrp_rxicmp_gd_frms (r) register accessor: Number of good IP datagrams with a good ICMP payload\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxicmp_gd_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxicmp_gd_frms`]
module"]
#[doc(alias = "gmacgrp_rxicmp_gd_frms")]
pub type GmacgrpRxicmpGdFrms = crate::Reg<gmacgrp_rxicmp_gd_frms::GmacgrpRxicmpGdFrmsSpec>;
#[doc = "Number of good IP datagrams with a good ICMP payload"]
pub mod gmacgrp_rxicmp_gd_frms;
#[doc = "gmacgrp_rxicmp_err_frms (r) register accessor: Number of good IP datagrams whose ICMP payload has a checksum error\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxicmp_err_frms::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxicmp_err_frms`]
module"]
#[doc(alias = "gmacgrp_rxicmp_err_frms")]
pub type GmacgrpRxicmpErrFrms = crate::Reg<gmacgrp_rxicmp_err_frms::GmacgrpRxicmpErrFrmsSpec>;
#[doc = "Number of good IP datagrams whose ICMP payload has a checksum error"]
pub mod gmacgrp_rxicmp_err_frms;
#[doc = "gmacgrp_rxipv4_gd_octets (r) register accessor: Number of bytes received in good IPv4 datagrams encapsulating TCP, UDP, or ICMP data\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_gd_octets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv4_gd_octets`]
module"]
#[doc(alias = "gmacgrp_rxipv4_gd_octets")]
pub type GmacgrpRxipv4GdOctets = crate::Reg<gmacgrp_rxipv4_gd_octets::GmacgrpRxipv4GdOctetsSpec>;
#[doc = "Number of bytes received in good IPv4 datagrams encapsulating TCP, UDP, or ICMP data"]
pub mod gmacgrp_rxipv4_gd_octets;
#[doc = "gmacgrp_rxipv4_hdrerr_octets (r) register accessor: Number of bytes received in IPv4 datagrams with header errors (checksum, length, version mismatch). The value in the Length field of IPv4 header is used to update this counter\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_hdrerr_octets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv4_hdrerr_octets`]
module"]
#[doc(alias = "gmacgrp_rxipv4_hdrerr_octets")]
pub type GmacgrpRxipv4HdrerrOctets =
    crate::Reg<gmacgrp_rxipv4_hdrerr_octets::GmacgrpRxipv4HdrerrOctetsSpec>;
#[doc = "Number of bytes received in IPv4 datagrams with header errors (checksum, length, version mismatch). The value in the Length field of IPv4 header is used to update this counter"]
pub mod gmacgrp_rxipv4_hdrerr_octets;
#[doc = "gmacgrp_rxipv4_nopay_octets (r) register accessor: Number of bytes received in IPv4 datagrams that did not have a TCP, UDP, or ICMP payload. The value in the IPv4 headers Length field is used to update this counter\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_nopay_octets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv4_nopay_octets`]
module"]
#[doc(alias = "gmacgrp_rxipv4_nopay_octets")]
pub type GmacgrpRxipv4NopayOctets =
    crate::Reg<gmacgrp_rxipv4_nopay_octets::GmacgrpRxipv4NopayOctetsSpec>;
#[doc = "Number of bytes received in IPv4 datagrams that did not have a TCP, UDP, or ICMP payload. The value in the IPv4 headers Length field is used to update this counter"]
pub mod gmacgrp_rxipv4_nopay_octets;
#[doc = "gmacgrp_rxipv4_frag_octets (r) register accessor: Number of bytes received in fragmented IPv4 datagrams. The value in the IPv4 headers Length field is used to update this counter\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_frag_octets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv4_frag_octets`]
module"]
#[doc(alias = "gmacgrp_rxipv4_frag_octets")]
pub type GmacgrpRxipv4FragOctets =
    crate::Reg<gmacgrp_rxipv4_frag_octets::GmacgrpRxipv4FragOctetsSpec>;
#[doc = "Number of bytes received in fragmented IPv4 datagrams. The value in the IPv4 headers Length field is used to update this counter"]
pub mod gmacgrp_rxipv4_frag_octets;
#[doc = "gmacgrp_rxipv4_udsbl_octets (r) register accessor: Number of bytes received in a UDP segment that had the UDP checksum disabled. This counter does not count IP Header bytes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_udsbl_octets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv4_udsbl_octets`]
module"]
#[doc(alias = "gmacgrp_rxipv4_udsbl_octets")]
pub type GmacgrpRxipv4UdsblOctets =
    crate::Reg<gmacgrp_rxipv4_udsbl_octets::GmacgrpRxipv4UdsblOctetsSpec>;
#[doc = "Number of bytes received in a UDP segment that had the UDP checksum disabled. This counter does not count IP Header bytes"]
pub mod gmacgrp_rxipv4_udsbl_octets;
#[doc = "gmacgrp_rxipv6_gd_octets (r) register accessor: Number of bytes received in good IPv6 datagrams encapsulating TCP, UDP or ICMPv6 data\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv6_gd_octets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv6_gd_octets`]
module"]
#[doc(alias = "gmacgrp_rxipv6_gd_octets")]
pub type GmacgrpRxipv6GdOctets = crate::Reg<gmacgrp_rxipv6_gd_octets::GmacgrpRxipv6GdOctetsSpec>;
#[doc = "Number of bytes received in good IPv6 datagrams encapsulating TCP, UDP or ICMPv6 data"]
pub mod gmacgrp_rxipv6_gd_octets;
#[doc = "gmacgrp_rxipv6_hdrerr_octets (r) register accessor: Number of bytes received in IPv6 datagrams with header errors (length, version mismatch). The value in the IPv6 headers Length field is used to update this counter\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv6_hdrerr_octets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv6_hdrerr_octets`]
module"]
#[doc(alias = "gmacgrp_rxipv6_hdrerr_octets")]
pub type GmacgrpRxipv6HdrerrOctets =
    crate::Reg<gmacgrp_rxipv6_hdrerr_octets::GmacgrpRxipv6HdrerrOctetsSpec>;
#[doc = "Number of bytes received in IPv6 datagrams with header errors (length, version mismatch). The value in the IPv6 headers Length field is used to update this counter"]
pub mod gmacgrp_rxipv6_hdrerr_octets;
#[doc = "gmacgrp_rxipv6_nopay_octets (r) register accessor: Number of bytes received in IPv6 datagrams that did not have a TCP, UDP, or ICMP payload. The value in the IPv6 headers Length field is used to update this counter\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv6_nopay_octets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxipv6_nopay_octets`]
module"]
#[doc(alias = "gmacgrp_rxipv6_nopay_octets")]
pub type GmacgrpRxipv6NopayOctets =
    crate::Reg<gmacgrp_rxipv6_nopay_octets::GmacgrpRxipv6NopayOctetsSpec>;
#[doc = "Number of bytes received in IPv6 datagrams that did not have a TCP, UDP, or ICMP payload. The value in the IPv6 headers Length field is used to update this counter"]
pub mod gmacgrp_rxipv6_nopay_octets;
#[doc = "gmacgrp_rxudp_gd_octets (r) register accessor: Number of bytes received in a good UDP segment. This counter does not count IP header bytes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxudp_gd_octets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxudp_gd_octets`]
module"]
#[doc(alias = "gmacgrp_rxudp_gd_octets")]
pub type GmacgrpRxudpGdOctets = crate::Reg<gmacgrp_rxudp_gd_octets::GmacgrpRxudpGdOctetsSpec>;
#[doc = "Number of bytes received in a good UDP segment. This counter does not count IP header bytes"]
pub mod gmacgrp_rxudp_gd_octets;
#[doc = "gmacgrp_rxudp_err_octets (r) register accessor: Number of bytes received in a UDP segment that had checksum errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxudp_err_octets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxudp_err_octets`]
module"]
#[doc(alias = "gmacgrp_rxudp_err_octets")]
pub type GmacgrpRxudpErrOctets = crate::Reg<gmacgrp_rxudp_err_octets::GmacgrpRxudpErrOctetsSpec>;
#[doc = "Number of bytes received in a UDP segment that had checksum errors"]
pub mod gmacgrp_rxudp_err_octets;
#[doc = "gmacgrp_rxtcp_gd_octets (r) register accessor: Number of bytes received in a good TCP segment\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxtcp_gd_octets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxtcp_gd_octets`]
module"]
#[doc(alias = "gmacgrp_rxtcp_gd_octets")]
pub type GmacgrpRxtcpGdOctets = crate::Reg<gmacgrp_rxtcp_gd_octets::GmacgrpRxtcpGdOctetsSpec>;
#[doc = "Number of bytes received in a good TCP segment"]
pub mod gmacgrp_rxtcp_gd_octets;
#[doc = "gmacgrp_rxtcperroctets (r) register accessor: Number of bytes received in a TCP segment with checksum errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxtcperroctets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxtcperroctets`]
module"]
#[doc(alias = "gmacgrp_rxtcperroctets")]
pub type GmacgrpRxtcperroctets = crate::Reg<gmacgrp_rxtcperroctets::GmacgrpRxtcperroctetsSpec>;
#[doc = "Number of bytes received in a TCP segment with checksum errors"]
pub mod gmacgrp_rxtcperroctets;
#[doc = "gmacgrp_rxicmp_gd_octets (r) register accessor: Number of bytes received in a good ICMP segment\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxicmp_gd_octets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxicmp_gd_octets`]
module"]
#[doc(alias = "gmacgrp_rxicmp_gd_octets")]
pub type GmacgrpRxicmpGdOctets = crate::Reg<gmacgrp_rxicmp_gd_octets::GmacgrpRxicmpGdOctetsSpec>;
#[doc = "Number of bytes received in a good ICMP segment"]
pub mod gmacgrp_rxicmp_gd_octets;
#[doc = "gmacgrp_rxicmp_err_octets (r) register accessor: Number of bytes received in an ICMP segment with checksum errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxicmp_err_octets::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_rxicmp_err_octets`]
module"]
#[doc(alias = "gmacgrp_rxicmp_err_octets")]
pub type GmacgrpRxicmpErrOctets = crate::Reg<gmacgrp_rxicmp_err_octets::GmacgrpRxicmpErrOctetsSpec>;
#[doc = "Number of bytes received in an ICMP segment with checksum errors"]
pub mod gmacgrp_rxicmp_err_octets;
#[doc = "gmacgrp_L3_L4_Control0 (rw) register accessor: This register controls the operations of the filter 0 of Layer 3 and Layer 4.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_l3_l4_control0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_l3_l4_control0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_l3_l4_control0`]
module"]
#[doc(alias = "gmacgrp_L3_L4_Control0")]
pub type GmacgrpL3L4Control0 = crate::Reg<gmacgrp_l3_l4_control0::GmacgrpL3L4Control0Spec>;
#[doc = "This register controls the operations of the filter 0 of Layer 3 and Layer 4."]
pub mod gmacgrp_l3_l4_control0;
#[doc = "gmacgrp_Layer4_Address0 (rw) register accessor: Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer4_address0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer4_address0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer4_address0`]
module"]
#[doc(alias = "gmacgrp_Layer4_Address0")]
pub type GmacgrpLayer4Address0 = crate::Reg<gmacgrp_layer4_address0::GmacgrpLayer4Address0Spec>;
#[doc = "Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock."]
pub mod gmacgrp_layer4_address0;
#[doc = "gmacgrp_Layer3_Addr0_Reg0 (rw) register accessor: For IPv4 frames, the Layer 3 Address 0 Register 0 contains the 32-bit IP Source Address field. For IPv6 frames, it contains Bits\\[31:0\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr0_reg0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr0_reg0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr0_reg0`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr0_Reg0")]
pub type GmacgrpLayer3Addr0Reg0 = crate::Reg<gmacgrp_layer3_addr0_reg0::GmacgrpLayer3Addr0Reg0Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 0 Register 0 contains the 32-bit IP Source Address field. For IPv6 frames, it contains Bits\\[31:0\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr0_reg0;
#[doc = "gmacgrp_Layer3_Addr1_Reg0 (rw) register accessor: For IPv4 frames, the Layer 3 Address 1 Register 0 contains the 32-bit IP Destination Address field. For IPv6 frames, it contains Bits\\[63:32\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr1_reg0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr1_reg0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr1_reg0`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr1_Reg0")]
pub type GmacgrpLayer3Addr1Reg0 = crate::Reg<gmacgrp_layer3_addr1_reg0::GmacgrpLayer3Addr1Reg0Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 1 Register 0 contains the 32-bit IP Destination Address field. For IPv6 frames, it contains Bits\\[63:32\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr1_reg0;
#[doc = "gmacgrp_Layer3_Addr2_Reg0 (rw) register accessor: For IPv4 frames, the Layer 3 Address 2 Register 0 is reserved. For IPv6 frames, it contains Bits \\[95:64\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr2_reg0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr2_reg0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr2_reg0`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr2_Reg0")]
pub type GmacgrpLayer3Addr2Reg0 = crate::Reg<gmacgrp_layer3_addr2_reg0::GmacgrpLayer3Addr2Reg0Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 2 Register 0 is reserved. For IPv6 frames, it contains Bits \\[95:64\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr2_reg0;
#[doc = "gmacgrp_Layer3_Addr3_Reg0 (rw) register accessor: For IPv4 frames, the Layer 3 Address 3 Register 0 is reserved. For IPv6 frames, it contains Bits \\[127:96\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr3_reg0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr3_reg0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr3_reg0`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr3_Reg0")]
pub type GmacgrpLayer3Addr3Reg0 = crate::Reg<gmacgrp_layer3_addr3_reg0::GmacgrpLayer3Addr3Reg0Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 3 Register 0 is reserved. For IPv6 frames, it contains Bits \\[127:96\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr3_reg0;
#[doc = "gmacgrp_L3_L4_Control1 (rw) register accessor: This register controls the operations of the filter 0 of Layer 3 and Layer 4.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_l3_l4_control1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_l3_l4_control1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_l3_l4_control1`]
module"]
#[doc(alias = "gmacgrp_L3_L4_Control1")]
pub type GmacgrpL3L4Control1 = crate::Reg<gmacgrp_l3_l4_control1::GmacgrpL3L4Control1Spec>;
#[doc = "This register controls the operations of the filter 0 of Layer 3 and Layer 4."]
pub mod gmacgrp_l3_l4_control1;
#[doc = "gmacgrp_Layer4_Address1 (rw) register accessor: Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer4_address1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer4_address1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer4_address1`]
module"]
#[doc(alias = "gmacgrp_Layer4_Address1")]
pub type GmacgrpLayer4Address1 = crate::Reg<gmacgrp_layer4_address1::GmacgrpLayer4Address1Spec>;
#[doc = "Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock."]
pub mod gmacgrp_layer4_address1;
#[doc = "gmacgrp_Layer3_Addr0_Reg1 (rw) register accessor: For IPv4 frames, the Layer 3 Address 0 Register 1 contains the 32-bit IP Source Address field. For IPv6 frames, it contains Bits\\[31:0\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr0_reg1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr0_reg1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr0_reg1`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr0_Reg1")]
pub type GmacgrpLayer3Addr0Reg1 = crate::Reg<gmacgrp_layer3_addr0_reg1::GmacgrpLayer3Addr0Reg1Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 0 Register 1 contains the 32-bit IP Source Address field. For IPv6 frames, it contains Bits\\[31:0\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr0_reg1;
#[doc = "gmacgrp_Layer3_Addr1_Reg1 (rw) register accessor: For IPv4 frames, the Layer 3 Address 1 Register 1 contains the 32-bit IP Destination Address field. For IPv6 frames, it contains Bits\\[63:32\\]
of the 128-bit IP Source Address or Destination Address field\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr1_reg1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr1_reg1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr1_reg1`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr1_Reg1")]
pub type GmacgrpLayer3Addr1Reg1 = crate::Reg<gmacgrp_layer3_addr1_reg1::GmacgrpLayer3Addr1Reg1Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 1 Register 1 contains the 32-bit IP Destination Address field. For IPv6 frames, it contains Bits\\[63:32\\]
of the 128-bit IP Source Address or Destination Address field"]
pub mod gmacgrp_layer3_addr1_reg1;
#[doc = "gmacgrp_Layer3_Addr2_Reg1 (rw) register accessor: For IPv4 frames, the Layer 3 Address 2 Register 1 is reserved. For IPv6 frames, it contains Bits \\[95:64\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr2_reg1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr2_reg1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr2_reg1`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr2_Reg1")]
pub type GmacgrpLayer3Addr2Reg1 = crate::Reg<gmacgrp_layer3_addr2_reg1::GmacgrpLayer3Addr2Reg1Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 2 Register 1 is reserved. For IPv6 frames, it contains Bits \\[95:64\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr2_reg1;
#[doc = "gmacgrp_Layer3_Addr3_Reg1 (rw) register accessor: For IPv4 frames, the Layer 3 Address 3 Register 1 is reserved. For IPv6 frames, it contains Bits \\[127:96\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr3_reg1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr3_reg1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr3_reg1`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr3_Reg1")]
pub type GmacgrpLayer3Addr3Reg1 = crate::Reg<gmacgrp_layer3_addr3_reg1::GmacgrpLayer3Addr3Reg1Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 3 Register 1 is reserved. For IPv6 frames, it contains Bits \\[127:96\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr3_reg1;
#[doc = "gmacgrp_L3_L4_Control2 (rw) register accessor: This register controls the operations of the filter 2 of Layer 3 and Layer 4.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_l3_l4_control2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_l3_l4_control2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_l3_l4_control2`]
module"]
#[doc(alias = "gmacgrp_L3_L4_Control2")]
pub type GmacgrpL3L4Control2 = crate::Reg<gmacgrp_l3_l4_control2::GmacgrpL3L4Control2Spec>;
#[doc = "This register controls the operations of the filter 2 of Layer 3 and Layer 4."]
pub mod gmacgrp_l3_l4_control2;
#[doc = "gmacgrp_Layer4_Address2 (rw) register accessor: Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer4_address2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer4_address2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer4_address2`]
module"]
#[doc(alias = "gmacgrp_Layer4_Address2")]
pub type GmacgrpLayer4Address2 = crate::Reg<gmacgrp_layer4_address2::GmacgrpLayer4Address2Spec>;
#[doc = "Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock."]
pub mod gmacgrp_layer4_address2;
#[doc = "gmacgrp_Layer3_Addr0_Reg2 (rw) register accessor: For IPv4 frames, the Layer 3 Address 0 Register 2 contains the 32-bit IP Source Address field. For IPv6 frames, it contains Bits \\[31:0\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr0_reg2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr0_reg2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr0_reg2`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr0_Reg2")]
pub type GmacgrpLayer3Addr0Reg2 = crate::Reg<gmacgrp_layer3_addr0_reg2::GmacgrpLayer3Addr0Reg2Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 0 Register 2 contains the 32-bit IP Source Address field. For IPv6 frames, it contains Bits \\[31:0\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr0_reg2;
#[doc = "gmacgrp_Layer3_Addr1_Reg2 (rw) register accessor: For IPv4 frames, the Layer 3 Address 1 Register 2 contains the 32-bit IP Destination Address field. For IPv6 frames, it contains Bits \\[63:32\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr1_reg2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr1_reg2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr1_reg2`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr1_Reg2")]
pub type GmacgrpLayer3Addr1Reg2 = crate::Reg<gmacgrp_layer3_addr1_reg2::GmacgrpLayer3Addr1Reg2Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 1 Register 2 contains the 32-bit IP Destination Address field. For IPv6 frames, it contains Bits \\[63:32\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr1_reg2;
#[doc = "gmacgrp_Layer3_Addr2_Reg2 (rw) register accessor: For IPv4 frames, the Layer 3 Address 2 Register 2 is reserved. For IPv6 frames, it contains Bits \\[95:64\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr2_reg2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr2_reg2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr2_reg2`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr2_Reg2")]
pub type GmacgrpLayer3Addr2Reg2 = crate::Reg<gmacgrp_layer3_addr2_reg2::GmacgrpLayer3Addr2Reg2Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 2 Register 2 is reserved. For IPv6 frames, it contains Bits \\[95:64\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr2_reg2;
#[doc = "gmacgrp_Layer3_Addr3_Reg2 (rw) register accessor: For IPv4 frames, the Layer 3 Address 3 Register 2 is reserved. For IPv6 frames, it contains Bits \\[127:96\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr3_reg2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr3_reg2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr3_reg2`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr3_Reg2")]
pub type GmacgrpLayer3Addr3Reg2 = crate::Reg<gmacgrp_layer3_addr3_reg2::GmacgrpLayer3Addr3Reg2Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 3 Register 2 is reserved. For IPv6 frames, it contains Bits \\[127:96\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr3_reg2;
#[doc = "gmacgrp_L3_L4_Control3 (rw) register accessor: This register controls the operations of the filter 0 of Layer 3 and Layer 4.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_l3_l4_control3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_l3_l4_control3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_l3_l4_control3`]
module"]
#[doc(alias = "gmacgrp_L3_L4_Control3")]
pub type GmacgrpL3L4Control3 = crate::Reg<gmacgrp_l3_l4_control3::GmacgrpL3L4Control3Spec>;
#[doc = "This register controls the operations of the filter 0 of Layer 3 and Layer 4."]
pub mod gmacgrp_l3_l4_control3;
#[doc = "gmacgrp_Layer4_Address3 (rw) register accessor: Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer4_address3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer4_address3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer4_address3`]
module"]
#[doc(alias = "gmacgrp_Layer4_Address3")]
pub type GmacgrpLayer4Address3 = crate::Reg<gmacgrp_layer4_address3::GmacgrpLayer4Address3Spec>;
#[doc = "Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock."]
pub mod gmacgrp_layer4_address3;
#[doc = "gmacgrp_Layer3_Addr0_Reg3 (rw) register accessor: For IPv4 frames, the Layer 3 Address 0 Register 3 contains the 32-bit IP Source Address field. For IPv6 frames, it contains Bits \\[31:0\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr0_reg3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr0_reg3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr0_reg3`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr0_Reg3")]
pub type GmacgrpLayer3Addr0Reg3 = crate::Reg<gmacgrp_layer3_addr0_reg3::GmacgrpLayer3Addr0Reg3Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 0 Register 3 contains the 32-bit IP Source Address field. For IPv6 frames, it contains Bits \\[31:0\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr0_reg3;
#[doc = "gmacgrp_Layer3_Addr1_Reg3 (rw) register accessor: For IPv4 frames, the Layer 3 Address 1 Register 3 contains the 32-bit IP Destination Address field. For IPv6 frames, it contains Bits \\[63:32\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr1_reg3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr1_reg3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr1_reg3`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr1_Reg3")]
pub type GmacgrpLayer3Addr1Reg3 = crate::Reg<gmacgrp_layer3_addr1_reg3::GmacgrpLayer3Addr1Reg3Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 1 Register 3 contains the 32-bit IP Destination Address field. For IPv6 frames, it contains Bits \\[63:32\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr1_reg3;
#[doc = "gmacgrp_Layer3_Addr2_Reg3 (rw) register accessor: For IPv4 frames, the Layer 3 Address 2 Register 3 is reserved. For IPv6 frames, it contains Bits \\[95:64\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr2_reg3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr2_reg3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr2_reg3`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr2_Reg3")]
pub type GmacgrpLayer3Addr2Reg3 = crate::Reg<gmacgrp_layer3_addr2_reg3::GmacgrpLayer3Addr2Reg3Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 2 Register 3 is reserved. For IPv6 frames, it contains Bits \\[95:64\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr2_reg3;
#[doc = "gmacgrp_Layer3_Addr3_Reg3 (rw) register accessor: For IPv4 frames, the Layer 3 Address 3 Register 3 is reserved. For IPv6 frames, it contains Bits \\[127:96\\]
of the 128-bit IP Source Address or Destination Address field.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer3_addr3_reg3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer3_addr3_reg3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_layer3_addr3_reg3`]
module"]
#[doc(alias = "gmacgrp_Layer3_Addr3_Reg3")]
pub type GmacgrpLayer3Addr3Reg3 = crate::Reg<gmacgrp_layer3_addr3_reg3::GmacgrpLayer3Addr3Reg3Spec>;
#[doc = "For IPv4 frames, the Layer 3 Address 3 Register 3 is reserved. For IPv6 frames, it contains Bits \\[127:96\\]
of the 128-bit IP Source Address or Destination Address field."]
pub mod gmacgrp_layer3_addr3_reg3;
#[doc = "gmacgrp_Hash_Table_Reg0 (rw) register accessor: This register contains the first 32 bits of the hash table. The 256-bit Hash table is used for group address filtering. For hash filtering, the content of the destination address in the incoming frame is passed through the CRC logic and the upper eight bits of the CRC register are used to index the content of the Hash table. The most significant bits determines the register to be used (Hash Table Register X), and the least significant five bits determine the bit within the register. For example, a hash value of 8b'10111111 selects Bit 31 of the Hash Table Register 5. The hash value of the destination address is calculated in the following way: 1. Calculate the 32-bit CRC for the DA (See IEEE 802.3, Section 3.2.8 for the steps to calculate CRC32). 2. Perform bitwise reversal for the value obtained in Step 1. 3. Take the upper 8 bits from the value obtained in Step 2. If the corresponding bit value of the register is 1'b1, the frame is accepted. Otherwise, it is rejected. If the Bit 1 (Pass All Multicast) is set in Register 1 (MAC Frame Filter), then all multicast frames are accepted regardless of the multicast hash values. Because the Hash Table register is double-synchronized to the (G)MII clock domain, the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Hash Table Register X registers are written. Note: Because of double-synchronization, consecutive writes to this register should be performed after at least four clock cycles in the destination clock domain.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_hash_table_reg0`]
module"]
#[doc(alias = "gmacgrp_Hash_Table_Reg0")]
pub type GmacgrpHashTableReg0 = crate::Reg<gmacgrp_hash_table_reg0::GmacgrpHashTableReg0Spec>;
#[doc = "This register contains the first 32 bits of the hash table. The 256-bit Hash table is used for group address filtering. For hash filtering, the content of the destination address in the incoming frame is passed through the CRC logic and the upper eight bits of the CRC register are used to index the content of the Hash table. The most significant bits determines the register to be used (Hash Table Register X), and the least significant five bits determine the bit within the register. For example, a hash value of 8b'10111111 selects Bit 31 of the Hash Table Register 5. The hash value of the destination address is calculated in the following way: 1. Calculate the 32-bit CRC for the DA (See IEEE 802.3, Section 3.2.8 for the steps to calculate CRC32). 2. Perform bitwise reversal for the value obtained in Step 1. 3. Take the upper 8 bits from the value obtained in Step 2. If the corresponding bit value of the register is 1'b1, the frame is accepted. Otherwise, it is rejected. If the Bit 1 (Pass All Multicast) is set in Register 1 (MAC Frame Filter), then all multicast frames are accepted regardless of the multicast hash values. Because the Hash Table register is double-synchronized to the (G)MII clock domain, the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Hash Table Register X registers are written. Note: Because of double-synchronization, consecutive writes to this register should be performed after at least four clock cycles in the destination clock domain."]
pub mod gmacgrp_hash_table_reg0;
#[doc = "gmacgrp_Hash_Table_Reg1 (rw) register accessor: This register contains the second 32 bits of the hash table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_hash_table_reg1`]
module"]
#[doc(alias = "gmacgrp_Hash_Table_Reg1")]
pub type GmacgrpHashTableReg1 = crate::Reg<gmacgrp_hash_table_reg1::GmacgrpHashTableReg1Spec>;
#[doc = "This register contains the second 32 bits of the hash table."]
pub mod gmacgrp_hash_table_reg1;
#[doc = "gmacgrp_Hash_Table_Reg2 (rw) register accessor: This register contains the third 32 bits of the hash table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_hash_table_reg2`]
module"]
#[doc(alias = "gmacgrp_Hash_Table_Reg2")]
pub type GmacgrpHashTableReg2 = crate::Reg<gmacgrp_hash_table_reg2::GmacgrpHashTableReg2Spec>;
#[doc = "This register contains the third 32 bits of the hash table."]
pub mod gmacgrp_hash_table_reg2;
#[doc = "gmacgrp_Hash_Table_Reg3 (rw) register accessor: This register contains the fourth 32 bits of the hash table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_hash_table_reg3`]
module"]
#[doc(alias = "gmacgrp_Hash_Table_Reg3")]
pub type GmacgrpHashTableReg3 = crate::Reg<gmacgrp_hash_table_reg3::GmacgrpHashTableReg3Spec>;
#[doc = "This register contains the fourth 32 bits of the hash table."]
pub mod gmacgrp_hash_table_reg3;
#[doc = "gmacgrp_Hash_Table_Reg4 (rw) register accessor: This register contains the fifth 32 bits of the hash table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_hash_table_reg4`]
module"]
#[doc(alias = "gmacgrp_Hash_Table_Reg4")]
pub type GmacgrpHashTableReg4 = crate::Reg<gmacgrp_hash_table_reg4::GmacgrpHashTableReg4Spec>;
#[doc = "This register contains the fifth 32 bits of the hash table."]
pub mod gmacgrp_hash_table_reg4;
#[doc = "gmacgrp_Hash_Table_Reg5 (rw) register accessor: This register contains the sixth 32 bits of the hash table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_hash_table_reg5`]
module"]
#[doc(alias = "gmacgrp_Hash_Table_Reg5")]
pub type GmacgrpHashTableReg5 = crate::Reg<gmacgrp_hash_table_reg5::GmacgrpHashTableReg5Spec>;
#[doc = "This register contains the sixth 32 bits of the hash table."]
pub mod gmacgrp_hash_table_reg5;
#[doc = "gmacgrp_Hash_Table_Reg6 (rw) register accessor: This register contains the seventh 32 bits of the hash table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_hash_table_reg6`]
module"]
#[doc(alias = "gmacgrp_Hash_Table_Reg6")]
pub type GmacgrpHashTableReg6 = crate::Reg<gmacgrp_hash_table_reg6::GmacgrpHashTableReg6Spec>;
#[doc = "This register contains the seventh 32 bits of the hash table."]
pub mod gmacgrp_hash_table_reg6;
#[doc = "gmacgrp_Hash_Table_Reg7 (rw) register accessor: This register contains the eighth 32 bits of the hash table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_hash_table_reg7`]
module"]
#[doc(alias = "gmacgrp_Hash_Table_Reg7")]
pub type GmacgrpHashTableReg7 = crate::Reg<gmacgrp_hash_table_reg7::GmacgrpHashTableReg7Spec>;
#[doc = "This register contains the eighth 32 bits of the hash table."]
pub mod gmacgrp_hash_table_reg7;
#[doc = "gmacgrp_VLAN_Incl_Reg (rw) register accessor: The VLAN Tag Inclusion or Replacement register contains the VLAN tag for insertion or replacement in the transmit frames.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_vlan_incl_reg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_vlan_incl_reg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_vlan_incl_reg`]
module"]
#[doc(alias = "gmacgrp_VLAN_Incl_Reg")]
pub type GmacgrpVlanInclReg = crate::Reg<gmacgrp_vlan_incl_reg::GmacgrpVlanInclRegSpec>;
#[doc = "The VLAN Tag Inclusion or Replacement register contains the VLAN tag for insertion or replacement in the transmit frames."]
pub mod gmacgrp_vlan_incl_reg;
#[doc = "gmacgrp_VLAN_Hash_Table_Reg (rw) register accessor: The 16-bit Hash table is used for group address filtering based on VLAN tag when Bit 18 (VTHM) of Register 7 (VLAN Tag Register) is set. For hash filtering, the content of the 16-bit VLAN tag or 12-bit VLAN ID (based on Bit 16 (ETV) of VLAN Tag Register) in the incoming frame is passed through the CRC logic and the upper four bits of the calculated CRC are used to index the contents of the VLAN Hash table. For example, a hash value of 4b'1000 selects Bit 8 of the VLAN Hash table. The hash value of the destination address is calculated in the following way: 1. Calculate the 32-bit CRC for the VLAN tag or ID (See IEEE 802.3, Section 3.2.8 for the steps to calculate CRC32). 2. Perform bitwise reversal for the value obtained in Step 1. 3. Take the upper four bits from the value obtained in Step 2. If the corresponding bit value of the register is 1'b1, the frame is accepted. Otherwise, it is rejected. Because the Hash Table register is double-synchronized to the (G)MII clock domain, the synchronization is triggered only when Bits\\[15:8\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of this register are written. Notes: * Because of double-synchronization, consecutive writes to this register should be performed after at least four clock cycles in the destination clock domain.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_vlan_hash_table_reg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_vlan_hash_table_reg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_vlan_hash_table_reg`]
module"]
#[doc(alias = "gmacgrp_VLAN_Hash_Table_Reg")]
pub type GmacgrpVlanHashTableReg =
    crate::Reg<gmacgrp_vlan_hash_table_reg::GmacgrpVlanHashTableRegSpec>;
#[doc = "The 16-bit Hash table is used for group address filtering based on VLAN tag when Bit 18 (VTHM) of Register 7 (VLAN Tag Register) is set. For hash filtering, the content of the 16-bit VLAN tag or 12-bit VLAN ID (based on Bit 16 (ETV) of VLAN Tag Register) in the incoming frame is passed through the CRC logic and the upper four bits of the calculated CRC are used to index the contents of the VLAN Hash table. For example, a hash value of 4b'1000 selects Bit 8 of the VLAN Hash table. The hash value of the destination address is calculated in the following way: 1. Calculate the 32-bit CRC for the VLAN tag or ID (See IEEE 802.3, Section 3.2.8 for the steps to calculate CRC32). 2. Perform bitwise reversal for the value obtained in Step 1. 3. Take the upper four bits from the value obtained in Step 2. If the corresponding bit value of the register is 1'b1, the frame is accepted. Otherwise, it is rejected. Because the Hash Table register is double-synchronized to the (G)MII clock domain, the synchronization is triggered only when Bits\\[15:8\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of this register are written. Notes: * Because of double-synchronization, consecutive writes to this register should be performed after at least four clock cycles in the destination clock domain."]
pub mod gmacgrp_vlan_hash_table_reg;
#[doc = "gmacgrp_Timestamp_Control (rw) register accessor: This register controls the operation of the System Time generator and the processing of PTP packets for timestamping in the Receiver.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_timestamp_control::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_timestamp_control::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_timestamp_control`]
module"]
#[doc(alias = "gmacgrp_Timestamp_Control")]
pub type GmacgrpTimestampControl =
    crate::Reg<gmacgrp_timestamp_control::GmacgrpTimestampControlSpec>;
#[doc = "This register controls the operation of the System Time generator and the processing of PTP packets for timestamping in the Receiver."]
pub mod gmacgrp_timestamp_control;
#[doc = "gmacgrp_Sub_Second_Increment (rw) register accessor: In the Coarse Update mode (TSCFUPDT bit in Register 448), the value in this register is added to the system time every clock cycle of clk_ptp_ref_i. In the Fine Update mode, the value in this register is added to the system time whenever the Accumulator gets an overflow.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_sub_second_increment::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_sub_second_increment::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_sub_second_increment`]
module"]
#[doc(alias = "gmacgrp_Sub_Second_Increment")]
pub type GmacgrpSubSecondIncrement =
    crate::Reg<gmacgrp_sub_second_increment::GmacgrpSubSecondIncrementSpec>;
#[doc = "In the Coarse Update mode (TSCFUPDT bit in Register 448), the value in this register is added to the system time every clock cycle of clk_ptp_ref_i. In the Fine Update mode, the value in this register is added to the system time whenever the Accumulator gets an overflow."]
pub mod gmacgrp_sub_second_increment;
#[doc = "gmacgrp_System_Time_Seconds (r) register accessor: The System Time -Seconds register, along with System-TimeNanoseconds register, indicates the current value of the system time maintained by the MAC. Though it is updated on a continuous basis, there is some delay from the actual time because of clock domain transfer latencies (from clk_ptp_ref_i to l3_sp_clk).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_system_time_seconds::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_system_time_seconds`]
module"]
#[doc(alias = "gmacgrp_System_Time_Seconds")]
pub type GmacgrpSystemTimeSeconds =
    crate::Reg<gmacgrp_system_time_seconds::GmacgrpSystemTimeSecondsSpec>;
#[doc = "The System Time -Seconds register, along with System-TimeNanoseconds register, indicates the current value of the system time maintained by the MAC. Though it is updated on a continuous basis, there is some delay from the actual time because of clock domain transfer latencies (from clk_ptp_ref_i to l3_sp_clk)."]
pub mod gmacgrp_system_time_seconds;
#[doc = "gmacgrp_System_Time_Nanoseconds (r) register accessor: The value in this field has the sub second representation of time, with an accuracy of 0.46 ns. When TSCTRLSSR is set, each bit represents 1 ns and the maximum value is 0x3B9A_C9FF, after which it rolls-over to zero.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_system_time_nanoseconds::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_system_time_nanoseconds`]
module"]
#[doc(alias = "gmacgrp_System_Time_Nanoseconds")]
pub type GmacgrpSystemTimeNanoseconds =
    crate::Reg<gmacgrp_system_time_nanoseconds::GmacgrpSystemTimeNanosecondsSpec>;
#[doc = "The value in this field has the sub second representation of time, with an accuracy of 0.46 ns. When TSCTRLSSR is set, each bit represents 1 ns and the maximum value is 0x3B9A_C9FF, after which it rolls-over to zero."]
pub mod gmacgrp_system_time_nanoseconds;
#[doc = "gmacgrp_System_Time_Seconds_Update (rw) register accessor: The System Time - Seconds Update register, along with the System Time - Nanoseconds Update register, initializes or updates the system time maintained by the MAC. You must write both of these registers before setting the TSINIT or TSUPDT bits in the Timestamp Control register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_system_time_seconds_update::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_system_time_seconds_update::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_system_time_seconds_update`]
module"]
#[doc(alias = "gmacgrp_System_Time_Seconds_Update")]
pub type GmacgrpSystemTimeSecondsUpdate =
    crate::Reg<gmacgrp_system_time_seconds_update::GmacgrpSystemTimeSecondsUpdateSpec>;
#[doc = "The System Time - Seconds Update register, along with the System Time - Nanoseconds Update register, initializes or updates the system time maintained by the MAC. You must write both of these registers before setting the TSINIT or TSUPDT bits in the Timestamp Control register."]
pub mod gmacgrp_system_time_seconds_update;
#[doc = "gmacgrp_System_Time_Nanoseconds_Update (rw) register accessor: Update system time\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_system_time_nanoseconds_update::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_system_time_nanoseconds_update::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_system_time_nanoseconds_update`]
module"]
#[doc(alias = "gmacgrp_System_Time_Nanoseconds_Update")]
pub type GmacgrpSystemTimeNanosecondsUpdate =
    crate::Reg<gmacgrp_system_time_nanoseconds_update::GmacgrpSystemTimeNanosecondsUpdateSpec>;
#[doc = "Update system time"]
pub mod gmacgrp_system_time_nanoseconds_update;
#[doc = "gmacgrp_Timestamp_Addend (rw) register accessor: This register value is used only when the system time is configured for Fine Update mode (TSCFUPDT bit in Register 448). This register content is added to a 32-bit accumulator in every clock cycle (of clk_ptp_ref_i) and the system time is updated whenever the accumulator overflows.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_timestamp_addend::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_timestamp_addend::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_timestamp_addend`]
module"]
#[doc(alias = "gmacgrp_Timestamp_Addend")]
pub type GmacgrpTimestampAddend = crate::Reg<gmacgrp_timestamp_addend::GmacgrpTimestampAddendSpec>;
#[doc = "This register value is used only when the system time is configured for Fine Update mode (TSCFUPDT bit in Register 448). This register content is added to a 32-bit accumulator in every clock cycle (of clk_ptp_ref_i) and the system time is updated whenever the accumulator overflows."]
pub mod gmacgrp_timestamp_addend;
#[doc = "gmacgrp_Target_Time_Seconds (rw) register accessor: The Target Time Seconds register, along with Target Time Nanoseconds register, is used to schedule an interrupt event (Register 458\\[1\\]
when Advanced Timestamping is enabled; otherwise, TS interrupt bit in Register14\\[9\\]) when the system time exceeds the value programmed in these registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_target_time_seconds::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_target_time_seconds::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_target_time_seconds`]
module"]
#[doc(alias = "gmacgrp_Target_Time_Seconds")]
pub type GmacgrpTargetTimeSeconds =
    crate::Reg<gmacgrp_target_time_seconds::GmacgrpTargetTimeSecondsSpec>;
#[doc = "The Target Time Seconds register, along with Target Time Nanoseconds register, is used to schedule an interrupt event (Register 458\\[1\\]
when Advanced Timestamping is enabled; otherwise, TS interrupt bit in Register14\\[9\\]) when the system time exceeds the value programmed in these registers."]
pub mod gmacgrp_target_time_seconds;
#[doc = "gmacgrp_Target_Time_Nanoseconds (rw) register accessor: Target time\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_target_time_nanoseconds::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_target_time_nanoseconds::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_target_time_nanoseconds`]
module"]
#[doc(alias = "gmacgrp_Target_Time_Nanoseconds")]
pub type GmacgrpTargetTimeNanoseconds =
    crate::Reg<gmacgrp_target_time_nanoseconds::GmacgrpTargetTimeNanosecondsSpec>;
#[doc = "Target time"]
pub mod gmacgrp_target_time_nanoseconds;
#[doc = "gmacgrp_System_Time_Higher_Word_Seconds (rw) register accessor: System time higher word\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_system_time_higher_word_seconds::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_system_time_higher_word_seconds::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_system_time_higher_word_seconds`]
module"]
#[doc(alias = "gmacgrp_System_Time_Higher_Word_Seconds")]
pub type GmacgrpSystemTimeHigherWordSeconds =
    crate::Reg<gmacgrp_system_time_higher_word_seconds::GmacgrpSystemTimeHigherWordSecondsSpec>;
#[doc = "System time higher word"]
pub mod gmacgrp_system_time_higher_word_seconds;
#[doc = "gmacgrp_Timestamp_Status (r) register accessor: Timestamp status. All bits except Bits\\[27:25\\]
get cleared when the host reads this register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_timestamp_status::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_timestamp_status`]
module"]
#[doc(alias = "gmacgrp_Timestamp_Status")]
pub type GmacgrpTimestampStatus = crate::Reg<gmacgrp_timestamp_status::GmacgrpTimestampStatusSpec>;
#[doc = "Timestamp status. All bits except Bits\\[27:25\\]
get cleared when the host reads this register."]
pub mod gmacgrp_timestamp_status;
#[doc = "gmacgrp_PPS_Control (rw) register accessor: Controls timestamp Pulse-Per-Second output\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_pps_control::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_pps_control::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_pps_control`]
module"]
#[doc(alias = "gmacgrp_PPS_Control")]
pub type GmacgrpPpsControl = crate::Reg<gmacgrp_pps_control::GmacgrpPpsControlSpec>;
#[doc = "Controls timestamp Pulse-Per-Second output"]
pub mod gmacgrp_pps_control;
#[doc = "gmacgrp_Auxiliary_Timestamp_Nanoseconds (r) register accessor: This register, along with Register 461 (Auxiliary Timestamp Seconds Register), gives the 64-bit timestamp stored as auxiliary snapshot. The two registers together form the read port of a 64-bit wide FIFO with a depth of 16. Multiple snapshots can be stored in this FIFO. The ATSNS bits in the Timestamp Status register indicate the fill-level of this FIFO. The top of the FIFO is removed only when the last byte of Register 461 (Auxiliary Timestamp - Seconds Register) is read. In the little-endian mode, this means when Bits\\[31:24\\]
are read. In big-endian mode, it corresponds to the reading of Bits\\[7:0\\]
of Register 461 (Auxiliary Timestamp - Seconds Register).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_auxiliary_timestamp_nanoseconds::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_auxiliary_timestamp_nanoseconds`]
module"]
#[doc(alias = "gmacgrp_Auxiliary_Timestamp_Nanoseconds")]
pub type GmacgrpAuxiliaryTimestampNanoseconds =
    crate::Reg<gmacgrp_auxiliary_timestamp_nanoseconds::GmacgrpAuxiliaryTimestampNanosecondsSpec>;
#[doc = "This register, along with Register 461 (Auxiliary Timestamp Seconds Register), gives the 64-bit timestamp stored as auxiliary snapshot. The two registers together form the read port of a 64-bit wide FIFO with a depth of 16. Multiple snapshots can be stored in this FIFO. The ATSNS bits in the Timestamp Status register indicate the fill-level of this FIFO. The top of the FIFO is removed only when the last byte of Register 461 (Auxiliary Timestamp - Seconds Register) is read. In the little-endian mode, this means when Bits\\[31:24\\]
are read. In big-endian mode, it corresponds to the reading of Bits\\[7:0\\]
of Register 461 (Auxiliary Timestamp - Seconds Register)."]
pub mod gmacgrp_auxiliary_timestamp_nanoseconds;
#[doc = "gmacgrp_Auxiliary_Timestamp_Seconds (r) register accessor: Contains the higher 32 bits (Seconds field) of the auxiliary timestamp.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_auxiliary_timestamp_seconds::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_auxiliary_timestamp_seconds`]
module"]
#[doc(alias = "gmacgrp_Auxiliary_Timestamp_Seconds")]
pub type GmacgrpAuxiliaryTimestampSeconds =
    crate::Reg<gmacgrp_auxiliary_timestamp_seconds::GmacgrpAuxiliaryTimestampSecondsSpec>;
#[doc = "Contains the higher 32 bits (Seconds field) of the auxiliary timestamp."]
pub mod gmacgrp_auxiliary_timestamp_seconds;
#[doc = "gmacgrp_PPS0_Interval (rw) register accessor: The PPS0 Interval register contains the number of units of sub-second increment value between the rising edges of PPS0 signal output (ptp_pps_o\\[0\\]).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_pps0_interval::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_pps0_interval::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_pps0_interval`]
module"]
#[doc(alias = "gmacgrp_PPS0_Interval")]
pub type GmacgrpPps0Interval = crate::Reg<gmacgrp_pps0_interval::GmacgrpPps0IntervalSpec>;
#[doc = "The PPS0 Interval register contains the number of units of sub-second increment value between the rising edges of PPS0 signal output (ptp_pps_o\\[0\\])."]
pub mod gmacgrp_pps0_interval;
#[doc = "gmacgrp_PPS0_Width (rw) register accessor: The PPS0 Width register contains the number of units of sub-second increment value between the rising and corresponding falling edges of the PPS0 signal output (ptp_pps_o\\[0\\]).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_pps0_width::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_pps0_width::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_pps0_width`]
module"]
#[doc(alias = "gmacgrp_PPS0_Width")]
pub type GmacgrpPps0Width = crate::Reg<gmacgrp_pps0_width::GmacgrpPps0WidthSpec>;
#[doc = "The PPS0 Width register contains the number of units of sub-second increment value between the rising and corresponding falling edges of the PPS0 signal output (ptp_pps_o\\[0\\])."]
pub mod gmacgrp_pps0_width;
#[doc = "gmacgrp_MAC_Address16_High (rw) register accessor: The MAC Address16 High register holds the upper 16 bits of the 17th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address16 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address16_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address16_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address16_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address16_High")]
pub type GmacgrpMacAddress16High =
    crate::Reg<gmacgrp_mac_address16_high::GmacgrpMacAddress16HighSpec>;
#[doc = "The MAC Address16 High register holds the upper 16 bits of the 17th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address16 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address16_high;
#[doc = "gmacgrp_MAC_Address16_Low (rw) register accessor: The MAC Address16 Low register holds the lower 32 bits of the 17th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address16_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address16_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address16_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address16_Low")]
pub type GmacgrpMacAddress16Low = crate::Reg<gmacgrp_mac_address16_low::GmacgrpMacAddress16LowSpec>;
#[doc = "The MAC Address16 Low register holds the lower 32 bits of the 17th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address16_low;
#[doc = "gmacgrp_MAC_Address17_High (rw) register accessor: The MAC Address17 High register holds the upper 16 bits of the 18th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address17 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address17_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address17_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address17_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address17_High")]
pub type GmacgrpMacAddress17High =
    crate::Reg<gmacgrp_mac_address17_high::GmacgrpMacAddress17HighSpec>;
#[doc = "The MAC Address17 High register holds the upper 16 bits of the 18th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address17 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address17_high;
#[doc = "gmacgrp_MAC_Address17_Low (rw) register accessor: The MAC Address17 Low register holds the lower 32 bits of the 18th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address17_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address17_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address17_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address17_Low")]
pub type GmacgrpMacAddress17Low = crate::Reg<gmacgrp_mac_address17_low::GmacgrpMacAddress17LowSpec>;
#[doc = "The MAC Address17 Low register holds the lower 32 bits of the 18th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address17_low;
#[doc = "gmacgrp_MAC_Address18_High (rw) register accessor: The MAC Address18 High register holds the upper 16 bits of the 19th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address18 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address18_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address18_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address18_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address18_High")]
pub type GmacgrpMacAddress18High =
    crate::Reg<gmacgrp_mac_address18_high::GmacgrpMacAddress18HighSpec>;
#[doc = "The MAC Address18 High register holds the upper 16 bits of the 19th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address18 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address18_high;
#[doc = "gmacgrp_MAC_Address18_Low (rw) register accessor: The MAC Address18 Low register holds the lower 32 bits of the 19th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address18_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address18_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address18_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address18_Low")]
pub type GmacgrpMacAddress18Low = crate::Reg<gmacgrp_mac_address18_low::GmacgrpMacAddress18LowSpec>;
#[doc = "The MAC Address18 Low register holds the lower 32 bits of the 19th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address18_low;
#[doc = "gmacgrp_MAC_Address19_High (rw) register accessor: The MAC Address19 High register holds the upper 16 bits of the 20th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address19 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address19_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address19_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address19_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address19_High")]
pub type GmacgrpMacAddress19High =
    crate::Reg<gmacgrp_mac_address19_high::GmacgrpMacAddress19HighSpec>;
#[doc = "The MAC Address19 High register holds the upper 16 bits of the 20th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address19 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address19_high;
#[doc = "gmacgrp_MAC_Address19_Low (rw) register accessor: The MAC Address19 Low register holds the lower 32 bits of the 20th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address19_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address19_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address19_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address19_Low")]
pub type GmacgrpMacAddress19Low = crate::Reg<gmacgrp_mac_address19_low::GmacgrpMacAddress19LowSpec>;
#[doc = "The MAC Address19 Low register holds the lower 32 bits of the 20th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address19_low;
#[doc = "gmacgrp_MAC_Address20_High (rw) register accessor: The MAC Address20 High register holds the upper 16 bits of the 21th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address20 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address20_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address20_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address20_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address20_High")]
pub type GmacgrpMacAddress20High =
    crate::Reg<gmacgrp_mac_address20_high::GmacgrpMacAddress20HighSpec>;
#[doc = "The MAC Address20 High register holds the upper 16 bits of the 21th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address20 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address20_high;
#[doc = "gmacgrp_MAC_Address20_Low (rw) register accessor: The MAC Address20 Low register holds the lower 32 bits of the 21th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address20_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address20_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address20_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address20_Low")]
pub type GmacgrpMacAddress20Low = crate::Reg<gmacgrp_mac_address20_low::GmacgrpMacAddress20LowSpec>;
#[doc = "The MAC Address20 Low register holds the lower 32 bits of the 21th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address20_low;
#[doc = "gmacgrp_MAC_Address21_High (rw) register accessor: The MAC Address21 High register holds the upper 16 bits of the 22th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address21 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address21_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address21_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address21_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address21_High")]
pub type GmacgrpMacAddress21High =
    crate::Reg<gmacgrp_mac_address21_high::GmacgrpMacAddress21HighSpec>;
#[doc = "The MAC Address21 High register holds the upper 16 bits of the 22th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address21 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address21_high;
#[doc = "gmacgrp_MAC_Address21_Low (rw) register accessor: The MAC Address21 Low register holds the lower 32 bits of the 22th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address21_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address21_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address21_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address21_Low")]
pub type GmacgrpMacAddress21Low = crate::Reg<gmacgrp_mac_address21_low::GmacgrpMacAddress21LowSpec>;
#[doc = "The MAC Address21 Low register holds the lower 32 bits of the 22th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address21_low;
#[doc = "gmacgrp_MAC_Address22_High (rw) register accessor: The MAC Address22 High register holds the upper 16 bits of the 23th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address22 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address22_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address22_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address22_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address22_High")]
pub type GmacgrpMacAddress22High =
    crate::Reg<gmacgrp_mac_address22_high::GmacgrpMacAddress22HighSpec>;
#[doc = "The MAC Address22 High register holds the upper 16 bits of the 23th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address22 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address22_high;
#[doc = "gmacgrp_MAC_Address22_Low (rw) register accessor: The MAC Address22 Low register holds the lower 32 bits of the 23th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address22_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address22_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address22_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address22_Low")]
pub type GmacgrpMacAddress22Low = crate::Reg<gmacgrp_mac_address22_low::GmacgrpMacAddress22LowSpec>;
#[doc = "The MAC Address22 Low register holds the lower 32 bits of the 23th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address22_low;
#[doc = "gmacgrp_MAC_Address23_High (rw) register accessor: The MAC Address23 High register holds the upper 16 bits of the 24th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address23 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address23_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address23_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address23_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address23_High")]
pub type GmacgrpMacAddress23High =
    crate::Reg<gmacgrp_mac_address23_high::GmacgrpMacAddress23HighSpec>;
#[doc = "The MAC Address23 High register holds the upper 16 bits of the 24th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address23 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address23_high;
#[doc = "gmacgrp_MAC_Address23_Low (rw) register accessor: The MAC Address23 Low register holds the lower 32 bits of the 24th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address23_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address23_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address23_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address23_Low")]
pub type GmacgrpMacAddress23Low = crate::Reg<gmacgrp_mac_address23_low::GmacgrpMacAddress23LowSpec>;
#[doc = "The MAC Address23 Low register holds the lower 32 bits of the 24th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address23_low;
#[doc = "gmacgrp_MAC_Address24_High (rw) register accessor: The MAC Address24 High register holds the upper 16 bits of the 25th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address24 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address24_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address24_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address24_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address24_High")]
pub type GmacgrpMacAddress24High =
    crate::Reg<gmacgrp_mac_address24_high::GmacgrpMacAddress24HighSpec>;
#[doc = "The MAC Address24 High register holds the upper 16 bits of the 25th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address24 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address24_high;
#[doc = "gmacgrp_MAC_Address24_Low (rw) register accessor: The MAC Address24 Low register holds the lower 32 bits of the 25th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address24_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address24_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address24_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address24_Low")]
pub type GmacgrpMacAddress24Low = crate::Reg<gmacgrp_mac_address24_low::GmacgrpMacAddress24LowSpec>;
#[doc = "The MAC Address24 Low register holds the lower 32 bits of the 25th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address24_low;
#[doc = "gmacgrp_MAC_Address25_High (rw) register accessor: The MAC Address25 High register holds the upper 16 bits of the 26th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address25 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address25_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address25_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address25_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address25_High")]
pub type GmacgrpMacAddress25High =
    crate::Reg<gmacgrp_mac_address25_high::GmacgrpMacAddress25HighSpec>;
#[doc = "The MAC Address25 High register holds the upper 16 bits of the 26th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address25 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address25_high;
#[doc = "gmacgrp_MAC_Address25_Low (rw) register accessor: The MAC Address25 Low register holds the lower 32 bits of the 26th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address25_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address25_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address25_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address25_Low")]
pub type GmacgrpMacAddress25Low = crate::Reg<gmacgrp_mac_address25_low::GmacgrpMacAddress25LowSpec>;
#[doc = "The MAC Address25 Low register holds the lower 32 bits of the 26th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address25_low;
#[doc = "gmacgrp_MAC_Address26_High (rw) register accessor: The MAC Address26 High register holds the upper 16 bits of the 27th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address26 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address26_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address26_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address26_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address26_High")]
pub type GmacgrpMacAddress26High =
    crate::Reg<gmacgrp_mac_address26_high::GmacgrpMacAddress26HighSpec>;
#[doc = "The MAC Address26 High register holds the upper 16 bits of the 27th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address26 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address26_high;
#[doc = "gmacgrp_MAC_Address26_Low (rw) register accessor: The MAC Address26 Low register holds the lower 32 bits of the 27th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address26_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address26_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address26_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address26_Low")]
pub type GmacgrpMacAddress26Low = crate::Reg<gmacgrp_mac_address26_low::GmacgrpMacAddress26LowSpec>;
#[doc = "The MAC Address26 Low register holds the lower 32 bits of the 27th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address26_low;
#[doc = "gmacgrp_MAC_Address27_High (rw) register accessor: The MAC Address27 High register holds the upper 16 bits of the 28th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address27 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address27_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address27_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address27_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address27_High")]
pub type GmacgrpMacAddress27High =
    crate::Reg<gmacgrp_mac_address27_high::GmacgrpMacAddress27HighSpec>;
#[doc = "The MAC Address27 High register holds the upper 16 bits of the 28th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address27 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address27_high;
#[doc = "gmacgrp_MAC_Address27_Low (rw) register accessor: The MAC Address27 Low register holds the lower 32 bits of the 28th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address27_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address27_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address27_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address27_Low")]
pub type GmacgrpMacAddress27Low = crate::Reg<gmacgrp_mac_address27_low::GmacgrpMacAddress27LowSpec>;
#[doc = "The MAC Address27 Low register holds the lower 32 bits of the 28th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address27_low;
#[doc = "gmacgrp_MAC_Address28_High (rw) register accessor: The MAC Address28 High register holds the upper 16 bits of the 29th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address28 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address28_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address28_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address28_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address28_High")]
pub type GmacgrpMacAddress28High =
    crate::Reg<gmacgrp_mac_address28_high::GmacgrpMacAddress28HighSpec>;
#[doc = "The MAC Address28 High register holds the upper 16 bits of the 29th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address28 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address28_high;
#[doc = "gmacgrp_MAC_Address28_Low (rw) register accessor: The MAC Address28 Low register holds the lower 32 bits of the 29th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address28_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address28_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address28_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address28_Low")]
pub type GmacgrpMacAddress28Low = crate::Reg<gmacgrp_mac_address28_low::GmacgrpMacAddress28LowSpec>;
#[doc = "The MAC Address28 Low register holds the lower 32 bits of the 29th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address28_low;
#[doc = "gmacgrp_MAC_Address29_High (rw) register accessor: The MAC Address29 High register holds the upper 16 bits of the 30th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address29 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address29_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address29_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address29_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address29_High")]
pub type GmacgrpMacAddress29High =
    crate::Reg<gmacgrp_mac_address29_high::GmacgrpMacAddress29HighSpec>;
#[doc = "The MAC Address29 High register holds the upper 16 bits of the 30th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address29 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address29_high;
#[doc = "gmacgrp_MAC_Address29_Low (rw) register accessor: The MAC Address29 Low register holds the lower 32 bits of the 30th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address29_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address29_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address29_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address29_Low")]
pub type GmacgrpMacAddress29Low = crate::Reg<gmacgrp_mac_address29_low::GmacgrpMacAddress29LowSpec>;
#[doc = "The MAC Address29 Low register holds the lower 32 bits of the 30th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address29_low;
#[doc = "gmacgrp_MAC_Address30_High (rw) register accessor: The MAC Address30 High register holds the upper 16 bits of the 31th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address30 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address30_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address30_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address30_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address30_High")]
pub type GmacgrpMacAddress30High =
    crate::Reg<gmacgrp_mac_address30_high::GmacgrpMacAddress30HighSpec>;
#[doc = "The MAC Address30 High register holds the upper 16 bits of the 31th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address30 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address30_high;
#[doc = "gmacgrp_MAC_Address30_Low (rw) register accessor: The MAC Address30 Low register holds the lower 32 bits of the 31th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address30_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address30_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address30_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address30_Low")]
pub type GmacgrpMacAddress30Low = crate::Reg<gmacgrp_mac_address30_low::GmacgrpMacAddress30LowSpec>;
#[doc = "The MAC Address30 Low register holds the lower 32 bits of the 31th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address30_low;
#[doc = "gmacgrp_MAC_Address31_High (rw) register accessor: The MAC Address31 High register holds the upper 16 bits of the 32th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address31 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address31_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address31_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address31_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address31_High")]
pub type GmacgrpMacAddress31High =
    crate::Reg<gmacgrp_mac_address31_high::GmacgrpMacAddress31HighSpec>;
#[doc = "The MAC Address31 High register holds the upper 16 bits of the 32th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address31 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address31_high;
#[doc = "gmacgrp_MAC_Address31_Low (rw) register accessor: The MAC Address31 Low register holds the lower 32 bits of the 32th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address31_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address31_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address31_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address31_Low")]
pub type GmacgrpMacAddress31Low = crate::Reg<gmacgrp_mac_address31_low::GmacgrpMacAddress31LowSpec>;
#[doc = "The MAC Address31 Low register holds the lower 32 bits of the 32th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address31_low;
#[doc = "gmacgrp_MAC_Address32_High (rw) register accessor: The MAC Address32 High register holds the upper 16 bits of the 33th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address32 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address32_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address32_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address32_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address32_High")]
pub type GmacgrpMacAddress32High =
    crate::Reg<gmacgrp_mac_address32_high::GmacgrpMacAddress32HighSpec>;
#[doc = "The MAC Address32 High register holds the upper 16 bits of the 33th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address32 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address32_high;
#[doc = "gmacgrp_MAC_Address32_Low (rw) register accessor: The MAC Address32 Low register holds the lower 32 bits of the 33th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address32_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address32_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address32_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address32_Low")]
pub type GmacgrpMacAddress32Low = crate::Reg<gmacgrp_mac_address32_low::GmacgrpMacAddress32LowSpec>;
#[doc = "The MAC Address32 Low register holds the lower 32 bits of the 33th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address32_low;
#[doc = "gmacgrp_MAC_Address33_High (rw) register accessor: The MAC Address33 High register holds the upper 16 bits of the 34th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address33 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address33_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address33_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address33_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address33_High")]
pub type GmacgrpMacAddress33High =
    crate::Reg<gmacgrp_mac_address33_high::GmacgrpMacAddress33HighSpec>;
#[doc = "The MAC Address33 High register holds the upper 16 bits of the 34th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address33 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address33_high;
#[doc = "gmacgrp_MAC_Address33_Low (rw) register accessor: The MAC Address33 Low register holds the lower 32 bits of the 34th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address33_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address33_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address33_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address33_Low")]
pub type GmacgrpMacAddress33Low = crate::Reg<gmacgrp_mac_address33_low::GmacgrpMacAddress33LowSpec>;
#[doc = "The MAC Address33 Low register holds the lower 32 bits of the 34th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address33_low;
#[doc = "gmacgrp_MAC_Address34_High (rw) register accessor: The MAC Address34 High register holds the upper 16 bits of the 35th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address34 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address34_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address34_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address34_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address34_High")]
pub type GmacgrpMacAddress34High =
    crate::Reg<gmacgrp_mac_address34_high::GmacgrpMacAddress34HighSpec>;
#[doc = "The MAC Address34 High register holds the upper 16 bits of the 35th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address34 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address34_high;
#[doc = "gmacgrp_MAC_Address34_Low (rw) register accessor: The MAC Address34 Low register holds the lower 32 bits of the 35th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address34_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address34_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address34_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address34_Low")]
pub type GmacgrpMacAddress34Low = crate::Reg<gmacgrp_mac_address34_low::GmacgrpMacAddress34LowSpec>;
#[doc = "The MAC Address34 Low register holds the lower 32 bits of the 35th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address34_low;
#[doc = "gmacgrp_MAC_Address35_High (rw) register accessor: The MAC Address35 High register holds the upper 16 bits of the 36th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address35 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address35_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address35_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address35_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address35_High")]
pub type GmacgrpMacAddress35High =
    crate::Reg<gmacgrp_mac_address35_high::GmacgrpMacAddress35HighSpec>;
#[doc = "The MAC Address35 High register holds the upper 16 bits of the 36th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address35 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address35_high;
#[doc = "gmacgrp_MAC_Address35_Low (rw) register accessor: The MAC Address35 Low register holds the lower 32 bits of the 36th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address35_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address35_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address35_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address35_Low")]
pub type GmacgrpMacAddress35Low = crate::Reg<gmacgrp_mac_address35_low::GmacgrpMacAddress35LowSpec>;
#[doc = "The MAC Address35 Low register holds the lower 32 bits of the 36th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address35_low;
#[doc = "gmacgrp_MAC_Address36_High (rw) register accessor: The MAC Address36 High register holds the upper 16 bits of the 37th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address36 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address36_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address36_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address36_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address36_High")]
pub type GmacgrpMacAddress36High =
    crate::Reg<gmacgrp_mac_address36_high::GmacgrpMacAddress36HighSpec>;
#[doc = "The MAC Address36 High register holds the upper 16 bits of the 37th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address36 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address36_high;
#[doc = "gmacgrp_MAC_Address36_Low (rw) register accessor: The MAC Address36 Low register holds the lower 32 bits of the 37th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address36_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address36_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address36_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address36_Low")]
pub type GmacgrpMacAddress36Low = crate::Reg<gmacgrp_mac_address36_low::GmacgrpMacAddress36LowSpec>;
#[doc = "The MAC Address36 Low register holds the lower 32 bits of the 37th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address36_low;
#[doc = "gmacgrp_MAC_Address37_High (rw) register accessor: The MAC Address37 High register holds the upper 16 bits of the 38th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address37 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address37_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address37_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address37_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address37_High")]
pub type GmacgrpMacAddress37High =
    crate::Reg<gmacgrp_mac_address37_high::GmacgrpMacAddress37HighSpec>;
#[doc = "The MAC Address37 High register holds the upper 16 bits of the 38th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address37 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address37_high;
#[doc = "gmacgrp_MAC_Address37_Low (rw) register accessor: The MAC Address37 Low register holds the lower 32 bits of the 38th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address37_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address37_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address37_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address37_Low")]
pub type GmacgrpMacAddress37Low = crate::Reg<gmacgrp_mac_address37_low::GmacgrpMacAddress37LowSpec>;
#[doc = "The MAC Address37 Low register holds the lower 32 bits of the 38th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address37_low;
#[doc = "gmacgrp_MAC_Address38_High (rw) register accessor: The MAC Address38 High register holds the upper 16 bits of the 39th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address38 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address38_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address38_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address38_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address38_High")]
pub type GmacgrpMacAddress38High =
    crate::Reg<gmacgrp_mac_address38_high::GmacgrpMacAddress38HighSpec>;
#[doc = "The MAC Address38 High register holds the upper 16 bits of the 39th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address38 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address38_high;
#[doc = "gmacgrp_MAC_Address38_Low (rw) register accessor: The MAC Address38 Low register holds the lower 32 bits of the 39th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address38_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address38_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address38_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address38_Low")]
pub type GmacgrpMacAddress38Low = crate::Reg<gmacgrp_mac_address38_low::GmacgrpMacAddress38LowSpec>;
#[doc = "The MAC Address38 Low register holds the lower 32 bits of the 39th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address38_low;
#[doc = "gmacgrp_MAC_Address39_High (rw) register accessor: The MAC Address39 High register holds the upper 16 bits of the 40th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address39 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address39_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address39_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address39_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address39_High")]
pub type GmacgrpMacAddress39High =
    crate::Reg<gmacgrp_mac_address39_high::GmacgrpMacAddress39HighSpec>;
#[doc = "The MAC Address39 High register holds the upper 16 bits of the 40th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address39 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address39_high;
#[doc = "gmacgrp_MAC_Address39_Low (rw) register accessor: The MAC Address39 Low register holds the lower 32 bits of the 40th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address39_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address39_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address39_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address39_Low")]
pub type GmacgrpMacAddress39Low = crate::Reg<gmacgrp_mac_address39_low::GmacgrpMacAddress39LowSpec>;
#[doc = "The MAC Address39 Low register holds the lower 32 bits of the 40th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address39_low;
#[doc = "gmacgrp_MAC_Address40_High (rw) register accessor: The MAC Address40 High register holds the upper 16 bits of the 41th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address40 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address40_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address40_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address40_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address40_High")]
pub type GmacgrpMacAddress40High =
    crate::Reg<gmacgrp_mac_address40_high::GmacgrpMacAddress40HighSpec>;
#[doc = "The MAC Address40 High register holds the upper 16 bits of the 41th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address40 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address40_high;
#[doc = "gmacgrp_MAC_Address40_Low (rw) register accessor: The MAC Address40 Low register holds the lower 32 bits of the 41th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address40_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address40_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address40_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address40_Low")]
pub type GmacgrpMacAddress40Low = crate::Reg<gmacgrp_mac_address40_low::GmacgrpMacAddress40LowSpec>;
#[doc = "The MAC Address40 Low register holds the lower 32 bits of the 41th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address40_low;
#[doc = "gmacgrp_MAC_Address41_High (rw) register accessor: The MAC Address41 High register holds the upper 16 bits of the 42th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address41 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address41_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address41_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address41_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address41_High")]
pub type GmacgrpMacAddress41High =
    crate::Reg<gmacgrp_mac_address41_high::GmacgrpMacAddress41HighSpec>;
#[doc = "The MAC Address41 High register holds the upper 16 bits of the 42th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address41 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address41_high;
#[doc = "gmacgrp_MAC_Address41_Low (rw) register accessor: The MAC Address41 Low register holds the lower 32 bits of the 42th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address41_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address41_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address41_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address41_Low")]
pub type GmacgrpMacAddress41Low = crate::Reg<gmacgrp_mac_address41_low::GmacgrpMacAddress41LowSpec>;
#[doc = "The MAC Address41 Low register holds the lower 32 bits of the 42th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address41_low;
#[doc = "gmacgrp_MAC_Address42_High (rw) register accessor: The MAC Address42 High register holds the upper 16 bits of the 43th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address42 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address42_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address42_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address42_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address42_High")]
pub type GmacgrpMacAddress42High =
    crate::Reg<gmacgrp_mac_address42_high::GmacgrpMacAddress42HighSpec>;
#[doc = "The MAC Address42 High register holds the upper 16 bits of the 43th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address42 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address42_high;
#[doc = "gmacgrp_MAC_Address42_Low (rw) register accessor: The MAC Address42 Low register holds the lower 32 bits of the 43th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address42_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address42_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address42_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address42_Low")]
pub type GmacgrpMacAddress42Low = crate::Reg<gmacgrp_mac_address42_low::GmacgrpMacAddress42LowSpec>;
#[doc = "The MAC Address42 Low register holds the lower 32 bits of the 43th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address42_low;
#[doc = "gmacgrp_MAC_Address43_High (rw) register accessor: The MAC Address43 High register holds the upper 16 bits of the 44th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address43 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address43_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address43_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address43_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address43_High")]
pub type GmacgrpMacAddress43High =
    crate::Reg<gmacgrp_mac_address43_high::GmacgrpMacAddress43HighSpec>;
#[doc = "The MAC Address43 High register holds the upper 16 bits of the 44th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address43 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address43_high;
#[doc = "gmacgrp_MAC_Address43_Low (rw) register accessor: The MAC Address43 Low register holds the lower 32 bits of the 44th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address43_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address43_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address43_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address43_Low")]
pub type GmacgrpMacAddress43Low = crate::Reg<gmacgrp_mac_address43_low::GmacgrpMacAddress43LowSpec>;
#[doc = "The MAC Address43 Low register holds the lower 32 bits of the 44th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address43_low;
#[doc = "gmacgrp_MAC_Address44_High (rw) register accessor: The MAC Address44 High register holds the upper 16 bits of the 45th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address44 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address44_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address44_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address44_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address44_High")]
pub type GmacgrpMacAddress44High =
    crate::Reg<gmacgrp_mac_address44_high::GmacgrpMacAddress44HighSpec>;
#[doc = "The MAC Address44 High register holds the upper 16 bits of the 45th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address44 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address44_high;
#[doc = "gmacgrp_MAC_Address44_Low (rw) register accessor: The MAC Address44 Low register holds the lower 32 bits of the 45th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address44_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address44_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address44_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address44_Low")]
pub type GmacgrpMacAddress44Low = crate::Reg<gmacgrp_mac_address44_low::GmacgrpMacAddress44LowSpec>;
#[doc = "The MAC Address44 Low register holds the lower 32 bits of the 45th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address44_low;
#[doc = "gmacgrp_MAC_Address45_High (rw) register accessor: The MAC Address45 High register holds the upper 16 bits of the 46th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address45 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address45_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address45_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address45_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address45_High")]
pub type GmacgrpMacAddress45High =
    crate::Reg<gmacgrp_mac_address45_high::GmacgrpMacAddress45HighSpec>;
#[doc = "The MAC Address45 High register holds the upper 16 bits of the 46th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address45 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address45_high;
#[doc = "gmacgrp_MAC_Address45_Low (rw) register accessor: The MAC Address45 Low register holds the lower 32 bits of the 46th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address45_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address45_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address45_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address45_Low")]
pub type GmacgrpMacAddress45Low = crate::Reg<gmacgrp_mac_address45_low::GmacgrpMacAddress45LowSpec>;
#[doc = "The MAC Address45 Low register holds the lower 32 bits of the 46th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address45_low;
#[doc = "gmacgrp_MAC_Address46_High (rw) register accessor: The MAC Address46 High register holds the upper 16 bits of the 47th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address46 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address46_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address46_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address46_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address46_High")]
pub type GmacgrpMacAddress46High =
    crate::Reg<gmacgrp_mac_address46_high::GmacgrpMacAddress46HighSpec>;
#[doc = "The MAC Address46 High register holds the upper 16 bits of the 47th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address46 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address46_high;
#[doc = "gmacgrp_MAC_Address46_Low (rw) register accessor: The MAC Address46 Low register holds the lower 32 bits of the 47th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address46_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address46_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address46_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address46_Low")]
pub type GmacgrpMacAddress46Low = crate::Reg<gmacgrp_mac_address46_low::GmacgrpMacAddress46LowSpec>;
#[doc = "The MAC Address46 Low register holds the lower 32 bits of the 47th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address46_low;
#[doc = "gmacgrp_MAC_Address47_High (rw) register accessor: The MAC Address47 High register holds the upper 16 bits of the 48th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address47 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address47_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address47_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address47_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address47_High")]
pub type GmacgrpMacAddress47High =
    crate::Reg<gmacgrp_mac_address47_high::GmacgrpMacAddress47HighSpec>;
#[doc = "The MAC Address47 High register holds the upper 16 bits of the 48th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address47 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address47_high;
#[doc = "gmacgrp_MAC_Address47_Low (rw) register accessor: The MAC Address47 Low register holds the lower 32 bits of the 48th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address47_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address47_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address47_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address47_Low")]
pub type GmacgrpMacAddress47Low = crate::Reg<gmacgrp_mac_address47_low::GmacgrpMacAddress47LowSpec>;
#[doc = "The MAC Address47 Low register holds the lower 32 bits of the 48th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address47_low;
#[doc = "gmacgrp_MAC_Address48_High (rw) register accessor: The MAC Address48 High register holds the upper 16 bits of the 49th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address48 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address48_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address48_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address48_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address48_High")]
pub type GmacgrpMacAddress48High =
    crate::Reg<gmacgrp_mac_address48_high::GmacgrpMacAddress48HighSpec>;
#[doc = "The MAC Address48 High register holds the upper 16 bits of the 49th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address48 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address48_high;
#[doc = "gmacgrp_MAC_Address48_Low (rw) register accessor: The MAC Address48 Low register holds the lower 32 bits of the 49th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address48_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address48_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address48_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address48_Low")]
pub type GmacgrpMacAddress48Low = crate::Reg<gmacgrp_mac_address48_low::GmacgrpMacAddress48LowSpec>;
#[doc = "The MAC Address48 Low register holds the lower 32 bits of the 49th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address48_low;
#[doc = "gmacgrp_MAC_Address49_High (rw) register accessor: The MAC Address49 High register holds the upper 16 bits of the 50th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address49 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address49_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address49_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address49_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address49_High")]
pub type GmacgrpMacAddress49High =
    crate::Reg<gmacgrp_mac_address49_high::GmacgrpMacAddress49HighSpec>;
#[doc = "The MAC Address49 High register holds the upper 16 bits of the 50th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address49 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address49_high;
#[doc = "gmacgrp_MAC_Address49_Low (rw) register accessor: The MAC Address49 Low register holds the lower 32 bits of the 50th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address49_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address49_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address49_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address49_Low")]
pub type GmacgrpMacAddress49Low = crate::Reg<gmacgrp_mac_address49_low::GmacgrpMacAddress49LowSpec>;
#[doc = "The MAC Address49 Low register holds the lower 32 bits of the 50th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address49_low;
#[doc = "gmacgrp_MAC_Address50_High (rw) register accessor: The MAC Address50 High register holds the upper 16 bits of the 51th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address50 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address50_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address50_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address50_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address50_High")]
pub type GmacgrpMacAddress50High =
    crate::Reg<gmacgrp_mac_address50_high::GmacgrpMacAddress50HighSpec>;
#[doc = "The MAC Address50 High register holds the upper 16 bits of the 51th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address50 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address50_high;
#[doc = "gmacgrp_MAC_Address50_Low (rw) register accessor: The MAC Address50 Low register holds the lower 32 bits of the 51th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address50_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address50_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address50_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address50_Low")]
pub type GmacgrpMacAddress50Low = crate::Reg<gmacgrp_mac_address50_low::GmacgrpMacAddress50LowSpec>;
#[doc = "The MAC Address50 Low register holds the lower 32 bits of the 51th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address50_low;
#[doc = "gmacgrp_MAC_Address51_High (rw) register accessor: The MAC Address51 High register holds the upper 16 bits of the 52th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address51 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address51_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address51_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address51_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address51_High")]
pub type GmacgrpMacAddress51High =
    crate::Reg<gmacgrp_mac_address51_high::GmacgrpMacAddress51HighSpec>;
#[doc = "The MAC Address51 High register holds the upper 16 bits of the 52th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address51 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address51_high;
#[doc = "gmacgrp_MAC_Address51_Low (rw) register accessor: The MAC Address51 Low register holds the lower 32 bits of the 52th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address51_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address51_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address51_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address51_Low")]
pub type GmacgrpMacAddress51Low = crate::Reg<gmacgrp_mac_address51_low::GmacgrpMacAddress51LowSpec>;
#[doc = "The MAC Address51 Low register holds the lower 32 bits of the 52th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address51_low;
#[doc = "gmacgrp_MAC_Address52_High (rw) register accessor: The MAC Address52 High register holds the upper 16 bits of the 53th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address52 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address52_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address52_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address52_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address52_High")]
pub type GmacgrpMacAddress52High =
    crate::Reg<gmacgrp_mac_address52_high::GmacgrpMacAddress52HighSpec>;
#[doc = "The MAC Address52 High register holds the upper 16 bits of the 53th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address52 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address52_high;
#[doc = "gmacgrp_MAC_Address52_Low (rw) register accessor: The MAC Address52 Low register holds the lower 32 bits of the 53th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address52_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address52_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address52_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address52_Low")]
pub type GmacgrpMacAddress52Low = crate::Reg<gmacgrp_mac_address52_low::GmacgrpMacAddress52LowSpec>;
#[doc = "The MAC Address52 Low register holds the lower 32 bits of the 53th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address52_low;
#[doc = "gmacgrp_MAC_Address53_High (rw) register accessor: The MAC Address53 High register holds the upper 16 bits of the 54th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address53 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address53_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address53_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address53_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address53_High")]
pub type GmacgrpMacAddress53High =
    crate::Reg<gmacgrp_mac_address53_high::GmacgrpMacAddress53HighSpec>;
#[doc = "The MAC Address53 High register holds the upper 16 bits of the 54th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address53 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address53_high;
#[doc = "gmacgrp_MAC_Address53_Low (rw) register accessor: The MAC Address53 Low register holds the lower 32 bits of the 54th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address53_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address53_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address53_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address53_Low")]
pub type GmacgrpMacAddress53Low = crate::Reg<gmacgrp_mac_address53_low::GmacgrpMacAddress53LowSpec>;
#[doc = "The MAC Address53 Low register holds the lower 32 bits of the 54th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address53_low;
#[doc = "gmacgrp_MAC_Address54_High (rw) register accessor: The MAC Address54 High register holds the upper 16 bits of the 55th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address54 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address54_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address54_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address54_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address54_High")]
pub type GmacgrpMacAddress54High =
    crate::Reg<gmacgrp_mac_address54_high::GmacgrpMacAddress54HighSpec>;
#[doc = "The MAC Address54 High register holds the upper 16 bits of the 55th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address54 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address54_high;
#[doc = "gmacgrp_MAC_Address54_Low (rw) register accessor: The MAC Address54 Low register holds the lower 32 bits of the 55th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address54_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address54_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address54_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address54_Low")]
pub type GmacgrpMacAddress54Low = crate::Reg<gmacgrp_mac_address54_low::GmacgrpMacAddress54LowSpec>;
#[doc = "The MAC Address54 Low register holds the lower 32 bits of the 55th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address54_low;
#[doc = "gmacgrp_MAC_Address55_High (rw) register accessor: The MAC Address55 High register holds the upper 16 bits of the 56th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address55 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address55_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address55_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address55_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address55_High")]
pub type GmacgrpMacAddress55High =
    crate::Reg<gmacgrp_mac_address55_high::GmacgrpMacAddress55HighSpec>;
#[doc = "The MAC Address55 High register holds the upper 16 bits of the 56th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address55 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address55_high;
#[doc = "gmacgrp_MAC_Address55_Low (rw) register accessor: The MAC Address55 Low register holds the lower 32 bits of the 56th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address55_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address55_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address55_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address55_Low")]
pub type GmacgrpMacAddress55Low = crate::Reg<gmacgrp_mac_address55_low::GmacgrpMacAddress55LowSpec>;
#[doc = "The MAC Address55 Low register holds the lower 32 bits of the 56th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address55_low;
#[doc = "gmacgrp_MAC_Address56_High (rw) register accessor: The MAC Address56 High register holds the upper 16 bits of the 57th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address56 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address56_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address56_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address56_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address56_High")]
pub type GmacgrpMacAddress56High =
    crate::Reg<gmacgrp_mac_address56_high::GmacgrpMacAddress56HighSpec>;
#[doc = "The MAC Address56 High register holds the upper 16 bits of the 57th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address56 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address56_high;
#[doc = "gmacgrp_MAC_Address56_Low (rw) register accessor: The MAC Address56 Low register holds the lower 32 bits of the 57th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address56_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address56_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address56_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address56_Low")]
pub type GmacgrpMacAddress56Low = crate::Reg<gmacgrp_mac_address56_low::GmacgrpMacAddress56LowSpec>;
#[doc = "The MAC Address56 Low register holds the lower 32 bits of the 57th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address56_low;
#[doc = "gmacgrp_MAC_Address57_High (rw) register accessor: The MAC Address57 High register holds the upper 16 bits of the 58th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address57 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address57_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address57_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address57_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address57_High")]
pub type GmacgrpMacAddress57High =
    crate::Reg<gmacgrp_mac_address57_high::GmacgrpMacAddress57HighSpec>;
#[doc = "The MAC Address57 High register holds the upper 16 bits of the 58th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address57 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address57_high;
#[doc = "gmacgrp_MAC_Address57_Low (rw) register accessor: The MAC Address57 Low register holds the lower 32 bits of the 58th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address57_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address57_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address57_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address57_Low")]
pub type GmacgrpMacAddress57Low = crate::Reg<gmacgrp_mac_address57_low::GmacgrpMacAddress57LowSpec>;
#[doc = "The MAC Address57 Low register holds the lower 32 bits of the 58th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address57_low;
#[doc = "gmacgrp_MAC_Address58_High (rw) register accessor: The MAC Address58 High register holds the upper 16 bits of the 59th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address58 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address58_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address58_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address58_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address58_High")]
pub type GmacgrpMacAddress58High =
    crate::Reg<gmacgrp_mac_address58_high::GmacgrpMacAddress58HighSpec>;
#[doc = "The MAC Address58 High register holds the upper 16 bits of the 59th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address58 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address58_high;
#[doc = "gmacgrp_MAC_Address58_Low (rw) register accessor: The MAC Address58 Low register holds the lower 32 bits of the 59th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address58_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address58_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address58_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address58_Low")]
pub type GmacgrpMacAddress58Low = crate::Reg<gmacgrp_mac_address58_low::GmacgrpMacAddress58LowSpec>;
#[doc = "The MAC Address58 Low register holds the lower 32 bits of the 59th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address58_low;
#[doc = "gmacgrp_MAC_Address59_High (rw) register accessor: The MAC Address59 High register holds the upper 16 bits of the 60th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address59 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address59_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address59_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address59_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address59_High")]
pub type GmacgrpMacAddress59High =
    crate::Reg<gmacgrp_mac_address59_high::GmacgrpMacAddress59HighSpec>;
#[doc = "The MAC Address59 High register holds the upper 16 bits of the 60th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address59 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address59_high;
#[doc = "gmacgrp_MAC_Address59_Low (rw) register accessor: The MAC Address59 Low register holds the lower 32 bits of the 60th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address59_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address59_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address59_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address59_Low")]
pub type GmacgrpMacAddress59Low = crate::Reg<gmacgrp_mac_address59_low::GmacgrpMacAddress59LowSpec>;
#[doc = "The MAC Address59 Low register holds the lower 32 bits of the 60th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address59_low;
#[doc = "gmacgrp_MAC_Address60_High (rw) register accessor: The MAC Address60 High register holds the upper 16 bits of the 61th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address60 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address60_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address60_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address60_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address60_High")]
pub type GmacgrpMacAddress60High =
    crate::Reg<gmacgrp_mac_address60_high::GmacgrpMacAddress60HighSpec>;
#[doc = "The MAC Address60 High register holds the upper 16 bits of the 61th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address60 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address60_high;
#[doc = "gmacgrp_MAC_Address60_Low (rw) register accessor: The MAC Address60 Low register holds the lower 32 bits of the 61th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address60_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address60_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address60_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address60_Low")]
pub type GmacgrpMacAddress60Low = crate::Reg<gmacgrp_mac_address60_low::GmacgrpMacAddress60LowSpec>;
#[doc = "The MAC Address60 Low register holds the lower 32 bits of the 61th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address60_low;
#[doc = "gmacgrp_MAC_Address61_High (rw) register accessor: The MAC Address61 High register holds the upper 16 bits of the 62th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address61 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address61_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address61_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address61_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address61_High")]
pub type GmacgrpMacAddress61High =
    crate::Reg<gmacgrp_mac_address61_high::GmacgrpMacAddress61HighSpec>;
#[doc = "The MAC Address61 High register holds the upper 16 bits of the 62th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address61 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address61_high;
#[doc = "gmacgrp_MAC_Address61_Low (rw) register accessor: The MAC Address61 Low register holds the lower 32 bits of the 62th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address61_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address61_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address61_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address61_Low")]
pub type GmacgrpMacAddress61Low = crate::Reg<gmacgrp_mac_address61_low::GmacgrpMacAddress61LowSpec>;
#[doc = "The MAC Address61 Low register holds the lower 32 bits of the 62th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address61_low;
#[doc = "gmacgrp_MAC_Address62_High (rw) register accessor: The MAC Address62 High register holds the upper 16 bits of the 63th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address62 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address62_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address62_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address62_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address62_High")]
pub type GmacgrpMacAddress62High =
    crate::Reg<gmacgrp_mac_address62_high::GmacgrpMacAddress62HighSpec>;
#[doc = "The MAC Address62 High register holds the upper 16 bits of the 63th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address62 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address62_high;
#[doc = "gmacgrp_MAC_Address62_Low (rw) register accessor: The MAC Address62 Low register holds the lower 32 bits of the 63th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address62_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address62_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address62_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address62_Low")]
pub type GmacgrpMacAddress62Low = crate::Reg<gmacgrp_mac_address62_low::GmacgrpMacAddress62LowSpec>;
#[doc = "The MAC Address62 Low register holds the lower 32 bits of the 63th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address62_low;
#[doc = "gmacgrp_MAC_Address63_High (rw) register accessor: The MAC Address63 High register holds the upper 16 bits of the 64th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address63 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address63_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address63_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address63_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address63_High")]
pub type GmacgrpMacAddress63High =
    crate::Reg<gmacgrp_mac_address63_high::GmacgrpMacAddress63HighSpec>;
#[doc = "The MAC Address63 High register holds the upper 16 bits of the 64th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address63 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address63_high;
#[doc = "gmacgrp_MAC_Address63_Low (rw) register accessor: The MAC Address63 Low register holds the lower 32 bits of the 64th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address63_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address63_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address63_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address63_Low")]
pub type GmacgrpMacAddress63Low = crate::Reg<gmacgrp_mac_address63_low::GmacgrpMacAddress63LowSpec>;
#[doc = "The MAC Address63 Low register holds the lower 32 bits of the 64th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address63_low;
#[doc = "gmacgrp_MAC_Address64_High (rw) register accessor: The MAC Address64 High register holds the upper 16 bits of the 65th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address64 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address64_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address64_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address64_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address64_High")]
pub type GmacgrpMacAddress64High =
    crate::Reg<gmacgrp_mac_address64_high::GmacgrpMacAddress64HighSpec>;
#[doc = "The MAC Address64 High register holds the upper 16 bits of the 65th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address64 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address64_high;
#[doc = "gmacgrp_MAC_Address64_Low (rw) register accessor: The MAC Address64 Low register holds the lower 32 bits of the 65th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address64_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address64_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address64_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address64_Low")]
pub type GmacgrpMacAddress64Low = crate::Reg<gmacgrp_mac_address64_low::GmacgrpMacAddress64LowSpec>;
#[doc = "The MAC Address64 Low register holds the lower 32 bits of the 65th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address64_low;
#[doc = "gmacgrp_MAC_Address65_High (rw) register accessor: The MAC Address65 High register holds the upper 16 bits of the 66th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address65 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address65_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address65_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address65_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address65_High")]
pub type GmacgrpMacAddress65High =
    crate::Reg<gmacgrp_mac_address65_high::GmacgrpMacAddress65HighSpec>;
#[doc = "The MAC Address65 High register holds the upper 16 bits of the 66th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address65 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address65_high;
#[doc = "gmacgrp_MAC_Address65_Low (rw) register accessor: The MAC Address65 Low register holds the lower 32 bits of the 66th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address65_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address65_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address65_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address65_Low")]
pub type GmacgrpMacAddress65Low = crate::Reg<gmacgrp_mac_address65_low::GmacgrpMacAddress65LowSpec>;
#[doc = "The MAC Address65 Low register holds the lower 32 bits of the 66th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address65_low;
#[doc = "gmacgrp_MAC_Address66_High (rw) register accessor: The MAC Address66 High register holds the upper 16 bits of the 67th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address66 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address66_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address66_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address66_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address66_High")]
pub type GmacgrpMacAddress66High =
    crate::Reg<gmacgrp_mac_address66_high::GmacgrpMacAddress66HighSpec>;
#[doc = "The MAC Address66 High register holds the upper 16 bits of the 67th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address66 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address66_high;
#[doc = "gmacgrp_MAC_Address66_Low (rw) register accessor: The MAC Address66 Low register holds the lower 32 bits of the 67th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address66_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address66_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address66_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address66_Low")]
pub type GmacgrpMacAddress66Low = crate::Reg<gmacgrp_mac_address66_low::GmacgrpMacAddress66LowSpec>;
#[doc = "The MAC Address66 Low register holds the lower 32 bits of the 67th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address66_low;
#[doc = "gmacgrp_MAC_Address67_High (rw) register accessor: The MAC Address67 High register holds the upper 16 bits of the 68th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address67 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address67_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address67_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address67_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address67_High")]
pub type GmacgrpMacAddress67High =
    crate::Reg<gmacgrp_mac_address67_high::GmacgrpMacAddress67HighSpec>;
#[doc = "The MAC Address67 High register holds the upper 16 bits of the 68th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address67 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address67_high;
#[doc = "gmacgrp_MAC_Address67_Low (rw) register accessor: The MAC Address67 Low register holds the lower 32 bits of the 68th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address67_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address67_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address67_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address67_Low")]
pub type GmacgrpMacAddress67Low = crate::Reg<gmacgrp_mac_address67_low::GmacgrpMacAddress67LowSpec>;
#[doc = "The MAC Address67 Low register holds the lower 32 bits of the 68th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address67_low;
#[doc = "gmacgrp_MAC_Address68_High (rw) register accessor: The MAC Address68 High register holds the upper 16 bits of the 69th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address68 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address68_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address68_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address68_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address68_High")]
pub type GmacgrpMacAddress68High =
    crate::Reg<gmacgrp_mac_address68_high::GmacgrpMacAddress68HighSpec>;
#[doc = "The MAC Address68 High register holds the upper 16 bits of the 69th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address68 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address68_high;
#[doc = "gmacgrp_MAC_Address68_Low (rw) register accessor: The MAC Address68 Low register holds the lower 32 bits of the 69th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address68_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address68_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address68_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address68_Low")]
pub type GmacgrpMacAddress68Low = crate::Reg<gmacgrp_mac_address68_low::GmacgrpMacAddress68LowSpec>;
#[doc = "The MAC Address68 Low register holds the lower 32 bits of the 69th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address68_low;
#[doc = "gmacgrp_MAC_Address69_High (rw) register accessor: The MAC Address69 High register holds the upper 16 bits of the 70th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address69 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address69_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address69_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address69_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address69_High")]
pub type GmacgrpMacAddress69High =
    crate::Reg<gmacgrp_mac_address69_high::GmacgrpMacAddress69HighSpec>;
#[doc = "The MAC Address69 High register holds the upper 16 bits of the 70th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address69 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address69_high;
#[doc = "gmacgrp_MAC_Address69_Low (rw) register accessor: The MAC Address69 Low register holds the lower 32 bits of the 70th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address69_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address69_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address69_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address69_Low")]
pub type GmacgrpMacAddress69Low = crate::Reg<gmacgrp_mac_address69_low::GmacgrpMacAddress69LowSpec>;
#[doc = "The MAC Address69 Low register holds the lower 32 bits of the 70th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address69_low;
#[doc = "gmacgrp_MAC_Address70_High (rw) register accessor: The MAC Address70 High register holds the upper 16 bits of the 71th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address70 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address70_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address70_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address70_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address70_High")]
pub type GmacgrpMacAddress70High =
    crate::Reg<gmacgrp_mac_address70_high::GmacgrpMacAddress70HighSpec>;
#[doc = "The MAC Address70 High register holds the upper 16 bits of the 71th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address70 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address70_high;
#[doc = "gmacgrp_MAC_Address70_Low (rw) register accessor: The MAC Address70 Low register holds the lower 32 bits of the 71th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address70_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address70_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address70_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address70_Low")]
pub type GmacgrpMacAddress70Low = crate::Reg<gmacgrp_mac_address70_low::GmacgrpMacAddress70LowSpec>;
#[doc = "The MAC Address70 Low register holds the lower 32 bits of the 71th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address70_low;
#[doc = "gmacgrp_MAC_Address71_High (rw) register accessor: The MAC Address71 High register holds the upper 16 bits of the 72th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address71 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address71_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address71_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address71_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address71_High")]
pub type GmacgrpMacAddress71High =
    crate::Reg<gmacgrp_mac_address71_high::GmacgrpMacAddress71HighSpec>;
#[doc = "The MAC Address71 High register holds the upper 16 bits of the 72th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address71 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address71_high;
#[doc = "gmacgrp_MAC_Address71_Low (rw) register accessor: The MAC Address71 Low register holds the lower 32 bits of the 72th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address71_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address71_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address71_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address71_Low")]
pub type GmacgrpMacAddress71Low = crate::Reg<gmacgrp_mac_address71_low::GmacgrpMacAddress71LowSpec>;
#[doc = "The MAC Address71 Low register holds the lower 32 bits of the 72th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address71_low;
#[doc = "gmacgrp_MAC_Address72_High (rw) register accessor: The MAC Address72 High register holds the upper 16 bits of the 73th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address72 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address72_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address72_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address72_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address72_High")]
pub type GmacgrpMacAddress72High =
    crate::Reg<gmacgrp_mac_address72_high::GmacgrpMacAddress72HighSpec>;
#[doc = "The MAC Address72 High register holds the upper 16 bits of the 73th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address72 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address72_high;
#[doc = "gmacgrp_MAC_Address72_Low (rw) register accessor: The MAC Address72 Low register holds the lower 32 bits of the 73th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address72_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address72_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address72_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address72_Low")]
pub type GmacgrpMacAddress72Low = crate::Reg<gmacgrp_mac_address72_low::GmacgrpMacAddress72LowSpec>;
#[doc = "The MAC Address72 Low register holds the lower 32 bits of the 73th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address72_low;
#[doc = "gmacgrp_MAC_Address73_High (rw) register accessor: The MAC Address73 High register holds the upper 16 bits of the 74th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address73 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address73_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address73_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address73_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address73_High")]
pub type GmacgrpMacAddress73High =
    crate::Reg<gmacgrp_mac_address73_high::GmacgrpMacAddress73HighSpec>;
#[doc = "The MAC Address73 High register holds the upper 16 bits of the 74th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address73 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address73_high;
#[doc = "gmacgrp_MAC_Address73_Low (rw) register accessor: The MAC Address73 Low register holds the lower 32 bits of the 74th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address73_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address73_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address73_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address73_Low")]
pub type GmacgrpMacAddress73Low = crate::Reg<gmacgrp_mac_address73_low::GmacgrpMacAddress73LowSpec>;
#[doc = "The MAC Address73 Low register holds the lower 32 bits of the 74th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address73_low;
#[doc = "gmacgrp_MAC_Address74_High (rw) register accessor: The MAC Address74 High register holds the upper 16 bits of the 75th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address74 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address74_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address74_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address74_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address74_High")]
pub type GmacgrpMacAddress74High =
    crate::Reg<gmacgrp_mac_address74_high::GmacgrpMacAddress74HighSpec>;
#[doc = "The MAC Address74 High register holds the upper 16 bits of the 75th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address74 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address74_high;
#[doc = "gmacgrp_MAC_Address74_Low (rw) register accessor: The MAC Address74 Low register holds the lower 32 bits of the 75th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address74_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address74_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address74_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address74_Low")]
pub type GmacgrpMacAddress74Low = crate::Reg<gmacgrp_mac_address74_low::GmacgrpMacAddress74LowSpec>;
#[doc = "The MAC Address74 Low register holds the lower 32 bits of the 75th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address74_low;
#[doc = "gmacgrp_MAC_Address75_High (rw) register accessor: The MAC Address75 High register holds the upper 16 bits of the 76th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address75 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address75_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address75_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address75_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address75_High")]
pub type GmacgrpMacAddress75High =
    crate::Reg<gmacgrp_mac_address75_high::GmacgrpMacAddress75HighSpec>;
#[doc = "The MAC Address75 High register holds the upper 16 bits of the 76th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address75 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address75_high;
#[doc = "gmacgrp_MAC_Address75_Low (rw) register accessor: The MAC Address75 Low register holds the lower 32 bits of the 76th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address75_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address75_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address75_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address75_Low")]
pub type GmacgrpMacAddress75Low = crate::Reg<gmacgrp_mac_address75_low::GmacgrpMacAddress75LowSpec>;
#[doc = "The MAC Address75 Low register holds the lower 32 bits of the 76th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address75_low;
#[doc = "gmacgrp_MAC_Address76_High (rw) register accessor: The MAC Address76 High register holds the upper 16 bits of the 77th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address76 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address76_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address76_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address76_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address76_High")]
pub type GmacgrpMacAddress76High =
    crate::Reg<gmacgrp_mac_address76_high::GmacgrpMacAddress76HighSpec>;
#[doc = "The MAC Address76 High register holds the upper 16 bits of the 77th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address76 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address76_high;
#[doc = "gmacgrp_MAC_Address76_Low (rw) register accessor: The MAC Address76 Low register holds the lower 32 bits of the 77th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address76_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address76_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address76_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address76_Low")]
pub type GmacgrpMacAddress76Low = crate::Reg<gmacgrp_mac_address76_low::GmacgrpMacAddress76LowSpec>;
#[doc = "The MAC Address76 Low register holds the lower 32 bits of the 77th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address76_low;
#[doc = "gmacgrp_MAC_Address77_High (rw) register accessor: The MAC Address77 High register holds the upper 16 bits of the 78th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address77 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address77_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address77_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address77_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address77_High")]
pub type GmacgrpMacAddress77High =
    crate::Reg<gmacgrp_mac_address77_high::GmacgrpMacAddress77HighSpec>;
#[doc = "The MAC Address77 High register holds the upper 16 bits of the 78th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address77 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address77_high;
#[doc = "gmacgrp_MAC_Address77_Low (rw) register accessor: The MAC Address77 Low register holds the lower 32 bits of the 78th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address77_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address77_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address77_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address77_Low")]
pub type GmacgrpMacAddress77Low = crate::Reg<gmacgrp_mac_address77_low::GmacgrpMacAddress77LowSpec>;
#[doc = "The MAC Address77 Low register holds the lower 32 bits of the 78th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address77_low;
#[doc = "gmacgrp_MAC_Address78_High (rw) register accessor: The MAC Address78 High register holds the upper 16 bits of the 79th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address78 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address78_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address78_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address78_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address78_High")]
pub type GmacgrpMacAddress78High =
    crate::Reg<gmacgrp_mac_address78_high::GmacgrpMacAddress78HighSpec>;
#[doc = "The MAC Address78 High register holds the upper 16 bits of the 79th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address78 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address78_high;
#[doc = "gmacgrp_MAC_Address78_Low (rw) register accessor: The MAC Address78 Low register holds the lower 32 bits of the 79th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address78_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address78_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address78_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address78_Low")]
pub type GmacgrpMacAddress78Low = crate::Reg<gmacgrp_mac_address78_low::GmacgrpMacAddress78LowSpec>;
#[doc = "The MAC Address78 Low register holds the lower 32 bits of the 79th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address78_low;
#[doc = "gmacgrp_MAC_Address79_High (rw) register accessor: The MAC Address79 High register holds the upper 16 bits of the 80th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address79 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address79_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address79_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address79_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address79_High")]
pub type GmacgrpMacAddress79High =
    crate::Reg<gmacgrp_mac_address79_high::GmacgrpMacAddress79HighSpec>;
#[doc = "The MAC Address79 High register holds the upper 16 bits of the 80th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address79 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address79_high;
#[doc = "gmacgrp_MAC_Address79_Low (rw) register accessor: The MAC Address79 Low register holds the lower 32 bits of the 80th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address79_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address79_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address79_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address79_Low")]
pub type GmacgrpMacAddress79Low = crate::Reg<gmacgrp_mac_address79_low::GmacgrpMacAddress79LowSpec>;
#[doc = "The MAC Address79 Low register holds the lower 32 bits of the 80th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address79_low;
#[doc = "gmacgrp_MAC_Address80_High (rw) register accessor: The MAC Address80 High register holds the upper 16 bits of the 81th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address80 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address80_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address80_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address80_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address80_High")]
pub type GmacgrpMacAddress80High =
    crate::Reg<gmacgrp_mac_address80_high::GmacgrpMacAddress80HighSpec>;
#[doc = "The MAC Address80 High register holds the upper 16 bits of the 81th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address80 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address80_high;
#[doc = "gmacgrp_MAC_Address80_Low (rw) register accessor: The MAC Address80 Low register holds the lower 32 bits of the 81th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address80_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address80_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address80_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address80_Low")]
pub type GmacgrpMacAddress80Low = crate::Reg<gmacgrp_mac_address80_low::GmacgrpMacAddress80LowSpec>;
#[doc = "The MAC Address80 Low register holds the lower 32 bits of the 81th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address80_low;
#[doc = "gmacgrp_MAC_Address81_High (rw) register accessor: The MAC Address81 High register holds the upper 16 bits of the 82th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address81 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address81_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address81_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address81_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address81_High")]
pub type GmacgrpMacAddress81High =
    crate::Reg<gmacgrp_mac_address81_high::GmacgrpMacAddress81HighSpec>;
#[doc = "The MAC Address81 High register holds the upper 16 bits of the 82th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address81 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address81_high;
#[doc = "gmacgrp_MAC_Address81_Low (rw) register accessor: The MAC Address81 Low register holds the lower 32 bits of the 82th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address81_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address81_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address81_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address81_Low")]
pub type GmacgrpMacAddress81Low = crate::Reg<gmacgrp_mac_address81_low::GmacgrpMacAddress81LowSpec>;
#[doc = "The MAC Address81 Low register holds the lower 32 bits of the 82th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address81_low;
#[doc = "gmacgrp_MAC_Address82_High (rw) register accessor: The MAC Address82 High register holds the upper 16 bits of the 83th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address82 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address82_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address82_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address82_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address82_High")]
pub type GmacgrpMacAddress82High =
    crate::Reg<gmacgrp_mac_address82_high::GmacgrpMacAddress82HighSpec>;
#[doc = "The MAC Address82 High register holds the upper 16 bits of the 83th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address82 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address82_high;
#[doc = "gmacgrp_MAC_Address82_Low (rw) register accessor: The MAC Address82 Low register holds the lower 32 bits of the 83th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address82_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address82_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address82_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address82_Low")]
pub type GmacgrpMacAddress82Low = crate::Reg<gmacgrp_mac_address82_low::GmacgrpMacAddress82LowSpec>;
#[doc = "The MAC Address82 Low register holds the lower 32 bits of the 83th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address82_low;
#[doc = "gmacgrp_MAC_Address83_High (rw) register accessor: The MAC Address83 High register holds the upper 16 bits of the 84th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address83 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address83_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address83_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address83_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address83_High")]
pub type GmacgrpMacAddress83High =
    crate::Reg<gmacgrp_mac_address83_high::GmacgrpMacAddress83HighSpec>;
#[doc = "The MAC Address83 High register holds the upper 16 bits of the 84th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address83 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address83_high;
#[doc = "gmacgrp_MAC_Address83_Low (rw) register accessor: The MAC Address83 Low register holds the lower 32 bits of the 84th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address83_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address83_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address83_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address83_Low")]
pub type GmacgrpMacAddress83Low = crate::Reg<gmacgrp_mac_address83_low::GmacgrpMacAddress83LowSpec>;
#[doc = "The MAC Address83 Low register holds the lower 32 bits of the 84th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address83_low;
#[doc = "gmacgrp_MAC_Address84_High (rw) register accessor: The MAC Address84 High register holds the upper 16 bits of the 85th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address84 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address84_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address84_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address84_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address84_High")]
pub type GmacgrpMacAddress84High =
    crate::Reg<gmacgrp_mac_address84_high::GmacgrpMacAddress84HighSpec>;
#[doc = "The MAC Address84 High register holds the upper 16 bits of the 85th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address84 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address84_high;
#[doc = "gmacgrp_MAC_Address84_Low (rw) register accessor: The MAC Address84 Low register holds the lower 32 bits of the 85th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address84_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address84_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address84_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address84_Low")]
pub type GmacgrpMacAddress84Low = crate::Reg<gmacgrp_mac_address84_low::GmacgrpMacAddress84LowSpec>;
#[doc = "The MAC Address84 Low register holds the lower 32 bits of the 85th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address84_low;
#[doc = "gmacgrp_MAC_Address85_High (rw) register accessor: The MAC Address85 High register holds the upper 16 bits of the 86th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address85 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address85_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address85_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address85_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address85_High")]
pub type GmacgrpMacAddress85High =
    crate::Reg<gmacgrp_mac_address85_high::GmacgrpMacAddress85HighSpec>;
#[doc = "The MAC Address85 High register holds the upper 16 bits of the 86th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address85 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address85_high;
#[doc = "gmacgrp_MAC_Address85_Low (rw) register accessor: The MAC Address85 Low register holds the lower 32 bits of the 86th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address85_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address85_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address85_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address85_Low")]
pub type GmacgrpMacAddress85Low = crate::Reg<gmacgrp_mac_address85_low::GmacgrpMacAddress85LowSpec>;
#[doc = "The MAC Address85 Low register holds the lower 32 bits of the 86th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address85_low;
#[doc = "gmacgrp_MAC_Address86_High (rw) register accessor: The MAC Address86 High register holds the upper 16 bits of the 87th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address86 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address86_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address86_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address86_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address86_High")]
pub type GmacgrpMacAddress86High =
    crate::Reg<gmacgrp_mac_address86_high::GmacgrpMacAddress86HighSpec>;
#[doc = "The MAC Address86 High register holds the upper 16 bits of the 87th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address86 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address86_high;
#[doc = "gmacgrp_MAC_Address86_Low (rw) register accessor: The MAC Address86 Low register holds the lower 32 bits of the 87th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address86_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address86_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address86_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address86_Low")]
pub type GmacgrpMacAddress86Low = crate::Reg<gmacgrp_mac_address86_low::GmacgrpMacAddress86LowSpec>;
#[doc = "The MAC Address86 Low register holds the lower 32 bits of the 87th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address86_low;
#[doc = "gmacgrp_MAC_Address87_High (rw) register accessor: The MAC Address87 High register holds the upper 16 bits of the 88th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address87 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address87_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address87_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address87_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address87_High")]
pub type GmacgrpMacAddress87High =
    crate::Reg<gmacgrp_mac_address87_high::GmacgrpMacAddress87HighSpec>;
#[doc = "The MAC Address87 High register holds the upper 16 bits of the 88th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address87 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address87_high;
#[doc = "gmacgrp_MAC_Address87_Low (rw) register accessor: The MAC Address87 Low register holds the lower 32 bits of the 88th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address87_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address87_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address87_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address87_Low")]
pub type GmacgrpMacAddress87Low = crate::Reg<gmacgrp_mac_address87_low::GmacgrpMacAddress87LowSpec>;
#[doc = "The MAC Address87 Low register holds the lower 32 bits of the 88th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address87_low;
#[doc = "gmacgrp_MAC_Address88_High (rw) register accessor: The MAC Address88 High register holds the upper 16 bits of the 89th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address88 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address88_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address88_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address88_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address88_High")]
pub type GmacgrpMacAddress88High =
    crate::Reg<gmacgrp_mac_address88_high::GmacgrpMacAddress88HighSpec>;
#[doc = "The MAC Address88 High register holds the upper 16 bits of the 89th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address88 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address88_high;
#[doc = "gmacgrp_MAC_Address88_Low (rw) register accessor: The MAC Address88 Low register holds the lower 32 bits of the 89th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address88_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address88_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address88_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address88_Low")]
pub type GmacgrpMacAddress88Low = crate::Reg<gmacgrp_mac_address88_low::GmacgrpMacAddress88LowSpec>;
#[doc = "The MAC Address88 Low register holds the lower 32 bits of the 89th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address88_low;
#[doc = "gmacgrp_MAC_Address89_High (rw) register accessor: The MAC Address89 High register holds the upper 16 bits of the 90th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address89 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address89_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address89_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address89_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address89_High")]
pub type GmacgrpMacAddress89High =
    crate::Reg<gmacgrp_mac_address89_high::GmacgrpMacAddress89HighSpec>;
#[doc = "The MAC Address89 High register holds the upper 16 bits of the 90th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address89 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address89_high;
#[doc = "gmacgrp_MAC_Address89_Low (rw) register accessor: The MAC Address89 Low register holds the lower 32 bits of the 90th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address89_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address89_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address89_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address89_Low")]
pub type GmacgrpMacAddress89Low = crate::Reg<gmacgrp_mac_address89_low::GmacgrpMacAddress89LowSpec>;
#[doc = "The MAC Address89 Low register holds the lower 32 bits of the 90th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address89_low;
#[doc = "gmacgrp_MAC_Address90_High (rw) register accessor: The MAC Address90 High register holds the upper 16 bits of the 91th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address90 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address90_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address90_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address90_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address90_High")]
pub type GmacgrpMacAddress90High =
    crate::Reg<gmacgrp_mac_address90_high::GmacgrpMacAddress90HighSpec>;
#[doc = "The MAC Address90 High register holds the upper 16 bits of the 91th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address90 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address90_high;
#[doc = "gmacgrp_MAC_Address90_Low (rw) register accessor: The MAC Address90 Low register holds the lower 32 bits of the 91th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address90_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address90_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address90_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address90_Low")]
pub type GmacgrpMacAddress90Low = crate::Reg<gmacgrp_mac_address90_low::GmacgrpMacAddress90LowSpec>;
#[doc = "The MAC Address90 Low register holds the lower 32 bits of the 91th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address90_low;
#[doc = "gmacgrp_MAC_Address91_High (rw) register accessor: The MAC Address91 High register holds the upper 16 bits of the 92th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address91 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address91_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address91_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address91_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address91_High")]
pub type GmacgrpMacAddress91High =
    crate::Reg<gmacgrp_mac_address91_high::GmacgrpMacAddress91HighSpec>;
#[doc = "The MAC Address91 High register holds the upper 16 bits of the 92th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address91 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address91_high;
#[doc = "gmacgrp_MAC_Address91_Low (rw) register accessor: The MAC Address91 Low register holds the lower 32 bits of the 92th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address91_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address91_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address91_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address91_Low")]
pub type GmacgrpMacAddress91Low = crate::Reg<gmacgrp_mac_address91_low::GmacgrpMacAddress91LowSpec>;
#[doc = "The MAC Address91 Low register holds the lower 32 bits of the 92th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address91_low;
#[doc = "gmacgrp_MAC_Address92_High (rw) register accessor: The MAC Address92 High register holds the upper 16 bits of the 93th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address92 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address92_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address92_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address92_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address92_High")]
pub type GmacgrpMacAddress92High =
    crate::Reg<gmacgrp_mac_address92_high::GmacgrpMacAddress92HighSpec>;
#[doc = "The MAC Address92 High register holds the upper 16 bits of the 93th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address92 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address92_high;
#[doc = "gmacgrp_MAC_Address92_Low (rw) register accessor: The MAC Address92 Low register holds the lower 32 bits of the 93th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address92_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address92_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address92_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address92_Low")]
pub type GmacgrpMacAddress92Low = crate::Reg<gmacgrp_mac_address92_low::GmacgrpMacAddress92LowSpec>;
#[doc = "The MAC Address92 Low register holds the lower 32 bits of the 93th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address92_low;
#[doc = "gmacgrp_MAC_Address93_High (rw) register accessor: The MAC Address93 High register holds the upper 16 bits of the 94th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address93 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address93_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address93_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address93_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address93_High")]
pub type GmacgrpMacAddress93High =
    crate::Reg<gmacgrp_mac_address93_high::GmacgrpMacAddress93HighSpec>;
#[doc = "The MAC Address93 High register holds the upper 16 bits of the 94th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address93 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address93_high;
#[doc = "gmacgrp_MAC_Address93_Low (rw) register accessor: The MAC Address93 Low register holds the lower 32 bits of the 94th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address93_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address93_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address93_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address93_Low")]
pub type GmacgrpMacAddress93Low = crate::Reg<gmacgrp_mac_address93_low::GmacgrpMacAddress93LowSpec>;
#[doc = "The MAC Address93 Low register holds the lower 32 bits of the 94th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address93_low;
#[doc = "gmacgrp_MAC_Address94_High (rw) register accessor: The MAC Address94 High register holds the upper 16 bits of the 95th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address94 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address94_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address94_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address94_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address94_High")]
pub type GmacgrpMacAddress94High =
    crate::Reg<gmacgrp_mac_address94_high::GmacgrpMacAddress94HighSpec>;
#[doc = "The MAC Address94 High register holds the upper 16 bits of the 95th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address94 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address94_high;
#[doc = "gmacgrp_MAC_Address94_Low (rw) register accessor: The MAC Address94 Low register holds the lower 32 bits of the 95th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address94_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address94_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address94_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address94_Low")]
pub type GmacgrpMacAddress94Low = crate::Reg<gmacgrp_mac_address94_low::GmacgrpMacAddress94LowSpec>;
#[doc = "The MAC Address94 Low register holds the lower 32 bits of the 95th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address94_low;
#[doc = "gmacgrp_MAC_Address95_High (rw) register accessor: The MAC Address95 High register holds the upper 16 bits of the 96th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address95 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address95_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address95_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address95_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address95_High")]
pub type GmacgrpMacAddress95High =
    crate::Reg<gmacgrp_mac_address95_high::GmacgrpMacAddress95HighSpec>;
#[doc = "The MAC Address95 High register holds the upper 16 bits of the 96th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address95 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address95_high;
#[doc = "gmacgrp_MAC_Address95_Low (rw) register accessor: The MAC Address95 Low register holds the lower 32 bits of the 96th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address95_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address95_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address95_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address95_Low")]
pub type GmacgrpMacAddress95Low = crate::Reg<gmacgrp_mac_address95_low::GmacgrpMacAddress95LowSpec>;
#[doc = "The MAC Address95 Low register holds the lower 32 bits of the 96th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address95_low;
#[doc = "gmacgrp_MAC_Address96_High (rw) register accessor: The MAC Address96 High register holds the upper 16 bits of the 97th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address96 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address96_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address96_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address96_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address96_High")]
pub type GmacgrpMacAddress96High =
    crate::Reg<gmacgrp_mac_address96_high::GmacgrpMacAddress96HighSpec>;
#[doc = "The MAC Address96 High register holds the upper 16 bits of the 97th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address96 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address96_high;
#[doc = "gmacgrp_MAC_Address96_Low (rw) register accessor: The MAC Address96 Low register holds the lower 32 bits of the 97th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address96_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address96_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address96_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address96_Low")]
pub type GmacgrpMacAddress96Low = crate::Reg<gmacgrp_mac_address96_low::GmacgrpMacAddress96LowSpec>;
#[doc = "The MAC Address96 Low register holds the lower 32 bits of the 97th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address96_low;
#[doc = "gmacgrp_MAC_Address97_High (rw) register accessor: The MAC Address97 High register holds the upper 16 bits of the 98th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address97 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address97_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address97_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address97_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address97_High")]
pub type GmacgrpMacAddress97High =
    crate::Reg<gmacgrp_mac_address97_high::GmacgrpMacAddress97HighSpec>;
#[doc = "The MAC Address97 High register holds the upper 16 bits of the 98th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address97 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address97_high;
#[doc = "gmacgrp_MAC_Address97_Low (rw) register accessor: The MAC Address97 Low register holds the lower 32 bits of the 98th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address97_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address97_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address97_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address97_Low")]
pub type GmacgrpMacAddress97Low = crate::Reg<gmacgrp_mac_address97_low::GmacgrpMacAddress97LowSpec>;
#[doc = "The MAC Address97 Low register holds the lower 32 bits of the 98th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address97_low;
#[doc = "gmacgrp_MAC_Address98_High (rw) register accessor: The MAC Address98 High register holds the upper 16 bits of the 99th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address98 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address98_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address98_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address98_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address98_High")]
pub type GmacgrpMacAddress98High =
    crate::Reg<gmacgrp_mac_address98_high::GmacgrpMacAddress98HighSpec>;
#[doc = "The MAC Address98 High register holds the upper 16 bits of the 99th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address98 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address98_high;
#[doc = "gmacgrp_MAC_Address98_Low (rw) register accessor: The MAC Address98 Low register holds the lower 32 bits of the 99th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address98_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address98_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address98_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address98_Low")]
pub type GmacgrpMacAddress98Low = crate::Reg<gmacgrp_mac_address98_low::GmacgrpMacAddress98LowSpec>;
#[doc = "The MAC Address98 Low register holds the lower 32 bits of the 99th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address98_low;
#[doc = "gmacgrp_MAC_Address99_High (rw) register accessor: The MAC Address99 High register holds the upper 16 bits of the 100th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address99 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address99_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address99_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address99_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address99_High")]
pub type GmacgrpMacAddress99High =
    crate::Reg<gmacgrp_mac_address99_high::GmacgrpMacAddress99HighSpec>;
#[doc = "The MAC Address99 High register holds the upper 16 bits of the 100th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address99 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address99_high;
#[doc = "gmacgrp_MAC_Address99_Low (rw) register accessor: The MAC Address99 Low register holds the lower 32 bits of the 100th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address99_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address99_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address99_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address99_Low")]
pub type GmacgrpMacAddress99Low = crate::Reg<gmacgrp_mac_address99_low::GmacgrpMacAddress99LowSpec>;
#[doc = "The MAC Address99 Low register holds the lower 32 bits of the 100th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address99_low;
#[doc = "gmacgrp_MAC_Address100_High (rw) register accessor: The MAC Address100 High register holds the upper 16 bits of the 101th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address100 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address100_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address100_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address100_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address100_High")]
pub type GmacgrpMacAddress100High =
    crate::Reg<gmacgrp_mac_address100_high::GmacgrpMacAddress100HighSpec>;
#[doc = "The MAC Address100 High register holds the upper 16 bits of the 101th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address100 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address100_high;
#[doc = "gmacgrp_MAC_Address100_Low (rw) register accessor: The MAC Address100 Low register holds the lower 32 bits of the 101th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address100_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address100_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address100_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address100_Low")]
pub type GmacgrpMacAddress100Low =
    crate::Reg<gmacgrp_mac_address100_low::GmacgrpMacAddress100LowSpec>;
#[doc = "The MAC Address100 Low register holds the lower 32 bits of the 101th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address100_low;
#[doc = "gmacgrp_MAC_Address101_High (rw) register accessor: The MAC Address101 High register holds the upper 16 bits of the 102th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address101 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address101_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address101_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address101_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address101_High")]
pub type GmacgrpMacAddress101High =
    crate::Reg<gmacgrp_mac_address101_high::GmacgrpMacAddress101HighSpec>;
#[doc = "The MAC Address101 High register holds the upper 16 bits of the 102th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address101 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address101_high;
#[doc = "gmacgrp_MAC_Address101_Low (rw) register accessor: The MAC Address101 Low register holds the lower 32 bits of the 102th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address101_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address101_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address101_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address101_Low")]
pub type GmacgrpMacAddress101Low =
    crate::Reg<gmacgrp_mac_address101_low::GmacgrpMacAddress101LowSpec>;
#[doc = "The MAC Address101 Low register holds the lower 32 bits of the 102th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address101_low;
#[doc = "gmacgrp_MAC_Address102_High (rw) register accessor: The MAC Address102 High register holds the upper 16 bits of the 103th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address102 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address102_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address102_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address102_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address102_High")]
pub type GmacgrpMacAddress102High =
    crate::Reg<gmacgrp_mac_address102_high::GmacgrpMacAddress102HighSpec>;
#[doc = "The MAC Address102 High register holds the upper 16 bits of the 103th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address102 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address102_high;
#[doc = "gmacgrp_MAC_Address102_Low (rw) register accessor: The MAC Address102 Low register holds the lower 32 bits of the 103th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address102_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address102_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address102_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address102_Low")]
pub type GmacgrpMacAddress102Low =
    crate::Reg<gmacgrp_mac_address102_low::GmacgrpMacAddress102LowSpec>;
#[doc = "The MAC Address102 Low register holds the lower 32 bits of the 103th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address102_low;
#[doc = "gmacgrp_MAC_Address103_High (rw) register accessor: The MAC Address103 High register holds the upper 16 bits of the 104th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address103 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address103_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address103_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address103_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address103_High")]
pub type GmacgrpMacAddress103High =
    crate::Reg<gmacgrp_mac_address103_high::GmacgrpMacAddress103HighSpec>;
#[doc = "The MAC Address103 High register holds the upper 16 bits of the 104th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address103 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address103_high;
#[doc = "gmacgrp_MAC_Address103_Low (rw) register accessor: The MAC Address103 Low register holds the lower 32 bits of the 104th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address103_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address103_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address103_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address103_Low")]
pub type GmacgrpMacAddress103Low =
    crate::Reg<gmacgrp_mac_address103_low::GmacgrpMacAddress103LowSpec>;
#[doc = "The MAC Address103 Low register holds the lower 32 bits of the 104th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address103_low;
#[doc = "gmacgrp_MAC_Address104_High (rw) register accessor: The MAC Address104 High register holds the upper 16 bits of the 105th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address104 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address104_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address104_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address104_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address104_High")]
pub type GmacgrpMacAddress104High =
    crate::Reg<gmacgrp_mac_address104_high::GmacgrpMacAddress104HighSpec>;
#[doc = "The MAC Address104 High register holds the upper 16 bits of the 105th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address104 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address104_high;
#[doc = "gmacgrp_MAC_Address104_Low (rw) register accessor: The MAC Address104 Low register holds the lower 32 bits of the 105th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address104_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address104_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address104_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address104_Low")]
pub type GmacgrpMacAddress104Low =
    crate::Reg<gmacgrp_mac_address104_low::GmacgrpMacAddress104LowSpec>;
#[doc = "The MAC Address104 Low register holds the lower 32 bits of the 105th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address104_low;
#[doc = "gmacgrp_MAC_Address105_High (rw) register accessor: The MAC Address105 High register holds the upper 16 bits of the 106th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address105 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address105_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address105_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address105_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address105_High")]
pub type GmacgrpMacAddress105High =
    crate::Reg<gmacgrp_mac_address105_high::GmacgrpMacAddress105HighSpec>;
#[doc = "The MAC Address105 High register holds the upper 16 bits of the 106th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address105 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address105_high;
#[doc = "gmacgrp_MAC_Address105_Low (rw) register accessor: The MAC Address105 Low register holds the lower 32 bits of the 106th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address105_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address105_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address105_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address105_Low")]
pub type GmacgrpMacAddress105Low =
    crate::Reg<gmacgrp_mac_address105_low::GmacgrpMacAddress105LowSpec>;
#[doc = "The MAC Address105 Low register holds the lower 32 bits of the 106th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address105_low;
#[doc = "gmacgrp_MAC_Address106_High (rw) register accessor: The MAC Address106 High register holds the upper 16 bits of the 107th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address106 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address106_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address106_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address106_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address106_High")]
pub type GmacgrpMacAddress106High =
    crate::Reg<gmacgrp_mac_address106_high::GmacgrpMacAddress106HighSpec>;
#[doc = "The MAC Address106 High register holds the upper 16 bits of the 107th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address106 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address106_high;
#[doc = "gmacgrp_MAC_Address106_Low (rw) register accessor: The MAC Address106 Low register holds the lower 32 bits of the 107th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address106_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address106_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address106_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address106_Low")]
pub type GmacgrpMacAddress106Low =
    crate::Reg<gmacgrp_mac_address106_low::GmacgrpMacAddress106LowSpec>;
#[doc = "The MAC Address106 Low register holds the lower 32 bits of the 107th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address106_low;
#[doc = "gmacgrp_MAC_Address107_High (rw) register accessor: The MAC Address107 High register holds the upper 16 bits of the 108th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address107 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address107_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address107_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address107_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address107_High")]
pub type GmacgrpMacAddress107High =
    crate::Reg<gmacgrp_mac_address107_high::GmacgrpMacAddress107HighSpec>;
#[doc = "The MAC Address107 High register holds the upper 16 bits of the 108th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address107 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address107_high;
#[doc = "gmacgrp_MAC_Address107_Low (rw) register accessor: The MAC Address107 Low register holds the lower 32 bits of the 108th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address107_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address107_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address107_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address107_Low")]
pub type GmacgrpMacAddress107Low =
    crate::Reg<gmacgrp_mac_address107_low::GmacgrpMacAddress107LowSpec>;
#[doc = "The MAC Address107 Low register holds the lower 32 bits of the 108th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address107_low;
#[doc = "gmacgrp_MAC_Address108_High (rw) register accessor: The MAC Address108 High register holds the upper 16 bits of the 109th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address108 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address108_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address108_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address108_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address108_High")]
pub type GmacgrpMacAddress108High =
    crate::Reg<gmacgrp_mac_address108_high::GmacgrpMacAddress108HighSpec>;
#[doc = "The MAC Address108 High register holds the upper 16 bits of the 109th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address108 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address108_high;
#[doc = "gmacgrp_MAC_Address108_Low (rw) register accessor: The MAC Address108 Low register holds the lower 32 bits of the 109th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address108_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address108_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address108_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address108_Low")]
pub type GmacgrpMacAddress108Low =
    crate::Reg<gmacgrp_mac_address108_low::GmacgrpMacAddress108LowSpec>;
#[doc = "The MAC Address108 Low register holds the lower 32 bits of the 109th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address108_low;
#[doc = "gmacgrp_MAC_Address109_High (rw) register accessor: The MAC Address109 High register holds the upper 16 bits of the 110th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address109 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address109_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address109_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address109_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address109_High")]
pub type GmacgrpMacAddress109High =
    crate::Reg<gmacgrp_mac_address109_high::GmacgrpMacAddress109HighSpec>;
#[doc = "The MAC Address109 High register holds the upper 16 bits of the 110th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address109 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address109_high;
#[doc = "gmacgrp_MAC_Address109_Low (rw) register accessor: The MAC Address109 Low register holds the lower 32 bits of the 110th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address109_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address109_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address109_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address109_Low")]
pub type GmacgrpMacAddress109Low =
    crate::Reg<gmacgrp_mac_address109_low::GmacgrpMacAddress109LowSpec>;
#[doc = "The MAC Address109 Low register holds the lower 32 bits of the 110th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address109_low;
#[doc = "gmacgrp_MAC_Address110_High (rw) register accessor: The MAC Address110 High register holds the upper 16 bits of the 111th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address110 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address110_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address110_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address110_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address110_High")]
pub type GmacgrpMacAddress110High =
    crate::Reg<gmacgrp_mac_address110_high::GmacgrpMacAddress110HighSpec>;
#[doc = "The MAC Address110 High register holds the upper 16 bits of the 111th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address110 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address110_high;
#[doc = "gmacgrp_MAC_Address110_Low (rw) register accessor: The MAC Address110 Low register holds the lower 32 bits of the 111th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address110_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address110_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address110_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address110_Low")]
pub type GmacgrpMacAddress110Low =
    crate::Reg<gmacgrp_mac_address110_low::GmacgrpMacAddress110LowSpec>;
#[doc = "The MAC Address110 Low register holds the lower 32 bits of the 111th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address110_low;
#[doc = "gmacgrp_MAC_Address111_High (rw) register accessor: The MAC Address111 High register holds the upper 16 bits of the 112th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address111 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address111_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address111_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address111_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address111_High")]
pub type GmacgrpMacAddress111High =
    crate::Reg<gmacgrp_mac_address111_high::GmacgrpMacAddress111HighSpec>;
#[doc = "The MAC Address111 High register holds the upper 16 bits of the 112th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address111 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address111_high;
#[doc = "gmacgrp_MAC_Address111_Low (rw) register accessor: The MAC Address111 Low register holds the lower 32 bits of the 112th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address111_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address111_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address111_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address111_Low")]
pub type GmacgrpMacAddress111Low =
    crate::Reg<gmacgrp_mac_address111_low::GmacgrpMacAddress111LowSpec>;
#[doc = "The MAC Address111 Low register holds the lower 32 bits of the 112th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address111_low;
#[doc = "gmacgrp_MAC_Address112_High (rw) register accessor: The MAC Address112 High register holds the upper 16 bits of the 113th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address112 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address112_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address112_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address112_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address112_High")]
pub type GmacgrpMacAddress112High =
    crate::Reg<gmacgrp_mac_address112_high::GmacgrpMacAddress112HighSpec>;
#[doc = "The MAC Address112 High register holds the upper 16 bits of the 113th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address112 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address112_high;
#[doc = "gmacgrp_MAC_Address112_Low (rw) register accessor: The MAC Address112 Low register holds the lower 32 bits of the 113th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address112_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address112_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address112_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address112_Low")]
pub type GmacgrpMacAddress112Low =
    crate::Reg<gmacgrp_mac_address112_low::GmacgrpMacAddress112LowSpec>;
#[doc = "The MAC Address112 Low register holds the lower 32 bits of the 113th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address112_low;
#[doc = "gmacgrp_MAC_Address113_High (rw) register accessor: The MAC Address113 High register holds the upper 16 bits of the 114th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address113 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address113_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address113_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address113_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address113_High")]
pub type GmacgrpMacAddress113High =
    crate::Reg<gmacgrp_mac_address113_high::GmacgrpMacAddress113HighSpec>;
#[doc = "The MAC Address113 High register holds the upper 16 bits of the 114th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address113 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address113_high;
#[doc = "gmacgrp_MAC_Address113_Low (rw) register accessor: The MAC Address113 Low register holds the lower 32 bits of the 114th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address113_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address113_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address113_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address113_Low")]
pub type GmacgrpMacAddress113Low =
    crate::Reg<gmacgrp_mac_address113_low::GmacgrpMacAddress113LowSpec>;
#[doc = "The MAC Address113 Low register holds the lower 32 bits of the 114th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address113_low;
#[doc = "gmacgrp_MAC_Address114_High (rw) register accessor: The MAC Address114 High register holds the upper 16 bits of the 115th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address114 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address114_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address114_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address114_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address114_High")]
pub type GmacgrpMacAddress114High =
    crate::Reg<gmacgrp_mac_address114_high::GmacgrpMacAddress114HighSpec>;
#[doc = "The MAC Address114 High register holds the upper 16 bits of the 115th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address114 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address114_high;
#[doc = "gmacgrp_MAC_Address114_Low (rw) register accessor: The MAC Address114 Low register holds the lower 32 bits of the 115th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address114_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address114_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address114_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address114_Low")]
pub type GmacgrpMacAddress114Low =
    crate::Reg<gmacgrp_mac_address114_low::GmacgrpMacAddress114LowSpec>;
#[doc = "The MAC Address114 Low register holds the lower 32 bits of the 115th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address114_low;
#[doc = "gmacgrp_MAC_Address115_High (rw) register accessor: The MAC Address115 High register holds the upper 16 bits of the 116th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address115 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address115_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address115_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address115_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address115_High")]
pub type GmacgrpMacAddress115High =
    crate::Reg<gmacgrp_mac_address115_high::GmacgrpMacAddress115HighSpec>;
#[doc = "The MAC Address115 High register holds the upper 16 bits of the 116th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address115 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address115_high;
#[doc = "gmacgrp_MAC_Address115_Low (rw) register accessor: The MAC Address115 Low register holds the lower 32 bits of the 116th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address115_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address115_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address115_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address115_Low")]
pub type GmacgrpMacAddress115Low =
    crate::Reg<gmacgrp_mac_address115_low::GmacgrpMacAddress115LowSpec>;
#[doc = "The MAC Address115 Low register holds the lower 32 bits of the 116th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address115_low;
#[doc = "gmacgrp_MAC_Address116_High (rw) register accessor: The MAC Address116 High register holds the upper 16 bits of the 117th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address116 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address116_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address116_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address116_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address116_High")]
pub type GmacgrpMacAddress116High =
    crate::Reg<gmacgrp_mac_address116_high::GmacgrpMacAddress116HighSpec>;
#[doc = "The MAC Address116 High register holds the upper 16 bits of the 117th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address116 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address116_high;
#[doc = "gmacgrp_MAC_Address116_Low (rw) register accessor: The MAC Address116 Low register holds the lower 32 bits of the 117th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address116_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address116_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address116_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address116_Low")]
pub type GmacgrpMacAddress116Low =
    crate::Reg<gmacgrp_mac_address116_low::GmacgrpMacAddress116LowSpec>;
#[doc = "The MAC Address116 Low register holds the lower 32 bits of the 117th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address116_low;
#[doc = "gmacgrp_MAC_Address117_High (rw) register accessor: The MAC Address117 High register holds the upper 16 bits of the 118th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address117 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address117_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address117_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address117_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address117_High")]
pub type GmacgrpMacAddress117High =
    crate::Reg<gmacgrp_mac_address117_high::GmacgrpMacAddress117HighSpec>;
#[doc = "The MAC Address117 High register holds the upper 16 bits of the 118th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address117 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address117_high;
#[doc = "gmacgrp_MAC_Address117_Low (rw) register accessor: The MAC Address117 Low register holds the lower 32 bits of the 118th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address117_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address117_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address117_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address117_Low")]
pub type GmacgrpMacAddress117Low =
    crate::Reg<gmacgrp_mac_address117_low::GmacgrpMacAddress117LowSpec>;
#[doc = "The MAC Address117 Low register holds the lower 32 bits of the 118th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address117_low;
#[doc = "gmacgrp_MAC_Address118_High (rw) register accessor: The MAC Address118 High register holds the upper 16 bits of the 119th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address118 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address118_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address118_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address118_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address118_High")]
pub type GmacgrpMacAddress118High =
    crate::Reg<gmacgrp_mac_address118_high::GmacgrpMacAddress118HighSpec>;
#[doc = "The MAC Address118 High register holds the upper 16 bits of the 119th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address118 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address118_high;
#[doc = "gmacgrp_MAC_Address118_Low (rw) register accessor: The MAC Address118 Low register holds the lower 32 bits of the 119th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address118_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address118_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address118_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address118_Low")]
pub type GmacgrpMacAddress118Low =
    crate::Reg<gmacgrp_mac_address118_low::GmacgrpMacAddress118LowSpec>;
#[doc = "The MAC Address118 Low register holds the lower 32 bits of the 119th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address118_low;
#[doc = "gmacgrp_MAC_Address119_High (rw) register accessor: The MAC Address119 High register holds the upper 16 bits of the 120th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address119 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address119_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address119_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address119_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address119_High")]
pub type GmacgrpMacAddress119High =
    crate::Reg<gmacgrp_mac_address119_high::GmacgrpMacAddress119HighSpec>;
#[doc = "The MAC Address119 High register holds the upper 16 bits of the 120th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address119 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address119_high;
#[doc = "gmacgrp_MAC_Address119_Low (rw) register accessor: The MAC Address119 Low register holds the lower 32 bits of the 120th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address119_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address119_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address119_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address119_Low")]
pub type GmacgrpMacAddress119Low =
    crate::Reg<gmacgrp_mac_address119_low::GmacgrpMacAddress119LowSpec>;
#[doc = "The MAC Address119 Low register holds the lower 32 bits of the 120th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address119_low;
#[doc = "gmacgrp_MAC_Address120_High (rw) register accessor: The MAC Address120 High register holds the upper 16 bits of the 121th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address120 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address120_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address120_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address120_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address120_High")]
pub type GmacgrpMacAddress120High =
    crate::Reg<gmacgrp_mac_address120_high::GmacgrpMacAddress120HighSpec>;
#[doc = "The MAC Address120 High register holds the upper 16 bits of the 121th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address120 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address120_high;
#[doc = "gmacgrp_MAC_Address120_Low (rw) register accessor: The MAC Address120 Low register holds the lower 32 bits of the 121th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address120_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address120_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address120_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address120_Low")]
pub type GmacgrpMacAddress120Low =
    crate::Reg<gmacgrp_mac_address120_low::GmacgrpMacAddress120LowSpec>;
#[doc = "The MAC Address120 Low register holds the lower 32 bits of the 121th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address120_low;
#[doc = "gmacgrp_MAC_Address121_High (rw) register accessor: The MAC Address121 High register holds the upper 16 bits of the 122th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address121 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address121_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address121_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address121_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address121_High")]
pub type GmacgrpMacAddress121High =
    crate::Reg<gmacgrp_mac_address121_high::GmacgrpMacAddress121HighSpec>;
#[doc = "The MAC Address121 High register holds the upper 16 bits of the 122th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address121 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address121_high;
#[doc = "gmacgrp_MAC_Address121_Low (rw) register accessor: The MAC Address121 Low register holds the lower 32 bits of the 122th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address121_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address121_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address121_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address121_Low")]
pub type GmacgrpMacAddress121Low =
    crate::Reg<gmacgrp_mac_address121_low::GmacgrpMacAddress121LowSpec>;
#[doc = "The MAC Address121 Low register holds the lower 32 bits of the 122th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address121_low;
#[doc = "gmacgrp_MAC_Address122_High (rw) register accessor: The MAC Address122 High register holds the upper 16 bits of the 123th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address122 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address122_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address122_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address122_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address122_High")]
pub type GmacgrpMacAddress122High =
    crate::Reg<gmacgrp_mac_address122_high::GmacgrpMacAddress122HighSpec>;
#[doc = "The MAC Address122 High register holds the upper 16 bits of the 123th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address122 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address122_high;
#[doc = "gmacgrp_MAC_Address122_Low (rw) register accessor: The MAC Address122 Low register holds the lower 32 bits of the 123th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address122_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address122_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address122_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address122_Low")]
pub type GmacgrpMacAddress122Low =
    crate::Reg<gmacgrp_mac_address122_low::GmacgrpMacAddress122LowSpec>;
#[doc = "The MAC Address122 Low register holds the lower 32 bits of the 123th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address122_low;
#[doc = "gmacgrp_MAC_Address123_High (rw) register accessor: The MAC Address123 High register holds the upper 16 bits of the 124th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address123 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address123_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address123_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address123_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address123_High")]
pub type GmacgrpMacAddress123High =
    crate::Reg<gmacgrp_mac_address123_high::GmacgrpMacAddress123HighSpec>;
#[doc = "The MAC Address123 High register holds the upper 16 bits of the 124th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address123 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address123_high;
#[doc = "gmacgrp_MAC_Address123_Low (rw) register accessor: The MAC Address123 Low register holds the lower 32 bits of the 124th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address123_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address123_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address123_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address123_Low")]
pub type GmacgrpMacAddress123Low =
    crate::Reg<gmacgrp_mac_address123_low::GmacgrpMacAddress123LowSpec>;
#[doc = "The MAC Address123 Low register holds the lower 32 bits of the 124th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address123_low;
#[doc = "gmacgrp_MAC_Address124_High (rw) register accessor: The MAC Address124 High register holds the upper 16 bits of the 125th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address124 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address124_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address124_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address124_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address124_High")]
pub type GmacgrpMacAddress124High =
    crate::Reg<gmacgrp_mac_address124_high::GmacgrpMacAddress124HighSpec>;
#[doc = "The MAC Address124 High register holds the upper 16 bits of the 125th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address124 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address124_high;
#[doc = "gmacgrp_MAC_Address124_Low (rw) register accessor: The MAC Address124 Low register holds the lower 32 bits of the 125th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address124_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address124_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address124_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address124_Low")]
pub type GmacgrpMacAddress124Low =
    crate::Reg<gmacgrp_mac_address124_low::GmacgrpMacAddress124LowSpec>;
#[doc = "The MAC Address124 Low register holds the lower 32 bits of the 125th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address124_low;
#[doc = "gmacgrp_MAC_Address125_High (rw) register accessor: The MAC Address125 High register holds the upper 16 bits of the 126th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address125 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address125_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address125_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address125_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address125_High")]
pub type GmacgrpMacAddress125High =
    crate::Reg<gmacgrp_mac_address125_high::GmacgrpMacAddress125HighSpec>;
#[doc = "The MAC Address125 High register holds the upper 16 bits of the 126th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address125 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address125_high;
#[doc = "gmacgrp_MAC_Address125_Low (rw) register accessor: The MAC Address125 Low register holds the lower 32 bits of the 126th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address125_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address125_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address125_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address125_Low")]
pub type GmacgrpMacAddress125Low =
    crate::Reg<gmacgrp_mac_address125_low::GmacgrpMacAddress125LowSpec>;
#[doc = "The MAC Address125 Low register holds the lower 32 bits of the 126th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address125_low;
#[doc = "gmacgrp_MAC_Address126_High (rw) register accessor: The MAC Address126 High register holds the upper 16 bits of the 127th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address126 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address126_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address126_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address126_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address126_High")]
pub type GmacgrpMacAddress126High =
    crate::Reg<gmacgrp_mac_address126_high::GmacgrpMacAddress126HighSpec>;
#[doc = "The MAC Address126 High register holds the upper 16 bits of the 127th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address126 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address126_high;
#[doc = "gmacgrp_MAC_Address126_Low (rw) register accessor: The MAC Address126 Low register holds the lower 32 bits of the 127th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address126_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address126_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address126_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address126_Low")]
pub type GmacgrpMacAddress126Low =
    crate::Reg<gmacgrp_mac_address126_low::GmacgrpMacAddress126LowSpec>;
#[doc = "The MAC Address126 Low register holds the lower 32 bits of the 127th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address126_low;
#[doc = "gmacgrp_MAC_Address127_High (rw) register accessor: The MAC Address127 High register holds the upper 16 bits of the 128th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address127 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address127_high::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address127_high::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address127_high`]
module"]
#[doc(alias = "gmacgrp_MAC_Address127_High")]
pub type GmacgrpMacAddress127High =
    crate::Reg<gmacgrp_mac_address127_high::GmacgrpMacAddress127HighSpec>;
#[doc = "The MAC Address127 High register holds the upper 16 bits of the 128th 6-byte MAC address of the station. Because the MAC address registers are configured to be double-synchronized to the (G)MII clock domains, the synchronization is triggered only when bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the MAC Address127 Low Register are written. For proper synchronization updates, the consecutive writes to this Address Low Register should be performed after at least four clock cycles in the destination clock domain. Note that all MAC Address High registers (except MAC Address0 High) have the same format."]
pub mod gmacgrp_mac_address127_high;
#[doc = "gmacgrp_MAC_Address127_Low (rw) register accessor: The MAC Address127 Low register holds the lower 32 bits of the 128th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mac_address127_low::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mac_address127_low::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@gmacgrp_mac_address127_low`]
module"]
#[doc(alias = "gmacgrp_MAC_Address127_Low")]
pub type GmacgrpMacAddress127Low =
    crate::Reg<gmacgrp_mac_address127_low::GmacgrpMacAddress127LowSpec>;
#[doc = "The MAC Address127 Low register holds the lower 32 bits of the 128th 6-byte MAC address of the station. Note that all MAC Address Low registers (except MAC Address0 Low) have the same format."]
pub mod gmacgrp_mac_address127_low;
#[doc = "dmagrp_Bus_Mode (rw) register accessor: The Bus Mode register establishes the bus operating modes for the DMA.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_bus_mode::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_bus_mode::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_bus_mode`]
module"]
#[doc(alias = "dmagrp_Bus_Mode")]
pub type DmagrpBusMode = crate::Reg<dmagrp_bus_mode::DmagrpBusModeSpec>;
#[doc = "The Bus Mode register establishes the bus operating modes for the DMA."]
pub mod dmagrp_bus_mode;
#[doc = "dmagrp_Transmit_Poll_Demand (rw) register accessor: The Transmit Poll Demand register enables the Tx DMA to check whether or not the DMA owns the current descriptor. The Transmit Poll Demand command is given to wake up the Tx DMA if it is in the Suspend mode. The Tx DMA can go into the Suspend mode because of an Underflow error in a transmitted frame or the unavailability of descriptors owned by it. You can give this command anytime and the Tx DMA resets this command when it again starts fetching the current descriptor from host memory.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_transmit_poll_demand::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_transmit_poll_demand::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_transmit_poll_demand`]
module"]
#[doc(alias = "dmagrp_Transmit_Poll_Demand")]
pub type DmagrpTransmitPollDemand =
    crate::Reg<dmagrp_transmit_poll_demand::DmagrpTransmitPollDemandSpec>;
#[doc = "The Transmit Poll Demand register enables the Tx DMA to check whether or not the DMA owns the current descriptor. The Transmit Poll Demand command is given to wake up the Tx DMA if it is in the Suspend mode. The Tx DMA can go into the Suspend mode because of an Underflow error in a transmitted frame or the unavailability of descriptors owned by it. You can give this command anytime and the Tx DMA resets this command when it again starts fetching the current descriptor from host memory."]
pub mod dmagrp_transmit_poll_demand;
#[doc = "dmagrp_Receive_Poll_Demand (rw) register accessor: The Receive Poll Demand register enables the receive DMA to check for new descriptors. This command is used to wake up the Rx DMA from the SUSPEND state. The RxDMA can go into the SUSPEND state only because of the unavailability of descriptors it owns.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_receive_poll_demand::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_receive_poll_demand::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_receive_poll_demand`]
module"]
#[doc(alias = "dmagrp_Receive_Poll_Demand")]
pub type DmagrpReceivePollDemand =
    crate::Reg<dmagrp_receive_poll_demand::DmagrpReceivePollDemandSpec>;
#[doc = "The Receive Poll Demand register enables the receive DMA to check for new descriptors. This command is used to wake up the Rx DMA from the SUSPEND state. The RxDMA can go into the SUSPEND state only because of the unavailability of descriptors it owns."]
pub mod dmagrp_receive_poll_demand;
#[doc = "dmagrp_Receive_Descriptor_List_Address (rw) register accessor: The Receive Descriptor List Address register points to the start of the Receive Descriptor List. The descriptor lists reside in the host's physical memory space and must be Word, Dword, or Lword-aligned (for 32-bit, 64-bit, or 128-bit data bus). The DMA internally converts it to bus width aligned address by making the corresponding LS bits low. Writing to this register is permitted only when reception is stopped. When stopped, this register must be written to before the receive Start command is given. You can write to this register only when Rx DMA has stopped, that is, Bit 1 (SR) is set to zero in Register 6 (Operation Mode Register). When stopped, this register can be written with a new descriptor list address. When you set the SR bit to 1, the DMA takes the newly programmed descriptor base address. If this register is not changed when the SR bit is set to 0, then the DMA takes the descriptor address where it was stopped earlier.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_receive_descriptor_list_address::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_receive_descriptor_list_address::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_receive_descriptor_list_address`]
module"]
#[doc(alias = "dmagrp_Receive_Descriptor_List_Address")]
pub type DmagrpReceiveDescriptorListAddress =
    crate::Reg<dmagrp_receive_descriptor_list_address::DmagrpReceiveDescriptorListAddressSpec>;
#[doc = "The Receive Descriptor List Address register points to the start of the Receive Descriptor List. The descriptor lists reside in the host's physical memory space and must be Word, Dword, or Lword-aligned (for 32-bit, 64-bit, or 128-bit data bus). The DMA internally converts it to bus width aligned address by making the corresponding LS bits low. Writing to this register is permitted only when reception is stopped. When stopped, this register must be written to before the receive Start command is given. You can write to this register only when Rx DMA has stopped, that is, Bit 1 (SR) is set to zero in Register 6 (Operation Mode Register). When stopped, this register can be written with a new descriptor list address. When you set the SR bit to 1, the DMA takes the newly programmed descriptor base address. If this register is not changed when the SR bit is set to 0, then the DMA takes the descriptor address where it was stopped earlier."]
pub mod dmagrp_receive_descriptor_list_address;
#[doc = "dmagrp_Transmit_Descriptor_List_Address (rw) register accessor: The Transmit Descriptor List Address register points to the start of the Transmit Descriptor List. The descriptor lists reside in the host's physical memory space and must be Word, Dword, or Lword-aligned (for 32-bit, 64-bit, or 128-bit data bus). The DMA internally converts it to bus width aligned address by making the corresponding LSB to low. You can write to this register only when the Tx DMA has stopped, that is, Bit 13 (ST) is set to zero in Register 6 (Operation Mode Register). When stopped, this register can be written with a new descriptor list address. When you set the ST bit to 1, the DMA takes the newly programmed descriptor base address. If this register is not changed when the ST bit is set to 0, then the DMA takes the descriptor address where it was stopped earlier.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_transmit_descriptor_list_address::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_transmit_descriptor_list_address::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_transmit_descriptor_list_address`]
module"]
#[doc(alias = "dmagrp_Transmit_Descriptor_List_Address")]
pub type DmagrpTransmitDescriptorListAddress =
    crate::Reg<dmagrp_transmit_descriptor_list_address::DmagrpTransmitDescriptorListAddressSpec>;
#[doc = "The Transmit Descriptor List Address register points to the start of the Transmit Descriptor List. The descriptor lists reside in the host's physical memory space and must be Word, Dword, or Lword-aligned (for 32-bit, 64-bit, or 128-bit data bus). The DMA internally converts it to bus width aligned address by making the corresponding LSB to low. You can write to this register only when the Tx DMA has stopped, that is, Bit 13 (ST) is set to zero in Register 6 (Operation Mode Register). When stopped, this register can be written with a new descriptor list address. When you set the ST bit to 1, the DMA takes the newly programmed descriptor base address. If this register is not changed when the ST bit is set to 0, then the DMA takes the descriptor address where it was stopped earlier."]
pub mod dmagrp_transmit_descriptor_list_address;
#[doc = "dmagrp_Status (rw) register accessor: The Status register contains all status bits that the DMA reports to the host. The software driver reads this register during an interrupt service routine or polling. Most of the fields in this register cause the host to be interrupted. The bits of this register are not cleared when read. Writing 1'b1 to (unreserved) Bits\\[16:0\\]
of this register clears these bits and writing 1'b0 has no effect. Each field (Bits\\[16:0\\]) can be masked by masking the appropriate bit in Register 7 (Interrupt Enable Register).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_status::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_status::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_status`]
module"]
#[doc(alias = "dmagrp_Status")]
pub type DmagrpStatus = crate::Reg<dmagrp_status::DmagrpStatusSpec>;
#[doc = "The Status register contains all status bits that the DMA reports to the host. The software driver reads this register during an interrupt service routine or polling. Most of the fields in this register cause the host to be interrupted. The bits of this register are not cleared when read. Writing 1'b1 to (unreserved) Bits\\[16:0\\]
of this register clears these bits and writing 1'b0 has no effect. Each field (Bits\\[16:0\\]) can be masked by masking the appropriate bit in Register 7 (Interrupt Enable Register)."]
pub mod dmagrp_status;
#[doc = "dmagrp_Operation_Mode (rw) register accessor: The Operation Mode register establishes the Transmit and Receive operating modes and commands. This register should be the last CSR to be written as part of the DMA initialization.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_operation_mode::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_operation_mode::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_operation_mode`]
module"]
#[doc(alias = "dmagrp_Operation_Mode")]
pub type DmagrpOperationMode = crate::Reg<dmagrp_operation_mode::DmagrpOperationModeSpec>;
#[doc = "The Operation Mode register establishes the Transmit and Receive operating modes and commands. This register should be the last CSR to be written as part of the DMA initialization."]
pub mod dmagrp_operation_mode;
#[doc = "dmagrp_Interrupt_Enable (rw) register accessor: The Interrupt Enable register enables the interrupts reported by Register 5 (Status Register). Setting a bit to 1'b1 enables a corresponding interrupt. After a hardware or software reset, all interrupts are disabled.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_interrupt_enable::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_interrupt_enable::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_interrupt_enable`]
module"]
#[doc(alias = "dmagrp_Interrupt_Enable")]
pub type DmagrpInterruptEnable = crate::Reg<dmagrp_interrupt_enable::DmagrpInterruptEnableSpec>;
#[doc = "The Interrupt Enable register enables the interrupts reported by Register 5 (Status Register). Setting a bit to 1'b1 enables a corresponding interrupt. After a hardware or software reset, all interrupts are disabled."]
pub mod dmagrp_interrupt_enable;
#[doc = "dmagrp_Missed_Frame_And_Buffer_Overflow_Counter (r) register accessor: The DMA maintains two counters to track the number of frames missed during reception. This register reports the current value of the counter. The counter is used for diagnostic purposes. Bits\\[15:0\\]
indicate missed frames because of the host buffer being unavailable. Bits\\[27:17\\]
indicate missed frames because of buffer overflow conditions (MTL and MAC) and runt frames (good frames of less than 64 bytes) dropped by the MTL.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_missed_frame_and_buffer_overflow_counter::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_missed_frame_and_buffer_overflow_counter`]
module"]
#[doc(alias = "dmagrp_Missed_Frame_And_Buffer_Overflow_Counter")]
pub type DmagrpMissedFrameAndBufferOverflowCounter = crate::Reg<
    dmagrp_missed_frame_and_buffer_overflow_counter::DmagrpMissedFrameAndBufferOverflowCounterSpec,
>;
#[doc = "The DMA maintains two counters to track the number of frames missed during reception. This register reports the current value of the counter. The counter is used for diagnostic purposes. Bits\\[15:0\\]
indicate missed frames because of the host buffer being unavailable. Bits\\[27:17\\]
indicate missed frames because of buffer overflow conditions (MTL and MAC) and runt frames (good frames of less than 64 bytes) dropped by the MTL."]
pub mod dmagrp_missed_frame_and_buffer_overflow_counter;
#[doc = "dmagrp_Receive_Interrupt_Watchdog_Timer (rw) register accessor: This register, when written with non-zero value, enables the watchdog timer for the Receive Interrupt (Bit 6) of Register 5 (Status Register)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_receive_interrupt_watchdog_timer::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_receive_interrupt_watchdog_timer::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_receive_interrupt_watchdog_timer`]
module"]
#[doc(alias = "dmagrp_Receive_Interrupt_Watchdog_Timer")]
pub type DmagrpReceiveInterruptWatchdogTimer =
    crate::Reg<dmagrp_receive_interrupt_watchdog_timer::DmagrpReceiveInterruptWatchdogTimerSpec>;
#[doc = "This register, when written with non-zero value, enables the watchdog timer for the Receive Interrupt (Bit 6) of Register 5 (Status Register)"]
pub mod dmagrp_receive_interrupt_watchdog_timer;
#[doc = "dmagrp_AXI_Bus_Mode (rw) register accessor: The AXI Bus Mode Register controls the behavior of the AXI master. It is mainly used to control the burst splitting and the number of outstanding requests.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_axi_bus_mode::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_axi_bus_mode::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_axi_bus_mode`]
module"]
#[doc(alias = "dmagrp_AXI_Bus_Mode")]
pub type DmagrpAxiBusMode = crate::Reg<dmagrp_axi_bus_mode::DmagrpAxiBusModeSpec>;
#[doc = "The AXI Bus Mode Register controls the behavior of the AXI master. It is mainly used to control the burst splitting and the number of outstanding requests."]
pub mod dmagrp_axi_bus_mode;
#[doc = "dmagrp_AHB_or_AXI_Status (r) register accessor: This register provides the active status of the AXI interface's read and write channels. This register is useful for debugging purposes. In addition, this register is valid only in the Channel 0 DMA when multiple channels are present in the AV mode.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_ahb_or_axi_status::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_ahb_or_axi_status`]
module"]
#[doc(alias = "dmagrp_AHB_or_AXI_Status")]
pub type DmagrpAhbOrAxiStatus = crate::Reg<dmagrp_ahb_or_axi_status::DmagrpAhbOrAxiStatusSpec>;
#[doc = "This register provides the active status of the AXI interface's read and write channels. This register is useful for debugging purposes. In addition, this register is valid only in the Channel 0 DMA when multiple channels are present in the AV mode."]
pub mod dmagrp_ahb_or_axi_status;
#[doc = "dmagrp_Current_Host_Transmit_Descriptor (r) register accessor: The Current Host Transmit Descriptor register points to the start address of the current Transmit Descriptor read by the DMA.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_current_host_transmit_descriptor::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_current_host_transmit_descriptor`]
module"]
#[doc(alias = "dmagrp_Current_Host_Transmit_Descriptor")]
pub type DmagrpCurrentHostTransmitDescriptor =
    crate::Reg<dmagrp_current_host_transmit_descriptor::DmagrpCurrentHostTransmitDescriptorSpec>;
#[doc = "The Current Host Transmit Descriptor register points to the start address of the current Transmit Descriptor read by the DMA."]
pub mod dmagrp_current_host_transmit_descriptor;
#[doc = "dmagrp_Current_Host_Receive_Descriptor (r) register accessor: The Current Host Receive Descriptor register points to the start address of the current Receive Descriptor read by the DMA.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_current_host_receive_descriptor::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_current_host_receive_descriptor`]
module"]
#[doc(alias = "dmagrp_Current_Host_Receive_Descriptor")]
pub type DmagrpCurrentHostReceiveDescriptor =
    crate::Reg<dmagrp_current_host_receive_descriptor::DmagrpCurrentHostReceiveDescriptorSpec>;
#[doc = "The Current Host Receive Descriptor register points to the start address of the current Receive Descriptor read by the DMA."]
pub mod dmagrp_current_host_receive_descriptor;
#[doc = "dmagrp_Current_Host_Transmit_Buffer_Address (r) register accessor: The Current Host Transmit Buffer Address register points to the current Transmit Buffer Address being read by the DMA.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_current_host_transmit_buffer_address::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_current_host_transmit_buffer_address`]
module"]
#[doc(alias = "dmagrp_Current_Host_Transmit_Buffer_Address")]
pub type DmagrpCurrentHostTransmitBufferAddress = crate::Reg<
    dmagrp_current_host_transmit_buffer_address::DmagrpCurrentHostTransmitBufferAddressSpec,
>;
#[doc = "The Current Host Transmit Buffer Address register points to the current Transmit Buffer Address being read by the DMA."]
pub mod dmagrp_current_host_transmit_buffer_address;
#[doc = "dmagrp_Current_Host_Receive_Buffer_Address (r) register accessor: The Current Host Receive Buffer Address register points to the current Receive Buffer address being read by the DMA.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_current_host_receive_buffer_address::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_current_host_receive_buffer_address`]
module"]
#[doc(alias = "dmagrp_Current_Host_Receive_Buffer_Address")]
pub type DmagrpCurrentHostReceiveBufferAddress = crate::Reg<
    dmagrp_current_host_receive_buffer_address::DmagrpCurrentHostReceiveBufferAddressSpec,
>;
#[doc = "The Current Host Receive Buffer Address register points to the current Receive Buffer address being read by the DMA."]
pub mod dmagrp_current_host_receive_buffer_address;
#[doc = "dmagrp_HW_Feature (r) register accessor: This register indicates the presence of the optional features or functions of the gmac. The software driver can use this register to dynamically enable or disable the programs related to the optional blocks.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_hw_feature::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmagrp_hw_feature`]
module"]
#[doc(alias = "dmagrp_HW_Feature")]
pub type DmagrpHwFeature = crate::Reg<dmagrp_hw_feature::DmagrpHwFeatureSpec>;
#[doc = "This register indicates the presence of the optional features or functions of the gmac. The software driver can use this register to dynamically enable or disable the programs related to the optional blocks."]
pub mod dmagrp_hw_feature;
