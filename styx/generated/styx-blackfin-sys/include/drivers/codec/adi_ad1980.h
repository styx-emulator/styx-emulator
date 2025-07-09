/******************************************************************************
Copyright (c), 2010  - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.

$Revision: 3939 $
$Date: 2010-12-10 09:07:11 -0500 (Fri, 10 Dec 2010) $

Title: ADI Device Drivers and System Services

Description:
    This is the primary include file for AD1980 AC'97 Audio CODEC driver

*****************************************************************************/

#ifndef __ADI_AD1980_H__
#define __ADI_AD1980_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*=============  I N C L U D E S   =============*/

/* AC'97 driver includes */
#include <drivers/codec/adi_ac97.h>

/*********************************************************************

Entry point to AD1980 device driver

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADIAD1980EntryPoint;

/*********************************************************************

Macros for the memory usage of AD1980 driver

*********************************************************************/

/* Base memory needed for one AD1980 AC'97 data frame
   inbound & outbound buffers operated in ping-pong fashion (32bytes * 4)    */
#define     ADI_AD1980_DATA_FRAME_BASE_MEMORY         (ADI_AC97_DATA_FRAME_BASE_MEMORY)

/*********************************************************************

AD1980 Codec Register definitions

**********************************************************************/

/* Reset Register */
#define     AD1980_REG_RESET                AC97_REG_RESET
/* Master Volume Control Register       */
#define     AD1980_REG_MASTER_VOL_CTRL      AC97_REG_MASTER_VOL_CTRL
/* Headphones Volume Control Register   */
#define     AD1980_REG_HP_VOL_CTRL          AC97_REG_HP_VOL_CTRL
/* Mono Volume Control Register         */
#define     AD1980_REG_MONO_VOL_CTRL        AC97_REG_MONO_VOL_CTRL
/* Phone In Volume Control Register     */
#define     AD1980_REG_PHONE_VOL_CTRL       AC97_REG_PHONE_VOL_CTRL
/* MIC Volume Control Register          */
#define     AD1980_REG_MIC_VOL_CTRL         AC97_REG_MIC_VOL_CTRL
/* Line-In Volume Control Register      */
#define     AD1980_REG_LINE_IN_VOL_CTRL     AC97_REG_LINE_IN_VOL_CTRL
/* CD Volume Control Register           */
#define     AD1980_REG_CD_VOL_CTRL          AC97_REG_CD_VOL_CTRL
/* AUX Volume Control Register          */
#define     AD1980_REG_AUX_VOL_CTRL         AC97_REG_AUX_VOL_CTRL
/* PCM Out Volume Control Register      */
#define     AD1980_REG_PCM_OUT_VOL_CTRL     AC97_REG_PCM_OUT_VOL_CTRL
/* Record select Control Register       */
#define     AD1980_REG_RECORD_SELECT        AC97_REG_RECORD_SELECT
/* Record gain Register                 */
#define     AD1980_REG_RECORD_GAIN          AC97_REG_RECORD_GAIN
/* General purpose Register             */
#define     AD1980_REG_GP                   AC97_REG_GP
/* Audio Interrupt an Paging            */
#define     AD1980_REG_AUDIO_INT_PAGE       AC97_REG_AUDIO_INT_PAGE
/* Power-down Control/Status Register   */
#define     AD1980_REG_POWER_CTRL_STAT      AC97_REG_POWER_CTRL_STAT
/* Extended Audio ID Register           */
#define     AD1980_REG_EXTD_AUDIO_ID        AC97_REG_EXTD_AUDIO_ID
/* Extended Audio Status/Control Reg    */
#define     AD1980_REG_EXTD_AUDIO_CTRL      AC97_REG_EXTD_AUDIO_CTRL
/* PCM Front DAC Sample Rate reg        */
#define     AD1980_REG_FRONT_DAC_RATE       AC97_REG_FRONT_DAC_RATE
/* PCM Surround DAC Sample Rate reg     */
#define     AD1980_REG_SURR_DAC_RATE        AC97_REG_SURR_DAC_RATE
/* PCM Center/LFE DAC Sample Rate reg   */
#define     AD1980_REG_CTR_LFE_DAC_RATE     AC97_REG_CTR_LFE_DAC_RATE
/* PCM ADC sample rate Register         */
#define     AD1980_REG_ADC_RATE             AC97_REG_ADC_RATE
/* Center/LFE Volume Control Register   */
#define     AD1980_REG_CTR_LFE_VOL_CTRL     AC97_REG_CTR_LFE_VOL_CTRL
/* Surround Volume Control Register     */
#define     AD1980_REG_SURR_VOL_CTRL        AC97_REG_SURR_VOL_CTRL
/* S/PDIF Control Register              */
#define     AD1980_REG_SPDIF_CTRL           AC97_REG_SPDIF_CTRL
/* Equaliser Control Register           */
#define     AD1980_REG_EQ_CTRL              AC97_REG_EQ_CTRL
/* Equaliser Data Register              */
#define     AD1980_REG_EQ_DATA              AC97_REG_EQ_DATA
/* not yet supported                    */
#define     AD1980_REG_JACK_SENSE           AC97_REG_JACK_SENSE
/* Serial Configuration Register        */
#define     AD1980_REG_SERIAL_CONFIG        AC97_REG_SERIAL_CONFIG
/* Miscellaneous Control Register       */
#define     AD1980_REG_MISC_CTRL            AC97_REG_MISC_CTRL_1
/* Vendor ID Register 1                 */
#define     AD1980_REG_VENDOR_ID_1          AC97_REG_VENDOR_ID_1
/* Vendor ID Register 2                 */
#define     AD1980_REG_VENDOR_ID_2          AC97_REG_VENDOR_ID_2

/*********************************************************************

AD1980 Register Field definitions

**********************************************************************/

/*****************************************************
Register Field definitions Common to
- AD1980_REG_RESET (Reset Register)
*****************************************************/

/* Identify Codec Capabilities */
#define     AD1980_RFLD_ID_CODEC_SUPPORT        AC97_RFLD_ID_CODEC_SUPPORT
/* 3D Stereo Enhancement support code   */
#define     AD1980_RFLD_3D_SURR_ENHANCE         AC97_RFLD_3D_SURR_ENHANCE

/*****************************************************
Register Field definitions Common to
- AD1980_REG_MASTER_VOL_CTRL (Master Volume Control Register)
- AD1980_REG_HP_VOL_CTRL     (Headphones Volume Control Register)
*****************************************************/

/* Master/HP Right Channel Volume */
#define     AD1980_RFLD_MASTER_HP_R_VOL         AC97_RFLD_MASTER_HP_R_VOL
/* Master/HP Right Channel Mute */
#define     AD1980_RFLD_MASTER_HP_R_MUTE        AC97_RFLD_MASTER_HP_R_MUTE
/* Master/HP Left Channel Volume */
#define     AD1980_RFLD_MASTER_HP_L_VOL         AC97_RFLD_MASTER_HP_L_VOL
/* Master/HP Left Channel Mute */
#define     AD1980_RFLD_MASTER_HP_L_MUTE        AC97_RFLD_MASTER_HP_L_MUTE
/* Mute Headphone/Master Volume */
#define     AD1980_RFLD_MASTER_HP_MUTE          AC97_RFLD_MASTER_HP_MUTE

/*****************************************************
Register Field definitions Common to
- AD1980_REG_MONO_VOL_CTRL (Mono Volume Control Register)
*****************************************************/

/* Mono Volume */
#define     AD1980_RFLD_MONO_VOL                AC97_RFLD_MONO_VOL
/* Mute Mono Volume */
#define     AD1980_RFLD_MONO_MUTE               AC97_RFLD_MONO_MUTE

/*****************************************************
Register Field definitions Common to
- AD1980_REG_PHONE_VOL_CTRL (Phone In Volume Control Register)
*****************************************************/

/* Phone In Volume */
#define     AD1980_RFLD_PHONE_VOL               AC97_RFLD_PHONE_VOL
/* Mute Phone In Volume */
#define     AD1980_RFLD_PHONE_MUTE              AC97_RFLD_PHONE_MUTE

/*****************************************************
Register Field definitions Common to
- AD1980_REG_MIC_VOL_CTRL (MIC Volume Control Register)
*****************************************************/

/* MIC Volume Gain */
#define     AD1980_RFLD_MIC_VOL_GAIN            AC97_RFLD_MIC_VOL_GAIN
/* MIC Volume Gain */
#define     AD1980_RFLD_MIC_BOOST_GAIN          AC97_RFLD_MIC_BOOST_GAIN_ENABLE
/* Mute MIC */
#define     AD1980_RFLD_MIC_MUTE                AC97_RFLD_MIC_MUTE

/*****************************************************
Register Field definitions Common to
- AD1980_REG_LINE_IN_VOL_CTRL (Line-In Volume Control Register)
- AD1980_REG_CD_VOL_CTRL      (CD Volume Control Register)
- AD1980_REG_AUX_VOL_CTRL     (AUX Volume Control Register)
*****************************************************/

/* AUX/CD/Line In Right Channel Volume */
#define     AD1980_RFLD_AUX_CD_LINE_IN_R_VOL    AC97_RFLD_AUX_CD_LINE_IN_R_VOL
/* AUX/CD/Line In Right Channel Mute */
#define     AD1980_RFLD_AUX_CD_LINE_IN_R_MUTE   AC97_RFLD_AUX_CD_LINE_IN_R_MUTE
/* AUX/CD/Line In Left Channel Volume */
#define     AD1980_RFLD_AUX_CD_LINE_IN_L_VOL    AC97_RFLD_AUX_CD_LINE_IN_L_VOL
/* AUX/CD/Line In Left Channel Mute */
#define     AD1980_RFLD_AUX_CD_LINE_IN_L_MUTE   AC97_RFLD_AUX_CD_LINE_IN_L_MUTE
/* Mute AUX/CD/Line In Volume */
#define     AD1980_RFLD_AUX_CD_LINE_IN_MUTE     AC97_RFLD_AUX_CD_LINE_IN_MUTE

/*****************************************************
Register Field definitions Common to
- AD1980_REG_PCM_OUT_VOL_CTRL (PCM Out Volume Control Register)
*****************************************************/

/* PCM Out Right Channel Volume */
#define     AD1980_RFLD_PCM_OUT_R_VOL           AC97_RFLD_PCM_OUT_R_VOL
/* PCM Out Right Channel Mute */
#define     AD1980_RFLD_PCM_OUT_R_MUTE          AC97_RFLD_PCM_OUT_R_MUTE
/* PCM Out Left Channel Volume */
#define     AD1980_RFLD_PCM_OUT_L_VOL           AC97_RFLD_PCM_OUT_L_VOL
/* PCM Out Left Channel Mute */
#define     AD1980_RFLD_PCM_OUT_L_MUTE          AC97_RFLD_PCM_OUT_L_MUTE
/* Mute PCM Out Volume */
#define     AD1980_RFLD_PCM_OUT_MUTE            AC97_RFLD_PCM_OUT_MUTE

/*****************************************************
Register Field definitions Common to
- AD1980_REG_RECORD_SELECT (Record Select Register)
*****************************************************/

#define     AD1980_RFLD_RECORD_SELECT_R         AC97_RFLD_RECORD_SELECT_R   /* Right Record Select          */
#define     AD1980_RFLD_RECORD_SELECT_L         AC97_RFLD_RECORD_SELECT_L   /* Left Record Select           */

/*****************************************************
Register Field definitions Common to
- AD1980_REG_RECORD_GAIN (Record Gain Register)
*****************************************************/

#define     AD1980_RFLD_RECORD_R_GAIN           AC97_RFLD_RECORD_R_GAIN     /* Right Input Mixer Gain       */
#define     AD1980_RFLD_RECORD_R_MUTE           AC97_RFLD_RECORD_R_MUTE     /* Right Input Channel Mute     */
#define     AD1980_RFLD_RECORD_L_GAIN           AC97_RFLD_RECORD_L_GAIN     /* Left Input Mixer Gain        */
#define     AD1980_RFLD_RECORD_L_MUTE           AC97_RFLD_RECORD_L_MUTE     /* Left Input Channel Mute      */
#define     AD1980_RFLD_RECORD_INPUT_MUTE       AC97_RFLD_RECORD_INPUT_MUTE /* Mute Input Channels          */

/*****************************************************
Register Field definitions Common to
- AD1980_REG_GP (General Purpose Register)
*****************************************************/

#define     AD1980_RFLD_LOOPBACK                AC97_RFLD_LOOPBACK          /* Loopback Control             */
#define     AD1980_RFLD_MIC_SELECT              AC97_RFLD_MIC_SELECT        /* Selects Mono MIC Input       */
#define     AD1980_RFLD_DOBULE_RATE_SLOTS       AC97_RFLD_DOBULE_RATE_SLOTS /* Dobule Rate Slot Select      */

/*****************************************************
Register Field definitions Common to
- AD1980_REG_AUDIO_INT_PAGE (Audio Interrupt and Paging Register)
*****************************************************/

#define     AD1980_RFLD_PAGE_SELECTOR           AC97_RFLD_PAGE_SELECTOR     /* Page Selector                */
#define     AD1980_RFLD_ENABLE_INT              AC97_RFLD_ENABLE_INT        /* 1 = Enable Interrupt         */
#define     AD1980_RFLD_INT_STATUS              AC97_RFLD_INT_STATUS        /* Interrupt Status             */

/*****************************************************
Register Field definitions Common to
- AD1980_REG_POWER_CTRL (Power Control/Status Register)
*****************************************************/

#define     AD1980_RFLD_ADC_READY               AC97_RFLD_ADC_READY     /* ADC Sections Ready to Transmit       */
#define     AD1980_RFLD_DAC_READY               AC97_RFLD_DAC_READY     /* DAC Sections Ready to Transmit       */
#define     AD1980_RFLD_ANL_READY               AC97_RFLD_ANL_READY     /* Analog Amps,Attenuators,Mixers Ready */
#define     AD1980_RFLD_VREF                    AC97_RFLD_VREF          /* Voltage references up to nominal lvl */
#define     AD1980_RFLD_PDN_ADC                 AC97_RFLD_PDN_ADC       /* Power Down PCM In ADCs & Input Mux   */
#define     AD1980_RFLD_PDN_DAC                 AC97_RFLD_PDN_DAC       /* Power Down PCM Out DACs              */
#define     AD1980_RFLD_PDN_MIXER               AC97_RFLD_PDN_MIXER     /* PowerDown Analog Mixer(Vref still on)*/
#define     AD1980_RFLD_PDN_VREF                AC97_RFLD_PDN_VREF      /* Power Down Analog Mixer(Vref off)    */
#define     AD1980_RFLD_PDN_AC_LINK             AC97_RFLD_PDN_AC_LINK   /* PowerDown AC Link (Digital interface)*/
#define     AD1980_RFLD_ICLK_DISABLE            AC97_RFLD_ICLK_DISABLE  /* Internal Clock Disable               */
#define     AD1980_RFLD_PDN_AUX_OUT             AC97_RFLD_PDN_AUX_OUT   /* Power Down AUX Out                   */
#define     AD1980_RFLD_PDN_EX_AMP              AC97_RFLD_PDN_EX_AMP    /* Power Down External power amplifier  */

/*****************************************************
Register Field definitions Common to
- AD1980_REG_EXTD_AUDIO_ID (Extended Audio ID Register)
*****************************************************/

#define     AD1980_RFLD_VRA_SUPPORT             AC97_RFLD_VRA_SUPPORT       /* Variable rate PCM Audio support      */
#define     AD1980_RFLD_DRA_SUPPORT             AC97_RFLD_DRA_SUPPORT       /* Dobule rate Audio support            */
#define     AD1980_RFLD_SPDIF_SUPPORT           AC97_RFLD_SPDIF_SUPPORT     /* SPDIF support                        */
#define     AD1980_RFLD_DAC_SLOT_ASSIGN         AC97_RFLD_DAC_SLOT_ASSIGN   /* DAC Slot Assignments                 */
#define     AD1980_RFLD_CTR_DAC_SUPPORT         AC97_RFLD_CTR_DAC_SUPPORT   /* PCM Center DAC Support               */
#define     AD1980_RFLD_SURR_DAC_SUPPORT        AC97_RFLD_SURR_DAC_SUPPORT  /* PCM Surround DAC Support             */
#define     AD1980_RFLD_LFE_DAC_SUPPORT         AC97_RFLD_LFE_DAC_SUPPORT   /* PCM LFE DAC Support                  */
#define     AD1980_RFLD_AMAP_SUPPORT            AC97_RFLD_AMAP_SUPPORT      /* support for Slot/DAC Mappings based on codec id  */
#define     AD1980_RFLD_REV_INFO                AC97_RFLD_REV_INFO          /* AD1980 revision compliant info        */
#define     AD1980_RFLD_CODEC_CONFIG_ID         AC97_RFLD_CODEC_CONFIG_ID   /* Codec Configuration ID               */

/*****************************************************
Register Field definitions Common to
- AD1980_REG_EXTD_AUDIO_CTRL (Extended Audio Status/Control Register)
*****************************************************/

#define     AD1980_RFLD_ENABLE_VRA              AC97_RFLD_ENABLE_VRA            /* 1 = Enable Variable Rate Audio       */
#define     AD1980_RFLD_ENABLE_DRA              AC97_RFLD_ENABLE_DRA            /* 1 = Enable Dobule Rate Audio         */
#define     AD1980_RFLD_ENABLE_SPDIF            AC97_RFLD_ENABLE_SPDIF          /* 1 = Enable SPDIF Tx Subsystem        */
#define     AD1980_RFLD_SPDIF_SLOT_ASSIGN       AC97_RFLD_SPDIF_SLOT_ASSIGN     /* SPDIF Slot Assignment Bits           */
#define     AD1980_RFLD_CTR_DAC_READY           AC97_RFLD_CTR_DAC_READY         /* Center DAC Status (1 = Ready)        */
#define     AD1980_RFLD_SURR_DAC_READY          AC97_RFLD_SURR_DAC_READY        /* Surround DAC Status (1 = Ready)      */
#define     AD1980_RFLD_LFE_DAC_READY           AC97_RFLD_LFE_DAC_READY         /* LFE DAC Status (1 = Ready)           */
#define     AD1980_RFLD_SPDIF_CONFIG_VALID      AC97_RFLD_SPDIF_CONFIG_VALID    /* 1 = SPDIF Congifuration Valid        */
#define     AD1980_RFLD_PDN_CTR_DAC             AC97_RFLD_PDN_CTR_DAC           /* Power Down Center DAC                */
#define     AD1980_RFLD_PDN_SURR_DAC            AC97_RFLD_PDN_SURR_DAC          /* Power Down Surround DAC              */
#define     AD1980_RFLD_PDN_LFE_DAC             AC97_RFLD_PDN_LFE_DAC           /* Power Down LFE DAC                   */
#define     AD1980_RFLD_FORCE_SPDIF_VALID       AC97_RFLD_FORCE_SPDIF_VALID     /* enable/disable SPDIF stream validity flag control */

/*****************************************************
Register Field definitions Common to
- AD1980_REG_CTR_LFE_VOL_CTRL (Center/LFE Volume Control Register)
*****************************************************/

#define     AD1980_RFLD_CTR_VOL                 AC97_RFLD_CTR_VOL   /* Center Volume Control    */
#define     AD1980_RFLD_CTR_MUTE                AC97_RFLD_CTR_MUTE  /* Center Volume Mute       */
#define     AD1980_RFLD_LFE_VOL                 AC97_RFLD_LFE_VOL   /* LFE Volume Control       */
#define     AD1980_RFLD_LFE_MUTE                AC97_RFLD_LFE_MUTE  /* LFE Volume Mute          */

/*****************************************************
Register Field definitions Common to
- AD1980_REG_SURR_VOL_CTRL (Surround Volume Control Register)
*****************************************************/

#define     AD1980_RFLD_SURR_R_VOL              AC97_RFLD_SURR_R_VOL    /* Surround Right Channel Volume    */
#define     AD1980_RFLD_SURR_R_MUTE             AC97_RFLD_SURR_R_MUTE   /* Surround Right Channel Mute      */
#define     AD1980_RFLD_SURR_L_VOL              AC97_RFLD_SURR_L_VOL    /* Surround Left Channel Volume     */
#define     AD1980_RFLD_SURR_L_MUTE             AC97_RFLD_SURR_L_MUTE   /* Surround Left Channel Mute       */

/*****************************************************
Register Field definitions Common to
- AD1980_REG_SPDIF_CTRL (SPDIF Control Register)
*****************************************************/

#define     AD1980_RFLD_SPDIF_PRO               AC97_RFLD_SPDIF_PRO             /* 1 = Professional, 0 = Consumer Audio */
#define     AD1980_RFLD_SPDIF_NON_AUDIO         AC97_RFLD_SPDIF_NON_AUDIO       /* 1 = Non-PCM Audio, 0 = PCM Audio     */
#define     AD1980_RFLD_SPDIF_COPYRIGHT         AC97_RFLD_SPDIF_COPYRIGHT       /* 1 = Copyright asserted               */
#define     AD1980_RFLD_SPDIF_PRE_EMPHASIS      AC97_RFLD_SPDIF_PRE_EMPHASIS    /* 1 = 50us/15us Pre-Emp, 0 = No Pre-Emp*/
#define     AD1980_RFLD_SPDIF_CATEFORY_CODE     AC97_RFLD_SPDIF_CATEFORY_COD    /* Category Code                        */
#define     AD1980_RFLD_SPDIF_GEN_LEVEL         AC97_RFLD_SPDIF_GEN_LEVEL       /* Generation Level                     */
#define     AD1980_RFLD_SPDIF_SAMPLE_RATE       AC97_RFLD_SPDIF_SAMPLE_RATE     /* SPDIF Transmit Sample Rate           */
#define     AD1980_RFLD_SPDIF_VALIDITY          AC97_RFLD_SPDIF_VALIDITY        /* SPDIF validity flag                  */

/*****************************************************
Register Field definitions Common to
- AD1980_REG_EQ_CTRL (Equaliser Control Register)
*****************************************************/

#define     AD1980_RFLD_BIQUAQ_COEFF_ADDR       AC97_RFLD_BIQUAQ_COEFF_ADDR /* Biquad & Coefficient address pointer */
#define     AD1980_RFLD_EQ_CHANNEL_SELECT       AC97_RFLD_EQ_CHANNEL_SELECT /* 0 = Left channel, 1 = Right channel  */
#define     AD1980_RFLD_EQ_SYMMETRY             AC97_RFLD_EQ_SYMMETRY       /* 1 = Right & Left channel coefficients are equal */
#define     AD1980_RFLD_EQ_MUTE                 AC97_RFLD_EQ_MUTE           /* 1 = Equaliser mute                   */

/*****************************************************
Register Field definitions Common to
- AD1980_REG_SERIAL_CONFIG (Serial Configuration Register)
*****************************************************/

#define     AD1980_RFLD_SPDIF_LINK              AC97_RFLD_SPDIF_LINK            /* 1 = SPDIF and DAC are linked, 0 = Not linked */
#define     AD1980_RFLD_SPDIF_DACZ              AC97_RFLD_SPDIF_DACZ            /* when FIFO under-runs, 1 = Forces midescale sample out, 0 = Repeat last sample out    */
#define     AD1980_RFLD_SPDIF_ADC_LOOPAROUND    AC97_RFLD_SPDIF_ADC_LOOPAROUND  /* 1 = Tx connected to AC-Link Stream, 0 = Tx connected to digital ADC stream           */
#define     AD1980_RFLD_INT_MODE_SELECT         AC97_RFLD_INT_MODE_SELECT       /* 1 = Bit 0 SLOT 12, 0 = Slot 6 valid bit  */
#define     AD1980_RFLD_LOOPBACK_SELECT         AC97_RFLD_LOOPBACK_SELECT       /* Loopback Select                          */
#define     AD1980_RFLD_ENABLE_CHAIN            AC97_RFLD_ENABLE_CHAIN          /* 1 = Enable Chain                         */
#define     AD1980_RFLD_DAC_REQUEST_FORCE       AC97_RFLD_DAC_REQUEST_FORCE     /* Sync DAC requests                        */
#define     AD1980_RFLD_SLAVE3_CODEC_MASK       AC97_RFLD_SLAVE3_CODEC_MASK     /* Slave 3 Codec Register Mask              */
#define     AD1980_RFLD_MASTER_CODEC_MASK       AC97_RFLD_MASTER_CODEC_MASK     /* Master Codec Register Mask               */
#define     AD1980_RFLD_SLAVE1_CODEC_MASK       AC97_RFLD_SLAVE1_CODEC_MASK     /* Slave 1 Codec Register Mask              */
#define     AD1980_RFLD_SLAVE2_CODEC_MASK       AC97_RFLD_SLAVE2_CODEC_MASK     /* Slave 2 Codec Register Mask              */
#define     AD1980_RFLD_ENABLE_SLOT16           AC97_RFLD_ENABLE_SLOT16         /* 1 = Enable Slot 16 Mode                  */

/*****************************************************
Register Field definitions Common to
- AD1980_REG_MISC_CTRL (Miscellaneous Control Bit Register)
*****************************************************/

#define     AD1980_RFLD_MIC_BOOST_GAIN          AC97_RFLD_MIC_BOOST_GAIN_ENABLE /* MIC Boost gain select                */
#define     AD1980_RFLD_DISABLE_VREF_OUT        AC97_RFLD_DISABLE_VREF_OUT      /* 1 = Set VREFOUT in High impedence mode, 0 = VREFOUT drivern by internal reference    */
#define     AD1980_RFLD_VREF_OUT_HIGH           AC97_RFLD_VREF_OUT_HIGH         /* 1 = VREFOUT set to 3.70 V, 0 = VREFOUT set to 2.25 V */
#define     AD1980_RFLD_SAMPLE_RATE_UNLOCK      AC97_RFLD_SAMPLE_RATE_UNLOCK    /* 1 = DAC sample rates can be set independently, 0 = All DAC sample rates locked to front sample rate  */
#define     AD1980_RFLD_LINE_OUT_AMP_INPUT      AC97_RFLD_LINE_OUT_AMP_INPUT    /* 1 = LINE_OUT Amps driven by surround DAC output, 0 = LINE_OUT Amps driven by Mixer output    */
#define     AD1980_RFLD_2CHANNEL_MIC_SELECT     AC97_RFLD_2CHANNEL_MIC_SELECT   /* 1 = Record from MIC1 & MIC2, 0 = determined by AD1980_RFLD_MIC_SELECT field value      */
#define     AD1980_RFLD_ENABLE_SPREAD           AC97_RFLD_ENABLE_SPREAD         /* 1 = Enable Spread                    */
#define     AD1980_RFLD_DOWN_MIX_MODE           AC97_RFLD_DOWN_MIX_MODE         /* Down Mix Mode Select                 */
#define     AD1980_RFLD_HEADPHONE_AMP_SELECT    AC97_RFLD_HEADPHONE_AMP_SELECT  /* Headphone Amplifier Select           */
#define     AD1980_RFLD_DISABLE_CTR_LFE_PINS    AC97_RFLD_DISABLE_CTR_LFE_PINS  /* 1 = Disable Center and LFE Out pins  */
#define     AD1980_RFLD_DISABLE_LINE_OUT_PINS   AC97_RFLD_DISABLE_LINE_OUT_PINS /* 1 = Disable Line Out (L & R) pins    */
#define     AD1980_RFLD_ENABLE_MUTE_SPLIT       AC97_RFLD_ENABLE_MUTE_SPLIT     /* 1 = Enable seperate Mute Control     */
#define     AD1980_RFLD_ENABLE_ADI_MODE         AC97_RFLD_ENABLE_ADI_MODE       /* 1 = Enable ADI Compatibility mode    */
#define     AD1980_RFLD_DAC_ZERO_FILL           AC97_RFLD_DAC_ZERO_FILL         /* when DAC's starved for data, 1 = DAC data is zero-filled , 0 = repeat DAC data   */

/*********************************************************************

Data structure to hold AD1980 driver initialisation information

**********************************************************************/
typedef struct ADI_AD1980_INIT_DRIVER
{

    /* Pointer to AD1980 AC'97 Data Frame memory allocated by the application */
    void                        *pDataFrame;

    /* Size of AC'97 Data Frame memory allocated by the application (in bytes) */
    u32                         DataFrameSize;

    /* Pointer to AC'97 Driver Instance memory allocated by the application */
    ADI_AC97_DRIVER_INSTANCE    *pAC97;

    /* Flag ID connected to the reset pin of this Audio Codec */
    ADI_FLAG_ID                 ResetFlagId;

    /* SPORT Device Number allocated for this Audio Codec */
    u32                         SportDevNumber;

}ADI_AD1980_INIT_DRIVER;

/*********************************************************************

Enumerations of Output Sampling Rates supported by AD1980

*********************************************************************/

enum
{
    /* Sampling Rate = 8kHz */
    ADI_AD1980_OUT_SR_8000  = 8000,
    /* Sampling Rate = 11.25kHz */
    ADI_AD1980_OUT_SR_11025 = 11025,
    /* Sampling Rate = 12kHz */
    ADI_AD1980_OUT_SR_12000 = 12000,
    /* Sampling Rate = 16kHz */
    ADI_AD1980_OUT_SR_16000 = 16000,
    /* Sampling Rate = 22.05kHz */
    ADI_AD1980_OUT_SR_22050 = 22050,
    /* Sampling Rate = 24kHz */
    ADI_AD1980_OUT_SR_24000 = 24000,
    /* Sampling Rate = 32kHz */
    ADI_AD1980_OUT_SR_32000 = 32000,
    /* Sampling Rate = 44.1kHz */
    ADI_AD1980_OUT_SR_44100 = 44100,
    /* Sampling Rate = 48kHz */
    ADI_AD1980_OUT_SR_48000 = 48000,
    /* Sampling Rate = 64kHz */
    ADI_AD1980_OUT_SR_64000 = 64000,
    /* Sampling Rate = 88.2kHz */
    ADI_AD1980_OUT_SR_88200 = 88200,
    /* Sampling Rate = 96kHz */
    ADI_AD1980_OUT_SR_96000 = 96000
};

/*********************************************************************

Enumerations for AD1980 Driver Command IDs

*********************************************************************/

enum
{

    /* 0x402D0000 - AD1980 driver enumuration start */
    ADI_AD1980_CMD_START = ADI_AD1980_ENUMERATION_START,

    /* 0x402D0001 - Initialise AD1980 driver
                    Command Param = ADI_AD1980_INIT_DRIVER *
                                    (Address of ADI_AD1980_INIT_DRIVER type structure)
                    Default = None.
                    Note: This Command is MANDATORY and MUST be issued
                          immediately after opening the driver */
    ADI_AD1980_CMD_INIT_DRIVER,

    /* 0x402D0002 - Sets AD1980 driver to use Deferred Callback instead of live callback to process AC'97 frames
                    Command Param = Handle to Deffered Callback Service (ADI_DCB_HANDLE)
                    Default = Live callback, means Frames are processed in\
                              SPORT ISR - at SPORT Rx IVG level
                    Note: To switch from Deferred to live callback, pass Command param as NULL */
    ADI_AD1980_CMD_USE_DCB_TO_PROCESS_FRAMES

    /* Use AC'97 driver commands to manage codec audio mode (stereo/multi-channel) and clear ADC/DAC buffer queue */

    /*  Use Device Access Commands (defined in adi_dev.h) to access AD1980 registers

        List of Device Access Commands supported by AD1980 driver
        +-----------------------------------------------------------------------------------------------------------------------------------+
        |           Command ID                      |       Command Argument            |               Comments                            |
        +-----------------------------------------------------------------------------------------------------------------------------------+
        | ADI_DEV_CMD_REGISTER_READ                 | ADI_DEV_ACCESS_REGISTER *         | Reads a single AD1980 register                    |
        | ADI_DEV_CMD_REGISTER_FIELD_READ           | ADI_DEV_ACCESS_REGISTER_FIELD *   | Reads a specific AD1980 register field            |
        | ADI_DEV_CMD_REGISTER_TABLE_READ           | ADI_DEV_ACCESS_REGISTER *         | Reads a table of AD1980 registers                 |
        | ADI_DEV_CMD_REGISTER_FIELD_TABLE_READ     | ADI_DEV_ACCESS_REGISTER_FIELD *   | Reads a table of AD1980 register(s) field(s)      |
        |                                           |                                   |                                                   |
        | ADI_DEV_CMD_REGISTER_WRITE                | ADI_DEV_ACCESS_REGISTER *         | Writes to a single AD1980 register                |
        | ADI_DEV_CMD_REGISTER_FIELD_WRITE          | ADI_DEV_ACCESS_REGISTER_FIELD *   | Writes to a AD1980 register field                 |
        | ADI_DEV_CMD_REGISTER_TABLE_WRITE          | ADI_DEV_ACCESS_REGISTER *         | Writes to a table of AD1980 registers             |
        | ADI_DEV_CMD_REGISTER_FIELD_TABLE_WRITE    | ADI_DEV_ACCESS_REGISTER_FIELD *   | Writes to a table of AD1980 register(s) field(s)  |
        +-----------------------------------------------------------------------------------------------------------------------------------+
        Please note that Device Block Access Commands are NOT supported by AC'97/AD1980 driver
    */
};

/*********************************************************************

Enumerations for AD1980 Driver return codes

*********************************************************************/

enum
{
    /* 0x402D0000 - AD1980 driver enumuration start */
    ADI_AD1980_RESULT_START = ADI_AD1980_ENUMERATION_START,
    /* 0x402D0001 - Command not supported by this driver */
    ADI_AD1980_RESULT_CMD_NOT_SUPPORTED,
    /* 0x402D0002 - AC'97 instance allocated to this driver is invalid */
    ADI_AD1980_RESULT_AC97_INSTANCE_INVALID,
    /* 0x402D0003 - Register Access already in use */
    ADI_AD1980_RESULT_REG_ACCESS_ALREADY_IN_USE,
    /* 0x402D0004 - Reset Flag ID is invalid */
    ADI_AD1980_RESULT_RESET_FLAG_ID_INVALID
};

/*********************************************************************

Enumerations for AD1980 Driver Events

*********************************************************************/

enum
{
    /* 0x402D0000 - AD1980 driver enumuration start */
    ADI_AD1980_EVENT_START = ADI_AD1980_ENUMERATION_START
};

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /* __ADI_AD1980_H__ */
