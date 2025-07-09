/**********************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_ac97.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
    This is the include file for Audio Codec '97 (AC'97) driver

***********************************************************************/

#ifndef __ADI_AC97_H__
#define __ADI_AC97_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*********************************************************************

Macros for the memory usage of AC'97 driver

*********************************************************************/

/* base memory needed for one AC'97 data frame
  inbound & outbound buffers operated in ping-pong fashion (32bytes * 4)    */
#define     ADI_AC97_DATA_FRAME_BASE_MEMORY         (128)   /* bytes */

/* Memory needed for one AC'97 driver instance */
#define     ADI_AC97_DRIVER_INSTANCE_MEMORY         (sizeof(ADI_AC97_DRIVER_INSTANCE))

/*********************************************************************

AC'97 Codec Register definitions

**********************************************************************/

#define     AC97_REG_RESET                          0x0000      /* Reset Register                       */
#define     AC97_REG_MASTER_VOL_CTRL                0x0200      /* Master Volume Control Register       */
#define     AC97_REG_HP_VOL_CTRL                    0x0400      /* Headphones Volume Control Register   */
#define     AC97_REG_MONO_VOL_CTRL                  0x0600      /* Mono Volume Control Register         */
#define     AC97_REG_MASTER_TONE                    0x0800      /* not yet supported                    */
#define     AC97_REG_PC_BEEP_VOL_CTRL               0x0A00      /* not yet supported                    */
#define     AC97_REG_PHONE_VOL_CTRL                 0x0C00      /* Phone In Volume Control Register     */
#define     AC97_REG_MIC_VOL_CTRL                   0x0E00      /* MIC Volume Control Register          */
#define     AC97_REG_LINE_IN_VOL_CTRL               0x1000      /* Line-In Volume Control Register      */
#define     AC97_REG_CD_VOL_CTRL                    0x1200      /* CD Volume Control Register           */
#define     AC97_REG_VIDEO_VOL_CTRL                 0x1400      /* not yet supported                    */
#define     AC97_REG_AUX_VOL_CTRL                   0x1600      /* AUX Volume Control Register          */
#define     AC97_REG_PCM_OUT_VOL_CTRL               0x1800      /* PCM Out Volume Control Register      */
#define     AC97_REG_RECORD_SELECT                  0x1A00      /* Record select Control Register       */
#define     AC97_REG_RECORD_GAIN                    0x1C00      /* Record gain Register                 */
#define     AC97_REG_RECORD_GAIN_MIC                0x1E00      /* not yet supported                    */
#define     AC97_REG_GP                             0x2000      /* General purpose Register             */
#define     AC97_REG_3D_CTRL                        0x2200      /* not yet supported                    */
#define     AC97_REG_AUDIO_INT_PAGE                 0x2400      /* Audio Interrupt an Paging            */
#define     AC97_REG_POWER_CTRL_STAT                0x2600      /* Power-down Control/Status Register   */
#define     AC97_REG_EXTD_AUDIO_ID                  0x2800      /* Extended Audio ID Register           */
#define     AC97_REG_EXTD_AUDIO_CTRL                0x2A00      /* Extended Audio Status/Control Reg    */
#define     AC97_REG_FRONT_DAC_RATE                 0x2C00      /* PCM Front DAC Sample Rate reg        */
#define     AC97_REG_SURR_DAC_RATE                  0x2E00      /* PCM Surround DAC Sample Rate reg     */
#define     AC97_REG_CTR_LFE_DAC_RATE               0x3000      /* PCM Center/LFE DAC Sample Rate reg   */
#define     AC97_REG_ADC_RATE                       0x3200      /* PCM ADC sample rate Register         */
#define     AC97_REG_MIC_ADC_RATE                   0x3400      /* not yet supported                    */
#define     AC97_REG_CTR_LFE_VOL_CTRL               0x3600      /* Center/LFE Volume Control Register   */
#define     AC97_REG_SURR_VOL_CTRL                  0x3800      /* Surround Volume Control Register     */
#define     AC97_REG_SPDIF_CTRL                     0x3A00      /* S/PDIF Control Register              */
#define     AC97_REG_EQ_CTRL                        0x6000      /* Equaliser Control Register           */
#define     AC97_REG_EQ_DATA                        0x6200      /* Equaliser Data Register              */
#define     AC97_REG_MISC_CTRL_2                    0x7000      /* not yet supported                    */
#define     AC97_REG_JACK_SENSE                     0x7200      /* not yet supported                    */
#define     AC97_REG_SERIAL_CONFIG                  0x7400      /* Serial Configuration Register        */
#define     AC97_REG_MISC_CTRL_1                    0x7600      /* Miscellaneous Control Register 1     */
#define     AC97_REG_ADV_JACK_SENSE                 0x7800      /* not yet supported                    */
#define     AC97_REG_MISC_CTRL_3                    0x7A00      /* not yet supported                    */
#define     AC97_REG_VENDOR_ID_1                    0x7C00      /* Vendor ID Register 1                 */
#define     AC97_REG_VENDOR_ID_2                    0x7E00      /* Vendor ID Register 2                 */

/*********************************************************************

AC'97 Register Field definitions
(Mask value to extract the corresponding Register field)

**********************************************************************/

/*****************************************************
Register Field definitions Common to
- AC97_REG_RESET (Reset Register)
*****************************************************/

#define     AC97_RFLD_ID_CODEC_SUPPORT          0x03FF      /* Identify Codec Capabilities          */
#define     AC97_RFLD_3D_SURR_ENHANCE           0x7C00      /* 3D Stereo Enhancement support code   */

/*****************************************************
Register Field definitions Common to
- AC97_REG_MASTER_VOL_CTRL (Master Volume Control Register)
- AC97_REG_HP_VOL_CTRL     (Headphones Volume Control Register)
*****************************************************/

#define     AC97_RFLD_MASTER_HP_R_VOL           0x003F      /* Master/HP Right Channel Volume       */
#define     AC97_RFLD_MASTER_HP_R_MUTE          0x0080      /* Master/HP Right Channel Mute         */
#define     AC97_RFLD_MASTER_HP_L_VOL           0x3F00      /* Master/HP Left Channel Volume        */
#define     AC97_RFLD_MASTER_HP_L_MUTE          0x8000      /* Master/HP Left Channel Mute          */
#define     AC97_RFLD_MASTER_HP_MUTE            0x8000      /* Mute Headphone/Master Volume         */

/*****************************************************
Register Field definitions Common to
- AC97_REG_MONO_VOL_CTRL (Mono Volume Control Register)
*****************************************************/

#define     AC97_RFLD_MONO_VOL                  0x003F      /* Mono Volume                          */
#define     AC97_RFLD_MONO_MUTE                 0x8000      /* Mute Mono Volume                     */

/*****************************************************
Register Field definitions Common to
- AC97_REG_PHONE_VOL_CTRL (Phone In Volume Control Register)
*****************************************************/

#define     AC97_RFLD_PHONE_VOL                 0x001F      /* Phone In Volume                      */
#define     AC97_RFLD_PHONE_MUTE                0x8000      /* Mute Phone In Volume                 */

/*****************************************************
Register Field definitions Common to
- AC97_REG_MIC_VOL_CTRL (MIC Volume Control Register)
*****************************************************/

#define     AC97_RFLD_MIC_VOL_GAIN              0x001F      /* MIC Volume Gain                      */
#define     AC97_RFLD_MIC_BOOST_GAIN_ENABLE     0x0040      /* 1 = Enable MIC Volume Gain           */
#define     AC97_RFLD_MIC_MUTE                  0x8000      /* Mute MIC                             */

/*****************************************************
Register Field definitions Common to
- AC97_REG_LINE_IN_VOL_CTRL (Line-In Volume Control Register)
- AC97_REG_CD_VOL_CTRL      (CD Volume Control Register)
- AC97_REG_AUX_VOL_CTRL     (AUX Volume Control Register)
*****************************************************/

#define     AC97_RFLD_AUX_CD_LINE_IN_R_VOL      0x001F      /* AUX/CD/Line In Right Channel Volume  */
#define     AC97_RFLD_AUX_CD_LINE_IN_R_MUTE     0x0080      /* AUX/CD/Line In Right Channel Mute    */
#define     AC97_RFLD_AUX_CD_LINE_IN_L_VOL      0x1F00      /* AUX/CD/Line In Left Channel Volume   */
#define     AC97_RFLD_AUX_CD_LINE_IN_L_MUTE     0x8000      /* AUX/CD/Line In Left Channel Mute     */
#define     AC97_RFLD_AUX_CD_LINE_IN_MUTE       0x8000      /* Mute AUX/CD/Line In Volume           */

/*****************************************************
Register Field definitions Common to
- AC97_REG_PCM_OUT_VOL_CTRL (PCM Out Volume Control Register)
*****************************************************/

#define     AC97_RFLD_PCM_OUT_R_VOL             0x001F      /* PCM Out Right Channel Volume         */
#define     AC97_RFLD_PCM_OUT_R_MUTE            0x0080      /* PCM Out Right Channel Mute           */
#define     AC97_RFLD_PCM_OUT_L_VOL             0x1F00      /* PCM Out Left Channel Volume          */
#define     AC97_RFLD_PCM_OUT_L_MUTE            0x8000      /* PCM Out Left Channel Mute            */
#define     AC97_RFLD_PCM_OUT_MUTE              0x8000      /* Mute PCM Out Volume                  */

/*****************************************************
Register Field definitions Common to
- AC97_REG_RECORD_SELECT (Record Select Register)
*****************************************************/

#define     AC97_RFLD_RECORD_SELECT_R           0x0007      /* Right Record Select                  */
#define     AC97_RFLD_RECORD_SELECT_L           0x0700      /* Left Record Select                   */

/*****************************************************
Register Field definitions Common to
- AC97_REG_RECORD_GAIN (Record Gain Register)
*****************************************************/

#define     AC97_RFLD_RECORD_R_GAIN             0x000F      /* Right Input Mixer Gain               */
#define     AC97_RFLD_RECORD_R_MUTE             0x0080      /* Right Input Channel Mute             */
#define     AC97_RFLD_RECORD_L_GAIN             0x0F00      /* Left Input Mixer Gain                */
#define     AC97_RFLD_RECORD_L_MUTE             0x8000      /* Left Input Channel Mute              */
#define     AC97_RFLD_RECORD_INPUT_MUTE         0x8000      /* Mute Input Channels                  */

/*****************************************************
Register Field definitions Common to
- AC97_REG_GP (General Purpose Register)
*****************************************************/

#define     AC97_RFLD_LOOPBACK                  0x0080      /* Loopback Control                     */
#define     AC97_RFLD_MIC_SELECT                0x0100      /* Selects Mono MIC Input               */
#define     AC97_RFLD_MONO_OUT_MIX              0x0200      /* Mono Output Select                   */
#define     AC97_RFLD_DOBULE_RATE_SLOTS         0x0400      /* Dobule Rate Slot Select              */
#define     AC97_RFLD_BASS_BOOST                0x1000      /* Loudness (Bass Boost) ON/OFF         */
#define     AC97_RFLD_3D_ENHANCE                0x2000      /* 3D Enhancement ON/OFF                */
#define     AC97_RFLD_STIMULATED_STEREO         0x4000      /* Stimulated Stereo Enhancement ON/OFF */
#define     AC97_RFLD_PCM_OUT_PATH              0x8000      /* PCM Out path                         */

/*****************************************************
Register Field definitions Common to
- AC97_REG_AUDIO_INT_PAGE (Audio Interrupt and Paging Register)
*****************************************************/

#define     AC97_RFLD_PAGE_SELECTOR             0x000F      /* Page Selector                        */
#define     AC97_RFLD_ENABLE_INT                0x0800      /* 1 = Enable Interrupt                 */
#define     AC97_RFLD_SENSE_CYCLE               0x1000      /* Sense Cycle                          */
#define     AC97_RFLD_INT_CAUSE                 0x6000      /* Interrupt Cause                      */
#define     AC97_RFLD_INT_STATUS                0x8000      /* Interrupt Status                     */

/*****************************************************
Register Field definitions Common to
- AC97_REG_POWER_CTRL (Power Control/Status Register)
*****************************************************/

#define     AC97_RFLD_ADC_READY                 0x0001      /* ADC Sections Ready to Transmit       */
#define     AC97_RFLD_DAC_READY                 0x0002      /* DAC Sections Ready to Transmit       */
#define     AC97_RFLD_ANL_READY                 0x0004      /* Analog Amps,Attenuators,Mixers Ready */
#define     AC97_RFLD_VREF                      0x0008      /* Voltage references up to nominal lvl */
#define     AC97_RFLD_PDN_ADC                   0x0100      /* Power Down PCM In ADCs & Input Mux   */
#define     AC97_RFLD_PDN_DAC                   0x0200      /* Power Down PCM Out DACs              */
#define     AC97_RFLD_PDN_MIXER                 0x0400      /* PowerDown Analog Mixer(Vref still on)*/
#define     AC97_RFLD_PDN_VREF                  0x0800      /* Power Down Analog Mixer(Vref off)    */
#define     AC97_RFLD_PDN_AC_LINK               0x1000      /* PowerDown AC Link (Digital interface)*/
#define     AC97_RFLD_ICLK_DISABLE              0x2000      /* Internal Clock Disable               */
#define     AC97_RFLD_PDN_AUX_OUT               0x4000      /* Power Down AUX Out                   */
#define     AC97_RFLD_PDN_EX_AMP                0x8000      /* Power Down External power amplifier  */

/*****************************************************
Register Field definitions Common to
- AC97_REG_EXTD_AUDIO_ID (Extended Audio ID Register)
*****************************************************/

#define     AC97_RFLD_VRA_SUPPORT               0x0001      /* Variable rate PCM Audio support      */
#define     AC97_RFLD_DRA_SUPPORT               0x0002      /* Dobule rate Audio support            */
#define     AC97_RFLD_SPDIF_SUPPORT             0x0004      /* SPDIF support                        */
#define     AC97_RFLD_VRM_SUPPORT               0x0008      /* Variable rate MIC Input support      */
#define     AC97_RFLD_DAC_SLOT_ASSIGN           0x0030      /* DAC Slot Assignments                 */
#define     AC97_RFLD_CTR_DAC_SUPPORT           0x0040      /* PCM Center DAC Support               */
#define     AC97_RFLD_SURR_DAC_SUPPORT          0x0080      /* PCM Surround DAC Support             */
#define     AC97_RFLD_LFE_DAC_SUPPORT           0x0100      /* PCM LFE DAC Support                  */
#define     AC97_RFLD_AMAP_SUPPORT              0x0200      /* support for Slot/DAC Mappings based on codec id  */
#define     AC97_RFLD_REV_INFO                  0x0C00      /* AC'97 revision compliant info        */
#define     AC97_RFLD_CODEC_CONFIG_ID           0xC000      /* Codec Configuration ID               */

/*****************************************************
Register Field definitions Common to
- AC97_REG_EXTD_AUDIO_CTRL (Extended Audio Status/Control Register)
*****************************************************/

#define     AC97_RFLD_ENABLE_VRA                0x0001      /* 1 = Enable Variable Rate Audio       */
#define     AC97_RFLD_ENABLE_DRA                0x0002      /* 1 = Enable Dobule Rate Audio         */
#define     AC97_RFLD_ENABLE_SPDIF              0x0004      /* 1 = Enable SPDIF Tx Subsystem        */
#define     AC97_RFLD_ENABLE_VRM                0x0008      /* 1=Enable Variable Rate Audio for MIC */
#define     AC97_RFLD_SPDIF_SLOT_ASSIGN         0x0030      /* SPDIF Slot Assignment Bits           */
#define     AC97_RFLD_CTR_DAC_READY             0x0040      /* Center DAC Status (1 = Ready)        */
#define     AC97_RFLD_SURR_DAC_READY            0x0080      /* Surround DAC Status (1 = Ready)      */
#define     AC97_RFLD_LFE_DAC_READY             0x0100      /* LFE DAC Status (1 = Ready)           */
#define     AC97_RFLD_MIC_ADC_READY             0x0200      /* MIC ADC Status (1 = Ready)           */
#define     AC97_RFLD_SPDIF_CONFIG_VALID        0x0400      /* 1 = SPDIF Congifuration Valid        */
#define     AC97_RFLD_PDN_CTR_DAC               0x0800      /* Power Down Center DAC                */
#define     AC97_RFLD_PDN_SURR_DAC              0x1000      /* Power Down Surround DAC              */
#define     AC97_RFLD_PDN_LFE_DAC               0x2000      /* Power Down LFE DAC                   */
#define     AC97_RFLD_PDN_MIC_ADC               0x4000      /* Power Down MIC ADC                   */
#define     AC97_RFLD_FORCE_SPDIF_VALID         0x8000      /* enable/disable SPDIF stream validity flag control */

/*****************************************************
Register Field definitions Common to
- AC97_REG_CTR_LFE_VOL_CTRL (Center/LFE Volume Control Register)
*****************************************************/

#define     AC97_RFLD_CTR_VOL                   0x003F      /* Center Volume Control                */
#define     AC97_RFLD_CTR_MUTE                  0x0080      /* Center Volume Mute                   */
#define     AC97_RFLD_LFE_VOL                   0x3F00      /* LFE Volume Control                   */
#define     AC97_RFLD_LFE_MUTE                  0x8000      /* LFE Volume Mute                      */

/*****************************************************
Register Field definitions Common to
- AC97_REG_SURR_VOL_CTRL (Surround Volume Control Register)
*****************************************************/

#define     AC97_RFLD_SURR_R_VOL                0x001F      /* Surround Right Channel Volume        */
#define     AC97_RFLD_SURR_R_MUTE               0x0080      /* Surround Right Channel Mute          */
#define     AC97_RFLD_SURR_L_VOL                0x1F00      /* Surround Left Channel Volume         */
#define     AC97_RFLD_SURR_L_MUTE               0x8000      /* Surround Left Channel Mute           */

/*****************************************************
Register Field definitions Common to
- AC97_REG_SPDIF_CTRL (SPDIF Control Register)
*****************************************************/

#define     AC97_RFLD_SPDIF_PRO                 0x0001      /* 1 = Professional, 0 = Consumer Audio */
#define     AC97_RFLD_SPDIF_NON_AUDIO           0x0002      /* 1 = Non-PCM Audio, 0 = PCM Audio     */
#define     AC97_RFLD_SPDIF_COPYRIGHT           0x0004      /* 1 = Copyright asserted               */
#define     AC97_RFLD_SPDIF_PRE_EMPHASIS        0x0008      /* 1 = 50us/15us Pre-Emp, 0 = No Pre-Emp*/
#define     AC97_RFLD_SPDIF_CATEFORY_CODE       0x07F0      /* Category Code                        */
#define     AC97_RFLD_SPDIF_GEN_LEVEL           0x0800      /* Generation Level                     */
#define     AC97_RFLD_SPDIF_SAMPLE_RATE         0x3000      /* SPDIF Transmit Sample Rate           */
#define     AC97_RFLD_SPDIF_ENABLE_DOBULE_RATE  0x4000      /* 1 = Enable Dobule Rate SPDIF         */
#define     AC97_RFLD_SPDIF_VALIDITY            0x8000      /* SPDIF validity flag                  */

/*****************************************************
Register Field definitions Common to
- AC97_REG_EQ_CTRL (Equaliser Control Register)
*****************************************************/

#define     AC97_RFLD_BIQUAQ_COEFF_ADDR         0x003F      /* Biquad & Coefficient address pointer */
#define     AC97_RFLD_EQ_CHANNEL_SELECT         0x0040      /* 0 = Left channel, 1 = Right channel  */
#define     AC97_RFLD_EQ_SYMMETRY               0x0080      /* 1 = Right & Left channel coefficients are equal */
#define     AC97_RFLD_EQ_MUTE                   0x8000      /* 1 = Equaliser mute                   */

/*****************************************************
Register Field definitions Common to
- AC97_REG_SERIAL_CONFIG (Serial Configuration Register)
*****************************************************/

#define     AC97_RFLD_SPDIF_LINK                0x0001      /* 1 = SPDIF and DAC are linked, 0 = Not linked */
#define     AC97_RFLD_SPDIF_DACZ                0x0002      /* when FIFO under-runs, 1 = Forces midescale sample out, 0 = Repeat last sample out    */
#define     AC97_RFLD_SPDIF_ADC_LOOPAROUND      0x0004      /* 1 = Tx connected to AC-Link Stream, 0 = Tx connected to digital ADC stream           */
#define     AC97_RFLD_INT_MODE_SELECT           0x0010      /* 1 = Bit 0 SLOT 12, 0 = Slot 6 valid bit  */
#define     AC97_RFLD_LOOPBACK_SELECT           0x0060      /* Loopback Select                          */
#define     AC97_RFLD_ENABLE_CHAIN              0x0100      /* 1 = Enable Chain                         */
#define     AC97_RFLD_DAC_REQUEST_FORCE         0x0400      /* Sync DAC requests                        */
#define     AC97_RFLD_SLAVE3_CODEC_MASK         0x0800      /* Slave 3 Codec Register Mask              */
#define     AC97_RFLD_MASTER_CODEC_MASK         0x1000      /* Master Codec Register Mask               */
#define     AC97_RFLD_SLAVE1_CODEC_MASK         0x2000      /* Slave 1 Codec Register Mask              */
#define     AC97_RFLD_SLAVE2_CODEC_MASK         0x4000      /* Slave 2 Codec Register Mask              */
#define     AC97_RFLD_ENABLE_SLOT16             0x8000      /* 1 = Enable Slot 16 Mode                  */

/*****************************************************
Register Field definitions Common to
- AC97_REG_MISC_CTRL_1 (Miscellaneous Control Bit Register 1)
*****************************************************/

#define     AC97_RFLD_MIC_BOOST_GAIN_SELECT     0x0003      /* MIC Boost gain select                */
#define     AC97_RFLD_DISABLE_VREF_OUT          0x0004      /* 1 = Set VREFOUT in High impedence mode, 0 = VREFOUT drivern by internal reference    */
#define     AC97_RFLD_VREF_OUT_HIGH             0x0008      /* 1 = VREFOUT set to 3.70 V, 0 = VREFOUT set to 2.25 V */
#define     AC97_RFLD_SAMPLE_RATE_UNLOCK        0x0010      /* 1 = DAC sample rates can be set independently, 0 = All DAC sample rates locked to front sample rate  */
#define     AC97_RFLD_LINE_OUT_AMP_INPUT        0x0020      /* 1 = LINE_OUT Amps driven by surround DAC output, 0 = LINE_OUT Amps driven by Mixer output    */
#define     AC97_RFLD_2CHANNEL_MIC_SELECT       0x0040      /* 1 = Record from MIC1 & MIC2, 0 = determined by AC97_RFLD_MIC_SELECT field value      */
#define     AC97_RFLD_ENABLE_SPREAD             0x0080      /* 1 = Enable Spread                    */
#define     AC97_RFLD_DOWN_MIX_MODE             0x0300      /* Down Mix Mode Select                 */
#define     AC97_RFLD_HEADPHONE_AMP_SELECT      0x0400      /* Headphone Amplifier Select           */
#define     AC97_RFLD_DISABLE_CTR_LFE_PINS      0x0800      /* 1 = Disable Center and LFE Out pins  */
#define     AC97_RFLD_DISABLE_LINE_OUT_PINS     0x1000      /* 1 = Disable Line Out (L & R) pins    */
#define     AC97_RFLD_ENABLE_MUTE_SPLIT         0x2000      /* 1 = Enable seperate Mute Control     */
#define     AC97_RFLD_ENABLE_ADI_MODE           0x4000      /* 1 = Enable ADI Compatibility mode    */
#define     AC97_RFLD_DAC_ZERO_FILL             0x8000      /* when DAC's starved for data, 1 = DAC data is zero-filled , 0 = repeat DAC data   */

/*********************************************************************

Enumerations for DAC Sample rates supported by AC'97 driver

**********************************************************************/
enum {

    ADI_AC97_SR_48000 = 48000,      /* 48kHz        */
    ADI_AC97_SR_44100 = 44100,      /* 44.1kHz      */
    ADI_AC97_SR_32000 = 32000,      /* 32kHz        */
    ADI_AC97_SR_24000 = 24000,      /* 24kHz        */
    ADI_AC97_SR_22050 = 22050,      /* 22.05kHz     */
    ADI_AC97_SR_16000 = 16000,      /* 16kHz        */
    ADI_AC97_SR_12000 = 12000,      /* 12kHz        */
    ADI_AC97_SR_11025 = 11025,      /* 11.025kHz    */
    ADI_AC97_SR_8000  = 8000        /* 8kHz         */
};
/*********************************************************************

Enumerations for AC'97 - Codec Register access mode

**********************************************************************/
typedef enum AD_AC97_CODEC_REG_ACCESS_MODE  {
    ADI_AC97_CODEC_REG_ACCESS_IDLE,             /* Register access is idle                          */
    ADI_AC97_CODEC_REG_ACCESS_READ,             /* Read a AC'97 Codec Register                      */
    ADI_AC97_CODEC_REG_ACCESS_WRITE,            /* Write to a AC'97 Codec Register                  */
    ADI_AC97_CODEC_REG_ACCESS_WRITE_IN_PROGRESS,/* Write to a AC'97 Codec Register is in progress   */
    ADI_AC97_CODEC_REG_ACCESS_COMPLETE          /* Register access is complete                      */
} AD_AC97_CODEC_REG_ACCESS_MODE;

/*********************************************************************

Enumerations for AC'97 Driver mode

**********************************************************************/
typedef enum ADI_AC97_DRIVER_MODE
{

    /* Codec is in Idle state */
    ADI_AC97_MODE_CODEC_IDLE                        = 0U,
    /* Wait until codec is ready */
    ADI_AC97_MODE_CODEC_WAIT_FOR_CODEC_READY        = 0x01U,
    /* Wait until codec sub-system is ready */
    ADI_AC97_MODE_CODEC_WAIT_FOR_SUB_SYSTEM_READY   = 0x02U,
    /* Codec is ready for audio streaming */
    ADI_AC97_MODE_CODEC_READY_FOR_AUDIO_STREAM      = 0x04U,
    /* Audio Transmit dataflow enabled/disabled */
    ADI_AC97_MODE_CODEC_TX_DATAFLOW_ENABLED         = 0x08U,
    /* Audio Receive dataflow enabled/disabled */
    ADI_AC97_MODE_CODEC_RX_DATAFLOW_ENABLED         = 0x10U

} ADI_AC97_DRIVER_MODE;

/*********************************************************************

Enumerations for sampling rates supported by the driver

**********************************************************************/
enum {
    ADI_AC97_PCM_SAMPLE_RATE_48KHZ      = 48000,    /* 48kHz Sampling Frequency     */
    ADI_AC97_PCM_SAMPLE_RATE_44_1KHZ    = 44100,    /* 44.1kHz Sampling Frequency   */
    ADI_AC97_PCM_SAMPLE_RATE_32KHZ      = 32000,    /* 32kHz Sampling Frequency     */
    ADI_AC97_PCM_SAMPLE_RATE_24KHZ      = 24000,    /* 24kHz Sampling Frequency     */
    ADI_AC97_PCM_SAMPLE_RATE_22_05KHZ   = 22050,    /* 22.05kHz Sampling Frequency  */
    ADI_AC97_PCM_SAMPLE_RATE_16KHZ      = 16000,    /* 16kHz Sampling Frequency     */
    ADI_AC97_PCM_SAMPLE_RATE_12KHZ      = 12000,    /* 12kHz Sampling Frequency     */
    ADI_AC97_PCM_SAMPLE_RATE_11_025KHZ  = 11025,    /* 11.025kHz Sampling Frequency */
    ADI_AC97_PCM_SAMPLE_RATE_8KHZ       = 8000      /* 8kHz Sampling Frequency      */
};

/*********************************************************************

Data structure to manage ADC data slots (24 bytes)

**********************************************************************/
typedef struct ADI_AC97_APP_ADC_DATA_BUFFER {
    ADI_DEV_1D_BUFFER   *pInHead;           /* head of ADC channel buffers                  */
    ADI_DEV_1D_BUFFER   *pInTail;           /* tail of ADC channel buffers                  */
}ADI_AC97_APP_ADC_DATA_BUFFER;

/*********************************************************************

Data structures to manage DAC data slots

**********************************************************************/

typedef struct ADI_AC97_OUT_SLOT_RATIO                  /* Valid/Invalid output slots ratio                             */
{
    u32                             RepeatSlotOut;      /* # times to repeat this slot out combination                  */
    u32                             ValidSlots;         /* # Valid slots                                                */
    u32                             InvalidSlots;       /* # Invalid slots                                              */
    struct ADI_AC97_OUT_SLOT_RATIO  *pNextSlotRatio;    /* pointer to next output slot ratio                            */
}ADI_AC97_OUT_SLOT_RATIO;

typedef struct ADI_AC97_SLOT_SEQUENCE                   /* Slot Output sequence                                         */
{
    u32                             RepeatSlotSequence; /* # times to repeat this sequence                              */
    ADI_AC97_OUT_SLOT_RATIO         *pSlotRatio;        /* Valid/Invalid output slots ratio                             */
    struct ADI_AC97_SLOT_SEQUENCE   *pNextSequence;     /* pointer to next slot interleave sequence                     */
}ADI_AC97_SLOT_SEQUENCE;

typedef struct ADI_AC97_APP_DAC_DATA_BUFFER {           /* Structure to manage DAC data slots                           */
    ADI_DEV_1D_BUFFER               *pOutHead;          /* head of Front/Surround/Center/LFE DAC channel buffers        */
    ADI_DEV_1D_BUFFER               *pOutTail;          /* tail of Front/Surround/Center/LFE DAC channel buffers        */
    ADI_AC97_OUT_SLOT_RATIO         SlotRatio[4];       /* to hold output slot ratios for selected DAC sampling rate    */
    ADI_AC97_SLOT_SEQUENCE          SlotSequence[2];    /* to hold slot output sequence for selected DAC sampling rate  */
    ADI_AC97_OUT_SLOT_RATIO         *pSlotOutRatio;     /* Pointer to slot output ratio we're working on                */
    ADI_AC97_SLOT_SEQUENCE          *pSlotSequence;     /* Pointer to slot output sequence we're working on             */
    volatile u32                    SlotRepeatCount;    /* # times to repeat this slot out combination                  */
    volatile u32                    SlotSequenceCount;  /* # times to repeat this slot out sequence                     */
    volatile u32                    ValidSlotsRemain;   /* number of valid slots remaining in this slot out ratio       */
    volatile u32                    InValidSlotsRemain; /* number of invalid slots remaining in this slot out ratio     */
}ADI_AC97_APP_DAC_DATA_BUFFER;

/*********************************************************************

Structure to hold Audio Codec Register Access information (16 bytes)

**********************************************************************/
typedef struct ADI_AC97_CODEC_REG_ACCESS {
    u32                             Cmd;            /* Device access command issued by the application                      */
    void                            *pTable;        /* Pointer to Register access table passed with the Device Access cmd   */
    u16                             *pAccess;       /* Pointer to Register access element presently being processed         */
    u16                             tRegData;       /* Temp location to hold the last register configuration data           */
    AD_AC97_CODEC_REG_ACCESS_MODE   Mode;           /* Register access mode                                                 */
}ADI_AC97_CODEC_REG_ACCESS;

/*********************************************************************

AC'97 driver instance structure

**********************************************************************/
typedef struct ADI_AC97_DRIVER_INSTANCE
{
    ADI_DEV_CIRCULAR_BUFFER         AdcCircBuf;         /* Circular buffer to handle ADC data (2 sub-buffers)               */
    ADI_DEV_CIRCULAR_BUFFER         DacCircBuf;         /* Circular buffer to handle DAC data (2 sub-buffers)               */
    u32                             FramesPerSubBuf;    /* # AC'97 frames per sub buffer                                    */
    u8                              CallbackSubBuffer;  /* Sub buffer id (0 or 1) that generated this callback              */
    ADI_AC97_APP_ADC_DATA_BUFFER    AdcAppBuf;          /* Structure to hold ADC data buffer(s) address                     */
    ADI_AC97_APP_DAC_DATA_BUFFER    DacAppBuf;          /* Structure to hold DAC data buffer(s) address                     */
    ADI_AC97_CODEC_REG_ACCESS       RegAccess;          /* Register Access information for this audio codec                 */
    ADI_DCB_CALLBACK_FN             CodecCallback;      /* Callback function supplied by the Audio Codec driver             */
    ADI_DCB_CALLBACK_FN             AC97Callback;       /* Callback function supplied by the this AC'97 driver instance     */
    void                            *pEnterCriticalArg; /* Critical region argument                                         */
    u8                              CodecId;            /* Audio Codec ID                                                   */
    volatile u16                    DriverStatus1;      /* AC'97 driver Status register 1                                   */
    volatile u16                    DriverStatus2;      /* AC'97 drvier Status register 2                                   */
    ADI_AC97_DRIVER_MODE            DriverMode;         /* AC'97 Driver Mode                                                */
}ADI_AC97_DRIVER_INSTANCE;

/*********************************************************************

Data structure to hold AC'97 supported
Audio Codec driver initialisation information

**********************************************************************/
typedef struct ADI_AC97_DRIVER_INIT
{
    void                        *pDataFrame;    /* Pointer to AC'97 Data Frame memory allocated by the application          */
    u32                         DataFrameSize;  /* Size of AC'97 Data Frame memory allocated by the application (in bytes)  */
    ADI_AC97_DRIVER_INSTANCE    *pAC97;         /* Pointer to AC'97 Driver Instance memory allocated by the application     */
    ADI_FLAG_ID                 ResetFlagId;    /* Flag ID connected Audio Codec Reset pin                                  */
    u32                         SportDevNumber; /* SPORT Device Number allocated for this Audio Codec                       */
}ADI_AC97_DRIVER_INIT;

/*********************************************************************

Enumerations for AC'97 Driver Command IDs

*********************************************************************/

enum
{

    /* 0x402C0000 - AC97 driver enumuration start */
    ADI_AC97_CMD_START = ADI_AC97_ENUMERATION_START,

    /*
    ** 0x402C0001 - Enable/Disable Multichannel Audio.
    **              Value   = TRUE/FALSE, TRUE for Multichannel Audio, FASLE for Stereo
    **              Default = FALSE (Stereo mode)
    **              Note:
    **              - When Disabled, DAC buffers are considered to hold multichannel
    **                audio or stereo audio in interleaved format (depends on whether
    **                true multichannel audio is enabled or disabled)
    **              - When Disabled, DAC buffers are considered to hold stereo audio
    **                in interleaved format (Line-Out Left, Line-Out Right)
    */
    ADI_AC97_CMD_ENABLE_MULTICHANNEL_AUDIO,

    /*
    ** 0x402C0002 - Enable/Disable true Multi-channel audio mode.
    **              Value   = TRUE/FALSE, TRUE for Enable True Multi-channel audio
    **              Default = FALSE (Pseudo Multi-channel audio)
    **              Note:
    **              - When Enabled, DAC buffers are considered to hold multichannel
    **                audio in interleaved format(Line-out Left, Line-Out Right, Center,
    **                Surround Left, Surround Right, LFE)
    **              - When Disabled, DAC buffers are considered to hold stereo audio
    **                in interleaved format (Line-Out Left, Line-Out Right). The driver
    **                mimics Multichannel audio by copying Line out Left channel data to
    **                Center & Surround Left channels and Line out Right channel data to
    **                LFE & Surround Right channels.
    **              - This command enables Multichannel audio regardless of the
    **                command value parameter being TRUE or FALSE.
    **                Multichannel audio mode can be disabled ONLY by passing
    **                ADI_AC97_CMD_ENABLE_MULTICHANNEL_AUDIO command
    **                with FALSE as command value parameter
    */
    ADI_AC97_CMD_ENABLE_TRUE_MULTICHANNEL_AUDIO,

    /*
    ** 0x402C0003 - Flushes application specific AC'97 DAC data buffer pointers
    **              Value = NULL
    */
    ADI_AC97_CMD_CLEAR_DAC_APP_BUFFER_PTRS,

    /*
    ** 0x402C0004 - Flushes application specific AC'97 ADC data buffer pointers
    **               Value = NULL
    */
    ADI_AC97_CMD_CLEAR_ADC_APP_BUFFER_PTRS,

    /*
    ** 0x402C0005 - Enable/Disable Transmit audio dataflow
    **              Value = true/false ('true' to enable, 'false' to disable)
    */
    ADI_AC97_CMD_SET_TRANSMIT_DATAFLOW,

    /*
    ** 0x402C0006 - Enable/Disable Receive audio dataflow
    **              Value = true/false ('true' to enable, 'false' to disable)
    */
    ADI_AC97_CMD_SET_RECEIVE_DATAFLOW,

    /*
    ** 0x402C0007 - Set Transmit audio dataflow method
    **              Value = ADI_DEV_MODE_CHAINED or ADI_DEV_MODE_CHAINED_LOOPBACK
    */
    ADI_AC97_CMD_SET_TRANSMIT_DATAFLOW_METHOD,

    /*
    ** 0x402C0008 - Set Receive audio dataflow method
    **              Value = ADI_DEV_MODE_CHAINED or ADI_DEV_MODE_CHAINED_LOOPBACK
    */
    ADI_AC97_CMD_SET_RECEIVE_DATAFLOW_METHOD,

    /*
    ** 0x402C0009 - Update SPORT DMA Bus width
    **              Value = uint32_t (DMA Bus width)
    */
    ADI_AC97_CMD_UPDATE_SPORT_DMA_BUS_WIDTH

};

/*********************************************************************

Enumerations for AC'97 Driver return codes

*********************************************************************/

enum
{
    /* 0x402C0000 - AC'97 driver enumuration start */
    ADI_AC97_RESULT_START = ADI_AC97_ENUMERATION_START,
    /* 0x402C0001 - AC'97 driver does not support this command */
    ADI_AC97_RESULT_CMD_NOT_SUPPORTED,
    /* 0x402C0002 - AC'97 data frame memory provided by the client is not sufficient */
    ADI_AC97_RESULT_INSUFFICIENT_DATA_FRAME_MEMORY,
    /* 0x402C0003 - Given AC'97 driver instance is invalid */
    ADI_AC97_RESULT_DRIVER_INSTANCE_INVALID,
    /* 0x402C0004 - AC'97 only supports 1D type buffers.
                    Driver returns this error code when client submits buffers other than 1D */
    ADI_AC97_RESULT_DRIVER_ONLY_SUPPORT_1D_BUFFERS,
    /* 0x402C0005 - Results when ADC/DAC buffer (1D) buffers submitted by the client has data pointer as NULL */
    ADI_AC97_RESULT_APP_DATA_POINTS_TO_NULL,
    /* 0x402C0006 - AC'97 codec is not ready for audio streaming */
    ADI_AC97_RESULT_CODEC_NOT_READY,
    /* 0x402C0007 - AC'97 Driver does not support the given ADC sampling rate */
    ADI_AC97_RESULT_ADC_SAMPLE_RATE_NOT_SUPPORTED,
    /* 0x402C0008 - AC'97 Driver does not support the given DAC sampling rate */
    ADI_AC97_RESULT_DAC_SAMPLE_RATE_NOT_SUPPORTED
};

/*********************************************************************

Enumerations for AC'97 Driver Events

*********************************************************************/

enum
{

    /* 0x402C0000 - AC'97 driver enumuration start */
    ADI_AC97_EVENT_START = ADI_AC97_ENUMERATION_START,
    /* 0x402C0001 - AC'97 driver has completed processing the given register table */
    ADI_AC97_EVENT_REGISTER_ACCESS_COMPLETE

};

/*********************************************************************

AC'97 Driver API Function declarations

*********************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise AC'97 Driver instance */
u32 adi_ac97_Init_Instance (
    ADI_AC97_DRIVER_INIT        *pInstance       /* address of AC'97 Driver init information table              */
);

/* Resets the Audio codec via Hardware */
u32 adi_ac97_HwReset(
    ADI_AC97_DRIVER_INSTANCE    *pAC97,         /* AC'97 driver instance we're working on                       */
    ADI_FLAG_ID                 ResetFlagId     /* Flag ID connected to Audio Codec Reset pin                   */
);

/* Queues ADC (Inbound) buffers */
u32 adi_ac97_Read (
    ADI_AC97_DRIVER_INSTANCE    *pAC97,         /* Pointer to AC'97 Driver Instance                             */
    ADI_DEV_BUFFER_TYPE         BufferType,     /* Buffer type (only supports ADI_DEV_1D_BUFFER type buffers)   */
    ADI_DEV_BUFFER              *pBuffer        /* pointer to buffer                                            */
);

/* Queues DAC (Outbound) buffers */
u32 adi_ac97_Write (
    ADI_AC97_DRIVER_INSTANCE    *pAC97,         /* Pointer to AC'97 Driver Instance                             */
    ADI_DEV_BUFFER_TYPE         BufferType,     /* Buffer type (only supports ADI_DEV_1D_BUFFER type buffers)   */
    ADI_DEV_BUFFER              *pBuffer        /* pointer to buffer                                            */
);

/* Sets/Senses AC'97 codec related information */
u32 adi_ac97_Control (
    ADI_AC97_DRIVER_INSTANCE    *pAC97,         /* Pointer to AC'97 Driver Instance                             */
    u32                         Command,        /* Command ID                                                   */
    void                        *Value          /* Command specific value                                       */
);

/* Checks whether the given codec register configuration value is valid */
u32 adi_ac97_ValidateRegVal (
    ADI_AC97_DRIVER_INSTANCE    *pAC97,         /* Pointer to AC'97 Driver Instance                             */
    u16                         RegAddr,        /* AC'97 Codec register address to be validated                 */
    u16                         RegVal          /* Register value                                               */
);

#ifdef __cplusplus
}
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /* __ADI_AC97_H__ */

/*****/
