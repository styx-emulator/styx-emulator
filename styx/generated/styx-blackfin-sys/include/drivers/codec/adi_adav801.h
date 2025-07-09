/*****************************************************************************

Copyright (c) 2005 Analog Devices.  All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.
******************************************************************************

$File: adi_adav801.h $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Project:    ADAV801 device driver - Audio Codec for Recordable DVD
Title:      ADAV801 definitions
Author(s):  Bala
Revised by:

Description:
    This is the primary include file for the ADAV801 Audio Codec
    for Recordable DVD driver.

References:

Access to the ADAV801 control registers is over the SPI port.
A 24 bit frame is sent over SPI as data which is broken down
as follows:
+------------------------------------+
| Register Addr | R/W |    Data      |
|------------------------------------|
| 15:9          |  8  |    7:0       |
+------------------------------------+
******************************************************************************

Modification History:
====================
Revision 1.00

*****************************************************************************/

#ifndef __ADI_ADAV801_H__
#define __ADI_ADAV801_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*****************************************************************************

Fixed enumerations and defines

*****************************************************************************/

/*****************************
ADAV801 Register definitions
*****************************/

#define     ADAV801_SRC_CLK_CTRL        0x00        // SRC and Clock Control Register
#define     ADAV801_SPDIF_CTRL          0x03        // SPDIF Loopback Control Register
#define     ADAV801_PBK_CTRL            0x04        // Playback Port Control Register
#define     ADAV801_AUXIN_PORT          0x05        // Auxiliary Input Port Register
#define     ADAV801_REC_CTRL            0x06        // Record Port Control Register
#define     ADAV801_AUXOUT_PORT         0x07        // Auxiliary Output Port Register
#define     ADAV801_GDLY_MUTE           0x08        // Group Delay and Mute Register
#define     ADAV801_RX_CON1             0x09        // Receiver Configuration 1 Register
#define     ADAV801_RX_CON2             0x0A        // Receiver Configuration 2 Register
#define     ADAV801_RXBUF_CON           0x0B        // Receiver Buffer Configuration Register
#define     ADAV801_TX_CTRL             0x0C        // Transmitter Control Register
#define     ADAV801_TXBUF_CON           0x0D        // Transmitter Buffer Configuration Register
#define     ADAV801_CSSBUF_TX           0x0E        // Channel Status Switch Buffer and Transmitter
#define     ADAV801_TXMSG_MSB           0x0F        // Transmitter Message Zeros Most Significant Byte
#define     ADAV801_TXMSG_LSB           0x10        // Transmitter Message Zeros Least Significant Byte
#define     ADAV801_AUTO_BUF            0x11        // Autobuffer Register
#define     ADAV801_SRR_MSB             0x12        // Sample Rate Ratio MSB Register (Read Only)
#define     ADAV801_SRR_LSB             0x13        // Sample Rate Ratio LSB Register (Read Only)
#define     ADAV801_PBL_C_MSB           0x14        // Preamble-C MSB Register (Read Only)
#define     ADAV801_PBL_C_LSB           0x15        // Preamble-C LSB Register (Read Only)
#define     ADAV801_PBL_D_MSB           0x16        // Preamble-D MSB Register (Read Only)
#define     ADAV801_PBL_D_LSB           0x17        // Preamble-D LSB Register (Read Only)
#define     ADAV801_RX_ERR              0x18        // Receiver Error Register (Read Only)
#define     ADAV801_RX_ERR_MASK         0x19        // Receiver Error Mask Register
#define     ADAV801_SRC_ERR             0x1A        // Sample Rate Conversion Error Register (Read Only)
#define     ADAV801_SRC_ERR_MASK        0x1B        // Sample Rate Conversion Error Mask Register
#define     ADAV801_INT_STAT            0x1C        // Interrupt Status Register
#define     ADAV801_INT_STAT_MASK       0x1D        // Interrupt Status Mask Register
#define     ADAV801_MUTE_DEEMP          0x1E        // Mute and De-Emphasis Register
#define     ADAV801_NONAUDIO_PBL        0x1F        // NonAudio Preamble Type Register (Read Only)
#define     ADAV801_RXUSER_IADDR        0x50        // Receiver User Bit Buffer Indirect Address Register
#define     ADAV801_RXUSER_DATA         0x51        // Receiver User Bit Buffer Data Register
#define     ADAV801_TXUSER_IADDR        0x52        // Transmitter User Bit Buffer Indirect Address Register
#define     ADAV801_TXUSER_DATA         0x53        // Transmitter User Bit Buffer Data Register
#define     ADAV801_QCRC_ERR_STATUS     0x54        // Q Subcode CRCError Status Register (Read-Only)
#define     ADAV801_Q_BUF1              0x55        // Q Subcode Buffer 1 (Holds Address)
#define     ADAV801_Q_BUF2              0x56        // Q Subcode Buffer 2 (Holds Track Number)
#define     ADAV801_Q_BUF3              0x57        // Q Subcode Buffer 3 (Holds Index)
#define     ADAV801_Q_BUF4              0x58        // Q Subcode Buffer 4 (Holds Minute)
#define     ADAV801_Q_BUF5              0x59        // Q Subcode Buffer 5 (Holds Second)
#define     ADAV801_Q_BUF6              0x5A        // Q Subcode Buffer 6 (Holds Frame)
#define     ADAV801_Q_BUF7              0x5B        // Q Subcode Buffer 7 (Holds Zero)
#define     ADAV801_Q_BUF8              0x5C        // Q Subcode Buffer 8 (Holds Absolute Minute)
#define     ADAV801_Q_BUF9              0x5D        // Q Subcode Buffer 9 (Holds Absolute Second)
#define     ADAV801_Q_BUF10             0x5E        // Q Subcode Buffer 10 (Holds Absolute Frame)
#define     ADAV801_DP_CTRL1            0x62        // Datapath Control Register 1
#define     ADAV801_DP_CTRL2            0x63        // Datapath Control Register 2
#define     ADAV801_DAC_CTRL1           0x64        // DAC Control Register 1
#define     ADAV801_DAC_CTRL2           0x65        // DAC Control Register 2
#define     ADAV801_DAC_CTRL3           0x66        // DAC Control Register 3
#define     ADAV801_DAC_CTRL4           0x67        // DAC Control Register 4
#define     ADAV801_DACL_VOL            0x68        // DAC Left Volume Register
#define     ADAV801_DACR_VOL            0x69        // DAC Right Volume Register
#define     ADAV801_DACLPEAK_VOL        0x6A        // DAC Left Peak Volume Register
#define     ADAV801_DACRPEAK_VOL        0x6B        // DAC Right Peak Volume Register
#define     ADAV801_ADCLEFT_PGA         0x6C        // ADC Left Channel PGA Gain Register
#define     ADAV801_ADC_RIGHT_PGA       0x6D        // ADC Right Channel PGA Gain Register
#define     ADAV801_ADC_CTRL1           0x6E        // ADC Control Register 1
#define     ADAV801_ADC_CTRL2           0x6F        // ADC Control Register 2
#define     ADAV801_ADCL_VOL            0x70        // ADC Left Volume Register
#define     ADAV801_ADCR_VOL            0x71        // ADC Right Volume Register
#define     ADAV801_ADCLPEAK_VOL        0x72        // ADC Left Peak Volume Register
#define     ADAV801_ADCRPEAK_VOL        0x73        // ADC Right Peak Volume Register
#define     ADAV801_PLL_CTRL1           0x74        // PLL Control Register 1
#define     ADAV801_PLL_CTRL2           0x75        // PLL Control Register 2
#define     ADAV801_ICLK_CTRL1          0x76        // Internal Clock Control Register 1
#define     ADAV801_ICLK_CTRL2          0x77        // Internal Clock Control Register 2
#define     ADAV801_PLL_CLK_SRC         0x78        // PLL Clock Source Register
#define     ADAV801_PLLOUT_ENBL         0x7A        // PLL Output Enable Register
#define     ADAV801_ALC_CTRL1           0x7B        // ALC Control Register 1
#define     ADAV801_ALC_CTRL2           0x7C        // ALC Control Register 2
#define     ADAV801_ALC_CTRL3           0x7D        // ALC Control Register 3

/**********************************
ADAV801 Register Field definitions
**********************************/

// SRC and Clock Control Register field definitions (ADAV801_SRC_CLK_CTRL)

#define     ADAV801_SRCDIV              0x06        // Divides the SRC master clock.
#define     ADAV801_CLK2DIV             0x04        // Clock divider for Internal Clock 2 (ICLK2).
#define     ADAV801_CLK1DIV             0x02        // Clock divider for Internal Clock 1 (ICLK1).
#define     ADAV801_MCLKSEL             0x00        // Clock selection for the SRC master clock.

// SPDIF Loopback Control Register field definitions (ADAV801_SPDIF_CTRL)

#define     ADAV801_TXMUX               0x00        // Selects the source for SPDIF output (DITOUT).

// Playback Port Control Register field definitions (ADAV801_PBK_CTRL)

#define     ADAV801_PBK_PORT_CLKSRC     0x03        // Selects the clock source for generating the ILRCLK and IBCLK.
#define     ADAV801_PBK_PORT_SPMODE     0x00        // Selects the serial format of the playback port.

// Auxiliary Input Port Register field definitions (ADAV801_AUXIN_PORT)

#define     ADAV801_AUX_IP_CLKSRC       0x03        // Selects the clock source for generating the IAUXLRCLK and IAUXBCLK.
#define     ADAV801_AUX_IP_SPMODE       0x00        // Selects the serial format of the Auxiliary Input port.

// Record Port Control Register field definitions (ADAV801_REC_CTRL)

#define     ADAV801_REC_PORT_CLKSRC     0x04        // Selects the clock source for generating the OLRCLK and OBCLK.
#define     ADAV801_REC_PORT_WLEN       0x02        // Selects the serial output word length.
#define     ADAV801_REC_PORT_SPMODE     0x00        // Selects the serial format of the Record port

// Auxiliary Output Port Register field definitions (ADAV801_AUXOUT_PORT)

#define     ADAV801_AUX_OP_CLKSRC       0x04        // Selects the clock source for generating the OAUXLRCLK and OAUXBCLK.
#define     ADAV801_AUX_OP_WLEN         0x02        // Selects the serial output word length.
#define     ADAV801_AUX_OP_SPMODE       0x00        // Selects the serial format of the Auxiliary record port

// Group Delay and Mute Register field definitions (ADAV801_GDLY_MUTE)

#define     ADAV801_MUTE_SRC            0x07        // Soft-mutes the output of the sample rate converter.
#define     ADAV801_GRPDLY              0x00        // Adds delay to the sample rate converter FIR filter by input samples.

// Receiver Configuration 1 Register field definitions (ADAV801_RX_CON1)

#define     ADAV801_NOCLOCK             0x07        // Selects the source of the receiver clock when the PLL is not locked.
#define     ADAV801_RXCLK               0x05        // Determines the oversampling ratio of the recovered receiver clock.
#define     ADAV801_AUTO_DEEMPH         0x04        // Automatically de-emphasizes the DATA from the receiver based on the channel status information.
#define     ADAV801_RXERR               0x02        // Defines what action the receiver should take, if the receiver detects a parity or biphase error.
#define     ADAV801_RXLOCK              0x00        // Defines what action the receiver should take, if the PLL loses lock.

// Receiver Configuration 2 Register field definitions (ADAV801_RX_CON2)

#define     ADAV801_RXMUTE              0x07        // Hard-mutes the audio output for the AES3/SPDIF receiver.
#define     ADAV801_SP_PLL              0x06        // AES3/SPDIF receiver PLL accepts a left/right clock from one of the four serial ports as the PLL reference clock.
#define     ADAV801_SP_PLL_SEL          0x04        // Selects one of the four serial ports as the reference clock to the PLL when SP_PLL is set.
#define     ADAV801_NO_NONAUDIO         0x01        // When the NONAUDIO bit is set, data from the AES3/SPDIF receiver is not allowed into the sample rate converter
                                                    // (SRC). If the NONAUDIO data is due to DTS, AAC, and so on, as defined by the IEC61937 standard, then the data from
                                                    // the AES3/SPDIF receiver is not allowed into the SRC regardless of the state of this bit.
#define     ADAV801_NO_VALIDITY         0x00        // When the VALIDITY bit is set, data from the AES3/SPDIF receiver is not allowed into the SRC.

// Receiver Buffer Configuration Register field definitions (ADAV801_RXBUF_CON)

#define     ADAV801_RXBCONF5            0x05        // If the user bits are formatted according to the IEC60958-3 standard and the DAT category is detected, the user bit
                                                    // interrupt is enabled only when there is a change in the start (ID) bit.
#define     ADAV801_RXBCONF4            0x04        // This bit determines whether Channel A and Channel B user bits are stored in the buffer together or separated
                                                    // between A and B
#define     ADAV801_RXBCONF3            0x03        // Defines the function of RxCSBINT.
#define     ADAV801_RXBCONF1            0x01        // Defines the user bit buffer. (2 bits)
#define     ADAV801_RXBCONF0            0x00        // Defines the user bit buffer size, if RxBCONF2_1 = 01.

// Transmitter Control Register field definitions (ADAV801_TX_CTRL)

#define     ADAV801_TXVALIDITY          0x06        // This bit is used to set or clear the VALIDITY bit in the AES3/SPDIF transmit stream.
#define     ADAV801_TXRATIO             0x03        // Determines the AES3/SPDIF transmitter to AES3/SPDIF receiver ratio.
#define     ADAV801_TXCLKSEL            0x01        // Selects the clock source for the AES3/SPDIF transmitter.
#define     ADAV801_TXENABLE            0x00        // Enables the AES3/SPDIF transmitter.

// Transmitter Buffer Configuration Register field definitions (ADAV801_TXBUF_CON)

#define     ADAV801_TX_IU_ZEROS         0x04        // Determines the number of zeros to be stuffed between IUs in a message up to a maximum of 8.
#define     ADAV801_TXBCONF3            0x03        // Transmitter user bits can be stored in separate buffers or stored together.
#define     ADAV801_TXBCONF1            0x01        // Configures the transmitter user bit buffer.
#define     ADAV801_TXBCONF0            0x00        // Determines the buffer size of the transmitter user bits when TxBCONF2_1 is 01.

// Channel Status Switch Buffer and Transmitter Register field definitions (ADAV801_CSSBUF_TX)

#define     ADAV801_TX_AB_SAME          0x05        // Transmitter Channel Status A and B are the same.
#define     ADAV801_DISABLE_TX_COPY     0x04        // Disables the copying of the channel status bits from the transmitter channel status buffer
                                            // to the SPDIF transmitter buffer.
#define     ADAV801_TXCSSWITCH          0x01        // Toggle switch for the transmit channel status buffer.
#define     ADAV801_RXCSSWITCH          0x00        // Toggle switch for the receive channel status buffer.

// Autobuffer Register field definitions (ADAV801_AUTO_BUF)

#define     ADAV801_ZERO_STUFF_IU       0x06        // Enables the addition or subtraction of zeros between IUs during autobuffering of the user bits in IEC60958-3 format.
#define     ADAV801_AUTO_UBITS          0x05        // Enables the user bits to be autobuffered Auto_UBits between the AES3/SPDIF receiver and transmitter.
#define     ADAV801_AUTO_CSBITS         0x04        // Enables the channel status bits to be autobuffered between the AES3/SPDIF receiver and transmitter.
#define     ADAV801_AUTO_IU_ZEROS       0x00        // Sets the maximum number of zero-stuffing to be added between IUs while autobuffering up to a maximum of 8.

// Receiver Error Register field definitions (ADAV801_RX_ERR) (Read Only)

#define     ADAV801_RXERR_RXVALIDITY    0x07        // This is the VALIDITY bit in the AES3 received stream.
#define     ADAV801_RXERR_EMPHASIS      0x06        // This bit is set, if the audio data is pre-emphasized.
#define     ADAV801_RXERR_NONAUDIO      0x05        // This bit is set, when Channel Status Bit 1 (nonaudio) is set.
#define     ADAV801_RXERR_NONAUDIO_PRE  0x04        // This bit is set, if the audio data is nonaudio due to the detection of a preamble.
#define     ADAV801_RXERR_CRC_ERROR     0x03        // This bit is the error flag for the channel status CRCError check.
#define     ADAV801_RXERR_NOSTREAM      0x02        // This bit is set, if there is no AES3/SPDIF stream present at the AES3/SPDIF receiver.
#define     ADAV801_RXERR_PARITY        0x01        // This bit is set, if a biphase or parity error occurred in the AES3/SPDIF stream.
#define     ADAV801_RXERR_LOCK          0x00        // This bit is set, if the PLL has locked or cleared when the PLL loses lock.

// Receiver Error Mask Register field definitions (ADAV801_RX_ERR_MASK)
// Set appropriate bit to generate its corresponding interrupt

#define     ADAV801_RXERR_RXVALIDITY_MASK   0x07    // Masks the RxValidity bit from generating an interrupt.
#define     ADAV801_RXERR_EMPHASIS_MASK     0x06    // Masks the emphasis bit from generating an interrupt
#define     ADAV801_RXERR_NONAUDIO_MASK     0x05    // Masks the NonAudio bit from generating an interrupt
#define     ADAV801_RXERR_NONAUDIO_PRE_MASK 0x04    // Masks the NonAudio preamble bit from generating an interrupt.
#define     ADAV801_RXERR_CRC_ERROR_MASK    0x03    // Masks the CRCError bit from generating an interrupt.
#define     ADAV801_RXERR_NOSTREAM_MASK     0x02    // Masks the NoStream bit from generating an interrupt.
#define     ADAV801_RXERR_PARITY_MASK       0x01    // Masks the BiPhase/Parity bit from generating an interrupt.
#define     ADAV801_RXERR_LOCK_MASK         0x00    // Masks the Lock bit from generating an interrupt.

// Sample Rate Conversion Error Register field definitions (ADAV801_SRC_ERR) (Read Only)

#define     ADAV801_SRC_ERR_TOO_SLOW        0x03    // This bit is set, when the clock to the SRC is too slow.
#define     ADAV801_SRC_ERR_OVRL            0x02    // This bit is set, when the left output data of the sample rate converter
                                                    // has gone over the full-scale range and has been clipped.
#define     ADAV801_SRC_ERR_OVRR            0x01    // This bit is set, when the right output data of the sample rate converter
                                                    // has gone over the full-scale range and has been clipped.
#define     ADAV801_SRC_ERR_MUTE_IND        0x00    // Mute indicated. This bit is set, when the SRC is in fast mode
                                                    // and clicks or pops can be heard in the SRC output data.

// Sample Rate Conversion Error Mask Register field definitions (ADAV801_SRC_ERR_MASK)

#define     ADAV801_SRC_ERR_OVRL_MASK       0x02    // Masks the OVRL from generating an interrupt.
#define     ADAV801_SRC_ERR_OVRR_MASK       0x01    // Masks the OVRR from generating an interrupt.
#define     ADAV801_SRC_ERR_MUTE_IND_MASK   0x00    // Masks the MUTE_IND from generating an interrupt

// Interrupt Status Register field definitions (ADAV801_INT_STAT)

#define     ADAV801_SRCERROR                0x07    // This bit is set, if one of the sample rate converter interrupts is asserted.
#define     ADAV801_TXCSTINT                0x06    // This bit is set, if a write to the transmitter channel status buffer was made while transmitter
                                                    // channel status bits were being copied from the transmitter CS buffer to the SPDIF transmit buffer.
#define     ADAV801_TXUBINT                 0x05    // This bit is set, if the SPDIF transmit buffer is empty.
#define     ADAV801_TXCSINT                 0x04    // This bit is set, if the transmitter channel status bit buffer has transmitted its block of channel status.
#define     ADAV801_RXCSDIFF                0x03    // This bit is set, if the receiver Channel Status A block is different from the receiver Channel Status B clock.
#define     ADAV801_RXUBINT                 0x02    // This bit is set, if the receiver user bit buffer has a new block or message.
#define     ADAV801_RXCSBINT                0x01    // This bit is set, if a new block of channel status is read when RxBOCNF3 = 0,
                                                    // or if the channel status has changed when RxBCONF3 = 1
#define     ADAV801_RXERROR                 0x00    // This bit is set, if one of the AES3/SPDIF receiver interrupts is asserted.

//Interrupt Status Mask Register field definitions (ADAV801_INT_STAT_MASK)

#define     ADAV801_MASK_SRC_ERROR          0x07    // Masks the SRCError bit from generating an interrupt.
#define     ADAV801_MASK_TXCSTINT           0x06    // Masks the TxCSTINT bit from generating an interrupt.
#define     ADAV801_MASK_TXUBINT            0x05    // Masks the TxUBINT bit from generating an interrupt.
#define     ADAV801_MASK_TXCSINT            0x04    // Masks the TxCSINT bit from generating an interrupt.
#define     ADAV801_MASK_RXCSDIFF           0x03    // Masks the RXCSDIFF bit from generating an interrupt.
#define     ADAV801_MASK_RXUBINT            0x02    // Masks the RXUBINT bit from generating an interrupt.
#define     ADAV801_MASK_RXCSBINT           0x01    // Masks the RXCSBINT bit from generating an interrupt.
#define     ADAV801_MASK_RXERROR            0x00    // Masks the RXERROR bit from generating an interrupt.

// Mute and De-Emphasis Register field definitions (ADAV801_MUTE_DEEMP)

#define     ADAV801_TXMUTE                  0x05    // Mutes the AES3/SPDIF transmitter.
#define     ADAV801_SRC_DEEM                0x01    // Selects the de-emphasis filter for the input data to the sample rate converter.

// NonAudio Preamble Type Register field definitions (ADAV801_NONAUDIO_PBL) (Read Only)

#define     ADAV801_DTS_CD_PBLE             0x03    // This bit is set, if the DTS-CD preamble is detected.
#define     ADAV801_NONAUDIO_FRAME          0x02    // This bit is set, if the data received through the AES3/SPDIF receiver is nonaudio data
#define     ADAV801_NONAUDIO_SUBFRAME_A     0x01    // This bit is set, if the data received through Channel A of the AES3/SPDIF receiver is
                                                    // subframe nonaudio data according to SMPTE337M.
#define     ADAV801_ NONAUDIO_SUBFRAME_B    0x00    // This bit is set, if the data received through Channel B of the AES3/SPDIF receiver is
                                                    // subframe nonaudio data according to SMPTE337M.

// Q Subcode CRCError Status Register field definitions (ADAV801_QCRC_ERR_STATUS) (Read Only)

#define     ADAV801_QCRCERROR               0x01    // This bit is set, if the CRC check of the Q subcode fails. This bit remains high, but does not generate an interrupt. This
                                                    // bit is cleared once the register is read.
#define     ADAV801_QSUB                    0x00    // This bit is set, if a Q subcode has been read into the Q subcode buffer

// Datapath Control Register 1 field definitions (ADAV801_DP_CTRL1)

#define     ADAV801_DATAPATH_SRC            0x06    // Datapath source select for sample rate converter (SRC).
#define     ADAV801_DATAPATH_REC            0x04    // Datapath source select for record output port.
#define     ADAV801_DATAPATH_AUXO           0x00    // Datapath source select for auxiliary output port.

// Datapath Control Register 2 field definitions (ADAV801_DP_CTRL2)

#define     ADAV801_DATAPATH_DAC            0x03    // Datapath source select for DAC.
#define     ADAV801_DATAPATH_DIT            0x00    // Datapath source select for DIT.

// DAC Control Register 1 field definitions (ADAV801_DAC_CTRL1)

#define     ADAV801_DR_ALL                  0x07    // Hardware Reset and Power Down
#define     ADAV801_DR_DIGITAL              0x06    // DAC Reset Digital
#define     ADAV801_DAC_CHSEL               0x04    // DAC Channel Select
#define     ADAV801_DAC_POL                 0x02    // DAC Channel Polarity
#define     ADAV801_DAC_MUTER               0x01    // Mute DAC Right Cannel
#define     ADAV801_DAC_MUTEL               0x00    // Mute DAC Left Channel

// DAC Control Register 2 field definitions (ADAV801_DAC_CTRL2)

#define     ADAV801_DMCLK                   0x04    // DAC MCLK divider.
#define     ADAV801_DFS                     0x02    // DAC interpolator select.
#define     ADAV801_DEEM                    0x00    // DAC de-emphasis select.

// DAC Control Register 3 field definitions (ADAV801_DAC_CTRL3)

#define     ADAV801_ZFVOL                   0x02    // DAC zero flag on mute and zero volume.
#define     ADAV801_ZFDATA                  0x01    // DAC zero flag on zero data disable.
#define     ADAV801_ZFPOL                   0x00    // DAC zero flag polarity.

// DAC Control Register 4 field definitions (ADAV801_DAC_CTRL4)

#define     ADAV801_INTRPT                  0x06    // This bit selects the functionality of the ZEROL/INT pin.
#define     ADAV801_ZEROSEL                 0x04    // These bits control the functionality of the ZEROR pin when the ZEROL/INT pin is used as an interrupt.

// ADC Control Register 1 field definitions (ADAV801_ADC_CTRL1)

#define     ADAV801_AMR                     0x07    // ADC Modular Clock
#define     ADAV801_HPF                     0x06    // High Pass Filter Enable
#define     ADAV801_ADC_PDN                 0x05    // ADC Power Down
#define     ADAV801_ADC_ANA_PDN             0x04    // ADC analog section power-down.
#define     ADAV801_ADC_MUTER               0x03    // Mute ADC Right Cannel
#define     ADAV801_ADC_MUTEL               0x02    // Mute ADC Left Channel
#define     ADAV801_PLPD                    0x01    // PGA left power-down.
#define     ADAV801_PRPD                    0x00    // PGA right power-down.

// ADC Control Register 2 field definitions (ADAV801_ADC_CTRL2)

#define     ADAV801_BUF_PDN                 0x04    // Reference buffer power-down control.
#define     ADAV801_MCD                     0x00    // ADC master clock divider.

// PLL Control Register 1 field definitions (ADAV801_PLL_CTRL1)

#define     ADAV801_DIRIN_CLK               0x06    // Recovered SPDIF clock sent to SYSCLK3.
#define     ADAV801_MCLKODIV                0x05    // Divide input MCLK by 2 to generate MCLKO.
#define     ADAV801_PLLDIV                  0x04    // Divide XIN by 2 to generate the PLL master clock.
#define     ADAV801_PLL2PD                  0x03    // Power-down PLL2.
#define     ADAV801_PLL1PD                  0x02    // Power-down PLL1.
#define     ADAV801_XRLPD                   0x01    // Power-down XTAL oscillator.
#define     ADAV801_SYSCLK3                 0x00    // Clock output for SYSCLK3.

// PLL Control Register 2 field definitions (ADAV801_PLL_CTRL2)

#define     ADAV801_PLL2_FS                 0x06    // Sample rate select for PLL2.
#define     ADAV801_PLL2_SEL                0x05    // Oversample ratio select for PLL2.
#define     ADAV801_PLL2_DOUB               0x04    // Double-selected sample rate on PLL2.
#define     ADAV801_PLL1_FS                 0x02    // Sample rate select for PLL1.
#define     ADAV801_PLL1_SEL                0x01    // Oversample ratio select for PLL1.
#define     ADAV801_PLL1_DOUB               0x00    // Double-selected sample rate on PLL1.

// Internal Clock Control Register 1 field definitions (ADAV801_ICLK_CTRL1)

#define     ADAV801_DCLK                    0x05    // DAC clock source select.
#define     ADAV801_ACLK                    0x02    // ADC clock source select.
#define     ADAV801_ICLK2                   0x00    // Source selector for internal clock ICLK2.

// Internal Clock Control Register 2 field definitions (ADAV801_ICLK_CTRL2)

#define     ADAV801_ICLK1                   0x03    // Source selector for internal clock ICLK2.
#define     ADAV801_PLL2INT                 0x01    // PLL2 internal selector
#define     ADAV801_PLL1INT                 0x00    // PLL1 internal selector

// PLL Clock Source Register field definitions (ADAV801_PLL_CLK_SRC)

#define     ADAV801_PLL1_SOURCE             0x07    // Selects the clock source for PLL1.
#define     ADAV801_PLL2_SOURCE             0x06    // Selects the clock source for PLL2.

// PLL Output Enable Register field definitions (ADAV801_PLLOUT_ENBL)

#define     ADAV801_DIRINPD                 0x05    // This bit powers down the SPDIF receiver.
#define     ADAV801_DIRIN_PIN               0x04    // This bit determines the input levels of the DIRIN pin.
#define     ADAV801_SYSCLK1_ENBL            0x02    // Enables the SYSCLK1 output.
#define     ADAV801_SYSCLK2_ENBL            0x01    // Enables the SYSCLK2 output.
#define     ADAV801_SYSCLK3_ENBL            0x00    // Enables the SYSCLK3 output.

// ALC Control Register 1 field definitions (ADAV801_ALC_CTRL1)

#define     ADAV801_FSSEL                   0x06    // These bits should equal the sample rate of the ADC.
#define     ADAV801_GAINCNTR                0x04    // These bits determine the limit of the counter used in limited recovery mode.
#define     ADAV801_RECMODE                 0x02    // These bits determine which recovery mode is used by the ALC section.
#define     ADAV801_LIMDET                  0x01    // These bits limit detect mode.
#define     ADAV801_ALCEN                   0x00    // These bits enable ALC.

// ALC Control Register 2 field definitions (ADAV801_ALC_CTRL2)

#define     ADAV801_RECTH                   0x05    // Recovery Threshold
#define     ADAV801_ATKTH                   0x03    // Attack Threshold
#define     ADAV801_RECTIME                 0x01    // Recovery time selection.
#define     ADAV801_ATKTIME                 0x00    // Attack time selection.

// Set status of SPORT device to be used for audio dataflow between Blackfin and ADAV801
typedef enum ADI_ADAV801_SET_SPORT_STATUS {
    ADI_ADAV801_SPORT_OPEN,             // Open SPORT device
    ADI_ADAV801_SPORT_CLOSE             // Close SPORT device
}   ADI_ADAV801_SET_SPORT_STATUS;

/*****************************************************************************

Extensible enumerations and defines

*****************************************************************************/

// Command IDs
enum    {

        ADI_ADAV801_CMD_START=ADI_ADAV801_ENUMERATION_START,    // 0x40070000

        // SPI related commands
        ADI_ADAV801_CMD_SET_SPI_CS,             // 0x40070001 - Set ADAV801 SPI Chipselect (configure Blackfin SPI_FLG to select ADAV801) (value = u8)
        ADI_ADAV801_CMD_GET_SPI_CS,             // 0x40070002 - Get present SPI Chipselect value for ADAV801 (value = u8*)

        // SPORT related commands
        // (value = 1 less than the serial word length (in bits) required, values of 0, 1 and > 31 are illegal)
        ADI_ADAV801_CMD_SET_SPORT_TX_WLEN,      // 0x40070003 - Set SPORT transmit data word length (default = 24 bits) (Value = u8)
        ADI_ADAV801_CMD_SET_SPORT_RX_WLEN,      // 0x40070004 - Set SPORT receive data word length (default = 24 bits) (Value = u8)
        ADI_ADAV801_CMD_SET_SPORT_DEVICE_NUMBER,// 0x40070005 - Set SPORT Device Number (Value = u8)
        ADI_ADAV801_CMD_SET_SPORT_STATUS        // 0x40070006 - Set SPORT Device status (Value = ADI_ADAV801_SET_SPORT_STATUS)
        };

// Events
enum    {

        ADI_ADAV801_EVENT_START=ADI_DEV_EVENT_PDD_START     // 0x40070000

        };

// Return codes
enum    {
        ADI_ADAV801_RESULT_START=ADI_DEV_RESULT_PDD_START,  // 0x40070000
        ADI_ADAV801_RESULT_CMD_NOT_SUPPORTED,               // 0x40070001 - ADAV801 command not supported
        ADI_ADAV801_RESULT_SPI_CS_NOT_VALID,                // 0x40070002 - ADAV801 chipselect for blackfin processor in not valid
        ADI_ADAV801_RESULT_SPORT_WLEN_ILLEGAL,              // 0x40070003 - Results when user provides an illegal SPORT Tx/Rx Word Length
        ADI_ADAV801_RESULT_BAD_SPORT_DEVICE,                // 0x40070004 - Results when user provides a wrong SPORT device number
        ADI_ADAV801_RESULT_SPORT_STATUS_INVALID             // 0x40070005 - Results when client tries to to operate SPORT in an invalid state
        };

/*****************************************************************************

Data Structures

*****************************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADIADAV801EntryPoint;  // entry point to the device driver

/*****************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_ADAV801_H__ */
