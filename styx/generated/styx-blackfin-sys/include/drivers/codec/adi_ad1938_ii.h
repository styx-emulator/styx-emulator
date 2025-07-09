/*****************************************************************************

Copyright (c) 2005 Analog Devices.  All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.
******************************************************************************

$File: adi_ad1938_ii.h $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Project:    AD1938 device driver with new API
Title:      AD1938 definitions
Author(s):  bmk
Revised by:

Description:
    This is the primary include file for the AD1938 Audio Codec.

References:

Access to the AD1938 control registers is over the SPI port.
A 24 bit frame is sent over SPI as data which is broken down
as follows:
+------------------------------------------------+
|Glabal Addr | R/W | Register Addr |   Data      |
|------------------------------------------------|
| 23:17      |  16 | 15:8          |   7:0       |
+------------------------------------------------+
******************************************************************************

Modification History:
====================
$Log: adi_ad1938_ii.h,v $
Revision 1.8  2007/03/02 21:26:42  bgiese
snapshot from VDSP 4.5

Revision 1.7  2006/09/05 01:25:15  bmk
added ADI_AD1938_CMD_ENABLE_AUTO_SPORT_CONFIG command to Enable/Disable Auto-SPORT configuration mode
Auto-SPORT configuration mode is enabled by default


*****************************************************************************/

#ifndef __ADI_AD1938_II_H__
#define __ADI_AD1938_II_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*****************************************************************************

Fixed enumerations and defines

*****************************************************************************/

/*****************************
AD1938 Register definitions
*****************************/
#define     AD1938_PLL_CLK_CTRL0        0x00    // PLL and Clock Control 0
#define     AD1938_PLL_CLK_CTRL1        0x01    // PLL and Clock Control 1
#define     AD1938_DAC_CTRL0            0x02    // DAC Control 0
#define     AD1938_DAC_CTRL1            0x03    // DAC Control 1
#define     AD1938_DAC_CTRL2            0x04    // DAC Control 2
#define     AD1938_DAC_CHNL_MUTE        0x05    // DAC Individual Channel Mutes
#define     AD1938_DAC1L_VOL_CTRL       0x06    // DAC 1 Left Volume Control
#define     AD1938_DAC1R_VOL_CTRL       0x07    // DAC 1 Right Volume Control
#define     AD1938_DAC2L_VOL_CTRL       0x08    // DAC 2 Left Volume Control
#define     AD1938_DAC2R_VOL_CTRL       0x09    // DAC 2 Right Volume Control
#define     AD1938_DAC3L_VOL_CTRL       0x0A    // DAC 3 Left Volume Control
#define     AD1938_DAC3R_VOL_CTRL       0x0B    // DAC 3 Right Volume Control
#define     AD1938_DAC4L_VOL_CTRL       0x0C    // DAC 4 Left Volume Control
#define     AD1938_DAC4R_VOL_CTRL       0x0D    // DAC 4 Right Volume Control
#define     AD1938_ADC_CTRL0            0x0E    // ADC Control 0
#define     AD1938_ADC_CTRL1            0x0F    // ADC Control 1
#define     AD1938_ADC_CTRL2            0x10    // ADC Control 2

/**********************************
AD1938 Register Field definitions
**********************************/

// PLL and Clock control 0 Register field definitions (AD1938_PLL_CLK_CTRL0)

#define     AD1938_MCLK_ENBL            0x07    // Internal MCLK Enable
#define     AD1938_PLL_INPUT            0x05    // PLL Input
#define     AD1938_MCLK_O               0x03    // MCLK_O pin
#define     AD1938_MCLK_FN              0x01    // MCLK pin functionality (PLL active)
#define     AD1938_PLL_PDN              0x00    // PLL power down

// PLL and Clock control 1 Register field definitions (AD1938_PLL_CLK_CTRL1)

#define     AD1938_PLL_LOCK             0x03    // PLL Lock Indicator (Read Only)
#define     AD1938_ONCHIP_VOLT          0x02    // On-chip Voltage Reference
#define     AD1938_ADC_CLK_SRC          0x01    // ADC Clock Source Select
#define     AD1938_DAC_CLK_SRC          0x00    // DAC Clock Source Select

// DAC control 0 Register field definitions (AD1938_DAC_CTRL0)

#define     AD1938_DAC_SERIAL_FORMAT    0x06    // Serial Format
#define     AD1938_DAC_SDATA_DELAY      0x03    // SDATA Delay (BCLK periods)
#define     AD1938_DAC_SAMPLE_RATE      0x01    // Sample Rate
#define     AD1938_DAC_PDN              0x00    // Power Down

// DAC control 1 Register field definitions (AD1938_DAC_CTRL1)

#define     AD1938_DAC_BCLK_POL         0x07    // BCLK Polarity
#define     AD1938_DAC_BCLK_SOURCE      0x06    // BCLK Source
#define     AD1938_DAC_BCLK_MS          0x05    // BCLK Master/Slave
#define     AD1938_DAC_LRCLK_MS         0x04    // LRCLK Master/Slave
#define     AD1938_DAC_LRCLK_POL        0x03    // LRCLK Polarity
#define     AD1938_DAC_BCLK_PER_FRAME   0x01    // BCLKs Per Frame
#define     AD1938_DAC_BCLK_EDGE        0x00    // BCLK Active Edge (TDM In)

// DAC control 2 Register field definitions (AD1938_DAC_CTRL2)

#define     AD1938_DAC_OUT_POL          0x05    // DAC Output Polarity
#define     AD1938_DAC_WORD_WIDTH       0x03    // Word width
#define     AD1938_DAC_DE_EMPHASIS      0x01    // Deemphasis (32/44.1/48 kHz mode only)
#define     AD1938_DAC_MUTE             0x00    // Master Mute

// DAC Individual Channel Mutes Register field definitions (AD1938_DAC_CHNL_MUTE)

#define     AD1938_DAC_4R_MUTE          0x07    // DAC 4 Right Mute
#define     AD1938_DAC_4L_MUTE          0x06    // DAC 4 Left Mute
#define     AD1938_DAC_3R_MUTE          0x05    // DAC 3 Right Mute
#define     AD1938_DAC_3L_MUTE          0x04    // DAC 3 Left Mute
#define     AD1938_DAC_2R_MUTE          0x03    // DAC 2 Right Mute
#define     AD1938_DAC_2L_MUTE          0x02    // DAC 2 Left Mute
#define     AD1938_DAC_1R_MUTE          0x01    // DAC 1 Right Mute
#define     AD1938_DAC_1L_MUTE          0x00    // DAC 1 Left Mute

// ADC control 0 Register field definitions (AD1938_ADC_CTRL0)

#define     AD1938_ADC_SAMPLE_RATE      0x06    // ADC Output Sample Rate
#define     AD1938_ADC_2R_MUTE          0x05    // ADC 2 Right Mute
#define     AD1938_ADC_2L_MUTE          0x04    // ADC 2 Left Mute
#define     AD1938_ADC_1R_MUTE          0x03    // ADC 1 Right Mute
#define     AD1938_ADC_1L_MUTE          0x02    // ADC 1 Left Mute
#define     AD1938_ADC_HPF              0x01    // Highpass Filter
#define     AD1938_ADC_PDN              0x00    // ADC Power Down

// ADC control 1 Register field definitions (AD1938_ADC_CTRL1)

#define     AD1938_ADC_BCLK_EDGE        0x07    // BCLK Active Edge (TDM In)
#define     AD1938_ADC_SERIAL_FORMAT    0x05    // Serial Format
#define     AD1938_ADC_SDATA_DELAY      0x02    // SDATA delay (BCLK periods)
#define     AD1938_ADC_WORD_WIDTH       0x00    // Word width

// ADC control 2 Register field definitions (AD1938_ADC_CTRL2)

#define     AD1938_ADC_BCLK_SOURCE      0x07    // BCLK Source
#define     AD1938_ADC_BCLK_MS          0x06    // BCLK Master/Slave
#define     AD1938_ADC_BCLK_PER_FRAME   0x04    // BCLKs Per Frame
#define     AD1938_ADC_LRCLK_MS         0x03    // LRCLK Master/Slave
#define     AD1938_ADC_LRCLK_POL        0x02    // LRCLK Polarity
#define     AD1938_ADC_BCLK_POL         0x01    // BCLK Polarity
#define     AD1938_ADC_LRCLK_FORMAT     0x00    // LRCLK Format

// Set status of SPORT device to be used for audio dataflow between Blackfin and AD1938
typedef enum ADI_AD1938_SET_SPORT_STATUS {
    ADI_AD1938_SPORT_OPEN,          // Open SPORT device
    ADI_AD1938_SPORT_CLOSE          // Close SPORT device
}   ADI_AD1938_SET_SPORT_STATUS;

/*** This Data type is no longer used/supported by this driver. Left here for backward compatibility ***/
typedef enum ADI_AD1938_SET_SPORT_MODE {
    ADI_AD1938_SET_TDM_MODE,        // Set SPORT Device in TDM Mode
    ADI_AD1938_SET_I2S_MODE         // Set SPORT Device in I2S Mode
}   ADI_AD1938_SET_SPORT_MODE;

/*****************************************************************************

Extensible enumerations and defines

*****************************************************************************/

// Command IDs
enum    {
            ADI_AD1938_CMD_START=ADI_AD1938_ENUMERATION_START,    // 0x40060000

            // SPI related commands
            // 0x40060001 - Set AD1938 SPI Chipselect (configure Blackfin SPI_FLG to select AD1938) (value = u8)
            ADI_AD1938_CMD_SET_SPI_CS,
            // 0x40060002 - Get present SPI Chipselect value for AD1938 (value = u8*)
            ADI_AD1938_CMD_GET_SPI_CS,
            // 0x40060003 - Set SPI Global address for AD1938 (value = u32)
            ADI_AD1938_CMD_SET_SPI_DEVICE_ADDRESS,

            // SPORT related commands
            // 0x40060004 - Set SPORT Device Number (Value = u8)
            ADI_AD1938_CMD_SET_SPORT_DEVICE_NUMBER,
            // 0x40060005 - Set SPORT Device status (Value = ADI_AD1938_SET_SPORT_STATUS)
            ADI_AD1938_CMD_SET_SPORT_STATUS,
            // 0x40060006 - Enable(TRUE)/Disable(FALSE) auto-SPORT configuration mode (value = TRUE/FALSE) (TRUE by default)
            ADI_AD1938_CMD_ENABLE_AUTO_SPORT_CONFIG,

            /*** This Command is no longer used/supported by this driver. Left here for backward compatibility ***/
            ADI_AD1938_CMD_SET_SPORT_OPERATION_MODE
        };

// Events
enum    {
            ADI_AD1938_EVENT_START=ADI_AD1938_ENUMERATION_START     // 0x40060000
        };

// Return codes
enum    {
            ADI_AD1938_RESULT_START=ADI_AD1938_ENUMERATION_START,   // 0x40060000
            // 0x40060001 - Command not supported by AD1938 driver
            ADI_AD1938_RESULT_CMD_NOT_SUPPORTED
        };

/*****************************************************************************

Data Structures

*****************************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADIAD1938IIEntryPoint;  // entry point to the device driver

/*****************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_AD1938_II_H__ */

/*****/
