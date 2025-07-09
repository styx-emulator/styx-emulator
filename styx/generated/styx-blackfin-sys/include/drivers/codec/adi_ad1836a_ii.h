/**********************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSFile: adi_ad1836a_ii.h $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
    This is the primary include file for the AD1836A Audio Codec.

References:

Access to the AD1836A control registers is over the SPI port.
A 16 bit frame is sent over SPI and the data is broken down as follows:

+------------------------------------------------+
| Reg Addr   | R/W | Reserved Bit  | Function    |
|------------------------------------------------|
| 15:12      | 11  | 10            | 9:0         |
+------------------------------------------------+

*****************************************************************************/

#ifndef __ADI_AD1836A_II_H__
#define __ADI_AD1836A_II_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*****************************************************************************

Fixed enumerations and defines

*****************************************************************************/

/*****************************
AD1836A Register definitions
*****************************/
#define     AD1836A_DAC_CTRL_1          0x0000  // DAC Control 1
#define     AD1836A_DAC_CTRL_2          0x1000  // DAC Control 2
#define     AD1836A_DAC_1L_VOL          0x2000  // DAC 1L Volume
#define     AD1836A_DAC_1R_VOL          0x3000  // DAC 1R Volume
#define     AD1836A_DAC_2L_VOL          0x4000  // DAC 2L Volume
#define     AD1836A_DAC_2R_VOL          0x5000  // DAC 2R Volume
#define     AD1836A_DAC_3L_VOL          0x6000  // DAC 3L Volume
#define     AD1836A_DAC_3R_VOL          0x7000  // DAC 3R Volume
#define     AD1836A_ADC_1L_VOL          0x8000  // ADC 1L Peak Volume
#define     AD1836A_ADC_1R_VOL          0x9000  // ADC 1R Peak Volume
#define     AD1836A_ADC_2L_VOL          0xA000  // ADC 2L Peak Volume
#define     AD1836A_ADC_2R_VOL          0xB000  // ADC 2R Peak Volume
#define     AD1836A_ADC_CTRL_1          0xC000  // ADC Control 1
#define     AD1836A_ADC_CTRL_2          0xD000  // ADC Control 2
#define     AD1836A_ADC_CTRL_3          0xE000  // ADC Control 3

/**********************************
AD1836A Register Field definitions
**********************************/

// DAC Control 1 Register field definitions (AD1836A_DAC_CTRL_1)

#define     AD1836A_DE_EMPHASIS         0x08    // De-Emphasis (bits 9,8)
#define     AD1836A_SERIAL_MODE         0x05    // Serial Mode (bits 7,6,5)
#define     AD1836A_DAC_WORD_WIDTH      0x03    // Data-Word width (bits 4,3)
#define     AD1836A_DAC_PDN             0x02    // Power-Down (bit 2)
#define     AD1836A_INTERPOLATOR_MODE   0x01    // Interpolator Mode (bit 1)

// DAC Control 2 Register field definitions (AD1836A_DAC_CTRL_2)

#define     AD1836A_DAC_3R_MUTE         0x05    // DAC 3R Mute (bit 5)
#define     AD1836A_DAC_3L_MUTE         0x04    // DAC 3L Mute (bit 4)
#define     AD1836A_DAC_2R_MUTE         0x03    // DAC 2R Mute (bit 3)
#define     AD1836A_DAC_2L_MUTE         0x02    // DAC 2L Mute (bit 2)
#define     AD1836A_DAC_1R_MUTE         0x01    // DAC 1R Mute (bit 1)
#define     AD1836A_DAC_1L_MUTE         0x00    // DAC 1L Mute (bit 0)

// ADC Control 1 Register field definitions (AD1836A_ADC_CTRL_1)

#define     AD1836A_FILTER              0x08    // Filter (bit 8)
#define     AD1836A_ADC_PDN             0x07    // ADC Power-Down (bit 7)
#define     AD1836A_SAMPLE_RATE         0x06    // Sample Rate (bit 6)
#define     AD1836A_LEFT_GAIN           0x03    // Left Gain (bits 5,4,3)
#define     AD1836A_RIGHT_GAIN          0x00    // Right Gain (bits 2,1,0)

// ADC Control 2 Register field definitions (AD1836A_ADC_CTRL_2)

#define     AD1836A_AUX_MODE            0x09    // Master/Slave AUX Mode (bit 9)
#define     AD1836A_SOUT_MODE           0x06    // SOUT Mode (bits 8,7,6)
#define     AD1836A_ADC_WORD_WIDTH      0x04    // Word Width (bits 5,4)
#define     AD1836A_ADC_2R_MUTE         0x03    // ADC 2R Mute (bit 3)
#define     AD1836A_ADC_2L_MUTE         0x02    // ADC 2L Mute (bit 2)
#define     AD1836A_ADC_1R_MUTE         0x01    // ADC 1R Mute (bit 1)
#define     AD1836A_ADC_1L_MUTE         0x00    // ADC 1L Mute (bit 0)

// ADC Control 3 Register field definitions (AD1836A_ADC_CTRL_3)

#define     AD1836A_CLOCK_MODE          0x06    // Clock Mode (bit 7,6)
#define     AD1836A_LEFT_DIFF_SELECT    0x05    // Left Differential I/P Select (bit 5)
#define     AD1836A_RIGHT_DIFF_SELECT   0x04    // Right Differential I/P Select (bit 4)
#define     AD1836A_LEFT_MUX_ENABLE     0x03    // Left MUX/PGA Enable (bit 3)
#define     AD1836A_LEFT_MUX_SELECT     0x02    // Left MUX I/P Select (bit 2)
#define     AD1836A_RIGHT_MUX_ENABLE    0x01    // Right MUX/PGA Enable (bit 1)
#define     AD1836A_RIGHT_MUX_SELECT    0x00    // Right MUX I/P Select (bit 0)

// Set status of SPORT device to be used for audio dataflow between Blackfin and AD1836A
typedef enum ADI_AD1836A_SET_SPORT_STATUS {
    ADI_AD1836A_SPORT_OPEN,                     // Opens SPORT device
    ADI_AD1836A_SPORT_CLOSE                     // Closes SPORT device
}   ADI_AD1836A_SET_SPORT_STATUS;

/*** This Data type is no longer used/supported by this driver. Left here for backward compatibility ***/
typedef enum ADI_AD1836A_SET_SPORT_MODE {
    ADI_AD1836A_SET_TDM_MODE,                   // Set SPORT Device in TDM Mode
    ADI_AD1836A_SET_I2S_MODE                    // Set SPORT Device in I2S Mode
}   ADI_AD1836A_SET_SPORT_MODE;

/*****************************************************************************

Extensible enumerations and defines

*****************************************************************************/

// Command IDs
enum    {
            ADI_AD1836A_CMD_START=ADI_AD1836_ENUMERATION_START, //0x40050000

            // SPI related commands
            // 0x40050001 - Set AD1836A SPI Chipselect (configure Blackfin SPI_FLG to select AD1836A) (value = u8)
            ADI_AD1836A_CMD_SET_SPI_CS,
            // 0x40050002 - Get present SPI Chipselect value for AD1836A (value = u8*)
            ADI_AD1836A_CMD_GET_SPI_CS,

            // SPORT related commands
            // 0x40050003 - Set SPORT Device Number (Value = u8)
            ADI_AD1836A_CMD_SET_SPORT_DEVICE_NUMBER,
            // 0x40050004 - Set SPORT Device status (Value = ADI_AD1836A_SET_SPORT_STATUS)
            ADI_AD1836A_CMD_SET_SPORT_STATUS,
            // 0x40050005 - Enable(TRUE)/Disable(FALSE) auto-SPORT configuration mode (value = TRUE/FALSE) (TRUE by default)
            ADI_AD1836A_CMD_ENABLE_AUTO_SPORT_CONFIG,

            /*** This Command is no longer used/supported by this driver. Left here for backward compatibility ***/
            ADI_AD1836A_CMD_SET_SPORT_OPERATION_MODE,

            /* Command to set SPI device number connected to ADV1836A */
            ADI_AD1836A_CMD_SET_SPI_DEVICE_NUMBER   /* 0x40050007 - Set SPI Device number to be used to access AD1836A registers */
        };

// Events
enum    {
            ADI_AD1836A_EVENT_START=ADI_AD1836_ENUMERATION_START    //  0x40050000
        };

// Return codes
enum    {
            ADI_AD1836A_RESULT_START=ADI_AD1836_ENUMERATION_START,  // 0x40050000
            // 0x40050001 - The driver doesnot support this command
            ADI_AD1836A_RESULT_CMD_NOT_SUPPORTED
        };

/*****************************************************************************

Data Structures

*****************************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADIAD1836AEntryPoint;  // entry point to the device driver

/*****************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_AD1836A_II_H__ */

/*****/
