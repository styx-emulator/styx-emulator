/*********************************************************************************

Copyright(c) 2005 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

Description:
            This is the include file for the AD7266 ADC SPORT driver.

*********************************************************************************/

#ifndef __ADI_AD7266_H__
#define __ADI_AD7266_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* ****************************************************************************
 *
 *
 * (c) Copyright Analog Devices Inc 2005
 *
 * ****************************************************************************
 */

/* ****************************************************************************
 * RESULT CODES
 * ****************************************************************************
 */
enum {
    ADI_AD7266_RESULT_START=ADI_AD7266_ENUMERATION_START,   // 0x40020000
    ADI_AD7266_RESULT_INVALID_CHANNEL_SELECTION,            // 0x0001 - Invalid Channel selection
    ADI_AD7266_RESULT_INVALID_PORT_SELECTION,               // 0x0002 - Invalid Flag pin port
    ADI_AD7266_RESULT_INVALID_PIN_SELECTION,                // 0x0003 - Invalid Flag pin selection
    ADI_AD7266_RESULT_INVALID_OPERATION_MODE                // 0x0004 - Invalid operation mode selection
};


/* ****************************************************************************
 * COMMAND CODES
 * ****************************************************************************
 */

enum {
    ADI_AD7266_CMD_START=ADI_AD7266_ENUMERATION_START,  // 0x40020000
    ADI_AD7266_CMD_SET_SAMPLE_RATE,                     // 0x0001 - set sample rate in sample/s (Value = address of value containing samples/sec)
    ADI_AD7266_CMD_SET_CHANNEL_SELECT_PINS,             // 0x0002 - set flag pin (value = address of ADI_AD7266_CHANNEL_SELECT_PIN_DEF structure)
    ADI_AD7266_CMD_SELECT_CHANNELS,                     // 0x0003 - select Channels
    ADI_AD7266_CMD_SET_DUAL_MODE,                       // 0x0004 - enables both outputs from the AD7266 (data will be interleaved)
    ADI_AD7266_CMD_USE_OPTIMAL_SCLK,                    // 0x0005 - instructs the driver to vary SCLK frequency to get closer to requested samplng rate
    ADI_AD7266_CMD_SET_OPERATION_MODE                   // 0x0006 - set mode of operation
};

/* ****************************************************************************
 * COMMAND VALUES
 * ****************************************************************************
 */

// Enum to describe the range of valid values for the
// ADI_AD7266_CMD_SET_OPERATION_MODE command
enum {
    ADI_AD7266_MODE_POWERDOWN,
    ADI_AD7266_MODE_PARTIAL_POWERDOWN,
    ADI_AD7266_MODE_NORMAL
};


// Enum to describe the range of valid values for the
// ADI_AD7266_CMD_SELECT_CHANNELS command
enum {
    ADI_AD7266_CHANNEL_VA1_VB1,
    ADI_AD7266_CHANNEL_VA2_VB2,
    ADI_AD7266_CHANNEL_VA3_VB3,
    ADI_AD7266_CHANNEL_VA4_VB4,
    ADI_AD7266_CHANNEL_VA5_VB5,
    ADI_AD7266_CHANNEL_VA6_VB6
};

// Enum to describe the range of valid values for PortIdent
// field in the ADI_AD7266_CHANNEL_SELECT_PIN_DEF structure
enum {
    ADI_AD7266_CHANNEL_SELECT_PORT_F,
    ADI_AD7266_CHANNEL_SELECT_PORT_G,
    ADI_AD7266_CHANNEL_SELECT_PORT_H
};

// Porgrammable pins
#define ADI_AD7266_NUM_PINS 3

// Structure to define the Channel Select Pin configuration
typedef struct {
    ADI_FLAG_ID A0_Pin;         // Pin # attached to A0 on converter
    ADI_FLAG_ID A1_Pin;         // Pin # attached to A1 on converter
    ADI_FLAG_ID A2_Pin;         // Pin # attached to A2 on converter
} ADI_AD7266_CHANNEL_SELECT_PIN_DEF;

// Entry point structure
#ifndef ADI_AD7266_MODULE
extern ADI_DEV_PDD_ENTRY_POINT ADI_AD7266_EntryPoint;
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_AD7266_H__ */
