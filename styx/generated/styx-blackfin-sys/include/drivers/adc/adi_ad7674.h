/*********************************************************************************

Copyright(c) 2005 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

Description:
            This is the include file for the AD7674 ADC PPI driver.

*********************************************************************************/

#ifndef __ADI_AD7674_H__
#define __ADI_AD7674_H__

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
    ADI_AD7674_RESULT_START=ADI_AD7674_ENUMERATION_START,   // 0x40040000
    ADI_AD7674_RESULT_INVALID_PORT_SELECTION,               // 0x0001 - Invalid Flag pin port
    ADI_AD7674_RESULT_INVALID_PIN_SELECTION,                // 0x0002 - Invalid Flag pin selection
    ADI_AD7674_RESULT_INVALID_CONVERSION_MODE,              // 0x0003 - Invalid operation mode selection
    ADI_AD7674_RESULT_INVALID_OPERATION_MODE,               // 0x0004 - Invalid operation mode selection
    ADI_AD7674_RESULT_INVALID_PCLK_DIV,                     // 0x0005 - Invalid PPI_CLK divider
    ADI_AD7674_RESULT_INVALID_SAMPLING_RATE                 // 0x0005 - Invalid throughput
};


/* ****************************************************************************
 * COMMAND CODES
 * ****************************************************************************
 */

enum {
    ADI_AD7674_CMD_START=ADI_AD7674_ENUMERATION_START,  // 0x40040000
    ADI_AD7674_CMD_SET_SAMPLE_RATE,                     // 0x0001 - Set sample rate in sample/s (Value = address of value containing samples/sec)
    ADI_AD7674_CMD_SET_PINS,                            // 0x0002 - Set flag pin (value = address of ADI_AD7674_PPI_DEF structure)
    ADI_AD7674_CMD_SET_CONVERSION_MODE,                 // 0x0003 - Set mode of operation
    ADI_AD7674_CMD_SET_MSB_FIRST,                       // 0x0004 - Determines order of data in memory - TRUE = MSB-LSB-MSB-LSB
    ADI_AD7674_CMD_SET_PPI_CLK,                         // 0x0005 - Sets the PPI_CLK frequency to supplied value
    ADI_AD7674_CMD_SET_A0_CONTINUOUS,                   // 0x0006 - Sets A0 as continuous signal at half PPI_CLK frequency
    ADI_AD7674_CMD_GET_SAMPLE_RATE                      // 0x0007 - Retrieve actual sampling rate
};

/* ****************************************************************************
 * COMMAND VALUES
 * ****************************************************************************
 */


 // Enum to describe the range of valid values for the
// ADI_AD7674_CMD_SET_CONVERSION_MODE command
enum {
    ADI_AD7674_IMPULSE_MODE,
    ADI_AD7674_NORMAL_MODE,
    ADI_AD7674_WARP_MODE
};

// Enum to describe the range of valid values for PortIdent
// field in the ADI_AD7674_PINS_PIN_DEF structure
enum {
    ADI_AD7674_PINS_PORT_F,
    ADI_AD7674_PINS_PORT_G,
    ADI_AD7674_PINS_PORT_H
};

// Programmable pins
#define ADI_AD7674_NUM_PINS 4

// Structure to define the Channel Select Pin configuration
#pragma pack(2)
typedef struct {
    u16 PortIdent;      // Port Identifier (F,G or H)
    u16 PPI_CLK_TIMER_pin;  // Pin # to supply the PPI_CLK
    u16 WARP_pin;
    u16 IMPULSE_pin;
    u16 CS_pin;
} ADI_AD7674_PIN_DEF;
#pragma pack()

// Entry point structure
#ifndef ADI_AD7674_MODULE
extern ADI_DEV_PDD_ENTRY_POINT ADI_AD7674_EntryPoint;
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_AD7674_H__ */
