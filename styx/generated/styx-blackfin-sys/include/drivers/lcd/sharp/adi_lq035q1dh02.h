/******************************************************************************
Copyright (c), 2010 - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.

$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Title: Sharp LQ035Q1DH02 LCD driver

Description: This is the primary include file for Sharp LQ035Q1DH02 LCD driver

*****************************************************************************/

#ifndef __ADI_LQ035Q1DH02_H__
#define __ADI_LQ035Q1DH02_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if defined(_LANGUAGE_C)

/*=============  I N C L U D E S   =============*/


/*==============  D E F I N E S  ===============*/

/*
** ADI_LQ035Q1DH02_OUT_SHIFT_MODE
**  - Enumerations of Output shift direction modes supported by
**    Sharp LQ035Q1DH02 LCD driver
*/
typedef enum __AdiLq035q1dh02OutShiftMode
{

    /* Top Shifts to Bottom, Left Shifts to Right */
    ADI_LQ035Q1DH02_OUT_SHIFT_TB_LR,
    /* Top Shifts to Bottom, Right Shifts to Left */
    ADI_LQ035Q1DH02_OUT_SHIFT_TB_RL,
    /* Bottom Shifts to Top, Left Shifts to Right */
    ADI_LQ035Q1DH02_OUT_SHIFT_BT_LR,
    /* Bottom Shifts to Top, Right Shifts to Left */
    ADI_LQ035Q1DH02_OUT_SHIFT_BT_RL

} ADI_LQ035Q1DH02_OUT_SHIFT_MODE;


/*
** Enumerations of Sharp LQ035Q1DH02 LCD driver specific commands
*/
enum
{
    /* 0x402F0000 - Sharp LQ035Q1DH02 LCD driver enumeration start          */
    ADI_LQ035Q1DH02_CMD_START   = ADI_LQ035Q1DH02_ENUMERATION_START,

    /*
    ** SPI related commands
    */

    /* 0x402F0001 - Sets SPI device number to use to configure LCD registers
                    Value   = u8 (SPI device number to use)
                    Default = 0xFF (SPI device number invalid)              */
    ADI_LQ035Q1DH02_CMD_SET_SPI_DEVICE_NUMBER,
    /* 0x402F0002 - Sets SPI Chipselect Number connected to LCD CSB pin
                    Value   = u8 (SPI Chipselect number)
                    Default = 0 (SPI Chipselect invalid)                    */
    ADI_LQ035Q1DH02_CMD_SET_SPI_CHIP_SELECT,

    /*
    ** PPI related commands
    */

    /* 0x402F0004 - Opens PPI device number connected to LCD
                    Value   = u8 (PPI device number to open)
                    Default = None                                          */
    ADI_LQ035Q1DH02_CMD_OPEN_PPI,
    /* 0x402F0005 - Closes PPI device previously opened for this LCD device
                    Value = NULL                                            */
    ADI_LQ035Q1DH02_CMD_CLOSE_PPI,
    /* 0x402F0006 - Enable/Disable Automatic PPI control register configuration
                    Value = true/false
                            'true' to allow the driver to automatically
                                   configure PPI control register as per
                                   LCD requirements
                            'false' to configure PPI control register from
                                    the application
                    Default = true                                          */
    ADI_LQ035Q1DH02_CMD_ENABLE_AUTO_PPI_CONTROL_CONFIG,

    /*
    ** Sharp LQ035Q1DH02 LCD query commands
    */
    /* 0x402F0007 - Gets Number of padding lines required at
                    the start/top of each frame
                    Value   = u32 *
                                                                            */
    ADI_LQ035Q1DH02_CMD_GET_TOP_PAD_LINES_PER_FRAME,
    /* 0x402F0008 - Gets Number of padding lines required at
                    the end/bottom of each frame
                    Value   = u32 *
                                                                            */
    ADI_LQ035Q1DH02_CMD_GET_BOTTOM_PAD_LINES_PER_FRAME,

    /*
    ** Sharp LQ035Q1DH02 LCD configuration commands
    */

    /* 0x402F0009 - Sets Output shift direction (Top to Bottom and
                    Left to Right) of the LCD display
                    Value   = Enumeration of type
                              ADI_LQ035Q1DH02_OUT_SHIFT_MODE
                    Default = ADI_LQ035Q1DH02_OUT_SHIFT_TB_RL               */
    ADI_LQ035Q1DH02_CMD_SET_OUTPUT_SHIFT_DIRECTION,
    /* 0x402F000A - Enables/Disables Reverse display
                    Value   = true/false ('true' to display all characters and
                                          graphics in reversal,
                                          'fasle' to display in normal mode)
                    Default = false (Reversal disabled)                     */
    ADI_LQ035Q1DH02_CMD_ENABLE_REVERSE_DISPLAY,
    /* 0x402F000B - Enables/Disables 256k color mode (OR)
                    Disables/Enables 8-color mode
                    Value   = true/false ('true' to select 256k color,
                                          'false' to select 8-color)
                    Default = true (256k color mode)                        */
    ADI_LQ035Q1DH02_CMD_ENABLE_256K_COLOR,
    /* 0x402F000C - Sets number of valid pixels per line
                    Value   = u16 (range between 1 and 320)
                    Default = 320                                           */
    ADI_LQ035Q1DH02_CMD_SET_NUM_VALID_PIXELS_PER_LINE,
    /* 0x402F000D - Sets number of dummy dot-clocks per line
                    Value   = u8 (range between 2 and 65)
                    Default = 8                                             */
    ADI_LQ035Q1DH02_CMD_SET_NUM_DUMMY_DOT_CLOCKS_PER_LINE,
    /* 0x402F000DE - Sets number of dummy lines per frame
                    Value   = u8 (range between 1 and 240)
                    Default = 2                                             */
    ADI_LQ035Q1DH02_CMD_SET_NUM_DUMMY_LINES_PER_FRAME,
    /* 0x402F000F - Enters sleep mode by writing to LCD SHUT register
                    Value   = NULL                                          */
    ADI_LQ035Q1DH02_CMD_ENTER_SLEEP,
    /* 0x402F0010 - Exits sleep mode by writing to LCD SHUT register
                    Value   = NULL                                          */
    ADI_LQ035Q1DH02_CMD_EXIT_SLEEP,
    /* 0x402F0011 - Resets LCD display by pulling down LCD reset line
                    Value   = enumeration of type ADI_FLAG_ID
                              (Flag ID connected to the LCD Reset line)     */
    ADI_LQ035Q1DH02_CMD_HARDWARE_RESET,
    /* 0x402F0012 - Supplies value for PPI_CONTROL register if default is
                    not suitable.
                    Value   = the appropriate PPI_CONTROL value
                    Default = suitable value for LCD Extender card          */
    ADI_LQ035Q1DH02_CMD_SET_PPI_CTL_VALUE,
    /* 0x402F0013 - Supplies ratio of PPI clocks to LCD 'dot' clocks.
                    Value   = the appropriate ratio (eg 3 on BF527 EZ-Kit)
                    Default = 1 (Suitable for the LCD Extender card)        */
    ADI_LQ035Q1DH02_CMD_SET_PPI_CLK_PER_DOT

    /* Add more driver specific commands here                               */

    /* Client can also use PPI driver specific commands to
       access PPI registers                                                 */
};

/*
** Enumerations of Sharp LQ035Q1DH02 LCD driver specific return codes
*/
enum
{

    /* 0x402F0000 - Sharp LQ035Q1DH02 LCD driver enumeration start          */
    ADI_LQ035Q1DH02_RESULT_START   = ADI_LQ035Q1DH02_ENUMERATION_START,
    /* 0x402F0001 - Results when client tries to submit buffers or
                    enable dataflow when the underlying PPI device in
                    closed state                                            */
    ADI_LQ035Q1DH02_RESULT_PPI_NOT_OPEN,
    /* 0x402F0002 - Given command is not recognised or supported
                    by the driver                                           */
    ADI_LQ035Q1DH02_RESULT_CMD_NOT_SUPPORTED,
    /* 0x402F0003 - Given Output Shift mode is invalid                      */
    ADI_LQ035Q1DH02_RESULT_OUT_SHIFT_MODE_INVALID,
    /* 0x402F0004 - Given Valid Pixels per line count is invalid            */
    ADI_LQ035Q1DH02_RESULT_PIXELS_PER_LINE_INVALID,
    /* 0x402F0005 - Given Dummy Dot clocks per line count is invalid        */
    ADI_LQ035Q1DH02_RESULT_DUMMY_DOT_CLOCKS_PER_LINE_INVALID,
    /* 0x402F0006 - Given Dummy Lines per Frame count is invalid            */
    ADI_LQ035Q1DH02_RESULT_DUMMY_LINES_PER_FRAME_INVALID,
    /* 0x402F0007 - Given SPI Device number is invalid                      */
    ADI_LQ035Q1DH02_RESULT_SPI_DEVICE_INVALID,
    /* 0x402F0008 - Given SPI chip select is invalid                        */
    ADI_LQ035Q1DH02_RESULT_SPI_CS_INVALID,
    /* 0x402F0009 - Results when client tries to open (allocate)
                    more than one PPI device for a LCD device instance      */
    ADI_LQ035Q1DH02_RESULT_PPI_ALREADY_ALLOCATED

    /* Driver also returns error code from the underlying Device Drivers and
       System Services                                                      */
};

/*=============  E X T E R N A L S  ============*/

/*
**
**  External Data section
**
*/
/*
** ADILQ035Q1DH02EntryPoint
**  - Device Manager Entry point for Sharp LQ035Q1DH02 driver
**
*/
extern ADI_DEV_PDD_ENTRY_POINT      ADILQ035Q1DH02EntryPoint;

/*=============  D A T A    T Y P E S   =============*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* C-specific definitions  */

/*
**
**  Data structures
**
*/

/*=======  P U B L I C   P R O T O T Y P E S  ========*/
/*            (globally-scoped functions)             */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#else /* not _LANGUAGE_C */

/* Assembler-specific */

#endif /* not _LANGUAGE_C */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_LQ035Q1DH02_H__ */
