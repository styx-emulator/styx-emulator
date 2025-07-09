/*****************************************************************************
Copyright (c), 2002-2009 - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.
******************************************************************************

$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Title:  AD7879/AD7879-1 Touchscreen Controller Driver common definitions

Description:
        This file contains definitions that are common to the AD7879 and
        AD7879-1 drivers.

Notes:  Do not #include this file.  Instead, #include the adi_dev_ad7879.h or
        adi_dev_ad7879_1.h header as appropriate.  They each #include this
        file.

*****************************************************************************/

#ifndef __ADI_AD7879_COMMON_H__
#define __ADI_AD7879_COMMON_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if defined(_LANGUAGE_C)

/*=============  I N C L U D E S   =============*/


/*==============  D E F I N E S  ===============*/

/*
**
** AD7879 Register addresses
**  - Read/Write Type Registers
**
*/

/*
** AD7879_REG_CONTROL_1
**  - Control Register 1
*/
#define     AD7879_REG_CONTROL_1            0x01U
/*
** AD7879_REG_CONTROL_2
**  - Control Register 2
*/
#define     AD7879_REG_CONTROL_2            0x02U
/*
** AD7879_REG_CONTROL_3
**  - Control Register 3
*/
#define     AD7879_REG_CONTROL_3            0x03U
/*
** AD7879_REG_AUX_BAT_HLIMIT
**  - AUX/VBAT high limit register
*/
#define     AD7879_REG_AUX_BAT_HLIMIT       0x04U
/*
** AD7879_REG_AUX_BAT_LLIMIT
**  - AUX/VBAT low limit register
*/
#define     AD7879_REG_AUX_BAT_LLIMIT       0x05U
/*
** AD7879_REG_TEMP_HLIMIT
**  - Temperature high limit register
*/
#define     AD7879_REG_TEMP_HLIMIT          0x06U
/*
** AD7879_REG_TEMP_LLIMIT
**  - Temperature low limit register
*/
#define     AD7879_REG_TEMP_LLIMIT          0x07U

/*
**
** AD7879 Register addresses
**  - Read-Only Type Registers
**
*/

/*
** AD7879_REG_XPOS
**  - X position measurement (Y+ input)
*/
#define     AD7879_REG_XPOS                 0x08U
/*
** AD7879_REG_YPOS
**  - Y position measurement (X+ input)
*/
#define     AD7879_REG_YPOS                 0x09U
/*
** AD7879_REG_Z1
**  - Z1 measurement (X- with X+ & Y- excited)
*/
#define     AD7879_REG_Z1                   0x0AU
/*
** AD7879_REG_Z2
**  - Z2 measurement (Y- with Y+ & X- excited)
*/
#define     AD7879_REG_Z2                   0x0BU
/*
** AD7879_REG_AUX_BAT
**  - Auxiliary/Battery Input value
*/
#define     AD7879_REG_AUX_BAT              0x0CU
/*
** AD7879_REG_TEMP
**  - Temperature measurement
*/
#define     AD7879_REG_TEMP                 0x0DU
/*
** AD7879_REG_XPOS
**  - Revision and Device ID
*/
#define     AD7879_REG_REF_ID               0x0EU

/*
**
** AD7879 Register field definitions
**  - Control Register 1 field definitions (AD7879_REG_CONTROL_1)
**
*/

/*
** AD7879_RFLD_PENIRQEN
**  - Enable/Disable PENIRQ interrupt (bit 15)
*/
#define     AD7879_RFLD_PENIRQEN             15U
/*
** AD7879_RFLD_CHADD
**  - ADC Channel Address (bits 12 to 14)
*/
#define     AD7879_RFLD_CHADD               12U
/*
** AD7879_RFLD_ADC_MODE
**  - ADC Mode code (bits 10,11)
*/
#define     AD7879_RFLD_ADC_MODE            10U
/*
** AD7879_RFLD_ACQ
**  - ADC Acquisition time (bits 9,8)
*/
#define     AD7879_RFLD_ACQ                 8U
/*
** AD7879_RFLD_CHADD
**  - Conversion Interval Timer (bits 0 to 7)
*/
#define     AD7879_RFLD_TMR                 0U

/*
**
** AD7879 Register field definitions
**  - Control Register 2 field definitions (AD7879_REG_CONTROL_2)
**
*/

/*
** AD7879_RFLD_PM
**  - ADC Power Management Code (bits 14,15)
*/
#define     AD7879_RFLD_PM                  14U
/*
** AD7879_RFLD_GPIO_EN
**  - Select the function of AUX or GPIO(bit13)
*/
#define     AD7879_RFLD_GPIO_EN             13U
/*
** AD7879_RFLD_GPIO_DAT
**  - GPIO Databit (bit 12)
*/
#define     AD7879_RFLD_GPIO_DAT            12U
/*
** AD7879_RFLD_GPIO_DIR
**  - Set GPIO Direction (bit 11)
*/
#define     AD7879_RFLD_GPIO_DIR            11U
/*
** AD7879_RFLD_SER_DFR
**  - Single-ended(1) or Differential(0) conversion (bit 10)
*/
#define     AD7879_RFLD_SER_DFR             10U
/*
** AD7879_RFLD_FIL_EN
**  - Enable/Disable Median and Averaging Filter (bit 9)
*/
#define     AD7879_RFLD_FIL_EN              9U
/*
** AD7879_RFLD_AVG
**  - ADC Averaging code (bits 7,8)
*/
#define     AD7879_RFLD_AVG                 7U
/*
** AD7879_RFLD_FIL
**  - Median filter size(bits 5,6)
*/
#define     AD7879_RFLD_FIL                 5U
/*
** AD7879_RFLD_SW_RESET
**  - Digital part is reset when this bit is set(bit 4)
*/
#define     AD7879_RFLD_SW_RESET            4U
/*
** AD7879_RFLD_FCD
**  - First Conversion Delay (bits 0 to 3)
*/
#define     AD7879_RFLD_FCD                 0U

/*
**
** AD7879 Register field definitions
**  - Control Register 3 field definitions (AD7879_REG_CONTROL_3)
**
*/

/*
** AD7879_RFLD_TEMPEN
**  - Enable/Disable TEMP as interrupt source (bit 15)
*/
#define     AD7879_RFLD_TEMPEN              15U
/*
** AD7879_RFLD_AUXEN
**  - Enable/Disable AUX/VBAT as interrupt source (bit 14)
*/
#define     AD7879_RFLD_AUXEN               14U
/*
** AD7879_RFLD_DAVINT_S
**  - DAV#/INT# mode select,0=DAV enb; 1=INT (bit 13)
*/
#define     AD7879_RFLD_DAVINT_S            13U
/*
** AD7879_RFLD_GPIO_ALEN
**  - Enable/Disable ALERT interrupt on GPIO (bit 12)
*/
#define     AD7879_RFLD_GPIO_ALEN           12U
/*
** AD7879_RFLD_AUXLO
**  - 1 = AUX/VBAT below low limit(bit 11)
*/
#define     AD7879_RFLD_AUXLO               11U
/*
** AD7879_RFLD_AUXHI
**  - 1 = AUX/VBAT above high limit(bit 10)
*/
#define     AD7879_RFLD_AUXHI               10U
/*
** AD7879_RFLD_TEMPLO
**  - 1 = TEMP below low limit (bit 9)
*/
#define     AD7879_RFLD_TEMPLO              9U
/*
** AD7879_RFLD_TEMPHI
**  - 1 = TEMP above high limit(bit 8)
*/
#define     AD7879_RFLD_TEMPHI              8U
/*
** AD7879_RFLD_YPOS_S
**  - 1 = Include measurement of Y position (X+ input) (bit 7)
*/
#define     AD7879_RFLD_YPOS_S              7U
/*
** AD7879_RFLD_XPOS_S
**  - 1 = Include measurement of X position (Y+ input) (bit 6)
*/
#define     AD7879_RFLD_XPOS_S              6U
/*
** AD7879_RFLD_Z1_S
**  - 1 = Include Z1 touch pressure measurement (X+ input)(bit 5)
*/
#define     AD7879_RFLD_Z1_S                5U
/*
** AD7879_RFLD_Z2_S
**  - 1 = Include Z2 touch pressure measurement (Y- input) (bit 4)
*/
#define     AD7879_RFLD_Z2_S                4U
/*
** AD7879_RFLD_AUX_S
**  - 1= Include measurement of AUX channel(bit 3)
*/
#define     AD7879_RFLD_AUX_S               3U
/*
** AD7879_RFLD_BAT_S
**  - 1 = Include measurement of battery monitor (VBAT)(bit 2)
*/
#define     AD7879_RFLD_BAT_S               2U
/*
** AD7879_RFLD_TEMP_S
**  - 1 = Include temperature measurement(bit 1)
*/
#define     AD7879_RFLD_TEMP_S              1U

/*
**
** Enumerations of AD7879 driver specific commands
**
*/
enum
{
    /* COMMAND IDS */

    ADI_AD7879_CMD_START = ADI_AD7879_ENUMERATION_START,
    /* 0x401A0000 - AD7879 driver enumeration start  */

    /*
    ** SPI related commands (for AD7879)
    */

    ADI_AD7879_CMD_SET_SPI_DEVICE_NUMBER,
    /* 0x401A0001 - Sets SPI Device Number to use to access AD7879 registers
                    Value = u8 (SPI Device number to use)
                    Default = 0xFF (SPI device number invalid)              */

    ADI_AD7879_CMD_SET_SPI_CS,
    /* 0x401A0002 - Sets SPI Chipselect to select AD7879
                    Value = u8 (SPI Chipselect to use)
                    Default = 0 (SPI Chipselect invalid)                    */

    /*
    ** AD7879 Interrupt signals (PENIRQ,INT,ALERT) related commands
    */

    ADI_AD7879_CMD_ENABLE_INTERRUPT_PEN_INT_IRQ,
    /* 0x401A0003 - Sets AD7879 driver to monitor PENIRQ and
                    Data Available/Alarm (INTIRQ) interrupts
                    Value = ADI_AD7879_INTERRUPT_PORT *
                    Default = Interrupt monitoring disabled                 */

     ADI_AD7879_CMD_DISABLE_INTERRUPT_PENIRQ,
    /* 0x401A0004 - Removes PENIRQ interrupt from being
                    monitored by AD7879 driver
                    Value = NULL                                            */

    ADI_AD7879_CMD_DISABLE_INTERRUPT_INTIRQ,
    /* 0x401A0005 - Removes Data Available/Alarm (INTIRQ) interrupt from being
                    monitored by AD7879 driver
                    Value = NULL                                            */


    /* EVENT IDS */

    /* Following (Callback) Events would occur only if
       the corresponding AD7879 interrupt signal is monitored by this driver */

    ADI_AD7879_EVENT_PENIRQ_TOUCH,
    /* 0x401A0006 - Callback Event indicates that
                    PENIRQ has detected a screen touch event.
                    Callback Argument - points to NULL
                    Note: On occurance of this event, client can program
                    AD7879 to begin channel conversion in either
                    Mode 01b or Mode 10b                                    */

    ADI_AD7879_EVENT_PENIRQ_RELEASE,
    /* 0x401A0007 - Callback Event indicates that
                    PENIRQ has detected a screen release event.
                    Callback Argument - pointer to a structure of type
                    ADI_AD7879_RESULT_REGS holding result value of
                    selected register sequence                              */

    ADI_AD7879_EVENT_SINGLE_DAV,
    /* 0x401A0008 - Callback Event occurs when AD7879
                    is configured in single channel mode and indicates
                    that a Data Available (DAV) interrupt has occurred.
                    Callback Argument - pointer to a location holding
                    result value of the selected channel.                   */

    ADI_AD7879_EVENT_SEQUENCER_DAV,
    /* 0x401A0009 - Callback Event occurs when AD7879 is configured in
                    Master Sequencer mode and indicates that a
                    Data Available (DAV) interrupt has occurred.
                    Callback Argument - pointer to a structure of type
                    ADI_AD7879_RESULT_REGS holding result value of
                    selected register sequence                              */

    ADI_AD7879_EVENT_ALARM_OFL,
    /* 0x401A000A - Callback Event occurs when AD7879
                    is configured in Out of limits alarm interrupt mode
                    and indicates that a OFL interrupt has occurred.
                    This function is not supported by the EZkit, this
                    Callback serves as indication only.                     */



    /* RESULT IDS */

    ADI_AD7879_RESULT_CMD_NOT_SUPPORTED,
    /* 0x401A000B - Occurs when client issues a command
                    that is not supported by this driver                    */

    /*
    ** TWI related commands (for AD7879-1)
    ** (added here so that preceding values are not changed)
    */

    ADI_AD7879_CMD_SET_TWI_DEVICE_ADDRESSES,
    /* 0x401A000C - Sets TWI controller number and 7879-1 TWI device address
     *              to use to access AD7879 registers
                    Value = (u8 (TWI controller number) << 8) |
                            (u8 (TWI device address))
                    Default = (0 << 8) | 0x2Fu
    */

    ADI_AD7879_CMD_SET_TWI_CONFIG_TABLE
    /* 0x401A000D - Sets TWI Configuration table specific to the application
                    Value = pointer to ADI_DEV_CMD_VALUE_PAIR
                    Default = pointer to a minimal set of commands that sets
                              the dataflow method to ADI_DEV_MODE_SEQ_CHAINED
                              and then enables dataflow.
    */

};

/*=============  E X T E R N A L S  ============*/


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

/*
** ADI_AD7879_RESULT_REGS
**  - AD7879 Result Register structure
**    Pointer to this register structure will be passed as callback argument
**    for Sequencer Slave and Master Mode read request, provided that
**    the client configures the driver to monitor the
**    Data Available (INTIRQ) interrupt
*/
typedef struct __AdiAd7879ResultRegs
{

    /* Variable: nX
        - X position measurement (Y+ input) */
    u16     nX;

    /* Variable: nY
        - Y position measurement (X+ input) */
    u16     nY;

    /* Variable: nZ1
        - Z1 measurement (X- input with X+ & Y- excited) */
    u16     nZ1;

    /* Variable: nZ2
        - Z2 measurement (Y- input with Y+ & X- excited) */
    u16     nZ2;

    /* Variable: nAuxVbat
        - AUX/VBAT voltage measurement */
    u16     nAuxVbat;

    /* Variable: nTemperature
        - Temperature conversion measurement */
    u16     nTemperature;

}ADI_AD7879_RESULT_REGS;

/*
** ADI_AD7879_INTERRUPT_PORT
**  - Structure to pass information on Blackfin flag pin connected to
**    This data structure can be used with
**    ADI_AD7879_CMD_ENABLE_INTERRUPT_PEN_INT_IRQ command that can be used to
**    configure the driver to monitor PENIRQ & Data Available (INTIRQ)
**    interrupt signal. Allowing driver to monitor these interrupts will
**    reduce Application code overhead  */

typedef struct __AdiAd7879InterruptPort
{

    /* Variable: eFlagId
        - Flag ID connected to AD7879 interrupt signal */
    ADI_FLAG_ID             eFlagId;

    /* Variable: eFlagIntId
        - Peripheral Interrupt ID of the corresponding flag */
    ADI_INT_PERIPHERAL_ID   eFlagIntId;

} ADI_AD7879_INTERRUPT_PORT;

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

#endif /* __ADI_AD7879_COMMON_H__ */

/*****/
