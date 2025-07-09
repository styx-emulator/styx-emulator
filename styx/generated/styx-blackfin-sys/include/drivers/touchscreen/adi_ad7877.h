/**********************************************************************
Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_ad7877.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
    This is the primary include file for AD7877 Touchscreen Controller.
    Use Device access commands to access AD7877 device registers
    (refer to adi_dev.h)

References:
Access to the AD7877 control registers is over the SPI port.
A 16 bit frame is sent over SPI and the data is broken down as follows:

+---------------------------+
| Reg Addr   |  Function    |
|---------------------------|
| 15:12      | 11:0         |
+---------------------------+

***********************************************************************/

#ifndef __ADI_AD7877_H__
#define __ADI_AD7877_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*********************************************************************

Entry point to the AD7877 device driver

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADIAD7877EntryPoint;

/*********************************************************************

Fixed enumerations and defines

*********************************************************************/
/*****************************
AD7877 Register definitions
*****************************/
/* Read/Write Type Registers                                                                */
#define     AD7877_CONTROL_REG1         0x01    /* Control Register 1                       */
#define     AD7877_CONTROL_REG2         0x02    /* Control Register 2                       */
#define     AD7877_ALERT_REG            0x03    /* Alert Status/Enable Register             */
#define     AD7877_AUX1_HIGH_LIMIT      0x04    /* High Limit for Auxiliary Input 1         */
#define     AD7877_AUX1_LOW_LIMIT       0x05    /* Low Limit for Auxiliary Input 1          */
#define     AD7877_BAT1_HIGH_LIMIT      0x06    /* High Limit for Battery Monitoring Input 1*/
#define     AD7877_BAT1_LOW_LIMIT       0x07    /* Low Limit for Battery Monitoring Input 1 */
#define     AD7877_BAT2_HIGH_LIMIT      0x08    /* High Limit for Battery Monitoring Input 2*/
#define     AD7877_BAT2_LOW_LIMIT       0x09    /* Low Limit for Battery Monitoring Input 2 */
#define     AD7877_TEMP1_LOW_LIMIT      0x0A    /* Low Limit for Temperature Measurement    */
#define     AD7877_TEMP1_HIGH_LIMIT     0x0B    /* High Limit for Temperature Measurement   */
#define     AD7877_SEQUENCER_REG0       0x0C    /* Sequencer Register 0                     */
#define     AD7877_SEQUENCER_REG1       0x0D    /* Sequencer Register 1                     */
#define     AD7877_DAC_REG              0x0E    /* DAC Register                             */

/* Read-Only Type Registers                                                                 */
#define     AD7877_YPOS                 0x10    /* Y position measurement (X+ input)        */
#define     AD7877_XPOS                 0x11    /* X position measurement (Y+ input)        */
#define     AD7877_Z2                   0x12    /* Z2 measurement (Y- with Y+ & X- excited) */
#define     AD7877_AUX1                 0x13    /* Auxiliary 1 Input value                  */
#define     AD7877_AUX2                 0x14    /* Auxiliary 2 Input value                  */
#define     AD7877_AUX3                 0x15    /* Auxiliary 3 Input value                  */
#define     AD7877_BAT1                 0x16    /* Battery Monitor Input 1 value            */
#define     AD7877_BAT2                 0x17    /* Battery Monitor Input 2 value            */
#define     AD7877_TEMP1                0x18    /* single-ended Temperature measurement     */
#define     AD7877_TEMP2                0x19    /* differential Temperature measurement     */
#define     AD7877_Z1                   0x1A    /* Z1 measurement (X- with Y+ & X- excited) */

/* Extended Read/Write Type Registers                                                       */
#define     AD7877_GPIO_CONTROL_REG1    0x1B    /* GPIO Control Register 1                  */
#define     AD7877_GPIO_CONTROL_REG2    0x1C    /* GPIO Control Register 2                  */
#define     AD7877_GPIO_DATA_REG        0x1D    /* GPIO Data Register                       */

/**********************************
AD7877 Register Field definitions
**********************************/
/* Control Register 1 field definitions (AD7877_CONTROL_REG1)                               */
#define     AD7877_SER_DFR              11      /* Single-ended(1) or Differential(0)
                                                   conversion (bit 11)                      */
#define     AD7877_CHADD                7       /* ADC Channel Address (bits 10 to 7)       */
#define     AD7877_RD                   2       /* Register Read Address (bits 6 to 2)      */
#define     AD7877_MODE                 0       /* Mode code (bits 1,0)                     */

/* Control Register 2 field definitions (AD7877_CONTROL_REG2)                               */
#define     AD7877_AVG                  10      /* ADC Averaging code (bits 11,10)          */
#define     AD7877_ACQ                  8       /* ADC Acquisition time (bits 9,8)          */
#define     AD7877_PM                   6       /* ADC Power Management Code (bits 7,6)     */
#define     AD7877_FCD                  4       /* First Conversion Delay (bits 5,4)        */
#define     AD7877_POL                  3       /* Polarity of signal on STOPACQ pin (bit 3)*/
#define     AD7877_REF                  2       /* Internal or external reference (bit 2)   */
#define     AD7877_TMR                  0       /* Conversion Interval Timer (bits 1,0)     */

/* Alert Status/Enable Register field definitions (AD7877_ALERT_REG)                        */
#define     AD7877_TEMP1EN              11      /* Enable/Disable TEMP1 as interrupt source
                                                   for ALERT output (bit 11)                */
#define     AD7877_BAT2EN               10      /* Enable/Disable BAT2 as interrupt source
                                                   for ALERT output (bit 10)                */
#define     AD7877_BAT1EN               9       /* Enable/Disable BAT1 as interrupt source
                                                   for ALERT output (bit 9)                 */
#define     AD7877_AUX1EN               8       /* Enable/Disable AUX1 as interrupt source
                                                   for ALERT output (bit 8)                 */
#define     AD7877_TEMP1HI              7       /*TEMP1 channel below its high limit?(bit 7)*/
#define     AD7877_BAT2HI               6       /* BAT2 channel above its high limit?(bit 6)*/
#define     AD7877_BAT1HI               5       /* BAT1 channel above its high limit?(bit 5)*/
#define     AD7877_AUX1HI               4       /* AUX1 channel above its high limit?(bit 4)*/
#define     AD7877_TEMP1LO              3       /*TEMP1 channel above its low limit?(bit 3) */
#define     AD7877_BAT2LO               2       /* BAT2 channel below its low limit?(bit 2) */
#define     AD7877_BAT1LO               1       /* BAT1 channel below its low limit?(bit 1) */
#define     AD7877_AUX1LO               0       /* AUX1 channel below its low limit?(bit 0) */

/* Sequencer Register 0 (AD7877_SEQUENCER_REG0) field definitions (Slave mode sequence)     */
/* Sequencer Register 1 (AD7877_SEQUENCER_REG1) field definitions (Master mode sequence)    */
#define     AD7877_YPOS_S               11      /* Enable Y Position Measurement (bit 11)   */
#define     AD7877_XPOS_S               10      /* Enable X Position Measurement (bit 10)   */
#define     AD7877_Z2_S                 9       /*Enable Z2 Touch pressure Measurement(bit9)*/
#define     AD7877_AUX1_S               8       /*Enable Auxiliary Input 1 Measurement(bit8)*/
#define     AD7877_AUX2_S               7       /*Enable Auxiliary Input 2 Measurement(bit7)*/
#define     AD7877_AUX3_S               6       /*Enable Auxiliary Input 3 Measurement(bit6)*/
#define     AD7877_BAT1_S               5       /* Enable Battery Monitor Input 1 Measurement
                                                  (bit 5)                                   */
#define     AD7877_BAT2_S               4       /* Enable Battery Monitor Input 2 Measurement
                                                  (bit 4)                                   */
#define     AD7877_TEMP1_S              3       /* Enable Single ended conversion Temperature
                                                  (bit3)                                    */
#define     AD7877_TEMP2_S              2       /* Enable Differential conversion Temperature
                                                  (bit3)                                    */
#define     AD7877_Z1_S                 1       /*Enable Z1 Touch pressure Measurement(bit1)*/

/* DAC Register (AD7877_DAC_REG) field definitions                                          */
#define     AD7877_DAC                  4       /* DAC Data (bits 11 to 4)                  */
#define     AD7877_DAC_PD               3       /* DAC Power Down (bit 3)                   */
#define     AD7877_DAC_V_I              2       /* Voltage Output and Current Output (bit 2)*/
#define     AD7877_DAC_RANGE            0       /* DAC Output range in Voltage mode (bit 0) */

/* GPIO Control Register 1 (AD7877_GPIO_CONTROL_REG1) field definitions                     */
#define     AD7877_GPIO2_EN             7       /*Select the function of AUX2 or GPIO2(bit7)*/
#define     AD7877_GPIO2_POL            6       /* Determine if GPIO2 is active high or low
                                                   (bit 6)                                  */
#define     AD7877_GPIO2_DIR            5       /* Set GPIO2 Direction (bit 5)              */
#define     AD7877_GPIO2_ALEN           4       /* Enable/Disable ALERT interrupt on GPIO2
                                                   (bit 4)                                  */
#define     AD7877_GPIO1_EN             3       /*Select the function of AUX1 or GPIO1(bit3)*/
#define     AD7877_GPIO1_POL            2       /* Determine if GPIO1 is active high or low
                                                   (bit 2)                                  */
#define     AD7877_GPIO1_DIR            1       /* Set GPIO1 Direction (bit 1)              */
#define     AD7877_GPIO1_ALEN           0       /* Enable/Disable ALERT interrupt on GPIO1
                                                   (bit 0)                                  */

/* GPIO Control Register 2 (AD7877_GPIO_CONTROL_REG2) field definitions                     */
#define     AD7877_GPIO4_EN             7       /*Select the function of AUX4 or GPIO4(bit7)*/
#define     AD7877_GPIO4_POL            6       /* Determine if GPIO4 is active high or low
                                                   (bit 6)                                  */
#define     AD7877_GPIO4_DIR            5       /* Set GPIO4 Direction (bit 5)              */
#define     AD7877_GPIO4_ALEN           4       /* Enable/Disable ALERT interrupt on GPIO4
                                                   (bit 4)                                  */
#define     AD7877_GPIO3_EN             3       /*Select the function of AUX3 or GPIO3(bit3)*/
#define     AD7877_GPIO3_POL            2       /* Determine if GPIO3 is active high or low
                                                   (bit 2)                                  */
#define     AD7877_GPIO3_DIR            1       /* Set GPIO3 Direction (bit 1)              */
#define     AD7877_GPIO3_ALEN           0       /* Enable/Disable ALERT interrupt on GPIO3
                                                   (bit 0)                                  */

/* GPIO Data Register (AD7877_GPIO_DATA_REG) field definitions                              */
#define     AD7877_GPIO1_DAT            7       /* GPIO1 Databit (bit 7)                    */
#define     AD7877_GPIO2_DAT            6       /* GPIO2 Databit (bit 6)                    */
#define     AD7877_GPIO3_DAT            5       /* GPIO3 Databit (bit 5)                    */
#define     AD7877_GPIO4_DAT            4       /* GPIO4 Databit (bit 4)                    */

/*********************************************************************

Data Structures

*********************************************************************/
/* AD7877 Result Register structure */
/* Pointer to this register structure will be passed as callback argument
   for Sequencer Slave and Master Mode read request, provided that the client
   configures the driver to handle the DAV interrupt */
typedef struct {
    u16     Y;              /* holds Y position measurement (X+ input)                      */
    u16     X;              /* holds X position measurement (Y+ input)                      */
    u16     Z2;             /* holds Z2 measurement (Y- input with Y+ & X- excited)         */
    u16     Aux1;           /* holds Auxiliary 1 Input value                                */
    u16     Aux2;           /* holds Auxiliary 2 Input value                                */
    u16     Aux3;           /* holds Auxiliary 3 Input value                                */
    u16     Bat1;           /* holds Battery Monitor Input 1 value                          */
    u16     Bat2;           /* holds Battery Monitor Input 2 value                          */
    u16     Temp1;          /* holds Temperature measurement using single-ended conversion  */
    u16     Temp2;          /* holds Temperature measurement using a differential conversion*/
    u16     Z1;             /* holds Z1 measurement (X- input with Y+ & X- excited)         */
}ADI_AD7877_RESULT_REGS;

/* Structure to set AD7877 PENIRQ/DAV/ALERT Interrupt Flag connected to Blackfin            */

/* This data structure can be used with ADI_AD7877_CMD_ENABLE_INTERRUPT_PENIRQ,
   ADI_AD7877_CMD_ENABLE_INTERRUPT_DAV and ADI_AD7877_CMD_ENABLE_INTERRUPT_ALERT commands.
   These commands can be used to configure this driver to monitor corresponding interrupt
   signals, which will reduce Application code overhead  */

/* To enable AD7877 PENIRQ or DAV or ALERT interrupt, client must pass corresponding
   interrupt enable command with pointer to following structure as value.
   The 'FlagId' field should hold the Blackfin processor Flag ID connected to the selected
   Interrupt signal and 'FlagIntId' field should hold the Peripheral Interrupt ID of
   the corresponding flag                                                                   */

typedef struct
{
    ADI_FLAG_ID             FlagId;     /* Flag ID connected to AD7877 interrupt signal     */
    ADI_INT_PERIPHERAL_ID   FlagIntId;  /* Peripheral Interrupt ID of the corresponding flag*/
} ADI_AD7877_INTERRUPT_PORT;

/*********************************************************************

Extensible enumerations and defines

*********************************************************************/
enum{                                                   /* AD7877 driver Command IDs        */
    ADI_AD7877_CMD_START=ADI_AD7877_ENUMERATION_START,  /* 0x40180000                       */

    /* Use Device access commands to configure AD7877 registers (refer to adi_dev.h)        */

    /* SPI related commands                                                                 */
    ADI_AD7877_CMD_SET_SPI_DEVICE_NUMBER,   /* 0x40180001 - Set AD7877 SPI Device Number to use
                                            (SPI Device used for AD7877 access) (value = u8)*/
    ADI_AD7877_CMD_SET_SPI_CS,              /* 0x40180002 - Set AD7877 SPI Chipselect
                                            (Blackfin SPI_FLG to select AD7877) (value = u8)*/

    /* AD7877 Interrupt signals (PENIRQ,DAV,ALERT) related commands                         */
    /* Commands to configure AD7877 driver to monitor selected interrupt signals            */
    ADI_AD7877_CMD_ENABLE_INTERRUPT_PENIRQ,  /* 0x40180003 - Sets AD7877 driver to monitor PENIRQ
                                            interrupt (value = ADI_AD7877_INTERRUPT_PORT*)  */
    ADI_AD7877_CMD_ENABLE_INTERRUPT_DAV,    /* 0x40180004 - Sets AD7877 driver to monitor DAV
                                            interrupt (value = ADI_AD7877_INTERRUPT_PORT*)  */
    ADI_AD7877_CMD_ENABLE_INTERRUPT_ALERT,  /*  0x40180005 - Sets AD7877 driver to monitor DAV
                                            interrupt (value = ADI_AD7877_INTERRUPT_PORT*)  */
    /* Commands to remove AD7877 interrupt signals from being monitored by the driver       */
    ADI_AD7877_CMD_DISABLE_INTERRUPT_PENIRQ,/* 0x40180006 - Removes PENIRQ interrupt from being
                                               monitored by AD7877 driver (value = NULL)    */
    ADI_AD7877_CMD_DISABLE_INTERRUPT_DAV,   /* 0x40180007 - Removes DAV interrupt from being
                                               monitored by AD7877 driver (value = NULL)    */
    ADI_AD7877_CMD_DISABLE_INTERRUPT_ALERT, /* 0x40180008 - Removes ALERT interrupt from being
                                               monitored by AD7877 driver (value = NULL)    */

    /*** Below six Commands are no longer used/supported by the driver.
         The commands are left here for backward compatibility ***/
    ADI_AD877_ENABLE_INTERRUPT_PENIRQ,
    ADI_AD877_ENABLE_INTERRUPT_DAV,
    ADI_AD877_ENABLE_INTERRUPT_ALERT,
    ADI_AD877_DISABLE_INTERRUPT_PENIRQ,
    ADI_AD877_DISABLE_INTERRUPT_DAV,
    ADI_AD877_DISABLE_INTERRUPT_ALERT

};

enum{                                   /* AD7877 Event IDs                                 */
    ADI_AD7877_EVENT_START=ADI_AD7877_ENUMERATION_START,    /* 0x40180000                   */
    /* Following (Callback) Events would occur only if the corresponding AD7877 interrupt
       signal is monitored by this driver                                                   */
    ADI_AD7877_EVENT_PENIRQ,            /* 0x40180001 - Callback Event indicates that
                                           PENIRQ has detected a screen touch event.
                                           Callback Argument - points to NULL               */
    ADI_AD7877_EVENT_PENIRQ_RELEASE,    /* 0x40180002 - Callback Event indicates that
                                           PENIRQ detected a screen release event.
                                           Callback Argument - points to NULL               */
    ADI_AD7877_EVENT_SINGLE_DAV,        /* 0x40180003 - Callback Event - occurs when AD7877
                                           is configured in single channel mode and indicates
                                           that a DAV interrupt has occurred.
                                           Callback Argument - pointer to a location holding
                                           result value of the selected channel.            */
    ADI_AD7877_EVENT_SEQUENCER_DAV,     /* 0x40180004 - Callback Event - occurs when AD7877
                                           is configured in Sequencer (slave or master) mode
                                           and indicates that a DAV interrupt has occurred.
                                           Callback Argument - pointer to a structure of type
                                           ADI_AD7877_RESULT_REGS holding result value of
                                           selected register sequence                       */
    ADI_AD7877_EVENT_ALERT              /* 0x40180005 - Callback Event - indicates that
                                           ALERT interrupt has occurred.
                                           Callback Argument - pointer to location holding
                                           AD7877 Alert Status/Enable register value        */
};

enum{                                       /* AD7877 Return codes                          */
    ADI_AD7877_RESULT_START=ADI_AD7877_ENUMERATION_START,   /* 0x40180000                   */
    ADI_AD7877_RESULT_CMD_NOT_SUPPORTED     /* 0x40180001 - Occurs when client issues a
                                               command not supported by this driver         */
};

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_AD7877_H__ */

/*****/
