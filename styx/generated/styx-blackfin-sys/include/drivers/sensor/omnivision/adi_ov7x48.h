/******************************************************************************

Copyright (c) 2005 Analog Devices.  All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.
*******************************************************************************

$File: adi_OV7X48.h $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Project:    OV7X48 Omnivision sensor device driver
Title:      OV7X48 definitions
Author(s):  BJ

Description:
   This is the primary include file for the OV7X48 omnivision sensor driver..

References:
    OV7X48 device driver documentation.pdf
    OV7X48_DS(1.5).pdf
    OV7X48BGA_AA.pdf
    pb_7168_7648.pdf
    omnivision_ds_note.pdf

Note:
    OV7X48 - Color CMOS VGA 640x480 sensor.
    OV7148 - Black and white CMOS VGA 640x480 sensor.

*******************************************************************************

Modification History:
====================
Revision 1.00
    Created driver
Revision 1.01 - 11/11/2005
    - Added check for frame size (registers ADI_OV7X48_HSTART, ADI_OV7X48_HSTOP,
    ADI_OV7X48_VSTART and ADI_OV7X48_VSTOP) to determine correct frames size
    of window, also updated ADI_OV7X48_CMD_GET_WIDTH and ADI_OV7X48_CMD_GET_WIDTH
    to reflect this.
    - Added new standard register access format.
    - Added extra commands to read/write register fields that are in multiple
    registers.
    - Added extra command to set PPI cotrol register manually from control
    command.
    - Added ADI_DEV_CMD_GET_MFRID to return the manufacturers ID word from the
    device
Revision 1.02 - BJ (8/2/2006)
    - Updated driver to use latest Register Access funcitons
Revision 1.03 - BJ (13/3/2006)
    - Modified control function to stop PPI being restarted for device access
    functions

******************************************************************************/

#ifndef __ADI_OV7X48_H__
#define __ADI_OV7X48_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*****************************************************************************/


enum {
    ADI_OV7X48_CMD_START=ADI_OV7x48_ENUMERATION_START,  //  starting enumeration

    // twi configuration commands
    ADI_OV7X48_CMD_SET_TWI,                     // Set the TWI device number
    ADI_OV7X48_CMD_SET_TWIADDR,                 // Set the sensors TWI address
    ADI_OV7X48_CMD_SET_TWICONFIG,               // Set the TWI command list

    // ppi configuration commands
    ADI_OV7X48_CMD_SET_PPI,                     // Set the PPI hardware number
    ADI_OV7X48_CMD_SET_PPICONFIG,               // Set the PPI config list
    ADI_OV7X48_CMD_SET_PPICMD,                  // Pass commands directly to PPI device

    // General OV7X48 config controls
    ADI_OV7X48_CMD_GET_HWID,                    // Get the hardware ID
    ADI_OV7X48_CMD_GET_MFRID,                   // Get the manufacturer ID
    ADI_OV7X48_CMD_GET_HEIGHT,                  // Get the height
    ADI_OV7X48_CMD_GET_WIDTH,                   // Get the width

    // access commands to fields that cross 2 registers
    ADI_OV7X48_CMD_SET_FRAMERATE,               // Sets framerate
    ADI_OV7X48_CMD_GET_FRAMERATE,
    ADI_OV7X48_CMD_SET_HSYNCRDELAY,             // Sets rising edge delay
    ADI_OV7X48_CMD_GET_HSYNCRDELAY,
    ADI_OV7X48_CMD_SET_HSYNCFDELAY,             // Sets falling edge delay
    ADI_OV7X48_CMD_GET_HSYNCFDELAY
};


enum {
    ADI_OV7X48_EVENT_START=ADI_OV7x48_ENUMERATION_START // starting enumeration
};


enum {
    ADI_OV7X48_RESULT_START=ADI_OV7x48_ENUMERATION_START,   // starting enumeration

    ADI_OV7X48_RESULT_ALREADYSTOPPED,           // Trying to stop already stopped driver
    ADI_OV7X48_RESULT_INVALID_DEVICE,           // Device connected to TWI is not a OV7X48 sensor
    ADI_OV7X48_RESULT_PPI_CLOSED
};


// Default sensor TWI address
#define ADI_OV7X48_TWIADDR 0x21


// entry point to OV7X48 driver
extern ADI_DEV_PDD_ENTRY_POINT ADIOV7X48EntryPoint;

/*****************************************************************************/



/******************************************************************************

OV7X48 Registers

******************************************************************************/


/********************************************************************

Macros

Description: Macros to create register values

********************************************************************/

#define ADI_OV7X48_REGISTER(reg,dir,dflt) reg

#define ADI_OV7X48_FIELD(reg,field) \
    (field&1?0:field&2?1:field&4?2:field&8?3:field&16?4:field&32?5:field&64?6:7)
//  (0x20000,((reg<<8)&0xFF00)| \
//  (((field&128?8:field&64?7:field&32?6:field&16?5:field&8?4:field&4?3:field&2?2:1)-(field&1?0:field&2?:field&4?2:field&8?3:field&16?4:field&32?5:field&64?6:7))<<4)| \
//  (field&1?0:field&2?1:field&4?2:field&8?3:field&16?4:field&32?5:field&64?6:7))


/********************************************************************

OV7X48 registers

Note: not all registers are availiable for OV7148

Note:
    1=Read only
    2=Write only
    3=Read/Write

********************************************************************/

// Register name            Address    Dir  Default Description
#define ADI_OV7X48_GAIN     ADI_OV7X48_REGISTER(0x00,3,0x00)    // Gain control [0x00-0x3F]
#define ADI_OV7X48_BLUE     ADI_OV7X48_REGISTER(0x01,3,0x80)    // Blue channel gain, [0x00-0xFF]
#define ADI_OV7X48_RED      ADI_OV7X48_REGISTER(0x02,3,0x80)    // Red channel gain, [0x00-0xFF]
#define ADI_OV7X48_SAT      ADI_OV7X48_REGISTER(0x03,3,0x84)    // Image format - colour saturation [0x00-0xFF]
#define ADI_OV7X48_HUE      ADI_OV7X48_REGISTER(0x04,3,0x34)    // Image format - colour hue control [0x00-0xFF]
#define ADI_OV7X48_CWF      ADI_OV7X48_REGISTER(0x05,3,0x3E)    // AWB - Red/Blue pre-amplifier gain setting
#define ADI_OV7X48_BRT      ADI_OV7X48_REGISTER(0x06,3,0x80)    // ABC - Brigthness setting [0x00-0xFF]
#define ADI_OV7X48_PID      ADI_OV7X48_REGISTER(0x0A,1,0x76)    // Product ID number (read only)
#define ADI_OV7X48_VER      ADI_OV7X48_REGISTER(0x0B,1,0x48)    // Product version number (read only)
#define ADI_OV7X48_AECH     ADI_OV7X48_REGISTER(0x10,3,0x41)    // Exposure value
#define ADI_OV7X48_CLKRC    ADI_OV7X48_REGISTER(0x11,3,0x00)    // Internal clock settings
#define ADI_OV7X48_COMA     ADI_OV7X48_REGISTER(0x12,3,0x14)    // Common control A
#define ADI_OV7X48_COMB     ADI_OV7X48_REGISTER(0x13,3,0xA3)    // Common control B
#define ADI_OV7X48_COMC     ADI_OV7X48_REGISTER(0x14,3,0x04)    // Common control C
#define ADI_OV7X48_COMD     ADI_OV7X48_REGISTER(0x15,3,0x00)    // Common control D
#define ADI_OV7X48_HSTART   ADI_OV7X48_REGISTER(0x17,3,0x1A)    // Output format - Horizontal frame (HREF column) start
#define ADI_OV7X48_HSTOP    ADI_OV7X48_REGISTER(0x18,3,0xBA)    // Output format - Horizontal frame (HREF column) stop
#define ADI_OV7X48_VSTART   ADI_OV7X48_REGISTER(0x19,3,0x03)    // Output format - Vertical frame (Row) start
#define ADI_OV7X48_VSTOP    ADI_OV7X48_REGISTER(0x1A,3,0xF3)    // Output format - Vertical frame (Row) stop
#define ADI_OV7X48_PSHIFT   ADI_OV7X48_REGISTER(0x1B,3,0x00)    // Data format - Pixel delay select (0x00=no delay, 0xFF=256 pixel delay)
#define ADI_OV7X48_MIDH     ADI_OV7X48_REGISTER(0x1C,1,0x7F)    // Manufacturer ID byte - High
#define ADI_OV7X48_MIDL     ADI_OV7X48_REGISTER(0x1D,1,0xA2)    // Manufacturer ID byte - Low
#define ADI_OV7X48_FACT     ADI_OV7X48_REGISTER(0x1F,3,0x01)    // Output format - Format control
#define ADI_OV7X48_COME     ADI_OV7X48_REGISTER(0x20,3,0xC0)    // Common control E
#define ADI_OV7X48_AEW      ADI_OV7X48_REGISTER(0x24,3,0x10)    //  AGC/AEC - Stable operating region - upper limit
#define ADI_OV7X48_AEB      ADI_OV7X48_REGISTER(0x25,3,0x8A)    // AGC/AEC - Stable operating region - lower limit
#define ADI_OV7X48_COMF     ADI_OV7X48_REGISTER(0x26,3,0xA2)    // Common control F
#define ADI_OV7X48_COMG     ADI_OV7X48_REGISTER(0x27,3,0xE2)    // Common control G
#define ADI_OV7X48_COMH     ADI_OV7X48_REGISTER(0x28,3,0x20)    // Common control H
#define ADI_OV7X48_COMI     ADI_OV7X48_REGISTER(0x29,1,0x00)    // Common control I
#define ADI_OV7X48_FRARH    ADI_OV7X48_REGISTER(0x2A,3,0x00)    // Output format - Frame rate adjust high
#define ADI_OV7X48_FRARL    ADI_OV7X48_REGISTER(0x2B,3,0x00)    // Data format - Frame rate adjust setting LSB
#define ADI_OV7X48_COMJ     ADI_OV7X48_REGISTER(0x2D,3,0x81)    // Common control J
#define ADI_OV7X48_SPCB     ADI_OV7X48_REGISTER(0x60,3,0x06)    // Signal process contral B
#define ADI_OV7X48_RMCO     ADI_OV7X48_REGISTER(0x6C,3,0x11)    // Colour matrix - RGB crosstalk compensation - R channel
#define ADI_OV7X48_GMCO     ADI_OV7X48_REGISTER(0x6D,3,0x01)    // Colour matrix - RGB crosstalk compensation - G channel
#define ADI_OV7X48_BMCO     ADI_OV7X48_REGISTER(0x6E,3,0x06)    // Colour matrix - RGB crosstalk compensation - B channel
#define ADI_OV7X48_COMK     ADI_OV7X48_REGISTER(0x70,3,0x01)    // Common control K
#define ADI_OV7X48_COML     ADI_OV7X48_REGISTER(0x71,3,0x00)    // Common control L
#define ADI_OV7X48_HSDYR    ADI_OV7X48_REGISTER(0x72,3,0x10)    // Data format - HSYNC rising edge delay LSB
#define ADI_OV7X48_HSDYF    ADI_OV7X48_REGISTER(0x73,3,0x50)    // Data format - HSYNC falling edge delay LSB
#define ADI_OV7X48_COMM     ADI_OV7X48_REGISTER(0x74,3,0x20)    // Common control M
#define ADI_OV7X48_COMN     ADI_OV7X48_REGISTER(0x75,3,0x02)    // Common control N
#define ADI_OV7X48_COMO     ADI_OV7X48_REGISTER(0x76,3,0x00)    // Common control O
#define ADI_OV7X48_AVGY     ADI_OV7X48_REGISTER(0x7E,3,0x00)    // AEC - Digital Y/G channel average
#define ADI_OV7X48_AVGR     ADI_OV7X48_REGISTER(0x7F,3,0x00)    // AEC - Digital R/V channel average
#define ADI_OV7X48_AVGB     ADI_OV7X48_REGISTER(0x80,3,0x00)    // AEC - Digital B/U channel average

/*******************************************************************/


/********************************************************************

OV7X48 register fields

********************************************************************/

/* GAIN Register ****************************************************/

#define ADI_OV7X48_GAINVALUE        ADI_OV7X48_FIELD(ADI_OV7X48_GAIN,0x3F)  // Gain setting


/* SAT Register ****************************************************/

#define ADI_OV7X48_SATVALUE         ADI_OV7X48_FIELD(ADI_OV7X48_SAT,0xF0)   // Saturation value


/* HUE Register ****************************************************/

#define ADI_OV7X48_HUEVALUE         ADI_OV7X48_FIELD(ADI_OV7X48_HUE,0x1F)   // Hue - Value
#define ADI_OV7X48_HUEENABLE        ADI_OV7X48_FIELD(ADI_OV7X48_HUE,0x20)   // Hue - Enable


/* CWF Register ****************************************************/

#define ADI_OV7X48_BLUEGAIN         ADI_OV7X48_FIELD(ADI_OV7X48_CWF,0x0F)   // blue channel pre-amplifier gain setting
#define ADI_OV7X48_REDGAIN          ADI_OV7X48_FIELD(ADI_OV7X48_CWF,0xF0)   // red channel pre-amplifier gain setting


/* CLKRC Register **************************************************/

#define ADI_OV7X48_CLKPRESCALAR     ADI_OV7X48_FIELD(ADI_OV7X48_CLKRC,0x3F) // Internal clock pre-scalar [0x00-0x3F]
#define ADI_OV7X48_SYNCPOLARITY     ADI_OV7X48_FIELD(ADI_OV7X48_CLKRC,0xC0) // Data format - HSYNC/VSYNC polarity
                                                                            // 00: HSYNC - Neg      VSYNC - Pos
                                                                            // 01: HSYNC - Neg      VSYNC - Neg
                                                                            // 10: HSYNC - Pos      VSYNC - Pos
                                                                            // 11: HSYNC - Neg      VSYNC - Pos


/* COMA Register ***************************************************/

#define ADI_OV7X48_AWBENABLE        ADI_OV7X48_FIELD(ADI_OV7X48_COMA,0x04)  // AWB - Enable
#define ADI_OV7X48_OUTPUTCHANNEL    ADI_OV7X48_FIELD(ADI_OV7X48_COMA,0x08)  // Output format - Output channel select A
#define ADI_OV7X48_YUVFORMAT        ADI_OV7X48_FIELD(ADI_OV7X48_COMA,0x10)  // YUV format
                                                                            // (When register COMD[0]=0)
                                                                            // 0: Y U Y V Y U Y V
                                                                            // 1: U Y V Y U Y V Y
                                                                            // (When register COMD[0]=1)
                                                                            // 0: Y V Y U Y V Y U
                                                                            // 1: V Y U Y V Y U Y
#define ADI_OV7X48_MIRRORIMAGE      ADI_OV7X48_FIELD(ADI_OV7X48_COMA,0x40)  // Output format - Mirror image enable
#define ADI_OV7X48_SCCBRESET        ADI_OV7X48_FIELD(ADI_OV7X48_COMA,0x80)  // SCCB - Register reset
                                                                            // 0: No change
                                                                            // 1: Reset all registers to default values


/* COMB Register ***************************************************/

#define ADI_OV7X48_AECENABLE        ADI_OV7X48_FIELD(ADI_OV7X48_COMB,0x01)  // AEC - Enable
#define ADI_OV7X48_AGCENABLE        ADI_OV7X48_FIELD(ADI_OV7X48_COMB,0x02)  // AGC - Enable
#define ADI_OV7X48_SCCBTRISTATE     ADI_OV7X48_FIELD(ADI_OV7X48_COMB,0x04)  // SCCB - Tri-state enable - Y[0:7]
#define ADI_OV7X48_ITUFORMAT        ADI_OV7X48_FIELD(ADI_OV7X48_COMB,0x10)  // Data format - ITU-656 Format enable
                                                                            // 0: YUV/YCbCr 4:2:2
                                                                            // 1: ITU-656 format enable


/* COMC Register ***************************************************/

#define ADI_OV7X48_HREFPOLARITY     ADI_OV7X48_FIELD(ADI_OV7X48_COMC,0x08)  // Data format - HREF polarity
                                                                            // 0: HREF Positive
                                                                            // 1: HREF Negative
#define ADI_OV7X48_RESOLUTION       ADI_OV7X48_FIELD(ADI_OV7X48_COMC,0x20)  // Output format - Resolution
                                                                            // 0: VGA (640x480)
                                                                            // 1: QVGA (320x240)


/* COMD Register ***************************************************/

#define ADI_OV7X48_BYTESWAP         ADI_OV7X48_FIELD(ADI_OV7X48_COMD,0x01)  // Data format - UV Sequence exchange
#define ADI_OV7X48_PCLKEDGE         ADI_OV7X48_FIELD(ADI_OV7X48_COMD,0x40)  // Data format - Y[7;0] - PCLK reference edge
                                                                            // 0: Y[7:0] data on PCLK falling edge
                                                                            // 1: Y[y:0] data out on PCLK rising edge
#define ADI_OV7X48_OFBD             ADI_OV7X48_FIELD(ADI_OV7X48_COMD,0x80)  // Data format - Output flag bit disable
                                                                            // 0: Frame = 254 data bits (00/FF = reserved flag bits)
                                                                            // 1: Frame = 256 data bits


/* FACT Register ***************************************************/

#define ADI_OV7X48_RGBFORMAT        ADI_OV7X48_FIELD(ADI_OV7X48_FACT,0x04)  // RGB:565/555 mode select
                                                                            // 0: RGB:565 output format
                                                                            // 1: RGB:555 output format
#define ADI_OV7X48_RGBFORMATENABLE  ADI_OV7X48_FIELD(ADI_OV7X48_FACT,0x10)  // RGB:565/555 enable control
                                                                            // 0: Disable
                                                                            // 1: Enable

/* COME Register ***************************************************/

#define ADI_OV7X48_COME_2XE         ADI_OV7X48_FIELD(ADI_OV7X48_COME,0x01)  // Y[7:0] 2x Iol/Ioh enable
#define ADI_OV7X48_EDGEENHANCE      ADI_OV7X48_FIELD(ADI_OV7X48_COME,0x10)  // Image Quality - Edge enhancement enable
#define ADI_OV7X48_AECDIGAVERAGE    ADI_OV7X48_FIELD(ADI_OV7X48_COME,0x40)  // AEC - Digital averaging enable


/* COMF Register ***************************************************/

#define ADI_OV7X48_SWAPENABLE       ADI_OV7X48_FIELD(ADI_OV7X48_COMF,0x04)  // Data format - Output data MSB/LSB swap enable


/* COMG Register ***************************************************/

#define ADI_OV7X48_OUTPUTRANGE      ADI_OV7X48_FIELD(ADI_OV7X48_COMG,0x02)  // Data format - Output full range enable
                                                                            // 0: Output range = [10] to [F0] (224 bits)
                                                                            // 1: Output range = [01] to [FE] (254/256 bits)
#define ADI_OV7X48_RGBCCD           ADI_OV7X48_FIELD(ADI_OV7X48_COMG,0x10)  // Colour matrix - RGB crosstalk compensation disable
                                                                            // (Used to increase each colour filter's effiency)

/* COMH Register ***************************************************/

#define ADI_OV7X48_SCANSELECT       ADI_OV7X48_FIELD(ADI_OV7X48_COMH,0x20)  // Output format - Scan select
                                                                            // 0: Interlaced
                                                                            // 1: Progressive
#define ADI_OV7X48_DEVICESELECT     ADI_OV7X48_FIELD(ADI_OV7X48_COMH,0x40)  // Device select
                                                                            // 0: OV7X48
                                                                            // 1: OV7148
#define ADI_OV7X48_RGBMODE          ADI_OV7X48_FIELD(ADI_OV7X48_COMH,0x80)  // Output format - RGB output select
                                                                            // 0: RGB
                                                                            // 1: Raw RGB
/* COMI Register ***************************************************/

#define ADI_OV7X48_DEVICEVERSION    ADI_OV7X48_FIELD(ADI_OV7X48_COMI,0x03)  // Device version (read-only)


/* FRARH Register **************************************************/

#define ADI_OV7X48_2PIXELDELAY      ADI_OV7X48_FIELD(ADI_OV7X48_FRARH,0x10) // A/D - UV channel '2 pixel delay' enable
#define ADI_OV7X48_FRAMERATEMSB     ADI_OV7X48_FIELD(ADI_OV7X48_FRARH,0x60) // Data format - Frame rate adjust setting MSB
                                                                            // FRA[9:0]=MSB + LSB=FRARH[6:5] +FRARL[7:0]
#define ADI_OV7X48_FRAMERATEEN      ADI_OV7X48_FIELD(ADI_OV7X48_FRARH,0x80) // Data format - Frame rate adjust enable


/* COMJ Register ***************************************************/

#define ADI_OV7X48_BANDFILTER       ADI_OV7X48_FIELD(ADI_OV7X48_COMJ,0x04)  // AEC - Band filter enable


/* SPCB Register ***************************************************/

#define ADI_OV7X48_PREAMPMULT       ADI_OV7X48_FIELD(ADI_OV7X48_SPCB,0x80)  // AEC - 1.5x multiplier (pre-amplifier) enable


/* COMK Register ***************************************************/

#define ADI_OV7X48_COMK_2XE         ADI_OV7X48_FIELD(ADI_OV7X48_COMK,0x40)  // Y[7:0] 2X Iol / Ioh enable


/* COML Register ***************************************************/

#define ADI_OV7X48_HSDYFMSB         ADI_OV7X48_FIELD(ADI_OV7X48_COML,0x03)  // Data format - HSYNC falling edge delay MSB
#define ADI_OV7X48_HSDYRMSB         ADI_OV7X48_FIELD(ADI_OV7X48_COML,0x0C)  // Data format - HSYNC rising edge delay MSB
#define ADI_OV7X48_HSYNCHREF        ADI_OV7X48_FIELD(ADI_OV7X48_COML,0x20)  // Data format - Output to HSYNC on HREF pin enable
#define ADI_OV7X48_PCLKHREF         ADI_OV7X48_FIELD(ADI_OV7X48_COML,0x40)  // Data format - PCLK output gated by HREF enable


/* COMM Register ***************************************************/

#define ADI_OV7X48_MAXGAINSELECT    ADI_OV7X48_FIELD(ADI_OV7X48_COMM,0x60)  // AGC - Maximum gain select


/* COMN Register ***************************************************/

#define ADI_OV7X48_VERTICALFLIP     ADI_OV7X48_FIELD(ADI_OV7X48_COMN,0x80)  // Output format - Vertical flip enable


/* COMO Register ***************************************************/

#define ADI_OV7X48_STANDBYMODE      ADI_OV7X48_FIELD(ADI_OV7X48_COMO,0x20)  // Standby mode enabled


/*****************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif
