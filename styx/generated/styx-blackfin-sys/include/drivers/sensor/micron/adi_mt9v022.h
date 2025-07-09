/******************************************************************************

Copyright (c) 2005 Analog Devices.  All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.
*******************************************************************************

$File: adi_MT9V022.h $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Project:    MT9V022 Micron Inaging sensor device driver
Title:      MT9V022 definitions
Author(s):  BJ

Description:
    This is the primary include file for the MT9V022 Micron Imaging sensor driver..

References:
    MT9V022 device driver documentation.pdf
    MT9V022.pdf
    MT9V022_(mi-0350)_flyer.pdf

Note:
    MT9V022 - Color CMOS VGA 640x480 sensor.
    MT9V022 - Black and white CMOS VGA 640x480 sensor.

*******************************************************************************

Modification History:
====================
Revision 1.00
    Created driver
Revision 1.01 - BJ - 22/1/2006
    Fixed PPI auto configuration
Revision 1.03 - BJ - 22/1/2006
    Fixed height and width command when binning is turned on

******************************************************************************/

#ifndef __ADI_MT9V022_H__
#define __ADI_MT9V022_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*****************************************************************************/


enum {
    ADI_MT9V022_CMD_START=ADI_MT9V022_ENUMERATION_START,    //  starting enumeration

    // twi configuration commands
    ADI_MT9V022_CMD_SET_TWI,                        // Set the TWI device number
    ADI_MT9V022_CMD_SET_TWIADDR,                    // Set the sensors TWI address
    ADI_MT9V022_CMD_SET_TWICONFIG,                  // Set the TWI command list

    // ppi configuration commands
    ADI_MT9V022_CMD_SET_PPI,                        // Set the PPI hardware number
    ADI_MT9V022_CMD_SET_PPICONFIG,                  // Manually config the PPI
    ADI_MT9V022_CMD_SET_PPICMD,                     // Pass commands directly to PPI device

    // General MT9V022 config controls
    ADI_MT9V022_CMD_GET_HWID,                       // Get the hardware ID
    ADI_MT9V022_CMD_GET_HEIGHT,                     // Get the height
    ADI_MT9V022_CMD_GET_WIDTH                       // Get the width

    // access commands to fields that cross 2 registers
};


enum {
    ADI_MT9V022_EVENT_START=ADI_MT9V022_ENUMERATION_START   // starting enumeration
};


enum {
    ADI_MT9V022_RESULT_START=ADI_MT9V022_ENUMERATION_START, // starting enumeration

    ADI_MT9V022_RESULT_ALREADYSTOPPED,              // Trying to stop already stopped driver
    ADI_MT9V022_RESULT_PPI_CLOSED
};


// Default sensor TWI address
//  S_CTRL_ADR0=addr bit3 (0x04)
//  S_CTRL_ADR1=addr bit5 (0x10)
#define ADI_MT9V022_TWIADDR1 0x48
#define ADI_MT9V022_TWIADDR2 0x4C
#define ADI_MT9V022_TWIADDR3 0x58
#define ADI_MT9V022_TWIADDR4 0x5C

#define ADI_MT9V022_TWIADDR ADI_MT9V022_TWIADDR4

// entry point to OV7X48 driver
extern ADI_DEV_PDD_ENTRY_POINT ADIMT9V022EntryPoint;

/*****************************************************************************/



/******************************************************************************

MT9V022 Registers

******************************************************************************/


/********************************************************************

Macros

Description: Macros to create register values

********************************************************************/

#define ADI_MT9V022_REGISTER(reg,dir,dflt) reg

#define ADI_MT9V022_FIELD(reg,field) \
    (field&1?0:field&2?1:field&4?2:field&8?3:field&16?4:field&32?5:field&64?6:field&128?7: \
    field&256?8:field&512?9:field&1024?10:field&2048?11:field&4096?12:field&8192?13:field&16384?14:15)


/********************************************************************

MT9V022 registers

Note:
    1=Read only
    2=Write only
    3=Read/Write

********************************************************************/

// Register name                        Address                             Description
#define ADI_MT9V022_CHIPVERSION         ADI_MT9V022_REGISTER(0x00,1,0x1311) //  Chip version
#define ADI_MT9V022_COLUMNSTART         ADI_MT9V022_REGISTER(0x01,3,0x0001) //  Column start
#define ADI_MT9V022_ROWSTART            ADI_MT9V022_REGISTER(0x02,3,0x0004) //  0x0004  Row start
#define ADI_MT9V022_WINDOWHEIGHT        ADI_MT9V022_REGISTER(0x03,3,0x01E0) //  Window height
#define ADI_MT9V022_WINDOWWIDTH         ADI_MT9V022_REGISTER(0x04,3,0x02F0) //  Window width
#define ADI_MT9V022_HBLANK              ADI_MT9V022_REGISTER(0x05,3,0x005E) //  Horizontal blanking
#define ADI_MT9V022_VBLANK              ADI_MT9V022_REGISTER(0x06,3,0x002D) //  Vertical blanking
#define ADI_MT9V022_CHIPCONTROL         ADI_MT9V022_REGISTER(0x07,3,0x0388) //  Chip control
#define ADI_MT9V022_SHUTTER1            ADI_MT9V022_REGISTER(0x08,3,0x01BB) //  Shutter width 1
#define ADI_MT9V022_SHUTTER2            ADI_MT9V022_REGISTER(0x09,3,0x01D9) //  Shutter width 2
#define ADI_MT9V022_SHUTTERCTRL         ADI_MT9V022_REGISTER(0x0A,3,0x0164) //  Shutter width control
#define ADI_MT9V022_SHUTTERTOTAL        ADI_MT9V022_REGISTER(0x0B,3,0x01E0) //  Total shutter width
#define ADI_MT9V022_RESET               ADI_MT9V022_REGISTER(0x0C,3,0x0000) //  Reset
#define ADI_MT9V022_READMODE            ADI_MT9V022_REGISTER(0x0D,3,0x0300) //  Read mode
#define ADI_MT9V022_MONITORMODE         ADI_MT9V022_REGISTER(0x0E,3,0x0000) //  Monitor mode
#define ADI_MT9V022_PIXELMODE           ADI_MT9V022_REGISTER(0x0F,3,0x0011) //  Pixel operation mode
#define ADI_MT9V022_LEDOUTCTRL          ADI_MT9V022_REGISTER(0x1B,3,0x0000) //  LED_OUT control
#define ADI_MT9V022_ADCMODECTRL         ADI_MT9V022_REGISTER(0x1C,3,0x0002) //  ADC mode control
#define ADI_MT9V022_VREFADCCTRL         ADI_MT9V022_REGISTER(0x2C,3,0x0004) //  Vref ADC control
#define ADI_MT9V022_V1                  ADI_MT9V022_REGISTER(0x31,3,0x001D) //
#define ADI_MT9V022_V2                  ADI_MT9V022_REGISTER(0x32,3,0x001B) //
#define ADI_MT9V022_V3                  ADI_MT9V022_REGISTER(0x33,3,0x0015) //
#define ADI_MT9V022_V4                  ADI_MT9V022_REGISTER(0x34,3,0x0004) //
#define ADI_MT9V022_ANALOGGAIN          ADI_MT9V022_REGISTER(0x35,3,0x0010) //  Analog gain
#define ADI_MT9V022_ANALOGGAINMAX       ADI_MT9V022_REGISTER(0x36,3,0x0040) //  Maximum analog gain
#define ADI_MT9V022_DARKAVERAGE         ADI_MT9V022_REGISTER(0x42,1,0x0000) //  Darkness average
#define ADI_MT9V022_DARKAVGTHRESHOLD    ADI_MT9V022_REGISTER(0x46,3,0x231D) //  Darkness average threshold
#define ADI_MT9V022_BLCALIBCTRL         ADI_MT9V022_REGISTER(0x47,3,0x8080) //  Black level calibration control
#define ADI_MT9V022_BLCALIBVALUE        ADI_MT9V022_REGISTER(0x48,3,0x0000) //  Black level calibration value
#define ADI_MT9V022_BICALIBSTEP         ADI_MT9V022_REGISTER(0x4C,3,0x0002) //  Black level calibration step size
#define ADI_MT9V022_ROWNOISECORRCTRL1   ADI_MT9V022_REGISTER(0x70,3,0x0034) //  Row noise correction control 1
#define ADI_MT9V022_ROWNOISECONSTANT    ADI_MT9V022_REGISTER(0x72,3,0x002A) //  Row noise constant
#define ADI_MT9V022_ROWNOISECORRCTRL2   ADI_MT9V022_REGISTER(0x73,3,0x02F7) //  Row noise correction control 2
#define ADI_MT9V022_PIXELCLK            ADI_MT9V022_REGISTER(0x74,3,0x0000) //  Pixel clock (FV and LV)
#define ADI_MT9V022_TESTPATTERN         ADI_MT9V022_REGISTER(0x7F,3,0x0000) //  Digital test pattern
#define ADI_MT9V022_TILEX0Y0            ADI_MT9V022_REGISTER(0x80,3,0x00F4) //  Tile weight/gain
#define ADI_MT9V022_TILEX1Y0            ADI_MT9V022_REGISTER(0x81,3,0x00F4) //
#define ADI_MT9V022_TILEX2Y0            ADI_MT9V022_REGISTER(0x82,3,0x00F4) //
#define ADI_MT9V022_TILEX3Y0            ADI_MT9V022_REGISTER(0x83,3,0x00F4) //
#define ADI_MT9V022_TILEX4Y0            ADI_MT9V022_REGISTER(0x84,3,0x00F4) //
#define ADI_MT9V022_TILEX0Y1            ADI_MT9V022_REGISTER(0x85,3,0x00F4) //
#define ADI_MT9V022_TILEX1Y1            ADI_MT9V022_REGISTER(0x86,3,0x00F4) //
#define ADI_MT9V022_TILEX2Y1            ADI_MT9V022_REGISTER(0x87,3,0x00F4) //
#define ADI_MT9V022_TILEX3Y1            ADI_MT9V022_REGISTER(0x88,3,0x00F4) //
#define ADI_MT9V022_TILEX4Y1            ADI_MT9V022_REGISTER(0x89,3,0x00F4) //
#define ADI_MT9V022_TILEX0Y2            ADI_MT9V022_REGISTER(0x8A,3,0x00F4) //
#define ADI_MT9V022_TILEX1Y2            ADI_MT9V022_REGISTER(0x8B,3,0x00F4) //
#define ADI_MT9V022_TILEX2Y2            ADI_MT9V022_REGISTER(0x8C,3,0x00F4) //
#define ADI_MT9V022_TILEX3Y2            ADI_MT9V022_REGISTER(0x8D,3,0x00F4) //
#define ADI_MT9V022_TILEX4Y2            ADI_MT9V022_REGISTER(0x8E,3,0x00F4) //
#define ADI_MT9V022_TILEX0Y3            ADI_MT9V022_REGISTER(0x8F,3,0x00F4) //
#define ADI_MT9V022_TILEX1Y3            ADI_MT9V022_REGISTER(0x90,3,0x00F4) //
#define ADI_MT9V022_TILEX2Y3            ADI_MT9V022_REGISTER(0x91,3,0x00F4) //
#define ADI_MT9V022_TILEX3Y3            ADI_MT9V022_REGISTER(0x92,3,0x00F4) //
#define ADI_MT9V022_TILEX4Y3            ADI_MT9V022_REGISTER(0x93,3,0x00F4) //
#define ADI_MT9V022_TILEX0Y4            ADI_MT9V022_REGISTER(0x94,3,0x00F4) //
#define ADI_MT9V022_TILEX1Y4            ADI_MT9V022_REGISTER(0x95,3,0x00F4) //
#define ADI_MT9V022_TILEX2Y4            ADI_MT9V022_REGISTER(0x96,3,0x00F4) //
#define ADI_MT9V022_TILEX3Y4            ADI_MT9V022_REGISTER(0x97,3,0x00F4) //
#define ADI_MT9V022_TILEX4Y4            ADI_MT9V022_REGISTER(0x98,3,0x00F4) //
#define ADI_MT9V022_TILECOORDX0         ADI_MT9V022_REGISTER(0x99,3,0x0000) //  Tile co-ordinate X 0/5
#define ADI_MT9V022_TILECOORDX1         ADI_MT9V022_REGISTER(0x9A,3,0x0096) //  " 1/5
#define ADI_MT9V022_TILECOORDX2         ADI_MT9V022_REGISTER(0x9B,3,0x012C) //  " 2/5
#define ADI_MT9V022_TILECOORDX3         ADI_MT9V022_REGISTER(0x9C,3,0x01C2) //  " 3/5
#define ADI_MT9V022_TILECOORDX4         ADI_MT9V022_REGISTER(0x9D,3,0x0258) //  " 4/5
#define ADI_MT9V022_TILECOORDX5         ADI_MT9V022_REGISTER(0x9E,3,0x02F0) //  " 5/5
#define ADI_MT9V022_TILECOORDY0         ADI_MT9V022_REGISTER(0x9F,3,0x0000) //  Tile co-ordinate Y 0/5
#define ADI_MT9V022_TILECOORDY1         ADI_MT9V022_REGISTER(0xA0,3,0x0060) //  " 1/5
#define ADI_MT9V022_TILECOORDY2         ADI_MT9V022_REGISTER(0xA1,3,0x00C0) //  " 2/5
#define ADI_MT9V022_TILECOORDY3         ADI_MT9V022_REGISTER(0xA2,3,0x0120) //  " 3/5
#define ADI_MT9V022_TILECOORDY4         ADI_MT9V022_REGISTER(0xA3,3,0x0180) //  " 4/5
#define ADI_MT9V022_TILECOORDY5         ADI_MT9V022_REGISTER(0xA4,3,0x01E0) //  " 5/5
#define ADI_MT9V022_AECAGCDESIREDBIN    ADI_MT9V022_REGISTER(0xA5,3,0x003A) //  AEC/AGC desired bin
#define ADI_MT9V022_AECUPDATEFREQ       ADI_MT9V022_REGISTER(0xA6,3,0x0002) //  AEC update frequency
#define ADI_MT9V022_AECLPF              ADI_MT9V022_REGISTER(0xA8,3,0x0000) //  AEC low pass filter
#define ADI_MT9V022_AGCUPDATEFREQ       ADI_MT9V022_REGISTER(0xA9,3,0x0002) //  AGC update frequency
#define ADI_MT9V022_AGCLPF              ADI_MT9V022_REGISTER(0xAB,3,0x0002) //  AGC low pass filter
#define ADI_MT9V022_AECAGCENABLE        ADI_MT9V022_REGISTER(0xAF,3,0x0003) //  AEC/AGC enable
#define ADI_MT9V022_AECAGCPIXELCOUNT    ADI_MT9V022_REGISTER(0xB0,3,0xABE0) //  AEC/AGC pixel count
#define ADI_MT9V022_LVDSMASTERCTRL      ADI_MT9V022_REGISTER(0xB1,3,0x0002) //  LVDS master control
#define ADI_MT9V022_LVDSSHIFTCLKCTRL    ADI_MT9V022_REGISTER(0xB2,3,0x0010) //  LVDS shift clock control
#define ADI_MT9V022_LVDSDATACTRL        ADI_MT9V022_REGISTER(0xB3,3,0x0010) //  LVDS data control
#define ADI_MT9V022_LVDSLATENCY         ADI_MT9V022_REGISTER(0xB4,3,0x0000) //  LVDS latency control
#define ADI_MT9V022_LVDSINTERNALSYNC    ADI_MT9V022_REGISTER(0xB5,3,0x0000) //  LVDS internal sync
#define ADI_MT9V022_LVDSPAYLOADCTRL     ADI_MT9V022_REGISTER(0xB6,3,0x0000) //  LVDS payload control
#define ADI_MT9V022_STEREOERRORCTRL     ADI_MT9V022_REGISTER(0xB7,3,0x0000) //  Stereoscope error control
#define ADI_MT9V022_STEREOERRORFLAG     ADI_MT9V022_REGISTER(0xB8,1,0x0000) //  Stereoscope error flag
#define ADI_MT9V022_LVDSDATAOUTPUT      ADI_MT9V022_REGISTER(0xB9,1,0x0000) //  LVDS data output
#define ADI_MT9V022_AGCGAINOUTPUT       ADI_MT9V022_REGISTER(0xBA,1,0x0000) //  AGC gain output
#define ADI_MT9V022_AECGAINOUTPUT       ADI_MT9V022_REGISTER(0xBB,1,0x0000) //  AEC gain output
#define ADI_MT9V022_AECAGCCURRENTBIN    ADI_MT9V022_REGISTER(0xBC,1,0x0000) //  AEC/AGC current bin
#define ADI_MT9V022_SHUTTERMAX          ADI_MT9V022_REGISTER(0xBD,3,0x01E0) //  Maximum shutter width
#define ADI_MT9V022_AECAGCDIFFBIN       ADI_MT9V022_REGISTER(0xBE,3,0x0014) //  AEC/AGC bin difference threshold
#define ADI_MT9V022_FIELDBLANK          ADI_MT9V022_REGISTER(0xBF,3,0x0016) //  Field blank
#define ADI_MT9V022_CAPTURECTRL         ADI_MT9V022_REGISTER(0xC0,3,0x000A) //  Monitor mode capture control
#define ADI_MT9V022_TEMPERATURE         ADI_MT9V022_REGISTER(0xC1,1,0x0000) //  Temperature
#define ADI_MT9V022_ANALOGCTRL          ADI_MT9V022_REGISTER(0xC2,3,0x1840) //  Analog control
#define ADI_MT9V022_NTSCCTRL            ADI_MT9V022_REGISTER(0xC3,3,0x3840) //  NTSC FV & LV control
#define ADI_MT9V022_NTSCHBLANKCTRL      ADI_MT9V022_REGISTER(0xC4,3,0x4416) //  NTSC horizontal blanking control
#define ADI_MT9V022_NTSCVBLANKCTRL      ADI_MT9V022_REGISTER(0xC5,3,0x4421) //  NTSC vertical blanking control
#define ADI_MT9V022_REGISTERLOCK        ADI_MT9V022_REGISTER(0xFE,3,0xBEEF) //  Register lock
                                                                            //      DEAD=lock all registers
                                                                            //      DEAF=lock READMODE(0x0D) register


/*******************************************************************/


/********************************************************************

MT9V022 register fields

********************************************************************/


/* CHIPCONTROL Register ********************************************/

#define ADI_MT9V022_CHIPCONTROLSCAN             ADI_MT9V022_FIELD(ADI_MT9V022_CHIPCONTROL,0x0007)       // Scan mode
#define ADI_MT9V022_CHIPCONTROLMASTERSLAVE      ADI_MT9V022_FIELD(ADI_MT9V022_CHIPCONTROL,0x0008)       // Sensor master/slave mode
#define ADI_MT9V022_CHIPCONTROLSNAPSHOT         ADI_MT9V022_FIELD(ADI_MT9V022_CHIPCONTROL,0x0010)       // Sensor snapshot mode
#define ADI_MT9V022_CHIPCONTROLSTEREO           ADI_MT9V022_FIELD(ADI_MT9V022_CHIPCONTROL,0x0020)       // Stereoscopy mode
#define ADI_MT9V022_CHIPCONTROLSTEREOMASTER     ADI_MT9V022_FIELD(ADI_MT9V022_CHIPCONTROL,0x0040)       // Stereoscopic master/slave mode
#define ADI_MT9V022_CHIPCONTROLPARALLEL         ADI_MT9V022_FIELD(ADI_MT9V022_CHIPCONTROL,0x0080)       // Parallel output enable
#define ADI_MT9V022_CHIPCONTROLSEQUENTIAL       ADI_MT9V022_FIELD(ADI_MT9V022_CHIPCONTROL,0x0100)       // Simultaneous/sequential mode
#define ADI_MT9V022_CHIPCONTROLPIXELCORR        ADI_MT9V022_FIELD(ADI_MT9V022_CHIPCONTROL,0x0200)       // Defect pixel correction enable


/* SHUTTERCTRL Register ********************************************/

#define ADI_MT9V022_SHUTTERCTRLT2RATIO          ADI_MT9V022_FIELD(ADI_MT9V022_SHUTTERCTRL,0x000F)       // T2 exposure
#define ADI_MT9V022_SHUTTERCTRLT3RATIO          ADI_MT9V022_FIELD(ADI_MT9V022_SHUTTERCTRL,0x00F0)       // T3 exposure
#define ADI_MT9V022_SHUTTERCTRLEXPOSURE         ADI_MT9V022_FIELD(ADI_MT9V022_SHUTTERCTRL,0x0100)       // Exposure knee point auto adjust enable
#define ADI_MT9V022_SHUTTERCTRLSINGLEKNEE       ADI_MT9V022_FIELD(ADI_MT9V022_SHUTTERCTRL,0x0200)       // Single knee enable


/* RESET Register **************************************************/

#define ADI_MT9V022_RESETSOFT                   ADI_MT9V022_FIELD(ADI_MT9V022_RESET,0x0001)             // Soft reset
#define ADI_MT9V022_RESETAUTOBLOCK              ADI_MT9V022_FIELD(ADI_MT9V022_RESET,0x0002)             // Auto block soft reset


/* READMODE Register ***********************************************/

#define ADI_MT9V022_READMODEROWBIN              ADI_MT9V022_FIELD(ADI_MT9V022_READMODE,0x0003)          // Row bin
#define ADI_MT9V022_READMODECOLBIN              ADI_MT9V022_FIELD(ADI_MT9V022_READMODE,0x000C)          // Column bin
#define ADI_MT9V022_READMODEROWFLIP             ADI_MT9V022_FIELD(ADI_MT9V022_READMODE,0x0010)          // Row flip
#define ADI_MT9V022_READMODECOLFLIP             ADI_MT9V022_FIELD(ADI_MT9V022_READMODE,0x0020)          // Column flip
#define ADI_MT9V022_READMODEROWDARK             ADI_MT9V022_FIELD(ADI_MT9V022_READMODE,0x0040)          // Show dark rows
#define ADI_MT9V022_READMODECOLDARK             ADI_MT9V022_FIELD(ADI_MT9V022_READMODE,0x0080)          // Show dark columns


/* PIXELMODE Register **********************************************/

#define ADI_MT9V022_PIXELMODECOLOUR             ADI_MT9V022_FIELD(ADI_MT9V022_PIXELMODE,0x0004)         // Colour/Mono
#define ADI_MT9V022_PIXELMODEDYNRANGE           ADI_MT9V022_FIELD(ADI_MT9V022_PIXELMODE,0x0040)         // High dynamic range
#define ADI_MT9V022_PIXELMODEEXTEXP             ADI_MT9V022_FIELD(ADI_MT9V022_PIXELMODE,0x0080)         // Enable extended exposure


/* LEDOUTCTRL Register *********************************************/

#define ADI_MT9V022_LEDOUTCTRLDISABLE           ADI_MT9V022_FIELD(ADI_MT9V022_LEDOUTCTRL,0x0001)        // Disable LED_OUT
#define ADI_MT9V022_LEDOUTCTRLINVERT            ADI_MT9V022_FIELD(ADI_MT9V022_LEDOUTCTRL,0x0002)        // Invert LED_OUT


/* BLCALIBCTRL Register ********************************************/

#define ADI_MT9V022_BLCALIBCTRLMANUAL           ADI_MT9V022_FIELD(ADI_MT9V022_BLCALIBCTRL,0x0001)       // Manual average
#define ADI_MT9V022_BLCALIBCTRLAVG              ADI_MT9V022_FIELD(ADI_MT9V022_BLCALIBCTRL,0x00E0)       // Frames to average over


/* ROWNOISECORRCTRL1 Register **************************************/

#define ADI_MT9V022_ROWNOISECORRCTRL1DARKPIX    ADI_MT9V022_FIELD(ADI_MT9V022_ROWNOISECORRCTRL1,0x000F) // Number of dark pixels
#define ADI_MT9V022_ROWNOISECORRCTRL1NOISE      ADI_MT9V022_FIELD(ADI_MT9V022_ROWNOISECORRCTRL1,0x0020) // Enable noise correction
#define ADI_MT9V022_ROWNOISECORRCTRL1BLAVG      ADI_MT9V022_FIELD(ADI_MT9V022_ROWNOISECORRCTRL1,0x0800) // Use black level average


/* PIXELCLK Register ***********************************************/

#define ADI_MT9V022_PIXELCLKINVERTLINE          ADI_MT9V022_FIELD(ADI_MT9V022_PIXELCLK,0x0001)          // Invert line valid
#define ADI_MT9V022_PIXELCLKINVERTFRAME         ADI_MT9V022_FIELD(ADI_MT9V022_PIXELCLK,0x0002)          // Invert frame valid
#define ADI_MT9V022_PIXELCLKXORLINE             ADI_MT9V022_FIELD(ADI_MT9V022_PIXELCLK,0x0004)          // Xor line valid
#define ADI_MT9V022_PIXELCLKCONTLINE            ADI_MT9V022_FIELD(ADI_MT9V022_PIXELCLK,0x0008)          // Continuous line valid
#define ADI_MT9V022_PIXELCLKINVERTPIXEL         ADI_MT9V022_FIELD(ADI_MT9V022_PIXELCLK,0x0010)          // Invert pixel clock


/* TESTPATTERN Register ********************************************/

#define ADI_MT9V022_TESTPATTERNTWIDATA          ADI_MT9V022_FIELD(ADI_MT9V022_TESTPATTERN,0x03FF)       // Two-wire serial interface test data
#define ADI_MT9V022_TESTPATTERNTWIENABLE        ADI_MT9V022_FIELD(ADI_MT9V022_TESTPATTERN,0x0400)       // Use two-wire serial interface test data
#define ADI_MT9V022_TESTPATTERNGREY             ADI_MT9V022_FIELD(ADI_MT9V022_LTESTPATTERN,0x1800)      // Grey shade test pattern
#define ADI_MT9V022_TESTPATTERNENABLE           ADI_MT9V022_FIELD(ADI_MT9V022_LTESTPATTERN,0x2000)      // Test enable
#define ADI_MT9V022_TESTPATTERNTWIFLIP          ADI_MT9V022_FIELD(ADI_MT9V022_LTESTPATTERN,0x4000)      // Flip two-wire serial interface test data


/* TILEX?Y? Registers **********************************************/

#define ADI_MT9V022_TILEGAIN                    ADI_MT9V022_FIELD(0,0x000F)                             // Tile gain
#define ADI_MT9V022_TILESAMPLE                  ADI_MT9V022_FIELD(0,0x00F0)                             // Sample weight


/* LVDSMASTERCTRL Register *****************************************/

#define ADI_MT9V022_LVDSMASTERCTRLPLL           ADI_MT9V022_FIELD(ADI_MT9V022_LVDSMASTERCTRL,0x0001)    // PLL bypass
#define ADI_MT9V022_LVDSMASTERCTRLPOWERDOWN     ADI_MT9V022_FIELD(ADI_MT9V022_LVDSMASTERCTRL,0x0002)    // LVDS power-down
#define ADI_MT9V022_LVDSMASTERCTRLPLLTEST       ADI_MT9V022_FIELD(ADI_MT9V022_LVDSMASTERCTRL,0x0004)    // PLL test mode
#define ADI_MT9V022_LVDSMASTERCTRLTEST          ADI_MT9V022_FIELD(ADI_MT9V022_LVDSMASTERCTRL,0x0008)    // LVDS test mode


/* LVDSSHIFTCLKCTRL Register ***************************************/

#define ADI_MT9V022_LVDSSHIFTCLKCTRLDELAY       ADI_MT9V022_FIELD(ADI_MT9V022_LVDSSHIFTCLKCTRL,0x0007)  // Shift clock delay element select
#define ADI_MT9V022_LVDSSHIFTCLKCTRLPOWERDOWN   ADI_MT9V022_FIELD(ADI_MT9V022_LVDSSHIFTCLKCTRL,0x0010)  // Shift clock(driver) power-down


/* LVDSDATACTRL Register *******************************************/

#define ADI_MT9V022_LVDSDATACTRLDELAY           ADI_MT9V022_FIELD(ADI_MT9V022_LVDSDATACTRL,0x0007)      // Data delay element select
#define ADI_MT9V022_LVDSDATACTRLPOWERDOWN       ADI_MT9V022_FIELD(ADI_MT9V022_LVDSDATACTRL,0x0010)      // Data(receiver) power-down


/* STEREOERRORCTRL Register ****************************************/

#define ADI_MT9V022_STEREOERRORCTRLERRORDETECT  ADI_MT9V022_FIELD(ADI_MT9V022_STEREOERRORCTRL,0x0001)   // Enable stereo error detect
#define ADI_MT9V022_STEREOERRORCTRLERRORSTICKY  ADI_MT9V022_FIELD(ADI_MT9V022_STEREOERRORCTRL,0x0002)   // Enable sticky stereo error flag
#define ADI_MT9V022_STEREOERRORCTRLERRORCLEAR   ADI_MT9V022_FIELD(ADI_MT9V022_STEREOERRORCTRL,0x0004)   // Clear stereo error flag


/* ANALOGCTRL Register *********************************************/

#define ADI_MT9V022_ANALOGCTRLANTIECLIPSE       ADI_MT9V022_FIELD(ADI_MT9V022_ANALOGCTRL,0x0080)        // Anti-eclipse enable
#define ADI_MT9V022_ANALOGCTRLREFVOLTAGE        ADI_MT9V022_FIELD(ADI_MT9V022_ANALOGCTRL,0x3800)        // V_RST_LIM voltage limit


/* NTSCCTRL Register ***********************************************/

#define ADI_MT9V022_NTSCCTRLEXTENDFRAME         ADI_MT9V022_FIELD(ADI_MT9V022_NTSCCTRL,0x0001)          // Extend frame valid
#define ADI_MT9V022_NTSCCTRLREPLACEFVLV         ADI_MT9V022_FIELD(ADI_MT9V022_NTSCCTRL,0x0002)          // Replace FV/LV with Ped/Sync


/* NTSCHBLANKCTRL Register *****************************************/

#define ADI_MT9V022_NTSCHBLANKCTRLPORCH         ADI_MT9V022_FIELD(ADI_MT9V022_NTSCHBLANKCTRL,0x00FF)    // Front porch width
#define ADI_MT9V022_NTSCHBLANKCTRLSYNC          ADI_MT9V022_FIELD(ADI_MT9V022_NTSCHBLANKCTRL,0xFF00)    // Sync width


/* NTSCVBLANKCTRL Register *****************************************/

#define ADI_MT9V022_NTSCVBLANKCTRLEQUALIZE      ADI_MT9V022_FIELD(ADI_MT9V022_NTSCVBLANKCTRL,0x00FF)    // Equalising pulse width
#define ADI_MT9V022_NTSCVBLANKCTRLSERRATION     ADI_MT9V022_FIELD(ADI_MT9V022_NTSCVBLANKCTRL,0xFF00)    // Vertical serration width


/*****************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif
