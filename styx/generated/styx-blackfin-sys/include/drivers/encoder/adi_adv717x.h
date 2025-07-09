/**********************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$File: adi_adv717x.c $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            This is the primary include file for the AD717x
            video encoder drivers.

***********************************************************************/

#ifndef __ADI_ADV717x_H__
#define __ADI_ADV717x_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/***********************************************************************

Entry points

***********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADIADV7170EntryPoint;  /* entry point to ADV7170 */
extern ADI_DEV_PDD_ENTRY_POINT ADIADV7171EntryPoint;  /* entry point to ADV7171 */
extern ADI_DEV_PDD_ENTRY_POINT ADIADV7174EntryPoint;  /* entry point to ADV7174 */
extern ADI_DEV_PDD_ENTRY_POINT ADIADV7179EntryPoint;  /* entry point to ADV7179 */

/**********************************************************************

Fixed enumerations and defines

***********************************************************************/

/* Samples per line for ITU-R 656 video */
#define     ADI_ADV71x_SAMPLES_PER_LINE_NTSC    1716
#define     ADI_ADV71x_SAMPLES_PER_LINE_PAL     1728

/* Lines Per Frame for ITU-R 656 video */
#define     ADI_ADV71x_LINES_PER_FRAME_NTSC     525
#define     ADI_ADV71x_LINES_PER_FRAME_PAL      625

/* Calculated Sub Carrier Frequency Register (SCFR) values */
#define     ADV717x_SCF_VALUE_NTSC      0x21F07C1E  /* SCFR for NTSC mode */
#define     ADV717x_SCF_VALUE_PAL_BI    0x2A098ACA  /* SCFR for PAL  mode */

/*****************************
ADV717x Register definitions
*****************************/

#define     ADV717x_MR0         0x00    // Mode Register 0
#define     ADV717x_MR1         0x01    // Mode Register 1
#define     ADV717x_MR2         0x02    // Mode Register 2
#define     ADV717x_MR3         0x03    // Mode Register 3
#define     ADV717x_MR4         0x04    // Mode Register 4
#define     ADV717x_TMR0        0x07    // Timing Mode Register 0
#define     ADV717x_TMR1        0x08    // Timing Mode Register 1
#define     ADV717x_SCFR0       0x09    // Subcarrier Frequency Register 0
#define     ADV717x_SCFR1       0x0A    // Subcarrier Frequency Register 1
#define     ADV717x_SCFR2       0x0B    // Subcarrier Frequency Register 2
#define     ADV717x_SCFR3       0x0C    // Subcarrier Frequency Register 3
#define     ADV717x_SCPR        0x0D    // Sub Carrier Phase Register
#define     ADV717x_CCED0       0x0E    // Closed Captioning Extended Data Byte 0
#define     ADV717x_CCED1       0x0F    // Closed Captioning Extended Data Byte 1
#define     ADV717x_CCD0        0x10    // Closed Captioning Data Byte 0
#define     ADV717x_CCD1        0x11    // Closed Captioning Data Byte 1
#define     ADV717x_PTCR0       0x12    // NTSC Pedestal Control Register 0 / PAL TTX Control Register 0
#define     ADV717x_PTCR1       0x13    // NTSC Pedestal Control Register 1 / PAL TTX Control Register 1
#define     ADV717x_PTCR2       0x14    // NTSC Pedestal Control Register 2 / PAL TTX Control Register 2
#define     ADV717x_PTCR3       0x15    // NTSC Pedestal Control Register 3 / PAL TTX Control Register 3
#define     ADV717x_CGMS_WSS0   0x16    // CGMS_WSS Register 0
#define     ADV717x_CGMS_WSS1   0x17    // CGMS_WSS Register 1
#define     ADV717x_CGMS_WSS2   0x18    // CGMS_WSS Register 2
#define     ADV717x_TTX_REQ     0x19    // Teletext request control register
#define     ADV717x_MVR01       0x1E    // Macrovision register 1
#define     ADV717x_MVR02       0x1F    // Macrovision register 2
#define     ADV717x_MVR03       0x20    // Macrovision register 3
#define     ADV717x_MVR04       0x21    // Macrovision register 4
#define     ADV717x_MVR05       0x22    // Macrovision register 5
#define     ADV717x_MVR06       0x23    // Macrovision register 6
#define     ADV717x_MVR07       0x24    // Macrovision register 7
#define     ADV717x_MVR08       0x25    // Macrovision register 8
#define     ADV717x_MVR09       0x26    // Macrovision register 9
#define     ADV717x_MVR10       0x27    // Macrovision register 10
#define     ADV717x_MVR11       0x28    // Macrovision register 11
#define     ADV717x_MVR12       0x29    // Macrovision register 12
#define     ADV717x_MVR13       0x2A    // Macrovision register 13
#define     ADV717x_MVR14       0x2B    // Macrovision register 14
#define     ADV717x_MVR15       0x2C    // Macrovision register 15
#define     ADV717x_MVR16       0x2D    // Macrovision register 16
#define     ADV717x_MVR17       0x2E    // Macrovision register 17
#define     ADV717x_MVR18       0x2F    // Macrovision register 18

/**********************************
ADV717x Register Field definitions
**********************************/

// Mode Register 0 field definitions

#define     ADV717x_CHROMA_FILTER       0x05    // Chroma Filter Select
#define     ADV717x_LUMA_FILTER         0x02    // Luma Filter Select
#define     ADV717x_OUT_VIDEO           0x00    // Output Video Standard Selection

// Mode Register 1 field definitions

#define     ADV717x_COLOR_BAR           0x07    // Color Bar control
#define     ADV717x_DAC_A               0x06    // DAC A Control
#define     ADV717x_DAC_B               0x05    // DAC B Control
#define     ADV717x_DAC_C               0x03    // DAC C Control
#define     ADV717x_CC_FIELD            0x01    // Closed Captioning Field Selection
#define     ADV717x_INTERLACE           0x00    // Interlace Control

// Mode Register 2 field definitions

#define     ADV717x_LOW_POWER           0x06    // Low Power Mode selection
#define     ADV717x_BURST_CONTROL       0x05    // Burst Control selection
#define     ADV717x_CROM_CONTROL        0x04    // Chrominance Control
#define     ADV717x_ACTIVE_LINES        0x03    // Active Video Line Duration
#define     ADV717x_GENLOCK             0x01    // Genlock Control
#define     ADV717x_SQ_PIXEL            0x00    // Square Pixel Control

// Mode Register 3 field definitions

#define     ADV717x_DEFAULT_COLOR       0x07    // Low Power Mode selection
#define     ADV717x_TTXREQ_MODE         0x06    // Burst Control selection
#define     ADV717x_TTX_ENABLE          0x05    // Teletext Enable
#define     ADV717x_CHROMA_OUT          0x04    // Chroma Output Select
#define     ADV717x_DAC_OUT             0x03    // DAC Output (SCART / EUROSCART configuration)
#define     ADV717x_VBI_OPEN            0x02    // Vertical Blanking Interval output select

// Mode Register 4 field definitions

#define     ADV717x_SLEEP_MODE          0x06    // Sleep mode control
#define     ADV717x_ACTIVE_VIDEO_FILTER 0x05    // Active Video Control
#define     ADV717x_PEDESTAL            0x04    // Pedestal Control
#define     ADV717x_VSYNC_3H            0x03    // VSYNC line control
#define     ADV717x_RGB_SYNC            0x02    // Setup RGB outputs
#define     ADV717x_RGB_YUV             0x01    // RGB/YUV Control
#define     ADV717x_OUTPUT_SELECT       0x00    // Output select (Composite video or RGB/YPbPr mode)

// Timing Mode Register 0 field definitions

#define     ADV717x_TIMING_REG_RST      0x07    // Timing Register Reset
#define     ADV717x_LUMA_DELAY          0x04    // Luma Delay
#define     ADV717x_BLANK_INPUT         0x03    // Blank\ Input control
#define     ADV717x_TIMING_MODE         0x01    // Timing Mode Selection
#define     ADV717x_MASTER_SLAVE        0x00    // Master / Slave control

// Timing Mode Register 1 field definitions

#define     ADV717x_HSYNC_ADJUST        0x06    // HSYNC\ to Pixel Data Adjust
#define     ADV717x_VSYNC_WIDTH         0x04    // HSYNC\ to Field Raising Edge delay (Mode 1) or VSYNC\ Width (Mode 2)
#define     ADV717x_HSYNC_VSYNC_DELAY   0x02    // HSYNC\ to Field/VSYNC\ Delay
#define     ADV717x_HSYNC_WIDTH         0x00    // HSYNC\ Width

// CGMS_WSS Register 0 field definitions

#define     ADV717x_WIDESCREEN_SIGNAL   0x07    // Wide screen signal control
#define     ADV717x_CGMS_EVEN_FIELD     0x06    // CGMS Even field control
#define     ADV717x_CGMS_ODD_FIELD      0x05    // CGMS Odd field control
#define     ADV717x_CGMS_CRC_CHECK      0x04    // CGMS CRC Check control
#define     ADV717x_CGMS_REG0_DATA      0x00    // CGMS_WSS register 0 Data bits (Data bits only for CGMS)

// CGMS_WSS Register 1 field definitions

#define     ADV717x_CGMS_REG1_DATA      0x06    // CGMS_WSS Register 1 Data bits (Data bits only for CGMS)
#define     ADV717x_CGMS_WSS_DATA       0x00    // CGMS_WSS Data bits (shard by CGMS & WSS)

// Teletext Request Control Register field definitions

#define     ADV717x_TTXREQ_RAISING      0x04    // Teletext request raising edge control
#define     ADV717x_TTXREQ_FALLING      0x00    // Teletext request falling edge control

/************************************************************
Timing Registers to generate Frame Sync(FS) signals
when ADV177x operated in non-standard video mode

* BF533 PPI0 uses Timer 0 & 1 to generate FS1 & FS2.
* BF537 PPI0 uses Timer 0 & 1 to generate FS1 & FS2.
* BF561 PPI0 uses Timer 8 & 9 to generate FS1 & FS2.
* BF561 PPI1 uses Timer 10 & 11 to generate FS1 & FS2.
************************************************************/

// Set status of PPI device to be used for video dataflow between Blackfin and ADV717x
typedef enum ADI_ADV717x_SET_PPI_STATUS {
    ADI_ADV717x_PPI_OPEN,           // Open PPI device
    ADI_ADV717x_PPI_CLOSE           // Close PPI device
}   ADI_ADV717x_SET_PPI_STATUS;

// Set Frame Sync Count (For non-standard video mode only)
typedef enum ADI_ADV717x_FS_COUNT {
    ADI_ADV717x_FRAME_COUNT_1,      // 1 Frame Sync
    ADI_ADV717x_FRAME_COUNT_2,      // 2 Frame Syncs
    ADI_ADV717x_FRAME_COUNT_3_FS1,  // 3 Frame Syncs with PPI_FS3 to assertion of PPI_FS1
    ADI_ADV717x_FRAME_COUNT_3_FS2   // 3 Frame Syncs with PPI_FS3 to assertion of PPI_FS2
}   ADI_ADV717x_FS_COUNT;

/***********************************************************************

Extensible enumerations and defines

***********************************************************************/

enum    {                                               /* ADV717x Driver Command id's  */

        ADI_ADV717x_CMD_START=ADI_ADV717x_ENUMERATION_START,    /* 0x400A0000 */

        /* Commands to access Sub-carrier frequency register (SCFR0 - SCFR3) */
        /* SCFR's should be accessed by these commands as they are not recommended to access separately */
        ADI_ADV717x_CMD_SET_SCF_REG,                    /* 0x400A0001 - Set Subcarrier Frequency Value (Value = u32) */
        ADI_ADV717x_CMD_GET_SCF_REG,                    /* 0x400A0002 - Get Subcarrier Frequency Register value (Value = u32*) */

        /* Timer configuration commands for non-standard video data */
        ADI_ADV717x_CMD_SET_TIMER_FRAME_SYNC_1,         /* 0x400A0003 - Command applicable only for PPI driven devices
                                                                      - set timer for frame sync 1 (PPI_FS1) (Value = ADI_PPI_FS_TMR *) */
        ADI_ADV717x_CMD_SET_TIMER_FRAME_SYNC_2,         /* 0x400A0004 - Command applicable only for PPI driven devices
                                                                      - set timer for frame sync 2 (PPI_FS2) (Value = ADI_PPI_FS_TMR *) */
        ADI_ADV717x_CMD_SET_FRAME_SYNC_COUNT,           /* 0x400A0005 - Command applicable only for PPI driven devices
                                                                      - set PPI Frame Sync count (Value = ADI_ADV717x_FS_COUNT) */

        /* PPI/EPPI Configuration */
        ADI_ADV717x_CMD_SET_FRAME_LINES_COUNT,          /* 0x400A0006 - set PPI/EPPI Lines per Frame count (Value = u32) */
        ADI_ADV717x_CMD_SET_PPI_DEVICE_NUMBER,          /* 0x400A0007 - Set PPI/EPPI Device Number that will be used to send video data to ADV717x (Value = u32) */
        ADI_ADV717x_CMD_SET_PPI_STATUS,                 /* 0x400A0008 - Set PPI/EPPI Device status (Value = ADI_ADV717x_SET_PPI_STATUS) */

        /* TWI Configuration */
        ADI_ADV717x_CMD_SET_TWI_DEVICE_NUMBER,          /* 0x400A0009 - Set TWI Device Number that will be used to access ADV717x registers (Value = u32) */
        ADI_ADV717x_CMD_SET_TWI_CONFIG_TABLE,           /* 0x400A000A - Set TWI Configuration table specific to the application (Value = ADI_DEV_CMD_VALUE_PAIR *) */
        ADI_ADV717x_CMD_SET_TWI_DEVICE_ADDRESS,         /* 0x400A000B - Set TWI address for the ADV717x device (Value = u32) */

        /* EPPI Configuration commands */
        ADI_ADV717x_CMD_SET_SAMPLES_PER_LINE            /* 0x400A000C - Command applicable only for EPPI driven devices
                                                                      - Set Output Samples per line */
                                                        /* For EPPI driven devices, to operate ADV717x in non-standard vide mode,
                                                           client must use EPPI driver commands to configure EPPI for required
                                                           Frame Syncs and Width,Period registers corresponding to selected Frame syncs */


        };

enum    {                                                       /* Event ids */
        ADI_ADV717x_EVENT_START=ADI_ADV717x_ENUMERATION_START   /* 0x400a0000 */
        };

enum    {                                                       /* Return codes */
        ADI_ADV717x_RESULT_START=ADI_ADV717x_ENUMERATION_START, /* 0x400a0000 */
        ADI_ADV717x_RESULT_CMD_NOT_SUPPORTED,               /* 0x400a0001 - Unknown command or accessing unknown/restricted registers */
        ADI_ADV717x_RESULT_TIMING_NOT_CONFIGURED,           /* 0x400a0002 - Enabling dataflow to ADV717x in mode 1/2/3 without configuring frame sync timers */
        ADI_ADV717x_RESULT_FRAME_ERROR,                     /* 0x400a0003 - Error in Frame Sync / Frame Line Count */
        ADI_ADV717x_RESULT_DISABLE_DATAFLOW,                /* 0x400a0004 - no longer used */
        ADI_ADV717x_RESULT_BAD_PPI_DEVICE,                  /* 0x400a0005 - no longer used */
        ADI_ADV717x_RESULT_OPERATING_MODE_MISMATCH,         /* 0x400a0006 - Results when clent tries to set Frame sync / Frame Line count with ADV717x in wrong mode */
        ADI_ADV717x_RESULT_PPI_STATUS_INVALID               /* 0x400a0007 - no longer used */
        };

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_ADV717x_H__ */
