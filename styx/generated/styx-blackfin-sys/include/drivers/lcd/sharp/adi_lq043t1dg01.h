/******************************************************************************
Copyright (c), 2010 - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.

$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Title: Sharp LQ035Q1DH02 LCD driver

Description: This is the primary include file for Sharp LQ043T1DG01 LCD driver

*****************************************************************************/

#ifndef __ADI_LQ043T1DG01_H__
#define __ADI_LQ043T1DG01_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*==============  D E F I N E S  ===============*/

/*
** ADI_LQ043T1DG01_EPPI_CTRL_REG_MODE
**  - Enumerations of EPPI Control register configuration modes
**    supported by the LCD driver
*/
typedef enum __AdiLq043t1dg01EppiCtrlRegMode
{

    /* Mode to disable driver from
       automatically configuring EPPI control register  */
    ADI_LQ043T1DG01_EPPI_CTRL_REG_AUTO_CONFIG_DISABLED = 0,

    /* Mode to confgiure EPPI Control register for RGB 24-bit out

        - EPPI as Output, GP 2 frame sync mode,
          Internal Clock generation disabled, Internal FS generation enabled,
          Receives samples on EPPI_CLK raising edge,
          Transmits samples on EPPI_CLK falling edge, FS1 & FS2 are active high,
          24 bits for RGB888 out, DMA unpacking enabled, Swapping Disabled,
          One (DMA) Channel Mode, RGB Formatting disabled,
          Regular watermark - 75% full, Urgent watermark - 25% full
    */
    ADI_LQ043T1DG01_EPPI_CTRL_REG_RGB24 = 0x68136E2E,

    /* Mode to confgiure EPPI Control register to format
       RGB 24-bit data and output as RGB 18-bit on-the-fly

        - EPPI as Output, GP 2 frame sync mode,
          Internal Clock generation disabled, Internal FS generation enabled,
          Receives samples on EPPI_CLK raising edge,
          Transmits samples on EPPI_CLK falling edge, FS1 & FS2 are active high,
          16 bits for RGB666 out, DMA unpacking enabled, Swapping Disabled,
          One (DMA) Channel Mode, RGB Formatting enabled,
          Regular watermark - 75% full, Urgent watermark - 25% full
    */
    ADI_LQ043T1DG01_EPPI_CTRL_REG_RGB24_TO_RGB18 = 0x6C12EE2E,

    /* Mode to confgiure EPPI Control register for RGB 18-bit out

        - EPPI as Output, GP 2 frame sync mode,
          Internal Clock generation disabled, Internal FS generation enabled,
          Receives samples on EPPI_CLK raising edge,
          Transmits samples on EPPI_CLK falling edge, FS1 & FS2 are active high,
          16 bits for RGB666 out, DMA unpacking enabled, Swapping Disabled,
          One (DMA) Channel Mode, RGB Formatting disabled,
          Regular watermark - 75% full, Urgent watermark - 25% full
    */
    ADI_LQ043T1DG01_EPPI_CTRL_REG_RGB18 = 0x6812EE2E

} ADI_LQ043T1DG01_EPPI_CTRL_REG_MODE;

/*
**
** Enumerations of Sharp LQ043T1DG01 LCD driver specific commands
**
*/
enum
{
    /* 0x40210000 - Sharp LQ043T1DG01 LCD Driver enumuration start */
    ADI_LQ043T1DG01_CMD_START = ADI_LQ043T1DG01_ENUMERATION_START,


    /* 0x40210001 - Sets Timer ID to generate DISP signal for the LCD and
                    Flag ID to which the DISP signal is connected to
                    Value = address of ADI_LQ043T1DG01_TIMER_FLAG type structure
                    Default = Flag ID undefined
    */
    ADI_LQ043T1DG01_CMD_SET_DISP_TIMER_FLAG,

    /* 0x40210002 - Sets EPPI Device number to use
                    Value   = u8 (EPPI Device number)
                    Default = 0 (EPPI 0)
    */
    ADI_LQ043T1DG01_CMD_SET_EPPI_DEV_NUMBER,

    /* 0x40210003 - Opens/Closes EPPI Device connected to the display device
                    Value   = true/false
                              'true' to open EPPI device, 'false' to close
                    Default = false (EPPI closed)
    */
    ADI_LQ043T1DG01_CMD_SET_OPEN_EPPI_DEVICE,

    /* 0x40210004 - Configures EPPI Control Register to pre-defined mode
                    Value   = enumerated value of type
                              ADI_LQ043T1DG01_EPPI_CTRL_REG_MODE
                    Default = ADI_LQ043T1DG01_EPPI_CTRL_REG_AUTO_CONFIG_DISABLED
                    Note: Automatic configuration of EPPI control register is
                          now disabled by default.
                          Selecting a valid, pre-defined, EPPI control register
                          configuration from the above enumeration table will
                          stop the programmer from configuring EPPI control
                          register fields directly from the application.
                          If the programmer intends to configure the EPPI
                          Control register fields from the application, then
                          the Automatic configuration of EPPI control register
                          should be disable by passing
                          'ADI_LQ043T1DG01_EPPI_CTRL_REG_AUTO_CONFIG_DISABLED'
                          as command value parameter
    */
    ADI_LQ043T1DG01_CMD_SET_EPPI_CTRL_REG_MODE

    /*
        The driver will automatically configure following EPPI registers with
        corresponding values to generate Frame Syncs required by this LCD

        ----------------------------------------------+--------------------
        EPPI Register                                 |        Value
        ----------------------------------------------+--------------------
        Samples Per Line            (EPPI_LINE)                 525
        Lines per Frame             (EPPI_FRAME)                286
        Frame Sync 1 Width          (EPPI_FS1W_HBL)              41
        Frame Sync 1 Period         (EPPI_FS1P_AVPL)            525
        Horizontal Delay            (EPPI_HDELAY)                43
        Horizontal Transfer Count   (EPPI_HCOUNT)               480
        Frame Sync 2 Width          (EPPI_FS2W_LVB)            5250
        Frame Sync 2 Period         (EPPI_FS2P_LAVF)         150150
        Vertical Delay              (EPPI_VDELAY)                12
        Vertical Transfer Count     (EPPI_VCOUNT)               272
        -------------------------------------------------------------------

        Application can use EPPI driver specific commands to
        configure other EPPI registers.
    */
};

/*
**
** Enumerations of Sharp LQ043T1DG01 LCD driver specific events
**
*/
enum
{
    /* 0x40210000 - Sharp LQ043T1DG01 LCD Driver enumuration start */
    ADI_LQ043T1DG01_EVENT_START = ADI_LQ043T1DG01_ENUMERATION_START

    /* The driver also passes event codes received from
       Timer/Flag service or EPPI driver */
};

/*
**
** Enumerations of Sharp LQ043T1DG01 LCD driver specific return codes
**
*/
enum
{
    /* 0x40210001 - Sharp LQ043T1DG01 LCD Driver enumuration start */
    ADI_LQ043T1DG01_RESULT_START = ADI_LQ043T1DG01_ENUMERATION_START,
    /* 0x40210002 - Results when client tries to
                    submit buffer(s) when EPPI is disabled */
    ADI_LQ043T1DG01_RESULT_PPI_STATE_INVALID,
    /* 0x40210003 - Results when client tries to enable dataflow
                    without providing a valid DISP generation Timer or Flag */
    ADI_LQ043T1DG01_RESULT_DISP_TIMER_FLAG_INVALID,
    /* 0x40210004 - Command not recogonised or supported by the driver */
    ADI_LQ043T1DG01_RESULT_CMD_NOT_SUPPORTED,
    /* 0x40210005 - Results when client tries to enable/disable dataflow while
                    DISP signal genertion is in progress */
    ADI_LQ043T1DG01_DISP_GENERATION_ALREADY_IN_PROGRESS

    /* The driver also passes result codes received from
       Timer/Flag service or EPPI driver */
};

/*=============  E X T E R N A L S  ============*/

/*
**
**  External Data section
**
*/

/*
** ADILQ043T1DG01EntryPoint
**  - Device Manager Entry point for Sharp LQ043T1DG01 driver
**
*/
extern ADI_DEV_PDD_ENTRY_POINT  ADILQ043T1DG01EntryPoint;

/*=============  D A T A    T Y P E S   =============*/

/*
** ADI_LQ043T1DG01_TIMER_FLAG
**  - Data Structure to pass Timer & Flag ID to generate DISP signal
*/

typedef struct
{

    /* Variable: DispTimerId
        - Timer ID to generate DISP signal for the LCD */
    u32             DispTimerId;

    /* Variable: DispFlagId
        - Flag ID to which the DISP signal is connected to */
    ADI_FLAG_ID     DispFlagId;

} ADI_LQ043T1DG01_TIMER_FLAG;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif      /* __ADI_LQ043T1DG01_H__   */
