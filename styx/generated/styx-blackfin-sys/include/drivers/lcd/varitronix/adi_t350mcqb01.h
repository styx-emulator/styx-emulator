/**********************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.


Description:
    This is the include file for Varitronix T350MCQB01 LCD driver

***********************************************************************/

#ifndef __ADI_T350MCQB01_H__
#define __ADI_T350MCQB01_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*********************************************************************

Entry point to the T350MCQB01 device driver

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT  ADIT350MCQB01EntryPoint;

/*********************************************************************

Extensible enumerations and defines

*********************************************************************/

// HS and VS timing parameters (all in number of PPI clk ticks)
#define T350MCQB01_CLOCKS_PER_BYTE  3

#define T350MCQB01_H_ACTPIX     (320*T350MCQB01_CLOCKS_PER_BYTE)   // active horizontal pixels
#define T350MCQB01_H_PERIOD     (408*T350MCQB01_CLOCKS_PER_BYTE)   // HS period (from data sheet- typical is 1224 Tosc)
                                                                   // 1224/3 = 408
#define T350MCQB01_H_PULSE      90                                 // HS pulse width (from data sheet)
                                                                   // 204/3 = 68
#define T350MCQB01_V_LINES      241                                // blanking line plus 240 data lines
#define T350MCQB01_V_PULSE      (3*T350MCQB01_H_PERIOD)            // VS pulse width per Varitronix spec
#define T350MCQB01_V_PERIOD     (T350MCQB01_H_PERIOD * T350MCQB01_V_LINES)     // VS period
#define T350MCQB01_HSTART       204                                            // IHS-DEN timer per Varitronix spec

#define T350MCQB01_H_LINES      320
#define T350MCQB01_H_ROWS       240

enum {                                                              /* T350MCQB01 driver Command id's                          */
    ADI_T350MCQB01_CMD_START=ADI_T350MCQB01_ENUMERATION_START,      /* T350MCQB01 enumuration start               */


    ADI_T350MCQB01_CMD_SET_PPI_DEV_NUMBER,                        /* Set the PPI Device number to use (Value = u8)           */
    ADI_T350MCQB01_CMD_SET_OPEN_PPI_DEVICE                        /* Open/Close PPI Device connected to this LCD
                                                                       (Value = TRUE/FALSE, TRUE to open & FALSE to close PPI  */

    /*
        The driver will automatically configure following PPI registers with corresponding values to
        generate Frame Sync signals required by this LCD

        ----------------------------------------------+--------------------
        PPI Register                                  |        Value
        ----------------------------------------------+--------------------
        Samples Per Line            (T350MCQB01_H_LINES*3)     960 (RGB 320 *3)
        Lines per Frame             (PPI_FRAME)                240 + 1 (+1 blanking line)
        Frame Sync 1 Width          (T350MCQB01_H_PULSE)        90 (Per Varitronix Spec)
        Frame Sync 1 Period         (T350MCQB01_H_PERIOD)     1224 (408*3 = typical Tosc)
        Horizontal Delay            (T350MCQB01_HSTART)        204  T(he) Per Varitronix Spec
        Horizontal Transfer Count   T350MCQB01_H_LINES*3)     960 (RGB 320 *3)
        Frame Sync 2 Width          (T350MCQB01_V_PULSE)            PPI_HS_PERIOD
        Frame Sync 2 Period         (T350MCQB01_V_PERIOD)           T350MCQB01_H_PERIOD * 241
        Vertical Delay              (PPI_VDELAY)                 0
        Vertical Transfer Count     (PPI_VCOUNT)               960 * 241 = 231,360
        -------------------------------------------------------------------

        Application can use PPI driver specific commands to configure other PPI registers.
    */
};



enum {                                                              /* T350MCQB01 Event id's                                   */
    ADI_T350MCQB01_EVENT_START=ADI_T350MCQB01_ENUMERATION_START    /* 0x40210000 - T350MCQB01 enumuration start               */
    /* The driver also passes the event code obtained from the Timer/Flag service or PPI driver                                */
};

enum {                                                             /* T350MCQB01 Result id's                                  */
    ADI_T350MCQB01_RESULT_START=ADI_T350MCQB01_ENUMERATION_START,  /* T350MCQB01 enumuration start               */
    ADI_T350MCQB01_RESULT_PPI_STATE_INVALID,                       /* Results when client tries to communicate    */
    ADI_T350MCQB01_RESULT_CMD_NOT_SUPPORTED                        /* Command not recogonised or supported
                                                                         by this driver                         */

    /* The driver also passes the result code obtained from Timer/Flag service or PPI driver                                   */
};

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif      /* __ADI_T350MCQB01_H__   */

/*****/
