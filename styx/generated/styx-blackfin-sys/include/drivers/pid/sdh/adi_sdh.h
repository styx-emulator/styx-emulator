/**********************************************************************

Copyright(c) 2009 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_sdh.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
    This is the include file for the ADI Secure Digital Host (SDH)

***********************************************************************/

#ifndef __ADI_SDH_H__
#define __ADI_SDH_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* system service header  */
#include <services/services.h>

#if defined(__ADSP_MOAB__) || defined(__ADSP_BRODIE__) || defined (__ADSP_MOY__)

#include <drivers/adi_dev.h>
#include <services/fss/adi_fss.h>

/*********************************************************************

Entry point to the SDH PID

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADI_SDH_EntryPoint;

/*********************************************************************

Enums to identify SDH SD Slot status

*********************************************************************/
typedef enum {
    ADI_SDH_SLOT_MEDIA_INSERTED,    /* SDH has detected a new media inserted to the SDH slot                    */
    ADI_SDH_SLOT_MEDIA_REMOVED,     /* Media in SDH slot has been removed                                       */
    ADI_SDH_SLOT_EMPTY,             /* No media found in the SDH Slot - Slot is empty                           */
    ADI_SDH_SLOT_CARD_NOT_SUPPORTED,/* SDH driver does not support this media (Memory Card)                     */
    ADI_SDH_SLOT_MMC,               /* Detected a Multimedia Card (DRIVER NOT TESTED FOR THIS TYPE OF MEDIA)    */
    ADI_SDH_SLOT_SD_CARD_VER_1_X,   /* Detected a Version 1.X standard capacity SD Card                         */
    ADI_SDH_SLOT_SD_CARD_VER_2_0,   /* Detected a Version 2.0 standard capacity SD Card                         */
    ADI_SDH_SLOT_SDIO_CARD,         /* Detected a SDIO Card (DRIVER NOT TESTED FOR THIS TYPE OF MEDIA)          */
    ADI_SDH_SLOT_SDIO_COMBO_CARD,   /* Detected a SDIO-Combo Card (DRIVER NOT TESTED FOR THIS TYPE OF MEDIA)    */
    ADI_SDH_SLOT_SDHC_CARD,         /* Detected a Version 2.0 Higher capacity SD (SDHC) Card                    */
    ADI_SDH_SLOT_MMC_HC             /* Detected a HC Multimedia Card (DRIVER NOT TESTED FOR THIS TYPE OF MEDIA) */
}ADI_SDH_SD_SLOT_STATUS;

/*********************************************************************

SDH Driver specific control commands

*********************************************************************/

enum {
    ADI_SDH_CMD_START = ADI_PID_CUSTOM_CMD_START,       /* (0x000AA000) */

    ADI_SDH_CMD_SET_SUPPORTED_CARD_OPERATING_CONDITION, /* (0x000AA001) Set Card operating condition supported by the hardware
                                                                        (Value = u32)
                                                                        Default settings - ADSP-BF548 Ez-Kit operating conditions
                                                        */

    ADI_SDH_CMD_SET_CARD_LOCK_ENABLED,                  /* (0x000AA002) Pass the present card lock (mechanical switch) status to SDH driver
                                                                        (Value = TRUE/FALSE, TRUE when card lock is enabled)
                                                                        Default settings - SDH driver assumes card lock as disabled
                                                        */

    ADI_SDH_CMD_ENABLE_WIDEBUS,                         /* (0x000AA003) Enable/Disable SDH wide-bus mode (4-bit bus)
                                                                        (Value = TRUE/FALSE, TRUE to use 4-bit bus, FALSE to use 1-Bit bus)
                                                                        Default settings - Wide-bus mode enabled
                                                        */

    ADI_SDH_CMD_SET_TIMEOUT_MULTIPLIER,                 /* (0x000AA004) Timeout multiply factor for DMA data transfer - this gives DMA
                                                                        and SDH card enough time to transfer larger multiple blocks
                                                                        Value = u32 (between 1 and 300) Default value = 100
                                                        */

    ADI_SDH_CMD_GET_SDH_SLOT_STATUS,                    /* (0x000AA005) Gets present Status of SDH slot
                                                                        Value = ADI_SDH_SD_SLOT_STATUS *
                                                        */

#if defined(__ADSP_BRODIE__) || defined (__ADSP_MOY__)
    ADI_SDH_CMD_ENABLE_BYTEBUS,                         /* (0x000AA006) Enable/Disable SDH Byte-bus mode (8-bit bus)
                                                                        (Value = TRUE/FALSE, TRUE to use 8-bit bus, FALSE to use 1-Bit bus)
                                                                        Default settings - Byte-bus mode disabled
                                                        */
#endif
    ADI_SDH_CMD_OVERRIDE_CLKDIV,                        /* (0x000AA007) Overrides the CLKDIV value for stability adjustments
                                                                        Value = u8
                                                        */

    ADI_SDH_CMD_SET_BLOCK_MODE,                        /* (0x000AA008)  Sets the Block mode support. Defaults to true, to use FSS
                                                                        File Cache
                                                        */

    ADI_SDH_CMD_SET_CDPRIO_MODE,                       /* (0x000AA009)  Sets the CDPRIO mode support. Defaults to true, to set CDPRIO for
                                                                        the duration of RSI DMAs to give DMA priority over the core.
                                                        */

    /* SD I/O related commands - to be added in future */
};

/*********************************************************************

The following is the default configuration for the SDH driver.
To use, define the _ADI_SDH_DEFAULT_DEF_ macro in the enclosing file

*********************************************************************/
#if defined(_ADI_SDH_DEFAULT_DEF_)

static ADI_FSS_DEVICE_DEF ADI_SDH_Def = {
    0,                                      /* Not Applicable                           */
    &ADI_SDH_EntryPoint,                    /* Entry Points for Driver                  */
    NULL,                                   /* Command Table to configure SDH Driver    */
    NULL,                                   /* Critical region data                     */
    ADI_DEV_DIRECTION_BIDIRECTIONAL,        /* Direction (RW media)                     */
    NULL                                    /* Device Handle                            */
};

#endif /* _ADI_SDH_DEFAULT_DEF_ */

#else
#error "The RSDH/RSI driver is not available for the current target processor"
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif      /* __ADI_SDH_H__   */
