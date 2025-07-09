/*****************************************************************************
Copyright (c), 2002-2009 - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.
******************************************************************************

$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Title:  AD7879-1 Touchscreen Controller Driver

Description:
        This is the primary include file for the AD7879-1 Touchscreen Controller
        Driver.  The driver supports Device access commands to access AD7879-1
        registers.

Notes: Access to the AD7879-1 control registers is over the TWI port.
       These registers are addressed through an address pointer register
       which is set up at the start of each transaction by the transmission
       of the AD7879-1's 7-bit TWI (I2C) device address, a read/write bit,
       and the 8-bit address of the first (or only) register involved in the
       transaction.  The address pointer register automatically increments
       during multi-register operations.

       The 16-bit register contents are sent and received as two 8-bit bytes
       in big-endian order (most significant byte first).

       Since the AD7879 and AD7879-1 are identical apart from the means of
       accessing their registers (SPI v. TWI respectively), all the register
       definitions and type specifications, and the driver command, event and
       result enumerations, are held in a common file.

       This file #includes the common file and then contains a declaration for
       the AD7879-1-specific entrypoint.

*****************************************************************************/

#ifndef __ADI_AD7879_1_H__
#define __ADI_AD7879_1_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* include common register definitions, commands, etc */
#include <drivers/touchscreen/adi_ad7879_common.h>

#if defined(_LANGUAGE_C)

/*
** ADIAD7879_1_EntryPoint
**  - Device Manager Entry point for AD7879-1 driver
**
*/
extern ADI_DEV_PDD_ENTRY_POINT ADIAD7879_1_EntryPoint;

#endif /* _LANGUAGE_C */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_AD7879_1_H__ */

/*****/
