/*****************************************************************************
Copyright (c), 2002-2009 - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.
******************************************************************************

$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Title:  AD7879 Touchscreen Controller Driver

Description:
        This is the primary include file for the AD7879 Touchscreen Controller
        Driver.  The driver supports Device access commands to access AD7879
        registers.

Notes: Access to the AD7879 control registers is over the SPI port.
       These registers are addressed through a 16-bit command word:

       +---------------------------------+
       |  Command Word bit positions     |
       +---------------------------------+
       | Command Word |  R/W | Reg Addr  |
       |--------------|------|-----------|
       |     15:11    |  10  |    9:0    |
       +--------------+------+-----------+

       Following the 16-bit command word, the next 16-bits of data are
       read from or written to the address specified in the command word.
       After 32 clock cycles (one command word followed by first data word),
       AD7879 automatically increments its address pointer and continues
       reading or writing data (without additional command words) until
       the rising edge of CS.

       Since the AD7879 and AD7879-1 are identical apart from the means of
       accessing their registers (SPI v. TWI respectively), all the register
       definitions and type specifications, and the driver command, event and
       result enumerations, are held in a common file.

       This file #includes the common file and then contains a declaration for
       the AD7879-specific entrypoint.

#endif

*****************************************************************************/

#ifndef __ADI_AD7879_H__
#define __ADI_AD7879_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* include common register definitions, commands, etc */
#include <drivers/touchscreen/adi_ad7879_common.h>

#if defined(_LANGUAGE_C)

/*
** ADIAD7879EntryPoint
**  - Device Manager Entry point for AD7879 driver
**
*/
extern ADI_DEV_PDD_ENTRY_POINT ADIAD7879EntryPoint;

#endif /* _LANGUAGE_C */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_AD7879_H__ */

/*****/
