/*******************************************************************************/
/*                                                                             */
/*   (C) Copyright 2004 - Analog Devices, Inc.  All rights reserved.           */
/*                                                                             */
/*    FILE:     adi_sst25wf040.h                                               */
/*																			   */
/*    PURPOSE:  This header file defines the public name(functions and types)  */
/*               exported from the module 'adi_sst25wf040.c'   		           */
/*                                                                             */
/*******************************************************************************/

#ifndef __ADI_SST25WF040_H__
#define __ADI_SST25WF040_H__

#ifdef _MISRA_RULES
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_15:"ADI header defines and/or undefines macros within a block")
#endif /* _MISRA_RULES */

/*---- I n c l u d e s  ----*/
#include <drivers/adi_dev.h>		/* device manager includes */

/* Application definitions */
#define COMMON_SPI_SETTINGS (SPE|MSTR) /* Settings to the SPI_CTL */
#define TIMOD01 (0x01)		/* sets the SPI to work with core instructions */

#define BAUD_RATE_DIVISOR 	6
#define PE4 0x0010

/*---- F u n c t i o n   P r o t o t y p e s  ----*/

extern ADI_DEV_PDD_ENTRY_POINT ADISST25WF040EntryPoint;	/* entry point to the device driver */

#endif  /* __ADI_SST25WF040_H__ */
