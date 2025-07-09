/*******************************************************************************/
/*                                                                             */
/*   (C) Copyright 2004 - Analog Devices, Inc.  All rights reserved.           */
/*                                                                             */
/*    FILE:     a d i _ M 2 5 P 1 6 . h ( )                                    */
/*                                                                             */
/*    CHANGES:  1.00.0  - initial release    								   */
/*																			   */
/*    PURPOSE:  This header file defines the public name(functions and types)  */
/*               exported from the module 'adi_M25P16.c'    		           */
/*                                                                             */
/*******************************************************************************/

#ifndef __ADI_M25P16_H__
#define __ADI_M25P16_H__

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

extern ADI_DEV_PDD_ENTRY_POINT ADIM25P16EntryPoint;	/* entry point to the device driver */
extern ADI_DEV_DEVICE_HANDLE DevHandleM25P16;


#endif	/* __ADI_M25P16_H__ */
