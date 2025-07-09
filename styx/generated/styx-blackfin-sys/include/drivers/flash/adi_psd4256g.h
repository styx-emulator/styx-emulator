/*******************************************************************************/
/*                                                                             */
/*   (C) Copyright 2004 - Analog Devices, Inc.  All rights reserved.           */
/*                                                                             */
/*    FILE:     a d i _ p s d 4 2 5 6 g . h ( )                                */
/*                                                                             */
/*    CHANGES:  1.00.0  - initial release    								   */
/*																			   */
/*    PURPOSE:  This header file defines the public name(functions and types)  */
/*               exported from the module 'adi_psd4256g.c'    		           */
/*                                                                             */
/*******************************************************************************/

#ifndef __ADI_PSD4256G_H__
#define __ADI_PSD4256G_H__

#ifdef _MISRA_RULES
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_15:"ADI header defines and/or undefines macros within a block")
#endif /* _MISRA_RULES */

/*---- I n c l u d e s  ----*/

#include <services/services.h>		/* system services includes */
#include <drivers/adi_dev.h>		/* device manager includes */


#define NUM_SECTORS 	40			/* number of sectors in the flash device */

/*---- F u n c t i o n   P r o t o t y p e s  ----*/

 extern ADI_DEV_PDD_ENTRY_POINT ADIPSD4256GEntryPoint;	/* entry point to the device driver */
 extern ADI_DEV_DEVICE_HANDLE DevHandlePSD4256G;


#endif	/* __ADI_PSD4256G_H__ */
