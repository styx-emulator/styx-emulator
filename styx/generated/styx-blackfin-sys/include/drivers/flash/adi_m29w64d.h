/*******************************************************************************/
/*                                                                             */
/*   (C) Copyright 2004 - Analog Devices, Inc.  All rights reserved.           */
/*                                                                             */
/*    FILE:     a d i _ m 2 9 w 6 4 d . h ( )                                  */
/*                                                                             */
/*    CHANGES:  1.00.0  - initial release    								   */
/*																			   */
/*    PURPOSE:  This header file defines the public name(functions and types)  */
/*               exported from the module 'adi_m29w64d.c'    		           */
/*                                                                             */
/*******************************************************************************/

#ifndef __ADI_M29W64D_H__
#define __ADI_M29W64D_H__

#ifdef _MISRA_RULES
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_15:"ADI header defines and/or undefines macros within a block")
#endif /* _MISRA_RULES */

/*---- I n c l u d e s  ----*/

#include <services/services.h>		/* system services includes */
#include <drivers/adi_dev.h>		/* device manager includes */


#define NUM_SECTORS 	135			/* number of sectors in the flash device */

/*---- F u n c t i o n   P r o t o t y p e s  ----*/

 extern ADI_DEV_PDD_ENTRY_POINT ADIM29W64DEntryPoint;	/* entry point to the device driver */
 extern ADI_DEV_DEVICE_HANDLE DevHandleM29W64D;

/* -- Flash manufacturer and device codes  ---- */

#define FLASH_MANUFACTURER_ST      0x20

#define FLASH_DEVCODE_ST_M29W640DT 0x22DE
#define FLASH_DEVCODE_ST_M29W640FT 0x22ED

#endif	/* __ADI_M29W64D_H__ */
