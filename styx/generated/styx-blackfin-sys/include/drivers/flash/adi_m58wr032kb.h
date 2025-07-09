/*******************************************************************************/
/*                                                                             */
/*   (C) Copyright 2004 - Analog Devices, Inc.  All rights reserved.           */
/*                                                                             */
/*                                                                             */
/*    CHANGES:  1.00.0  - initial release    								   */
/*																			   */
/*    PURPOSE:  This header file defines the public name(functions and types)  */
/*               exported from the module 'adi_m58wr032kb.c'  		           */
/*                                                                             */
/*******************************************************************************/

#ifndef __ADI_M58WR032KB_H__
#define __ADI_M58WR032KB_H__

#ifdef _MISRA_RULES
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_15:"ADI header defines and/or undefines macros within a block")
#endif /* _MISRA_RULES */

/*---- I n c l u d e s  ----*/

#include <services/services.h>		/* system services includes */
#include <drivers/adi_dev.h>		/* device manager includes */

#define ERASE_TIMEOUT			50000000
#define PROGRAM_TIMEOUT			1000000

/*---- F u n c t i o n   P r o t o t y p e s  ----*/

extern ADI_DEV_PDD_ENTRY_POINT ADIM58WR032KBEntryPoint;    /* entry point to the device driver */

#endif  /* __ADI_M58WR032KB_H__ */
