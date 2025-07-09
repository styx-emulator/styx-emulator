/*******************************************************************************/
/*                                                                             */
/*   (C) Copyright 2004 - Analog Devices, Inc.  All rights reserved.           */
/*                                                                             */
/*    FILE:     u t i l . h ( )        					                       */
/*																			   */
/*    PURPOSE:  This header file defines the devices commands.				   */
/*                                                                             */
/*******************************************************************************/

#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef _MISRA_RULES
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_15:"ADI header defines and/or undefines macros within a block")
#endif /* _MISRA_RULES */

#include "adi_flash.h"	/* flash driver includes */


/* enum describing the flash width */
typedef enum
{
	_FLASH_WIDTH_8 = 1,
	_FLASH_WIDTH_16 = 2,
	_FLASH_WIDTH_32 = 4,
	_FLASH_WIDTH_64 = 8

} enFlashWidth;


/* enum for adi_pdd_control */
typedef enum
{
	CNTRL_GET_CODES,		/* 0 - gets manufacturer and device IDs */
	CNTRL_RESET,			/* 1 - resets device */
	CNTRL_ERASE_ALL,		/* 2 - erase entire device */
	CNTRL_ERASE_SECT,		/* 3 - erase a sector */
	CNTRL_GET_SECTNUM,		/* 4 - get sector number */
	CNTRL_GET_SECSTARTEND,	/* 5 - get sector start and end addresses */
	CNTRL_GET_DESC,			/* 6 - get device description */
	CNTRL_GETNUM_SECTORS,	/* 7 - get number of sectors in device */
	CNTRL_GET_FLASH_WIDTH,	/* 8 - get the flash width */
	CNTRL_SUPPORTS_CFI,		/* 9 - does the device support CFI? */
	CNTRL_GET_CFI_DATA		/* 10 - gets CFI data */
} enCntrlCmds;


 #endif	/* __ADI_UTIL_H__ */
