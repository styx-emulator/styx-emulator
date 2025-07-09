/*******************************************************************************/
/*                                                                             */
/*   (C) Copyright 2004 - Analog Devices, Inc.  All rights reserved.           */
/*                                                                             */
/*    FILE:     u t i l . h ( )        					                       */
/*                                                                             */
/*    CHANGES:  1.00.0  - initial release    								   */
/*																			   */
/*    PURPOSE:  This header file defines the devices commands				   */
/*                                                                             */
/*******************************************************************************/

#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef _MISRA_RULES
#pragma diag(suppress:misra_rule_5_1:"ADI header uses long identifier names")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_2:"ADI header uses non-standard characters in #include header file names")
#pragma diag(suppress:misra_rule_19_15:"ADI header defines and/or undefines macros within a block")
#endif /* _MISRA_RULES */


#include <drivers\flash\adi_flash.h>	/* flash driver includes */

/*---- c o n s t a n t   d e f i n i t i o n s -----*/

/* enum for adi_pdd_control */
typedef enum
{
	ADI_FPGA_CMD_GET_CODES,
	ADI_FPGA_CMD_RESET,
	ADI_FPGA_CMD_ERASE_ALL,
	ADI_FPGA_CMD_ERASE_SECT,
	ADI_FPGA_CMD_GET_SECTNUM,
	ADI_FPGA_CMD_GET_SECSTARTEND,
	ADI_FPGA_CMD_GET_DESC,
	ADI_FPGA_CMD_GETNUM_SECTORS
}enCntrlCmds;


 #endif	/* __ADI_UTIL_H__ */
