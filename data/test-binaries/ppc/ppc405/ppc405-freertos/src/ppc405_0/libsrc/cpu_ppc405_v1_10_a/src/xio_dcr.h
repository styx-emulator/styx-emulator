/* $Id: xio_dcr.h,v 1.1 2007/04/04 18:23:27 wre Exp $ */
/******************************************************************************
*
*       XILINX IS PROVIDING THIS DESIGN, CODE, OR INFORMATION "AS IS"
*       AS A COURTESY TO YOU, SOLELY FOR USE IN DEVELOPING PROGRAMS AND
*       SOLUTIONS FOR XILINX DEVICES.  BY PROVIDING THIS DESIGN, CODE,
*       OR INFORMATION AS ONE POSSIBLE IMPLEMENTATION OF THIS FEATURE,
*       APPLICATION OR STANDARD, XILINX IS MAKING NO REPRESENTATION
*       THAT THIS IMPLEMENTATION IS FREE FROM ANY CLAIMS OF INFRINGEMENT,
*       AND YOU ARE RESPONSIBLE FOR OBTAINING ANY RIGHTS YOU MAY REQUIRE
*       FOR YOUR IMPLEMENTATION.  XILINX EXPRESSLY DISCLAIMS ANY
*       WARRANTY WHATSOEVER WITH RESPECT TO THE ADEQUACY OF THE
*       IMPLEMENTATION, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OR
*       REPRESENTATIONS THAT THIS IMPLEMENTATION IS FREE FROM CLAIMS OF
*       INFRINGEMENT, IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
*       FOR A PARTICULAR PURPOSE.
*
*       (c) Copyright 2002 Xilinx Inc.
*       All rights reserved.
*
******************************************************************************/
/*****************************************************************************/
/**
*
* @file xio_dcr.h
*
* The DCR I/O access functions.
*
* @note
*
* These access functions are specific to the PPC405 CPU. Changes might be
* necessary for other members of the IBM PPC Family.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a ecm  10/18/01 First release
* 1.10a wgr  03/22/07 Converted to new coding style.
* </pre>
*
* @internal
*
* The C functions which subsequently call into either the assembly code
* or into the provided table of functions are required since the registers
* assigned to the calling and return from functions are strictly defined
* in the ABI and that definition is used in the low-level functions
* directly. The use of macros is not recommended since the temporary
* registers in the ABI are defined but there is no way to force
* the compiler to use a specific register in a block of code.
*
* Also, the function table created at compile time is in the data space,
* not the text space. This leads to the following possible issues:
* 1. If the MMU is used, the data and instruction spaces must be mapped
*    the same. If this condition is not met, the 405 could start executing
*    random code.
* 2. If the MMU is used, the EXECUTE bit must be set in the table used
*    for the data space. If this is not the case, an exception will occur.
* 3. If the memory is configured as a true Harvard where instruction and
*    data spaces are on independent busses, the DCR code will fail since
*    the function table is not resident in the instruction space.
*
* There are macros available to solve these issues. They are located in
* xpseudo_asm_gcc.h (or xpseudo_asm_dcc.h if Diab is used).
*
******************************************************************************/

#ifndef XDCRIO_H		/* prevent circular inclusions */
#define XDCRIO_H		/* by using protection macros */

#ifdef __cplusplus
extern "C" {
#endif


/***************************** Include Files *********************************/
#include "xbasic_types.h"

/************************** Constant Definitions *****************************/


#define MAX_DCR_REGISTERS           1024
#define MAX_DCR_REGISTER            MAX_DCR_REGISTERS - 1
#define MIN_DCR_REGISTER            0

/**************************** Type Definitions *******************************/


/***************** Macros (Inline Functions) Definitions *********************/


/************************** Function Prototypes ******************************/

/*
 * Access Functions
 */
void XIo_DcrOut(u32 DcrRegister, u32 Data);
u32 XIo_DcrIn(u32 DcrRegister);

#ifdef __cplusplus
}
#endif

#endif /* end of protection macro */
