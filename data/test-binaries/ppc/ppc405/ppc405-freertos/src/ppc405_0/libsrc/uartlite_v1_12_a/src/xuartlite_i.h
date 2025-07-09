/* $Id: xuartlite_i.h,v 1.3 2007/05/31 00:29:42 wre Exp $ */
/*****************************************************************************
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
*****************************************************************************/
/****************************************************************************/
/**
*
* @file xuartlite_i.h
*
* Contains data which is shared between the files of the XUartLite component.
* It is intended for internal use only.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a ecm  08/31/01 First release
* 1.00b jhl  02/21/02 Reparitioned the driver for smaller files
* 1.00b rpm  04/24/02 Moved register definitions to xuartlite_l.h and
*                     updated macro naming convention
* </pre>
*
*****************************************************************************/

#ifndef XUARTLITE_I_H /* prevent circular inclusions */
#define XUARTLITE_I_H /* by using protection macros */

#ifdef __cplusplus
extern "C" {
#endif

/***************************** Include Files ********************************/

#include "xuartlite.h"
#include "xuartlite_l.h"

/************************** Constant Definitions ****************************/

/**************************** Type Definitions ******************************/

/***************** Macros (Inline Functions) Definitions ********************/

/****************************************************************************
*
* Update the statistics of the instance.
*
* @param	InstancePtr is a pointer to the XUartLite instance.
* @param	StatusRegister contains the contents of the UART status
*		register to update the statistics with.
*
* @return	None.
*
* @note
*
* Signature: void XUartLite_mUpdateStats(XUartLite *InstancePtr,
*						u32 StatusRegister)
*
*****************************************************************************/
#define XUartLite_mUpdateStats(InstancePtr, StatusRegister)	\
{								\
	if ((StatusRegister) & XUL_SR_OVERRUN_ERROR)		\
	{							\
		(InstancePtr)->Stats.ReceiveOverrunErrors++;	\
	}							\
	if ((StatusRegister) & XUL_SR_PARITY_ERROR)		\
	{							\
		(InstancePtr)->Stats.ReceiveParityErrors++;	\
	}							\
	if ((StatusRegister) & XUL_SR_FRAMING_ERROR)		\
	{							\
		(InstancePtr)->Stats.ReceiveFramingErrors++;	\
	}							\
}

/****************************************************************************
*
* Clear the statistics for the instance.
*
* @param	InstancePtr is a pointer to the XUartLite instance.
*
* @return	None.
*
* @note
*
* Signature: void XUartLite_mClearStats(XUartLite *InstancePtr)
*
*****************************************************************************/
#define XUartLite_mClearStats(InstancePtr)			\
{								\
	(InstancePtr)->Stats.TransmitInterrupts = 0UL;		\
	(InstancePtr)->Stats.ReceiveInterrupts = 0UL;		\
	(InstancePtr)->Stats.CharactersTransmitted = 0UL;	\
	(InstancePtr)->Stats.CharactersReceived = 0UL;		\
	(InstancePtr)->Stats.ReceiveOverrunErrors = 0UL;	\
	(InstancePtr)->Stats.ReceiveFramingErrors = 0UL;	\
	(InstancePtr)->Stats.ReceiveParityErrors = 0UL;		\
}

/************************** Variable Definitions ****************************/

/* the configuration table */
extern XUartLite_Config XUartLite_ConfigTable[];

/************************** Function Prototypes *****************************/

unsigned int XUartLite_SendBuffer(XUartLite *InstancePtr);
unsigned int XUartLite_ReceiveBuffer(XUartLite *InstancePtr);

#ifdef __cplusplus
}
#endif

#endif		/* end of protection macro */
