/* $Id: xgpio_extra.c,v 1.1 2007/05/15 06:49:42 mta Exp $ */
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
*       (c) Copyright 2002-2007 Xilinx Inc.
*       All rights reserved.
*
******************************************************************************/
/**
* @file xgpio_extra.c
*
* The implementation of the XGpio component's advanced discrete functions.
* See xgpio.h for more information about the component.
*
* @note
*
* None
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a rmm  02/04/02 First release
* 2.00a jhl  12/16/02 Update for dual channel and interrupt support
* 2.11a mta  03/21/07 Updated to new coding style
* </pre>
*
*****************************************************************************/

/***************************** Include Files ********************************/

#include "xgpio.h"
#include "xgpio_i.h"

/************************** Constant Definitions ****************************/

/**************************** Type Definitions ******************************/

/***************** Macros (Inline Functions) Definitions ********************/

/************************** Variable Definitions ****************************/

/************************** Function Prototypes *****************************/


/****************************************************************************/
/**
* Set output discrete(s) to logic 1 for the specified GPIO channel.
*
* @param	InstancePtr is a pointer to an XGpio instance to be worked on.
* @param	Channel contains the channel of the GPIO (1 or 2) to operate on.
* @param	Mask is the set of bits that will be set to 1 in the discrete
*		data register. All other bits in the data register are
*		unaffected.
*
* @return	None.
*
* @note
*
* The hardware must be built for dual channels if this function is used
* with any channel other than 1.  If it is not, this function will assert.
*
*****************************************************************************/
void XGpio_DiscreteSet(XGpio * InstancePtr, unsigned Channel, u32 Mask)
{
	u32 Current;
	unsigned DataOffset;

	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_VOID((Channel == 1) ||
		     ((Channel == 2) && (InstancePtr->IsDual == TRUE)));

	/*
	 * Calculate the offset to the data register of the GPIO once
	 */
	DataOffset = ((Channel - 1) * XGPIO_CHAN_OFFSET) + XGPIO_DATA_OFFSET;

	/*
	 * Read the contents of the data register, merge in Mask and write
	 * back results
	 */
	Current = XGpio_mReadReg(InstancePtr->BaseAddress, DataOffset);
	Current |= Mask;
	XGpio_mWriteReg(InstancePtr->BaseAddress, DataOffset, Current);
}


/****************************************************************************/
/**
* Set output discrete(s) to logic 0 for the specified GPIO channel.
*
* @param	InstancePtr is a pointer to an XGpio instance to be worked on.
* @param	Channel contains the channel of the GPIO (1 or 2) to operate on.
* @param	Mask is the set of bits that will be set to 0 in the discrete
*		data register. All other bits in the data register are
*		unaffected.
*
* @return	None.
*
* @note
*
* The hardware must be built for dual channels if this function is used
* with any channel other than 1.  If it is not, this function will assert.
*
*****************************************************************************/
void XGpio_DiscreteClear(XGpio * InstancePtr, unsigned Channel, u32 Mask)
{
	u32 Current;
	unsigned DataOffset;

	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_VOID((Channel == 1) ||
		     ((Channel == 2) && (InstancePtr->IsDual == TRUE)));

	/*
	 * Calculate the offset to the data register of the GPIO once
	 */
	DataOffset = ((Channel - 1) * XGPIO_CHAN_OFFSET) + XGPIO_DATA_OFFSET;

	/*
	 * Read the contents of the data register, merge in Mask and write
	 * back results
	 */
	Current = XGpio_mReadReg(InstancePtr->BaseAddress, DataOffset);
	Current &= ~Mask;
	XGpio_mWriteReg(InstancePtr->BaseAddress, DataOffset, Current);
}
