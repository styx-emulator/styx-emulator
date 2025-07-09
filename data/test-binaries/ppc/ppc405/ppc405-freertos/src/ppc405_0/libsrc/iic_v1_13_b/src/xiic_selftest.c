/* $Id: xiic_selftest.c,v 1.1 2007/12/03 15:44:58 meinelte Exp $ */
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
*       (c) Copyright 2002-2005 Xilinx Inc.
*       All rights reserved.
*
******************************************************************************/
/*****************************************************************************/
/**
*
* @file xiic_selftest.c
*
* Contains selftest functions for the XIic component.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- --- ------- -----------------------------------------------
* 1.01b jhl 03/26/02 repartioned the driver
* 1.01c ecm 12/05/02 new rev
* 1.01c sv  05/09/05 Changed the data being written to the Address/Control
*                    Register and removed the code for testing the
*                    Receive Data Register.
* 1.13a wgr  03/22/07 Converted to new coding style.
* </pre>
*
****************************************************************************/

/***************************** Include Files *******************************/

#include "xiic.h"
#include "xiic_i.h"
#include "xio.h"

/************************** Constant Definitions ***************************/


/**************************** Type Definitions *****************************/


/***************** Macros (Inline Functions) Definitions *******************/


/************************** Function Prototypes ****************************/


/************************** Variable Definitions **************************/


/*****************************************************************************/
/**
*
* Runs a limited self-test on the driver/device. The self-test is destructive
* in that a reset of the device is performed in order to check the reset
* values of the registers and to get the device into a known state. There is no
* loopback capabilities for the device such that this test does not send or
* receive data.
*
* @param    InstancePtr is a pointer to the XIic instance to be worked on.
*
* @return
*
* <pre>
*   XST_SUCCESS                         No errors found
*   XST_IIC_STAND_REG_ERROR             One or more IIC regular registers did
*                                       not zero on reset or read back
*                                       correctly based on what was written
*                                       to it
*   XST_IIC_TX_FIFO_REG_ERROR           One or more IIC parametrizable TX
*                                       FIFO registers did not zero on reset
*                                       or read back correctly based on what
*                                       was written to it
*   XST_IIC_RX_FIFO_REG_ERROR           One or more IIC parametrizable RX
*                                       FIFO registers did not zero on reset
*                                       or read back correctly based on what
*                                       was written to it
*   XST_IIC_STAND_REG_RESET_ERROR       A non parameterizable reg  value after
*                                       reset not valid
*   XST_IIC_TX_FIFO_REG_RESET_ERROR     Tx fifo, included in design, value
*                                       after reset not valid
*   XST_IIC_RX_FIFO_REG_RESET_ERROR     Rx fifo, included in design, value
*                                       after reset not valid
*   XST_IIC_TBA_REG_RESET_ERROR         10 bit addr, incl in design, value
*                                       after reset not valid
*   XST_IIC_CR_READBACK_ERROR           Read of the control register didn't
*                                       return value written
*   XST_IIC_DTR_READBACK_ERROR          Read of the data Tx reg didn't return
*                                       value written
*   XST_IIC_DRR_READBACK_ERROR          Read of the data Receive reg didn't
*                                       return value written
*   XST_IIC_ADR_READBACK_ERROR          Read of the data Tx reg didn't return
*                                       value written
*   XST_IIC_TBA_READBACK_ERROR          Read of the 10 bit addr reg didn't
*                                       return written value
* </pre>
*
* @note
*
* Only the registers that have be included into the hardware design are
* tested, such as, 10-bit vs 7-bit addressing.
*
****************************************************************************/
int XIic_SelfTest(XIic * InstancePtr)
{
	int Status = XST_SUCCESS;

	XASSERT_NONVOID(InstancePtr != NULL);
	XASSERT_NONVOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);

	/*
	 * Reset the device so it's in a known state and the default state of
	 * the registers can be tested
	 */
	XIic_Reset(InstancePtr);

	/*
	 * Test the standard - non parameterizable registers to ensure they are
	 * in the default state
	 */
	if ((XIo_In8(InstancePtr->BaseAddress + XIIC_CR_REG_OFFSET) &
	     XIo_In8(InstancePtr->BaseAddress + XIIC_SR_REG_OFFSET) &
	     XIo_In8(InstancePtr->BaseAddress + XIIC_DTR_REG_OFFSET) &
	     XIo_In8(InstancePtr->BaseAddress + XIIC_DRR_REG_OFFSET) &
	     XIo_In8(InstancePtr->BaseAddress + XIIC_ADR_REG_OFFSET)) != 0) {
		Status = XST_IIC_STAND_REG_RESET_ERROR;
	}

	if (XIo_In8(InstancePtr->BaseAddress + XIIC_TFO_REG_OFFSET) != 0) {
		Status = XST_IIC_TX_FIFO_REG_RESET_ERROR;
	}

	if ((XIo_In8(InstancePtr->BaseAddress + XIIC_RFO_REG_OFFSET) &
	     XIo_In8(InstancePtr->BaseAddress + XIIC_RFD_REG_OFFSET)) != 0) {
		Status = XST_IIC_RX_FIFO_REG_RESET_ERROR;
	}

	/*
	 * Test the 10-bit address parameterizable register only if it's supposed
	 * to be in the hardware
	 */
	if (InstancePtr->Has10BitAddr == TRUE) {
		if (XIo_In8(InstancePtr->BaseAddress + XIIC_TBA_REG_OFFSET) !=
		    0) {
			Status = XST_IIC_TBA_REG_RESET_ERROR;
		}
	}

	/*
	 * Perform register write/readback tests to verify the registers are
	 * working, test the control register by writing all 1's except the
	 * MSMS bit.
	 */
	XIo_Out8(InstancePtr->BaseAddress + XIIC_CR_REG_OFFSET, 0x7B);
	if (XIo_In8(InstancePtr->BaseAddress + XIIC_CR_REG_OFFSET) != 0x7B) {
		Status = XST_IIC_CR_READBACK_ERROR;
	}

	/* Reset device to remove the affects of the previous test */

	XIic_Reset(InstancePtr);

	/* Test the data transmit register */

	XIo_Out8(InstancePtr->BaseAddress + XIIC_DTR_REG_OFFSET, 0xFF);
	if (XIo_In8(InstancePtr->BaseAddress + XIIC_DTR_REG_OFFSET) != 0xFF) {
		Status = XST_IIC_DTR_READBACK_ERROR;
	}

	/* Test the address register */

	XIo_Out8(InstancePtr->BaseAddress + XIIC_ADR_REG_OFFSET, 0xFE);
	if (XIo_In8(InstancePtr->BaseAddress + XIIC_ADR_REG_OFFSET) != 0xFE) {
		Status = XST_IIC_ADR_READBACK_ERROR;
	}

	/* Test 10-bit address register only if it's in the hardware */

	if (InstancePtr->Has10BitAddr == TRUE) {
		XIo_Out8(InstancePtr->BaseAddress + XIIC_TBA_REG_OFFSET, 0x07);
		if (XIo_In8(InstancePtr->BaseAddress + XIIC_TBA_REG_OFFSET) !=
		    0x07) {
			Status = XST_IIC_TBA_READBACK_ERROR;
		}
	}


	/* Reset the device so that it's in a known state before returning */

	XIic_Reset(InstancePtr);
	return Status;
}
