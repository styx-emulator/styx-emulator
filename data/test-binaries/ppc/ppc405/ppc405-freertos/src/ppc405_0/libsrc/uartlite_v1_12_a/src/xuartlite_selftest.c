/* $Id: xuartlite_selftest.c,v 1.1 2007/05/15 07:00:27 mta Exp $ */
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
* @file xuartlite_selftest.c
*
* This file contains the self-test functions for the UART Lite component
* (XUartLite).
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a ecm  08/31/01 First release
* 1.00b jhl  02/21/02 Repartitioned the driver for smaller files
* </pre>
*
*****************************************************************************/

/***************************** Include Files ********************************/

#include "xbasic_types.h"
#include "xstatus.h"
#include "xuartlite.h"
#include "xuartlite_i.h"
#include "xio.h"

/************************** Constant Definitions ****************************/


/**************************** Type Definitions ******************************/


/***************** Macros (Inline Functions) Definitions ********************/


/************************** Variable Definitions ****************************/


/************************** Function Prototypes *****************************/


/****************************************************************************/
/**
*
* Runs a self-test on the device hardware.  Since there is no way to perform a
* loopback in the hardware, this test can only check the state of the status
* register to verify it is correct.  This test assumes that the hardware
* device is still in its reset state, but has been initialized with the
* Initialize function.
*
* @param	InstancePtr is a pointer to the XUartLite instance.
*
* @return
* 		- XST_SUCCESS if the self-test was successful.
* 		- XST_FAILURE if the self-test failed, the status register
*			value was not correct
*
* @note		None.
*
******************************************************************************/
int XUartLite_SelfTest(XUartLite *InstancePtr)
{
	u32 StatusRegister;

	/*
	 * Assert validates the input arguments
	 */
	XASSERT_NONVOID(InstancePtr != NULL);
	XASSERT_NONVOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);

	/* get the control register value to check if it's the correct value
	 * after a reset
	 */
	StatusRegister = XIo_In32(InstancePtr->RegBaseAddress +
					XUL_STATUS_REG_OFFSET);

	/* if the status register is any other value other than
	 * XUL_SR_TX_FIFO_EMPTY then the test is a failure since this is
	 * the not the value after reset
	 */
	if (StatusRegister != XUL_SR_TX_FIFO_EMPTY) {
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}
