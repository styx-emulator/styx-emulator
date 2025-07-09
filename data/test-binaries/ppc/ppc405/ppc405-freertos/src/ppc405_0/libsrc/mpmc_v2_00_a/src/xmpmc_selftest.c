/* $Id: xmpmc_selftest.c,v 1.2 2007/12/03 16:22:46 svemula Exp $ */
/******************************************************************************
*
*       XILINX IS PROVIDING THIS DESIGN, CODE, OR INFORMATION "AS IS"
*       AS A COURTESY TO YOU, SOLELY FOR USE IN DEVELOPING PROGRAMS AND
*       SOLUTIONS FOR XILINX DEVICES. BY PROVIDING THIS DESIGN, CODE,
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
*       (c) Copyright 2007 Xilinx Inc.
*       All rights reserved.
*
******************************************************************************/
/**
* @file xmpmc_selftest.c
*
* The implementation of the XMpmc component's functionality that is related
* to self test. See xmpmc.h for more information about the component.
*
* @note		None.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a mta  02/22/07 First release
* </pre>
*
*****************************************************************************/

/***************************** Include Files ********************************/

#include "xmpmc.h"

/************************** Constant Definitions ****************************/

/**************************** Type Definitions ******************************/

/***************** Macros (Inline Functions) Definitions ********************/

/************************** Variable Definitions ****************************/

/************************** Function Prototypes *****************************/

/****************************************************************************/
/**
* Perform a self-test on the MPMC device. Self-test will read, write and verify
* that some of the registers of the device are functioning correctly. This
* function will restore the state of the device to state it was in prior to
* the function call.
*
* @param	InstancePtr is the MPMC component to operate on.
*
* @return	XST_SUCCESS if successful else XST_FAILURE.
*
* @note		None.
*
*****************************************************************************/
int XMpmc_SelfTest(XMpmc * InstancePtr)
{
	int Status = XST_SUCCESS;
	u32 IeRegister;
	u32 GieRegister;
	u32 PmCtrlReg;


	/*
	 * Assert arguments
	 */
	XASSERT_NONVOID(InstancePtr != NULL);
	XASSERT_NONVOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);

	/*
	 * Self Test for the MPMC ECC functionality.
	 */
	if (InstancePtr->ConfigPtr.EccSupportPresent == TRUE) {

		/*
		 * Save a copy of the Global Interrupt Enable register
		 * and interrupt enable register before writing them so
		 * that they can be restored.
		 */
		GieRegister = XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
					     XMPMC_DGIE_OFFSET);

		IeRegister = XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
					    XMPMC_IPIER_OFFSET);
		/*
		 * Disable the Global Interrupt so that enabling the interrupts
		 * won't affect the user.
		 */
		XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress,
				XMPMC_DGIE_OFFSET, 0);

		/*
		 * Enable the Single Error interrupt and then verify that the
		 * register reads back correctly.
		 */
		XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress,
				XMPMC_IPIER_OFFSET,
				XMPMC_IPIXR_SE_IX_MASK);

		if (XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
				   XMPMC_IPIER_OFFSET) !=
				   XMPMC_IPIXR_SE_IX_MASK) {
			Status = XST_FAILURE;
		}

		/*
		 * Restore the IP Interrupt Enable Register to the value before
		 * the test.
		 */
		XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress,
				XMPMC_IPIER_OFFSET, IeRegister);

		/*
		 * Restore the Global Interrupt Register to the value before the
		 * test.
		 */
		XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress,
				XMPMC_DGIE_OFFSET, GieRegister);

	}

	/*
	 * Self Test for the MPMC Static Phy functionality.
	 */
	if (InstancePtr->ConfigPtr.StaticPhyPresent == TRUE) {

	}

	/*
	 * Self Test for the MPMC Performance Monitor functionality.
	 */
	if (InstancePtr->ConfigPtr.PerfMonitorEnable == TRUE) {


		/*
		 * Save a copy of the Performance Monitor Control Register
		 * before writing it so that it can be restored.
		 */
		PmCtrlReg = XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
					  XMPMC_PMCTRL_OFFSET);

		/*
		 * Disable the Performance Monitoring for all the ports and
		 * verify that it is disabled.
		 */
		XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress,
				XMPMC_PMCTRL_OFFSET, 0x0);
		if (XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
				   XMPMC_PMCTRL_OFFSET) != 0x0) {
			Status = XST_FAILURE;
		}

		/*
		 * Enable the Performance Monitoring for the Port 0 and
		 * verify that it is enabled.
		 */
		XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress,
				XMPMC_PMCTRL_OFFSET, XMPMC_PMREG_PM0_MASK);
		if (XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
					XMPMC_PMCTRL_OFFSET) !=
					XMPMC_PMREG_PM0_MASK) {
			Status = XST_FAILURE;
		}


		/*
		 * Restore the Performance Monitor Control Register to the value
		 * before the test.
		 */
		XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress,
				XMPMC_PMCTRL_OFFSET, PmCtrlReg);

	}


	return Status;
}
