/* $Id: xmpmc_intr.c,v 1.2 2007/12/03 16:22:46 svemula Exp $ */
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
* @file xmpmc_intr.c
*
* The implementation of the XMpmc component's functionality that is related
* to interrupts. See xmpmc.h for more information about the component. The
* functions that are contained in this file require that the hardware device
* is built with interrupt support.
*
* @note		None
*
* <pre>
*
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a mta  02/24/07 First release
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
* Enable the core's interrupt output signal. Interrupts enabled through
* XMpmc_IntrEnable() will not occur until the global enable bit is set
* by this function. This function is designed to allow all interrupts to be
* enabled easily for exiting a critical section.
*
* @param	InstancePtr is the MPMC component to operate on.
*
* @return	None.

* @note		This function will assert if the hardware device has not been
*		built with interrupt capabilities.
*
*****************************************************************************/
void XMpmc_IntrGlobalEnable(XMpmc * InstancePtr)
{
	u32 Register;

	/*
	 * Assert arguments
	 */
	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_VOID(InstancePtr->ConfigPtr.EccSupportPresent == TRUE);

	Register = XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
				  XMPMC_DGIE_OFFSET);
	XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress, XMPMC_DGIE_OFFSET,
			Register | XMPMC_DGIE_GIE_MASK);
}

/****************************************************************************/
/**
* Disable the core's interrupt output signal. Interrupts enabled through
* XMpmc_IntrEnable() will not occur until the global enable bit is set by
* XMpmc_IntrGlobalEnable(). This function is designed to allow all
* interrupts to be disabled easily for entering a critical section.
*
* @param	InstancePtr is the MPMC component to operate on.
*
* @return 	None.
*
* @note		This function will assert if the hardware device has not been
*		built with interrupt capabilities.
*
*****************************************************************************/
void XMpmc_IntrGlobalDisable(XMpmc * InstancePtr)
{
	u32 Register;

	/*
	 * Assert arguments.
	 */
	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_VOID(InstancePtr->ConfigPtr.EccSupportPresent == TRUE);

	Register = XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
				  XMPMC_DGIE_OFFSET);
	XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress, XMPMC_DGIE_OFFSET,
			Register & (~XMPMC_DGIE_GIE_MASK));
}

/****************************************************************************/
/**
* Enable ECC interrupts so that specific ECC errors will cause an interrupt.
* The function XMpmc_IntrGlobalEnable must also be called to enable any
* interrupt to occur.
*
* @param 	InstancePtr is the MPMC component to operate on.
* @param 	Mask is the mask to enable. Bit positions of 1 are enabled.
*		The mask is formed by OR'ing bits from XMPMC_IPIXR_*_MASK.
*
* @return 	None.
*
* @note		This function will assert if the hardware device has not been
*		built with interrupt capabilities.
*
*****************************************************************************/
void XMpmc_IntrEnable(XMpmc * InstancePtr, u32 Mask)
{
	u32 Register;

	/*
	 * Assert arguments.
	 */
	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_VOID(InstancePtr->ConfigPtr.EccSupportPresent == TRUE);

	/*
	 * Read the interrupt enable register and only enable the specified
	 * interrupts without disabling or enabling any others.
	 */
	Register = XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
				  XMPMC_IPIER_OFFSET);
	XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress, XMPMC_IPIER_OFFSET,
			Register | Mask);
}

/****************************************************************************/
/**
* Disable ECC interrupts so that ECC errors will not cause an interrupt.
*
* @param 	InstancePtr is the MPMC component to operate on.
* @param 	Mask is the mask to disable. Bits set to 1 are disabled.
*		The mask is formed by OR'ing bits from XMPMC_IPIXR_*_MASK.
*
* @return 	None.
*
* @note 	This function will assert if the hardware device has not been
*		built with interrupt capabilities.
*
*****************************************************************************/
void XMpmc_IntrDisable(XMpmc * InstancePtr, u32 Mask)
{
	u32 Register;

	/*
	 * Assert arguments.
	 */
	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_VOID(InstancePtr->ConfigPtr.EccSupportPresent == TRUE);

	/*
	 * Read the interrupt enable register and only disable the specified
	 * interrupts without enabling or disabling any others.
	 */
	Register = XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
				  XMPMC_IPIER_OFFSET);
	XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress, XMPMC_IPIER_OFFSET,
			Register & (~Mask));
}

/****************************************************************************/
/**
* Clear pending interrupts with the provided mask. An interrupt must be
* cleared after software has serviced it or it can cause another interrupt.
*
* @param 	InstancePtr is the MPMC component to operate on.
* @param 	Mask is the mask to clear pending interrupts for. Bit positions
*		of 1 are cleared. This mask is formed by OR'ing bits from
*		XMPMC_IPIXR_*_MASK.
*
* @return 	None.
*
* @note		This function will assert if the hardware device has not been
*		built with interrupt capabilities.
*
*****************************************************************************/
void XMpmc_IntrClear(XMpmc * InstancePtr, u32 Mask)
{
	u32 Register;

	/*
	 * Assert arguments.
	 */
	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_VOID(InstancePtr->ConfigPtr.EccSupportPresent == TRUE);

	/*
	 * Read the interrupt status register and only clear the interrupts
	 * that are specified without affecting any others. Since the register
	 * is a toggle on write, make sure any bits to be written are already
	 * set.
	 */
	Register = XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
				  XMPMC_IPISR_OFFSET);
	XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress, XMPMC_IPISR_OFFSET,
			Register & Mask);

}

/****************************************************************************/
/**
* Returns the interrupt enable mask as set by XMpmc_IntrEnable() which
* indicates which ECC interrupts are enabled or disabled.
*
* @param	InstancePtr is the MPMC component to operate on.
*
* @return	Mask of bits made from XMPMC_IPIXR_*_MASK.
*
* @note 	This function will assert if the hardware device has not been
*		built with interrupt capabilities.
*
*****************************************************************************/
u32 XMpmc_IntrGetEnabled(XMpmc * InstancePtr)
{
	/*
	 * Assert arguments.
	 */
	XASSERT_NONVOID(InstancePtr != NULL);
	XASSERT_NONVOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_NONVOID(InstancePtr->ConfigPtr.EccSupportPresent == TRUE);

	return XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
			      XMPMC_IPIER_OFFSET);
}

/****************************************************************************/
/**
* Returns the status of interrupts which indicates which ECC interrupts are
* pending.
*
* @param	InstancePtr is the MPMC component to operate on.
*
* @return 	Mask of bits made from XMPMC_IPIXR_*_MASK.
*
* @note		The interrupt status indicates the status of the device
*		irregardless if the interrupts from the devices have been
*		enabled or not through XMpmc_IntrEnable().
*
* 		This function will assert if the hardware device has not
*		been built with interrupt capabilities.
*
*****************************************************************************/
u32 XMpmc_IntrGetStatus(XMpmc * InstancePtr)
{
	/*
	 * Assert arguments
	 */
	XASSERT_NONVOID(InstancePtr != NULL);
	XASSERT_NONVOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_NONVOID(InstancePtr->ConfigPtr.EccSupportPresent == TRUE);

	return XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
			      XMPMC_IPISR_OFFSET);
}
