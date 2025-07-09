/* $Id */
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
/*****************************************************************************/
/**
* @file xgpio_intr.c
*
* Implements GPIO interrupt processing functions for the XGpio
* component. See xgpio.h for more information about the component.
*
* The functions in this file require the hardware device to be built with
* interrupt capabilities. The functions will assert if called using hardware
* that does not have interrupt capabilities.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 2.00a jhl  11/26/03 Initial release
* 2.11a mta  03/21/07 Updated to new coding style
* </pre>
*
*****************************************************************************/

/***************************** Include Files ********************************/
#include "xgpio.h"


/************************** Constant Definitions ****************************/

/**************************** Type Definitions ******************************/

/***************** Macros (Inline Functions) Definitions ********************/

/************************** Variable Definitions ****************************/

/************************** Function Prototypes *****************************/


/****************************************************************************/
/**
* Enable the interrupt output signal. Interrupts enabled through
* XGpio_InterruptEnable() will not be passed through until the global enable
* bit is set by this function. This function is designed to allow all
* interrupts (both channels) to be enabled easily for exiting a critical
* section. This function will assert if the hardware device has not been
* built with interrupt capabilities.
*
* @param	InstancePtr is the GPIO component to operate on.
*
* @return	None.
*
* @note		None.
*
*****************************************************************************/
void XGpio_InterruptGlobalEnable(XGpio * InstancePtr)
{
	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_VOID(InstancePtr->InterruptPresent == TRUE);

	XGpio_mWriteReg(InstancePtr->BaseAddress, XGPIO_GIE_OFFSET,
			XGPIO_GIE_GINTR_ENABLE_MASK);
}


/****************************************************************************/
/**
* Disable the interrupt output signal. Interrupts enabled through
* XGpio_InterruptEnable() will no longer be passed through until the global
* enable bit is set by XGpio_InterruptGlobalEnable(). This function is
* designed to allow all interrupts (both channels) to be disabled easily for
* entering a critical section. This function will assert if the hardware
* device has not been built with interrupt capabilities.
*
* @param	InstancePtr is the GPIO component to operate on.
*
* @return	None.
*
* @note		None.
*
*****************************************************************************/
void XGpio_InterruptGlobalDisable(XGpio * InstancePtr)
{
	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_VOID(InstancePtr->InterruptPresent == TRUE);


	XGpio_mWriteReg(InstancePtr->BaseAddress, XGPIO_GIE_OFFSET, 0x0);

}


/****************************************************************************/
/**
* Enable interrupts. The global interrupt must also be enabled by calling
* XGpio_InterruptGlobalEnable() for interrupts to occur. This function will
* assert if the hardware device has not been built with interrupt capabilities.
*
* @param	InstancePtr is the GPIO component to operate on.
* @param	Mask is the mask to enable. Bit positions of 1 are enabled.
*		This mask is formed by OR'ing bits from XGPIO_IR* bits which
*		are contained in xgpio_l.h.
*
* @return	None.
*
* @note		None.
*
*****************************************************************************/
void XGpio_InterruptEnable(XGpio * InstancePtr, u32 Mask)
{
	u32 Register;

	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_VOID(InstancePtr->InterruptPresent == TRUE);

	/*
	 * Read the interrupt enable register and only enable the specified
	 * interrupts without disabling or enabling any others.
	 */

	Register = XGpio_mReadReg(InstancePtr->BaseAddress, XGPIO_IER_OFFSET);
	XGpio_mWriteReg(InstancePtr->BaseAddress, XGPIO_IER_OFFSET,
			Register | Mask);

}


/****************************************************************************/
/**
* Disable interrupts. This function allows specific interrupts for each
* channel to be disabled. This function will assert if the hardware device
* has not been built with interrupt capabilities.
*
* @param	InstancePtr is the GPIO component to operate on.
* @param 	Mask is the mask to disable. Bits set to 1 are disabled. This
*		mask is formed by OR'ing bits from XGPIO_IR* bits which are
*		contained in xgpio_l.h.
*
* @return	None.
*
* @note		None.
*
*****************************************************************************/
void XGpio_InterruptDisable(XGpio * InstancePtr, u32 Mask)
{
	u32 Register;

	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_VOID(InstancePtr->InterruptPresent == TRUE);

	/*
	 * Read the interrupt enable register and only disable the specified
	 * interrupts without enabling or disabling any others.
	 */
	Register = XGpio_mReadReg(InstancePtr->BaseAddress, XGPIO_IER_OFFSET);
	XGpio_mWriteReg(InstancePtr->BaseAddress, XGPIO_IER_OFFSET,
			Mask & ~Register);

}

/****************************************************************************/
/**
* Clear pending interrupts with the provided mask. This function should be
* called after the software has serviced the interrupts that are pending.
* This function will assert if the hardware device has not been built with
* interrupt capabilities.
*
* @param 	InstancePtr is the GPIO component to operate on.
* @param 	Mask is the mask to clear pending interrupts for. Bit positions
*		of 1 are cleared. This mask is formed by OR'ing bits from
*		XGPIO_IR* bits which are contained in xgpio_l.h.
*
* @return	None.
*
* @note		None.
*
*****************************************************************************/
void XGpio_InterruptClear(XGpio * InstancePtr, u32 Mask)
{
	u32 Register;

	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_VOID(InstancePtr->InterruptPresent == TRUE);

	/*
	 * Read the interrupt status register and only clear the interrupts
	 * that are specified without affecting any others.  Since the register
	 * is a toggle on write, make sure any bits to be written are already
	 * set.
	 */
	Register = XGpio_mReadReg(InstancePtr->BaseAddress, XGPIO_ISR_OFFSET);
	XGpio_mWriteReg(InstancePtr->BaseAddress, XGPIO_ISR_OFFSET,
			Register & Mask);


}


/****************************************************************************/
/**
* Returns the interrupt enable mask. This function will assert if the
* hardware device has not been built with interrupt capabilities.
*
* @param	InstancePtr is the GPIO component to operate on.
*
* @return	A mask of bits made from XGPIO_IR* bits which are contained in
*		xgpio_l.h.
*
* @return	None.
*
* @note		None.
*
*****************************************************************************/
u32 XGpio_InterruptGetEnabled(XGpio * InstancePtr)
{
	XASSERT_NONVOID(InstancePtr != NULL);
	XASSERT_NONVOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_NONVOID(InstancePtr->InterruptPresent == TRUE);

	return XGpio_mReadReg(InstancePtr->BaseAddress, XGPIO_IER_OFFSET);
}


/****************************************************************************/
/**
* Returns the status of interrupt signals. Any bit in the mask set to 1
* indicates that the channel associated with the bit has asserted an interrupt
* condition. This function will assert if the hardware device has not been
* built with interrupt capabilities.
*
* @param	InstancePtr is the GPIO component to operate on.
*
* @return	A pointer to a mask of bits made from XGPIO_IR* bits which are
*		 contained in xgpio_l.h.
*
* @note
*
* The interrupt status indicates the status of the device irregardless if
* the interrupts from the devices have been enabled or not through
* XGpio_InterruptEnable().
*
*****************************************************************************/
u32 XGpio_InterruptGetStatus(XGpio * InstancePtr)
{
	XASSERT_NONVOID(InstancePtr != NULL);
	XASSERT_NONVOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_NONVOID(InstancePtr->InterruptPresent == TRUE);


	return XGpio_mReadReg(InstancePtr->BaseAddress, XGPIO_ISR_OFFSET);
}
