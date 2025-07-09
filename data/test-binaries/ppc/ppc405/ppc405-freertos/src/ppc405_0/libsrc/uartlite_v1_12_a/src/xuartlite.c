/* $Id: xuartlite.c,v 1.1 2007/05/15 07:00:27 mta Exp $ */
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
*       (c) Copyright 2002-2005 Xilinx Inc.
*       All rights reserved.
*
*****************************************************************************/
/****************************************************************************/
/**
*
* @file xuartlite.c
*
* Contains required functions for the XUartLite driver. See the xuartlite.h
* header file for more details on this driver.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a ecm  08/31/01 First release
* 1.00b jhl  02/21/02 Repartitioned the driver for smaller files
* 1.00b rmm  05/13/03 Fixed diab compiler warnings relating to asserts
* 1.01a jvb  12/13/05 I changed Initialize() into CfgInitialize(), and made
*                     CfgInitialize() take a pointer to a config structure
*                     instead of a device id. I moved Initialize() into
*                     xgpio_sinit.c, and had Initialize() call CfgInitialize()
*                     after it retrieved the config structure using the device
*                     id. I removed include of xparameters.h along with any
*                     dependencies on xparameters.h and the _g.c config table.
* 1.01a wsy  05/08/06 fix CR220811 and CR224103.
*
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

static void StubHandler(void *CallBackRef, unsigned int ByteCount);

/****************************************************************************/
/**
*
* Initialize a XUartLite instance. The receive and transmit FIFOs of the
* UART are not flushed, so the user may want to flush them. The hardware
* device does not have any way to disable the receiver such that any valid
* data may be present in the receive FIFO.  This function disables the UART
* interrupt. The baudrate and format of the data are fixed in the hardware
* at hardware build time.
*
* @param	InstancePtr is a pointer to the XUartLite instance.
* @param	Config is a reference to a structure containing information
*		about a specific UART Lite device. This function initializes an
*		InstancePtr object for a specific device specified by the
*		contents of Config. This function can initialize multiple
*		instance objects with the use of multiple calls giving different
*		Config information on each call.
* @param 	EffectiveAddr is the device base address in the virtual memory
*		address space. The caller is responsible for keeping the address
*		mapping from EffectiveAddr to the device physical base address
*		unchanged once this function is invoked. Unexpected errors may
*		occur if the address mapping changes after this function is
*		called. If address translation is not used, use
*		Config->BaseAddress for this parameters, passing the physical
*		address instead.
*
* @return
* 		- XST_SUCCESS if everything starts up as expected.
*
* @note		The Config pointer argument is not used by this function,
*		but is provided to keep the function signature consistent
*		with other drivers.
*
*****************************************************************************/
int XUartLite_CfgInitialize(XUartLite *InstancePtr, XUartLite_Config *Config,
				u32 EffectiveAddr)
{
	/*
	 * Assert validates the input arguments
	 */
	XASSERT_NONVOID(InstancePtr != NULL);

	/*
	 * Set some default values, including setting the callback
	 * handlers to stubs.
	 */

	InstancePtr->SendBuffer.NextBytePtr = NULL;
	InstancePtr->SendBuffer.RemainingBytes = 0;
	InstancePtr->SendBuffer.RequestedBytes = 0;

	InstancePtr->ReceiveBuffer.NextBytePtr = NULL;
	InstancePtr->ReceiveBuffer.RemainingBytes = 0;
	InstancePtr->ReceiveBuffer.RequestedBytes = 0;

	InstancePtr->IsReady = XCOMPONENT_IS_READY;
	InstancePtr->RegBaseAddress = EffectiveAddr;
	InstancePtr->RecvHandler = StubHandler;
	InstancePtr->SendHandler = StubHandler;

	/* Write to the control register to disable the interrupts, don't
	 * reset the FIFOs are the user may want the data that's present
	 */
	XIo_Out32(InstancePtr->RegBaseAddress + XUL_CONTROL_REG_OFFSET, 0);

	/*
	 * Clear the statistics for this driver
	 */
	XUartLite_mClearStats(InstancePtr);

	return XST_SUCCESS;
}

/****************************************************************************/
/**
*
* This functions sends the specified buffer of data using the UART in either
* polled or interrupt driven modes. This function is non-blocking such that it
* will return before the data has been sent by the UART. If the UART is busy
* sending data, it will return and indicate zero bytes were sent.
*
* In a polled mode, this function will only send as much data as the UART can
* buffer in the FIFO. The application may need to call it repeatedly to
* send a buffer.
*
* In interrupt mode, this function will start sending the specified buffer and
* then the interrupt handler of the driver will continue sending data until the
* buffer has been sent. A callback function, as specified by the application,
* will be called to indicate the completion of sending the buffer.
*
* @param	InstancePtr is a pointer to the XUartLite instance.
* @param	BufferPtr is pointer to a buffer of data to be sent.
* @param	NumBytes contains the number of bytes to be sent. A value of
*		zero will stop a previous send operation that is in progress
*		in interrupt mode. Any data that was already put into the
*		transmit FIFO will be sent.
*
* @return	The number of bytes actually sent.
*
* @note		The number of bytes is not asserted so that this function may
*		be called with a value of zero to stop an operation that is
*		already in progress.
*
******************************************************************************/
unsigned int XUartLite_Send(XUartLite *InstancePtr, u8 *DataBufferPtr,
				unsigned int NumBytes)
{
	unsigned int BytesSent;
	u32 StatusRegister;

	/*
	 * Assert validates the input arguments
	 */
	XASSERT_NONVOID(InstancePtr != NULL);
	XASSERT_NONVOID(DataBufferPtr != NULL);
	XASSERT_NONVOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_NONVOID(((signed)NumBytes) >= 0);

	/* Enter a critical region by disabling the UART interrupts to
	 * allow this call to stop a previous operation that may be interrupt
	 * driven
	 */
	StatusRegister = XUartLite_mGetStatusReg(InstancePtr->RegBaseAddress);

	XIo_Out32(InstancePtr->RegBaseAddress + XUL_CONTROL_REG_OFFSET, 0);

	/* Setup the specified buffer to be sent by setting the instance
	 * variables so it can be sent with polled or interrupt mode
	 */
	InstancePtr->SendBuffer.RequestedBytes = NumBytes;
	InstancePtr->SendBuffer.RemainingBytes = NumBytes;
	InstancePtr->SendBuffer.NextBytePtr = DataBufferPtr;

	/* Restore the interrupt enable register to it's previous value such
	 * that the critical region is exited.
	 * This is done here to minimize the amount of time the interrupt is
	 * disabled since there is only one interrupt and the receive could
	 * be filling up while interrupts are blocked.
	 */

	StatusRegister &= XUL_CR_ENABLE_INTR;
	XIo_Out32(InstancePtr->RegBaseAddress + XUL_CONTROL_REG_OFFSET,
			StatusRegister);

	/* Send the buffer using the UART and return the number of bytes sent */

	BytesSent = XUartLite_SendBuffer(InstancePtr);

	return BytesSent;
}


/****************************************************************************/
/**
*
* This function will attempt to receive a specified number of bytes of data
* from the UART and store it into the specified buffer. This function is
* designed for either polled or interrupt driven modes. It is non-blocking
* such that it will return if no data has already received by the UART.
*
* In a polled mode, this function will only receive as much data as the UART
* can buffer in the FIFO. The application may need to call it repeatedly to
* receive a buffer. Polled mode is the default mode of operation for the driver.
*
* In interrupt mode, this function will start receiving and then the interrupt
* handler of the driver will continue receiving data until the buffer has been
* received. A callback function, as specified by the application, will be called
* to indicate the completion of receiving the buffer or when any receive errors
* or timeouts occur. Interrupt mode must be enabled using the SetOptions
* function.
*
* @param	InstancePtr is a pointer to the XUartLite instance.
* @param	BufferPtr is pointer to buffer for data to be received into
* @param	NumBytes is the number of bytes to be received. A value of zero
*		will stop a previous receive operation that is in progress in
*		interrupt mode.
*
* @return	The number of bytes received.
*
* @note 	The number of bytes is not asserted so that this function
*		may be called with a value of zero to stop an operation
*		that is already in progress.
*
*****************************************************************************/
unsigned int XUartLite_Recv(XUartLite *InstancePtr, u8 *DataBufferPtr,
				unsigned int NumBytes)
{
	unsigned int ReceivedCount;
	u32 StatusRegister;

	/*
	 * Assert validates the input arguments
	 */
	XASSERT_NONVOID(InstancePtr != NULL);
	XASSERT_NONVOID(DataBufferPtr != NULL);
	XASSERT_NONVOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);
	XASSERT_NONVOID(((signed)NumBytes) >= 0);

	/* Enter a critical region by disabling all the UART interrupts to allow
	 * this call to stop a previous operation that may be interrupt driven
	 */
	StatusRegister = XUartLite_mGetStatusReg(InstancePtr->RegBaseAddress);
	XIo_Out32(InstancePtr->RegBaseAddress + XUL_CONTROL_REG_OFFSET, 0);

	/* Setup the specified buffer to be received by setting the instance
	 * variables so it can be received with polled or interrupt mode
	 */
	InstancePtr->ReceiveBuffer.RequestedBytes = NumBytes;
	InstancePtr->ReceiveBuffer.RemainingBytes = NumBytes;
	InstancePtr->ReceiveBuffer.NextBytePtr = DataBufferPtr;

	/* Restore the interrupt enable register to it's previous value such
	 * that the critical region is exited
	 */
	StatusRegister &= XUL_CR_ENABLE_INTR;
	XIo_Out32(InstancePtr->RegBaseAddress + XUL_CONTROL_REG_OFFSET,
			StatusRegister);

	/* Receive the data from the UART and return the number of bytes
	 * received
	 * This is done here to minimize the amount of time the interrupt is
	 * disabled since there is only one interrupt and the transmit could
	 * be emptying out while interrupts are blocked.
	 */

	ReceivedCount = XUartLite_ReceiveBuffer(InstancePtr);

	return ReceivedCount;

}

/****************************************************************************/
/**
*
* This function resets the FIFOs, both transmit and receive, of the UART such
* that they are emptied.  Since the UART does not have any way to disable it
* from receiving data, it may be necessary for the application to reset the
* FIFOs to get rid of any unwanted data.
*
* @param	InstancePtr is a pointer to the XUartLite instance .
*
* @return	None.
*
* @note		None.
*
*****************************************************************************/
void XUartLite_ResetFifos(XUartLite *InstancePtr)
{
	u32 Register;

	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);

	/* Read the status register 1st such that the next write to the control
	 * register won't destroy the state of the interrupt enable bit
	 */
	Register =
		XIo_In32(InstancePtr->RegBaseAddress + XUL_STATUS_REG_OFFSET);

	/*
	 * Mask off the interrupt enable bit to maintain it's state.
	 */

	Register &= XUL_SR_INTR_ENABLED;

	/* Write to the control register to reset both FIFOs, these bits are
	 * self-clearing such that there's no need to clear them
	 */
	XIo_Out32(InstancePtr->RegBaseAddress + XUL_CONTROL_REG_OFFSET,
			Register | XUL_CR_FIFO_TX_RESET | XUL_CR_FIFO_RX_RESET);
}

/****************************************************************************/
/**
*
* This function determines if the specified UART is sending data. If the
* transmitter register is not empty, it is sending data.
*
* @param	InstancePtr is a pointer to the XUartLite instance.
*
* @return	A value of TRUE if the UART is sending data, otherwise FALSE.
*
* @note		None.
*
*****************************************************************************/
int XUartLite_IsSending(XUartLite *InstancePtr)
{
	u32 StatusRegister;

	/*
	 * Assert validates the input arguments
	 */
	XASSERT_NONVOID(InstancePtr != NULL);

	/* Read the status register to determine if the transmitter is
	 * empty
	 */
	StatusRegister = XIo_In32(InstancePtr->RegBaseAddress +
					XUL_STATUS_REG_OFFSET);

	/* If the transmitter is not empty then indicate that the UART is still
	 * sending some data
	 */
	return ((StatusRegister & XUL_SR_TX_FIFO_EMPTY) == 0);
}


/****************************************************************************
*
* This function provides a stub handler such that if the application does not
* define a handler but enables interrupts, this function will be called.
*
* @param	CallBackRef has no purpose but is necessary to match the
*		interface for a handler.
* @param	ByteCount has no purpose but is necessary to match the
*		interface for a handler.
*
* @return	None.
*
* @note		None.
*
*****************************************************************************/
static void StubHandler(void *CallBackRef, unsigned int ByteCount)
{
	/*
	 * Assert occurs always since this is a stub and should never be called
	 */
	XASSERT_VOID_ALWAYS();
}


/****************************************************************************/
/**
*
* This function sends a buffer that has been previously specified by setting
* up the instance variables of the instance. This function is designed to be
* an internal function for the XUartLite component such that it may be called
* from a shell function that sets up the buffer or from an interrupt handler.
*
* This function sends the specified buffer of data to the UART in either
* polled or interrupt driven modes. This function is non-blocking such that
* it will return before the data has been sent by the UART.
*
* In a polled mode, this function will only send as much data as the UART can
* buffer, either in the transmitter or in the FIFO if present and enabled.
* The application may need to call it repeatedly to send a buffer.
*
* In interrupt mode, this function will start sending the specified buffer and
* then the interrupt handler of the driver will continue until the buffer
* has been sent. A callback function, as specified by the application, will
* be called to indicate the completion of sending the buffer.
*
* @param	InstancePtr is a pointer to the XUartLite instance.
*
* @return	NumBytes is the number of bytes actually sent (put into the
*		UART transmitter and/or FIFO).
*
* @note		None.
*
*****************************************************************************/
unsigned int XUartLite_SendBuffer(XUartLite *InstancePtr)
{
	unsigned int SentCount = 0;
	u8 StatusRegister;

	/* Read the line status register to determine if the transmitter is
	 * full
	 */

	StatusRegister = XUartLite_mGetStatusReg(InstancePtr->RegBaseAddress);

	/*
	 * Fill the FIFO from the the buffer that was specified
	 */

	while (((StatusRegister & XUL_SR_TX_FIFO_FULL) == 0) &&
		(SentCount < InstancePtr->SendBuffer.RemainingBytes)) {
		XIo_Out32(InstancePtr->RegBaseAddress + XUL_TX_FIFO_OFFSET,
				InstancePtr->SendBuffer.NextBytePtr[SentCount]);

		SentCount++;

		StatusRegister =
			XUartLite_mGetStatusReg(InstancePtr->RegBaseAddress);

	}

	/* Enter a critical region by disabling all the UART interrupts to allow
	 * this call to stop a previous operation that may be interrupt driven
	 */
	StatusRegister = XUartLite_mGetStatusReg(InstancePtr->RegBaseAddress);
	XIo_Out32(InstancePtr->RegBaseAddress + XUL_CONTROL_REG_OFFSET, 0);

	/*
	 * Update the buffer to reflect the bytes that were sent from it
	 */
	InstancePtr->SendBuffer.NextBytePtr += SentCount;
	InstancePtr->SendBuffer.RemainingBytes -= SentCount;

	/*
	 * Increment associated counters
	 */
	 InstancePtr->Stats.CharactersTransmitted += SentCount;

	/* Restore the interrupt enable register to it's previous value such
	 * that the critical region is exited
	 */
	StatusRegister &= XUL_CR_ENABLE_INTR;
	XIo_Out32(InstancePtr->RegBaseAddress + XUL_CONTROL_REG_OFFSET,
			StatusRegister);

	/*
	 * Return the number of bytes that were sent, althought they really were
	 * only put into the FIFO, not completely sent yet
	 */
	return SentCount;
}

/****************************************************************************/
/**
*
* This function receives a buffer that has been previously specified by setting
* up the instance variables of the instance. This function is designed to be
* an internal function for the XUartLite component such that it may be called
* from a shell function that sets up the buffer or from an interrupt handler.
*
* This function will attempt to receive a specified number of bytes of data
* from the UART and store it into the specified buffer. This function is
* designed for either polled or interrupt driven modes. It is non-blocking
* such that it will return if there is no data has already received by the
* UART.
*
* In a polled mode, this function will only receive as much data as the UART
* can buffer, either in the receiver or in the FIFO if present and enabled.
* The application may need to call it repeatedly to receive a buffer. Polled
* mode is the default mode of operation for the driver.
*
* In interrupt mode, this function will start receiving and then the interrupt
* handler of the driver will continue until the buffer has been received. A
* callback function, as specified by the application, will be called to indicate
* the completion of receiving the buffer or when any receive errors or timeouts
* occur. Interrupt mode must be enabled using the SetOptions function.
*
* @param	InstancePtr is a pointer to the XUartLite instance.
*
* @return	The number of bytes received.
*
* @note		None.
*
*****************************************************************************/
unsigned int XUartLite_ReceiveBuffer(XUartLite *InstancePtr)
{
	u8 StatusRegister;
	unsigned int ReceivedCount = 0;

	/* Loop until there is not more data buffered by the UART or the
	specified
	 * number of bytes is received
	 */

	while (ReceivedCount < InstancePtr->ReceiveBuffer.RemainingBytes) {
		/* Read the Status Register to determine if there is any data in
		 * the receiver/FIFO
		 */
		StatusRegister =
			XUartLite_mGetStatusReg(InstancePtr->RegBaseAddress);

		/* If there is data ready to be removed, then put the next byte
		 * received into the specified buffer and update the stats to
		 reflect
 		* any receive errors for the byte
		 */
		if (StatusRegister & XUL_SR_RX_FIFO_VALID_DATA) {
			InstancePtr->ReceiveBuffer.NextBytePtr[ReceivedCount++]
			=
				XIo_In32(InstancePtr->RegBaseAddress +
					XUL_RX_FIFO_OFFSET);

			XUartLite_mUpdateStats(InstancePtr, StatusRegister);
		}

		/* There's no more data buffered, so exit such that this
		 * function does not block waiting for data
		 */
		else {
			break;
		}
	}

	/* Enter a critical region by disabling all the UART interrupts to allow
	 * this call to stop a previous operation that may be interrupt driven
	 */
	StatusRegister = XUartLite_mGetStatusReg(InstancePtr->RegBaseAddress);
	XIo_Out32(InstancePtr->RegBaseAddress + XUL_CONTROL_REG_OFFSET, 0);

	/* Update the receive buffer to reflect the number of bytes that was
	 * received
	 */
	InstancePtr->ReceiveBuffer.NextBytePtr += ReceivedCount;
	InstancePtr->ReceiveBuffer.RemainingBytes -= ReceivedCount;

	/*
	 * Increment associated counters in the statistics
	 */
	InstancePtr->Stats.CharactersReceived += ReceivedCount;

	/* Restore the interrupt enable register to it's previous value such
	 * that the critical region is exited
	 */
	StatusRegister &= XUL_CR_ENABLE_INTR;
	XIo_Out32(InstancePtr->RegBaseAddress + XUL_CONTROL_REG_OFFSET,
			StatusRegister);

	return ReceivedCount;
}
