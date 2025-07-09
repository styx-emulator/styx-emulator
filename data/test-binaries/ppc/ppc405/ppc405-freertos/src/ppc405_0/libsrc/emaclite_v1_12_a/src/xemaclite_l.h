/* $Id: xemaclite_l.h,v 1.1 2007/11/30 11:43:03 svemula Exp $ */
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
*       (c) Copyright 2004-2007 Xilinx Inc.
*       All rights reserved.
*
******************************************************************************/
/*****************************************************************************/
/**
*
* @file xemaclite_l.h
*
* This header file contains identifiers and basic driver functions and
* macros that can be used to access the device.
*
* The Xilinx Ethernet Lite driver component. This component supports the Xilinx
* Lite Ethernet 10/100 MAC (EMAC Lite).
*
* Refer to xemaclite.h for more details.
*
* @note
*
* The functions and macros in this file assume that the proper device address is
* provided in the argument. If the ping buffer is the source or destination,
* the argument should be DeviceAddress + XEL_(T/R)XBUFF_OFFSET. If the pong
* buffer is the source or destination, the argument should be
* DeviceAddress + XEL_(T/R)XBUFF_OFFSET + XEL_BUFFER_OFFSET. The driver does
* not take the different buffers into consideration.
* For more details on the ping/pong buffer configuration please refer to the
* PLB Ethernet Lite Media Access Controller hardware specification.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a ecm  06/01/02 First release
* 1.01a ecm  03/31/04 Additional functionality and the _AlignedRead and
*                     AlignedWrite functions.
*                     Moved the bulk of description to xemaclite.h
* 1.11a mta  03/21/07 Updated to new coding style
* </pre>
*
******************************************************************************/

#ifndef XEMAC_LITE_L_H		/* prevent circular inclusions */
#define XEMAC_LITE_L_H		/* by using protection macros */

#ifdef __cplusplus
extern "C" {
#endif

/***************************** Include Files *********************************/

#include "xbasic_types.h"
#include "xio.h"

/************************** Constant Definitions *****************************/
/**
 * Register offsets for the Ethernet MAC.
 */
#define XEL_TXBUFF_OFFSET (0x00000000)			/**< Transmit Buffer */
#define XEL_GIER_OFFSET   (XEL_TXBUFF_OFFSET + 0x07F8)	/**< Offset for the GIE
							     Register */
#define XEL_TSR_OFFSET	(XEL_TXBUFF_OFFSET + 0x07FC)	/**< Tx status */
#define XEL_TPLR_OFFSET   (XEL_TXBUFF_OFFSET + 0x07F4)	/**< Tx packet length */

#define XEL_RXBUFF_OFFSET (0x00001000)			/**< Receive Buffer */
#define XEL_RSR_OFFSET	(XEL_RXBUFF_OFFSET + 0x07FC)	/**< Rx status */
#define XEL_RPLR_OFFSET   (XEL_RXBUFF_OFFSET + 0x0C)	/**< Rx packet length */

#define XEL_MAC_HI_OFFSET (XEL_TXBUFF_OFFSET + 0x14)	/**< MAC address hi
							     offset */
#define XEL_MAC_LO_OFFSET (XEL_TXBUFF_OFFSET)		/**< MAC address lo
							     offset */

#define XEL_BUFFER_OFFSET (0x00000800)			/**< Next buffer's
							     offset  same for
							     both TX and RX */

/**
 * Global Interrupt Enable Register (GIER) Bit Masks
 */
#define XEL_GIER_GIE_MASK		0x80000000UL	/**< Global Enable */

/**
 * Transmit Status Register (TSR) Bit Masks
 */
#define XEL_TSR_XMIT_BUSY_MASK		0x00000001UL	/**< Xmit complete */
#define XEL_TSR_PROGRAM_MASK		0x00000002UL	/**< Program the MAC
							     address */
#define XEL_TSR_XMIT_IE_MASK		0x00000008UL	/**< Xmit interrupt
							     enable bit */
#define XEL_TSR_XMIT_ACTIVE_MASK	0x80000000UL	/**< Buffer is active,
							     SW bit only */

/**
 * define for programming the MAC address into the EMAC Lite
 */
#define XEL_TSR_PROG_MAC_ADDR   (XEL_TSR_XMIT_BUSY_MASK | XEL_TSR_PROGRAM_MASK)

/**
 * Receive Status Register (RSR)
 */
#define XEL_RSR_RECV_DONE_MASK		0x00000001	/**< Recv complete */
#define XEL_RSR_RECV_IE_MASK		0x00000008	/**< Recv interrupt
							     enable bit */

/**
 * Transmit Packet Length Register (TPLR)
 */
#define XEL_TPLR_LENGTH_MASK_HI		0x0000FF00 /**< Transmit packet length
							  upper byte */
#define XEL_TPLR_LENGTH_MASK_LO		0x000000FF /**< Transmit packet length
							  lower byte */

/**
 * Receive Packet Length Register (RPLR)
 */
#define XEL_RPLR_LENGTH_MASK_HI		0x0000FF00 /**< Receive packet length
							  upper byte */
#define XEL_RPLR_LENGTH_MASK_LO		0x000000FF /**< Receive packet length
							  lower byte */

#define XEL_HEADER_SIZE			14  /**< Size of header in bytes */
#define XEL_MTU_SIZE			1500 /**< Max size of data in frame */
#define XEL_FCS_SIZE			4    /**< Size of CRC */

#define XEL_HEADER_OFFSET		12   /**< Offset to length field */
#define XEL_HEADER_SHIFT		16   /**< Right shift value to align
						  length */


#define XEL_MAX_FRAME_SIZE (XEL_HEADER_SIZE+XEL_MTU_SIZE+ XEL_FCS_SIZE)	/**< Max
						length of rx frame  used if
						length/type field
						contains the type (> 1500) */

#define XEL_MAC_ADDR_SIZE		6	/**< length of MAC address */


/***************** Macros (Inline Functions) Definitions *********************/

#define XEmacLite_In32 XIo_In32

#define XEmacLite_Out32 XIo_Out32

/****************************************************************************/
/**
*
* Read from the specified EmacLite device register.
*
* @param	BaseAddress contains the base address of the device.
* @param	RegOffset contains the offset from the 1st register of the
*		device to select the specific register.
*
* @return	The value read from the register.
*
* @note		C-Style signature:
*		u32 XEmacLite_mReadReg(u32 BaseAddress, u32 RegOffset);
*
******************************************************************************/
#define XEmacLite_mReadReg(BaseAddress, RegOffset) \
	XEmacLite_In32((BaseAddress) + (RegOffset))

/***************************************************************************/
/**
*
* Write to the specified EmacLite device register.
*
* @param	BaseAddress contains the base address of the device.
* @param	RegOffset contains the offset from the 1st register of the
*		device to select the specific register.
* @param	RegisterValue is the value to be written to the register.
*
* @return	None.
*
* @note		C-Style signature:
*		void XEmacLite_mWriteReg(u32 BaseAddress, u32 RegOffset,
*					u32 RegisterValue);
******************************************************************************/
#define XEmacLite_mWriteReg(BaseAddress, RegOffset, RegisterValue) \
	XEmacLite_Out32((BaseAddress) + (RegOffset), (RegisterValue))

/****************************************************************************/
/**
*
* Check to see if the transmission is complete.
*
* @param	BaseAddress is the base address of the device
*
* @return	TRUE if it is done, or FALSE if it is not.
*
* @note		C-Style signature:
* 		int XEmacLite_mIsTxDone(u32 BaseAddress)
*
*****************************************************************************/
#define XEmacLite_mIsTxDone(BaseAddress)			\
		 ((XEmacLite_mReadReg((BaseAddress), XEL_TSR_OFFSET) & 	 \
			 XEL_TSR_XMIT_BUSY_MASK) != XEL_TSR_XMIT_BUSY_MASK)


/****************************************************************************/
/**
*
* Check to see if the receive is empty.
*
* @param	BaseAddress is the base address of the device
*
* @return	TRUE if it is empty, or FALSE if it is not.
*
* @note		C-Style signature:
*		int XEmacLite_mIsRxEmpty(u32 BaseAddress)
*
*****************************************************************************/
#define XEmacLite_mIsRxEmpty(BaseAddress) \
		  ((XEmacLite_mReadReg((BaseAddress), XEL_RSR_OFFSET) & \
			XEL_RSR_RECV_DONE_MASK) != XEL_RSR_RECV_DONE_MASK)

/************************** Function Prototypes ******************************/

void XEmacLite_SendFrame(u32 BaseAddress, u8 *FramePtr, unsigned ByteCount);
u16 XEmacLite_RecvFrame(u32 BaseAddress, u8 *FramePtr);

#ifdef __cplusplus
}
#endif

#endif /* end of protection macro */
