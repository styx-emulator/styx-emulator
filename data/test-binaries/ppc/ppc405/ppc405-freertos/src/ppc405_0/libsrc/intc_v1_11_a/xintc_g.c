/* $Id: xintc_g.c,v 1.1 2008/02/12 13:46:32 svemula Exp $ */
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
*
* @file xintc_g.c
*
* This file contains a configuration table that specifies the configuration of
* interrupt controller devices in the system.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a rpm  01/09/02 First release
* 1.00b jhl  02/21/02 Repartitioned the driver for smaller files
* 1.00b jhl  04/24/02 Compressed the ack table into a bit mask.
* 1.00c rpm  10/17/03 New release. Support the static vector table created
*                     in the xintc_g.c configuration table.
* 1.10c mta  03/21/07 Updated to new coding style
* </pre>
*
* @internal
*
* This configuration table contains entries that are modified at runtime
* by the driver. The EDK tools populate the table with default values for the
* vector table and the options flag. These default values can be, and are,
* overwritten at runtime by the driver.  This is a deviation from most drivers'
* configuration tables in that most are created statically by the tools and
* are never modified during runtime.  Most tables reflect only the hardware
* configuration of the device. This Intc configuration table contains software
* information in addition to hardware configuration.  The Intc configuration
* table should be considered an exception to the usage of the configuration
* table rather than the norm.
*
******************************************************************************/

/***************************** Include Files *********************************/

#include "xintc.h"
#include "xparameters.h"

/************************** Constant Definitions *****************************/


/**************************** Type Definitions *******************************/


/***************** Macros (Inline Functions) Definitions *********************/


/************************** Function Prototypes ******************************/


/************************** Variable Prototypes ******************************/

/**
 * This table contains configuration information for each intc device
 * in the system. The XIntc driver must know when to acknowledge the interrupt.
 * The entry which specifies this as a bit mask where each bit corresponds to
 * a specific interrupt.  A bit set indicates to ack it before servicing it.
 * Generally, acknowledge before service is used when the interrupt signal is
 * edge-sensitive, and after when the signal is level-sensitive.
 *
 * Refer to the XIntc_Config data structure in xintc.h for details on how this
 * table should be initialized.
 */
XIntc_Config XIntc_ConfigTable[XPAR_XINTC_NUM_INSTANCES] = {
	{
	 XPAR_INTC_0_DEVICE_ID,	/* Unique ID  of device */
	 XPAR_INTC_0_BASEADDR,	/* Register base address */
	 XPAR_INTC_0_ACK_BEFORE,	/* Ack before or after service */
	 0			/* Device options */
	 }
	,
	{
	 XPAR_INTC_1_DEVICE_ID,	/* Unique ID  of device */
	 XPAR_INTC_1_BASEADDR,	/* Register base address */
	 XPAR_INTC_1_ACK_BEFORE,	/* Ack before or after service */
	 0			/* Device options */
	 }
};
