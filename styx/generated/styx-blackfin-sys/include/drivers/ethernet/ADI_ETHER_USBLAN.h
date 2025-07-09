/*********************************************************************************

Copyright(c) 2004 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.



*********************************************************************************/


/*********************************************************************

Include files

*********************************************************************/
#ifndef _ADI_USBLAN_H_
#define _ADI_USBLAN_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <drivers/ethernet/ADI_ETHER.h>

/*********************************************************************

User configurable items

*********************************************************************/



/*********************************************************************

Extensible enumerations and defines

*********************************************************************/


enum {										/* Command IDs	*/
	ADI_ETHER_USBLAN_CMD_FIRST=ADI_ETHER_CMD_SPECIFIC_START,	/* insure this order remains	*/
	ADI_ETHER_CMD_USBLAN_USE_IVG,
	ADI_ETHER_CMD_USBLAN_USE_DMA,
	ADI_ETHER_CMD_USBLAN_USE_PF
};


enum {										/* Events	*/
	ADI_ETHER_EVENT_USBLAN_FIRST=ADI_ETHER_EVENT_SPECIFIC_START
};


enum {								/* Return codes	*/
	ADI_ETHER_USBLAN_RESULT_START=ADI_ETHER_RESULT_SPECIFIC_START
};

#define ADI_ETHER_MEM_USBLAN_BASE_SIZE 0x180
#define ADI_ETHER_MEM_USBLAN_PER_RECV 0x4
#define ADI_ETHER_MEM_USBLAN_PER_XMIT 0x4

/**************************************
 external memory offset EZLAN
****************************************/
#ifdef __ADSPBF535__
	#define MSMC    0x2C000300      /* bank select 1 BF535 Ezlan Board	*/
#endif

#ifdef __ADSPBF561__
	#define MSMC    0x2C010300      /* BF561	*/
#endif


#if ( defined(__ADSPBF533__) || defined(__ADSPBF537__) || defined(__ADSPBF538__) )
 #define MSMC    0x20310300      /* USB-LAN	*/
#endif

/*********************************************************************

Data Structures

*********************************************************************/
extern ADI_DEV_PDD_ENTRY_POINT ADI_ETHER_USBLAN_Entrypoint;		/* entry point to the device driver	*/






/********************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif
