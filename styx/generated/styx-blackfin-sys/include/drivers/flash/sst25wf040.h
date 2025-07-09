/*******************************************************************************/
/*                                                                             */
/*   (C) Copyright 2004 - Analog Devices, Inc.  All rights reserved.           */
/*                                                                             */
/*    FILE:     sst25wf040.h                                                   */
/*																			   */
/*    PURPOSE:  This header file defines items specific to the SST25WF040      */
/*               flash exported from the file sst25wf040.c.    		           */
/*                                                                             */
/*******************************************************************************/

#ifndef __SST25WF040_H__
#define __SST25WF040_H__

#ifdef _MISRA_RULES
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_15:"ADI header defines and/or undefines macros within a block")
#endif /* _MISRA_RULES */


/* ids */
#define MAN_CODE_SST	0xbf		/* SST, Inc. */
#define DEV_CODE_040	0x04		/* SST25WF040 (4Mbit SPI flash) */
#define DEV_CODE_020	0x03		/* SST25WF020 (2Mbit SPI flash) */
#define DEV_CODE_010	0x02		/* SST25WF010 (1Mbit SPI flash) */
#define DEV_CODE_512	0x01		/* SST25WF512 (512Kbit SPI flash) */

#define NUM_SECTORS_040	128			/* num sectors */


/* common settings */
#define COMMON_SPI_SETTINGS (SPE|MSTR)	/* for SPI_CTL */
#define TIMOD01 (0x01)					/* sets the SPI to work with write to SPI_TBDR */

#define BAUD_RATE_DIVISOR 	6
#define PE4 0x0010

/* interface function prototypes */
ERROR_CODE sst25wf040_Open(void);						/* open the flash device */
ERROR_CODE sst25wf040_Close(void);						/* close the flas device */
ERROR_CODE sst25wf040_Read(	unsigned short *pusData,	/* read some bytes from flash */
					   		unsigned long ulStartAddress,
							unsigned int uiCount );
ERROR_CODE sst25wf040_Write(unsigned short *pusData,	/* write some bytes to flash */
					    	unsigned long ulStartAddress,
					    	unsigned int uiCount );
ERROR_CODE sst25wf040_Control(	unsigned int uiCmd,		/* send a command to device */
						  		COMMAND_STRUCT *pCmdStruct);

#endif  /* __SST25WF040_H__ */
