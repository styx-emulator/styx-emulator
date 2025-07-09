/*******************************************************************************/
/*                                                                             */
/*   (C) Copyright 2008 - Analog Devices, Inc.  All rights reserved.           */
/*                                                                             */
/*    FILE:     m25p16.h                                                       */
/*																			   */
/*    PURPOSE:  This header file defines items specific to the M25P16 flash.   */
/*                                                                             */
/*******************************************************************************/

#ifndef __M25P16_H__
#define __M25P16_H__

/* application definitions */
#define COMMON_SPI_SETTINGS (SPE|MSTR)  /* settings to the SPI_CTL */
#define TIMOD01 (0x01)                  /* sets the SPI to work with core instructions */

#define BAUD_RATE_DIVISOR 	6
#define PE4 0x0010

/* interface function prototypes */
ERROR_CODE m25p16_Open(void);						/* open the flash device */
ERROR_CODE m25p16_Close(void);						/* close the flas device */
ERROR_CODE m25p16_Read(unsigned short *pusData,		/* read some bytes from flash */
					   unsigned long ulStartAddress,
					   unsigned int uiCount );
ERROR_CODE m25p16_Write(unsigned short *pusData,	/* write some bytes to flash */
					    unsigned long ulStartAddress,
					    unsigned int uiCount );
ERROR_CODE m25p16_Control(unsigned int uiCmd,		/* send a command to device */
						  COMMAND_STRUCT *pCmdStruct);

#endif	/* __M25P16_H__ */
