/**********************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_ftl.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            This is the include file for the ADI implementation of
            the HCC FTL.

*********************************************************************/

#ifndef __ADI_FTL_H__
#define __ADI_FTL_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*=============  I N C L U D E S   =============*/

#include <services/services.h>
#include <drivers/adi_dev.h>
#include "api_f.h"
/*==============  D E F I N E S  ===============*/

/*=============  E X T E R N A L S  ============*/

/*
**  External Data section
*/
/* Location to hold NFC driver handle */
extern ADI_DEV_DEVICE_HANDLE   ghAdiNfcDriver;
/* Location to hold NFD block number to start with for FSS use */
extern u16                  gnAdiFtlFssStartBlock;
/* Location to hold last NFD block number available for FSS */
extern u16                  gnAdiFtlFssEndBlock;

/*
**  External Function Prototypes
*/

/* prototype for FTL initialization routine */
F_DRIVER *adi_ftl_Init(void);
/* prototype for formatting NAND memory for HCC FTL use */
unsigned char adi_ftl_NandFormat(void);
/* prototype for retrieving library revision number */
unsigned long adi_ftl_GetRevision(void);

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_FTL_H__ */

/*****/
