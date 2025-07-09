/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

Description:
            This is the include file for LCD driver.

*********************************************************************************/

#ifndef __ADI_LCD_H__
#define __ADI_LCD_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <drivers/lcd/nec/adi_nl6448bc33_54.h>  // NEC NL6448BC33_54 driver includes
//#include <drivers/lcd/sharp/adi_lq10d368.h>   // SHARP LQ10D368 driver includes

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif
