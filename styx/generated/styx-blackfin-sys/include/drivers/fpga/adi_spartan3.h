
#ifndef __ADI_SPARTAN3_H__
#define __ADI_SPARTAN3_H__

#ifdef _MISRA_RULES
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_15:"ADI header defines and/or undefines macros within a block")
#endif /* _MISRA_RULES */

/*===== I n c l u d e s  =====*/

#include <services/services.h>
#include <drivers/adi_dev.h>		/* device manager includes */

extern ADI_DEV_PDD_ENTRY_POINT ADISPARTAN3EntryPoint;	/* entry point to the device driver */
extern ADI_DEV_DEVICE_HANDLE DevHandleSpartan3;

#endif	/* __ADI_MSPARTAN3_H__ */
