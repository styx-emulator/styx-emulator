#if defined(__ECC__)
#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* tbubp.h */
#endif
#endif /* __ECC__ */
/************************************************************************
 *
 * tbubp.h
 *
 * (c) Copyright 2002-2008 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

#ifndef _TBUBP_H
#define _TBUBP_H

#include "pci_ids.h"

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_19_4)
#endif /* _MISRA_RULES */

#define TBUBP_SDRAM_NUM_BANKS	1		/* only 1 bank populated */
#define TBUBP_SDRAM_SIZE	0x1000000	/* 16 MB */

/*
 * PCI target definitions
 */
#define TBUBP_PCI_VENDOR_ID	PCI_VENDOR_ID_ADI
#define TBUBP_PCI_DEVICE_ID	PCI_DEVICE_ID_ADSPBF535
#define TBUBP_PCI_CLASS		PCI_CLASS_SP_OTHER	/* other signal proc */
#define TBUBP_PCI_REVISION_ID	0x0	/* board rev */
#define TBUBP_PCI_MIN_GRANT	0x1	/* = 0.25 usecs for 8 DWord FIFO */
#define TBUBP_PCI_MAX_LATENCY	0x2	/* = 0.50 usecs for 32-byte PCI read (16 PCI clks) */
#define TBUBP_PCI_MEM_BARMASK 0xFC000000
#define TBUBP_PCI_IO_BARMASK 0xFFFFFF00

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif	/* _TBUBP_H */
