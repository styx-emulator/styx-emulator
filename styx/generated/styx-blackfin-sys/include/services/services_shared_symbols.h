/* These symbols are ones that, when used in a dual-core
** system, must be mapped to the same address in both cores.
** These symbols are required for Dual-Core System Services' Implementation.
** Copyright (C) 2006 Analog Devices, Inc. All Rights Reserved.
*/
#ifdef OTHERCORE
   RESOLVE(_adi_pwr_lockvar, OTHERCORE)
#endif
