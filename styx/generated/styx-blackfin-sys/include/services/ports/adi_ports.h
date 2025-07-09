/*********************************************************************************

Copyright(c) 2005 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential. By using this software you agree
to the terms of the associated Analog Devices License Agreement.

Description:
            Port Configuration module header file for the System Services Library.

*********************************************************************************/
#if !defined(_LANGUAGE_ASM)

#if defined(__ADSP_BRAEMAR__)
#include "adi_ports_bf534.h"
#endif

#if defined(__ADSP_STIRLING__)
#include "adi_ports_bf538.h"
#endif

#if defined(__ADSP_MOAB__)
#include "adi_ports_bf54x.h"
#endif

#if defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__)
#include "adi_ports_bf52x.h"
#endif

#if defined(__ADSP_BRODIE__)
#include "adi_ports_bf51x.h"
#endif

#if defined(__ADSP_MOY__)
#include "adi_ports_bf50x.h"
#endif

#if defined(__ADSP_DELTA__)
#include "adi_ports_bf59x.h"
#endif

#endif /* Language_ASM */
