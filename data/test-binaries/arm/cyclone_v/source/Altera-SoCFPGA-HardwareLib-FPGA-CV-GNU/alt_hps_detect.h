/******************************************************************************
*
* Copyright 2014 Altera Corporation. All Rights Reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
* this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
* this list of conditions and the following disclaimer in the documentation
* and/or other materials provided with the distribution.
*
* 3. Neither the name of the copyright holder nor the names of its contributors
* may be used to endorse or promote products derived from this software without
* specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
******************************************************************************/

/*
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-FPGA-CV-GNU/alt_hps_detect.h#1 $
 */

#ifndef ___ALT_HPS_DETECT_H___
#define ___ALT_HPS_DETECT_H___

#ifdef __cplusplus
extern "C"
{
#endif

#include "hwlib.h"

/*!
 * Detects if the SoCFPGA variant of the current HPS is a Cyclone 5 SoCFPGA.
 *
 * Internally it looks at the system manager silicon ID to determine the
 * current device is a generation 5 device. To differentiate between Cyclone 5
 * and Arria 5, it attempts to query the CAN reset bits.
 *
 * \retval      true            Current device is a Cyclone 5 SoCFPGA.
 * \retval      false           Current device is something else.
 */
bool alt_hps_detect_is_cyclone5(void);

/*!
 * Detects if the SoCFPGA variant of the current HPS is an Arria 5 SoCFPGA.
 *
 * For internal logic, see documentation for alt_hps_detect_is_cyclone5(). It is
 * changed slightly to detect the absense of the CAN interface.
 *
 * \retval      true            Current device is an Arria 5 SoCFPGA.
 * \retval      false           Current device is something else.
 */
bool alt_hps_detect_is_arria5(void);


#ifdef __cplusplus
}
#endif

#endif /* ___ALT_HPS_DETECT_H___ */
