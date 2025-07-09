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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-FPGA-CV-GNU/alt_hps_detect.c#1 $
 */

#include "alt_hps_detect.h"
#include "socal/alt_sysmgr.h"
#include "socal/hps.h"
#include "socal/socal.h"

static bool alt_hps_detect_is_gen5(void)
{
    // Determine if device is in Generation 5.
    return (ALT_SYSMGR_SILICONID1_ID_GET(alt_read_word(ALT_SYSMGR_SILICONID1_ADDR))
            == ALT_SYSMGR_SILICONID1_ID_E_CYCLONEV_ARRIAV);
}

static bool alt_hps_detect_gen5_can_is_present(void)
{
    return (ALT_SYSMGR_HPSINFO_CAN_GET(alt_read_word(ALT_SYSMGR_HPSINFO_ADDR))
            == ALT_SYSMGR_HPSINFO_CAN_E_CAN_AVAILABLE);
}

bool alt_hps_detect_is_cyclone5(void)
{
    if (!alt_hps_detect_is_gen5())
    {
        return false;
    }

    return alt_hps_detect_gen5_can_is_present();
}

bool alt_hps_detect_is_arria5(void)
{
    if (!alt_hps_detect_is_gen5())
    {
        return false;
    }

    return !alt_hps_detect_gen5_can_is_present();
}
