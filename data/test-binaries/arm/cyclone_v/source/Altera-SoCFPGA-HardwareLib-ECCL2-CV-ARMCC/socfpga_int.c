/*****************************************************************************
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
*****************************************************************************/

/*
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-ECCL2-CV-ARMCC/socfpga_int.c#1 $
 */

#include <stdio.h>
#include <inttypes.h>
#include "socfpga_int.h"
#include "alt_printf.h"

ALT_STATUS_CODE socfpga_int_setup_common(void)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    ALT_PRINTF("INFO: Setup Interrupt System.\n");

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_global_init();
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_cpu_init();
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_cpu_enable();
        if (status != ALT_E_SUCCESS)
        {
            ALT_PRINTF("ERROR: alt_int_cpu_enable() failed, %" PRIi32 ".\n", status);
        }
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_global_enable();
        if (status != ALT_E_SUCCESS)
        {
            ALT_PRINTF("ERROR: alt_int_global_enable() failed, %" PRIi32 ".\n", status);
        }
    }

    return status;
}

void socfpga_int_cleanup_common(void)
{
    ALT_PRINTF("INFO: Cleanup Interrupt System.\n");

    if (alt_int_global_disable() != ALT_E_SUCCESS)
    {
        ALT_PRINTF("WARN: alt_int_global_disable() return non-SUCCESS.\n");
    }

    if (alt_int_cpu_disable() != ALT_E_SUCCESS)
    {
        ALT_PRINTF("WARN: alt_int_cpu_disable() return non-SUCCESS.\n");
    }

    if (alt_int_cpu_uninit() != ALT_E_SUCCESS)
    {
        ALT_PRINTF("WARN: alt_int_cpu_uninit() return non-SUCCESS.\n");
    }

    if (alt_int_global_uninit() != ALT_E_SUCCESS)
    {
        ALT_PRINTF("WARN: alt_int_global_uninit() return non-SUCCESS.\n");
    }
}

ALT_STATUS_CODE socfpga_int_setup_list(ALT_INT_INTERRUPT_t * int_ids,
                                       ALT_INT_TRIGGER_t * triggers,
                                       alt_int_callback_t * callbacks,
                                       void ** contexts,
                                       size_t count)
{
    size_t i;
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    ALT_PRINTF("INFO: Setup Interrupt List [ ");
    for (i = 0; i < count; ++i)
    {
        ALT_PRINTF("%d ", int_ids[i]);
    }
    ALT_PRINTF("].\n");

    /*
    // Setup the interrupt specific items
    */

    for (i = 0; i < count; ++i)
    {
        ALT_INT_INTERRUPT_t int_id   = int_ids[i];
        ALT_INT_TRIGGER_t   trigger  = triggers[i];
        alt_int_callback_t  callback = callbacks[i];
        void *              context  = contexts[i];

        if (   (status == ALT_E_SUCCESS)
            && (int_id >= 32)) /* Ignore target_set() for non-SPI interrupts. */
        {
            int target = 0x3;
            status = alt_int_dist_target_set(int_id, target);

            if (status != ALT_E_SUCCESS)
            {
                ALT_PRINTF("ERROR: alt_int_dist_target_set(%u, 0x%x) failed, %" PRIi32 ".\n", int_id, target, status);
            }
        }

        if (status == ALT_E_SUCCESS)
        {
            status = alt_int_dist_trigger_set(int_id, trigger);
            if (status != ALT_E_SUCCESS)
            {
                ALT_PRINTF("ERROR: alt_int_dist_trigger_set(%d, %d) failed, %" PRIi32 ".\n", int_id, trigger, status);
            }
        }

        if (status == ALT_E_SUCCESS)
        {
            status = alt_int_isr_register(int_id,
                                          callback, context);
            if (status != ALT_E_SUCCESS)
            {
                ALT_PRINTF("ERROR: alt_int_isr_register(%d) failed, %" PRIi32 ".\n", int_id, status);
            }
        }

        /*
        // Enable the distributor interrupt
        */

        if (status == ALT_E_SUCCESS)
        {
            status = alt_int_dist_enable(int_id);
            if (status != ALT_E_SUCCESS)
            {
                ALT_PRINTF("ERROR: alt_int_dist_enable(%d) failed, %" PRIi32 ".\n", int_id, status);
            }
        }
    }

    return status;
}

void socfpga_int_cleanup_list(ALT_INT_INTERRUPT_t * int_ids,
                              size_t count)
{
    size_t i;
    ALT_PRINTF("INFO: Cleanup Interrupt List [ ");
    for (i = 0; i < count; ++i)
    {
        ALT_PRINTF("%d ", int_ids[i]);
    }
    ALT_PRINTF("].\n");

    for (i = 0; i < count; ++i)
    {
        ALT_INT_INTERRUPT_t int_id = int_ids[i];

        /*
        // Disable the distributor interrupt
        */

        if (alt_int_dist_disable(int_id) != ALT_E_SUCCESS)
        {
            ALT_PRINTF("WARN: alt_int_dist_disable() return non-SUCCESS.\n");
        }

        /*
        // Unregister any ISR.
        */

        if (alt_int_isr_unregister(int_id) != ALT_E_SUCCESS)
        {
            ALT_PRINTF("WARN: alt_int_isr_unregister(int_id=%d) return non-SUCCESS.\n", int_id);
        }
    }
}
