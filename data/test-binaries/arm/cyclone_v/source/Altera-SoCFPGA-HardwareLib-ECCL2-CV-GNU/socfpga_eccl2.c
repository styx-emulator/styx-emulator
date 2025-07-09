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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-ECCL2-CV-GNU/socfpga_eccl2.c#1 $
 */

#include <stdio.h>
#include "socfpga_eccl2.h"
#include "socfpga_int.h"
#include "alt_cache.h"
#include "alt_ecc.h"
#include "alt_printf.h"

#define ARRAY_COUNT(array) (sizeof(array) / sizeof(array[0]))

static void socfpga_eccl2_isr(uint32_t icciar, void * context)
{
    ALT_INT_INTERRUPT_t int_id = (ALT_INT_INTERRUPT_t)ALT_INT_ICCIAR_ACKINTID_GET(icciar);
    SOCFPGA_ECCL2_DATA_t * data = (SOCFPGA_ECCL2_DATA_t *)context;

    switch (int_id)
    {
    case ALT_INT_INTERRUPT_L2_ECC_CORRECTED_IRQ:
        data->serr_callback(data->serr_context);
        break;
    case ALT_INT_INTERRUPT_L2_ECC_UNCORRECTED_IRQ:
        data->derr_callback(data->derr_context);
        break;
    case ALT_INT_INTERRUPT_L2_ECC_BYTE_WR_IRQ:
    default:
        break;
    }
}

static ALT_INT_INTERRUPT_t l2_ecc_int[] =
{
    ALT_INT_INTERRUPT_L2_ECC_BYTE_WR_IRQ,
    ALT_INT_INTERRUPT_L2_ECC_CORRECTED_IRQ,
    ALT_INT_INTERRUPT_L2_ECC_UNCORRECTED_IRQ
};

static ALT_INT_TRIGGER_t l2_ecc_trig[] =
{
    ALT_INT_TRIGGER_AUTODETECT,
    ALT_INT_TRIGGER_AUTODETECT,
    ALT_INT_TRIGGER_AUTODETECT
};

static alt_int_callback_t l2_ecc_callbacks[] =
{
    socfpga_eccl2_isr,
    socfpga_eccl2_isr,
    socfpga_eccl2_isr
};

ALT_STATUS_CODE socfpga_eccl2_setup(SOCFPGA_ECCL2_DATA_t * eccl2_data,
                                    socfpga_eccl2_callback_t serr_callback, void * serr_context,
                                    socfpga_eccl2_callback_t derr_callback, void * derr_context)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    /* Precondition: L2 enabled */
    void * l2_ecc_contexts[3];
    l2_ecc_contexts[0] = eccl2_data;
    l2_ecc_contexts[1] = eccl2_data;
    l2_ecc_contexts[2] = eccl2_data;

    ALT_PRINTF("INFO: Setup ECC L2 Notification System.\n");

    eccl2_data->serr_callback = serr_callback;
    eccl2_data->serr_context  = serr_context;
    eccl2_data->derr_callback = derr_callback;
    eccl2_data->derr_context  = derr_context;

    if (status == ALT_E_SUCCESS)
    {
        status = alt_ecc_start(ALT_ECC_RAM_L2_DATA);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = socfpga_int_setup_list(l2_ecc_int,
                                        l2_ecc_trig,
                                        l2_ecc_callbacks,
                                        l2_ecc_contexts,
                                        ARRAY_COUNT(l2_ecc_int));
    }

    return status;
}

void socfpga_eccl2_cleanup(void)
{
    ALT_PRINTF("INFO: Cleanup ECC L2 Notification System.\n");

    socfpga_int_cleanup_list(l2_ecc_int, ARRAY_COUNT(l2_ecc_int));

    alt_ecc_stop(ALT_ECC_RAM_L2_DATA);
}

static ALT_STATUS_CODE socfpga_eccl2_inject_common_pre(uint32_t * cache_line)
{
    /* Due to technical details of how the L2 RAM is implemented, we need to ensure that
    // a read first occurs on the L2. This way the Write Enable (WE) is set low. Then set
    // the ECC injection, and write to the same spot. This way, the WE will edge high
    // causing the injection logic to procede correctly. If the last IO was a write, the
    // WE does not come down, and the ECC injection is not done. This is an artifact of
    // the ARM L2 controller logic. */

    /* Zero out our cache line. */
    register uint32_t * iter = cache_line;
    register int i;
    for (i = 0; i < ALT_CACHE_LINE_SIZE; i += sizeof(*iter))
    {
        *iter = 0xffffffff;
        ++iter;
    }

    /* Now clean and invalidate the data from L1 to L2. */
    alt_cache_l1_data_purge(cache_line, ALT_CACHE_LINE_SIZE);

    /* Read that buffer to ensure that the last IO on that line was a read. */
    if (*cache_line != 0xffffffff)
    {
        ALT_PRINTF("ERROR: See %s:%d.\n", __FILE__, __LINE__);

        return ALT_E_ERROR;
    }
    else
    {
        return ALT_E_SUCCESS;
    }
}

static ALT_STATUS_CODE socfpga_eccl2_inject_common_post(uint32_t * cache_line)
{
    /* Write to buffer and flush to L2. */
    register uint32_t * iter = cache_line;
    register int i;
    for (i = 0; i < ALT_CACHE_LINE_SIZE; i += sizeof(*iter))
    {
        *iter = i;
        ++iter;
    }

    /* Purge that line. This way the next time that buffer is read, it will be fetched from L2. */
    alt_cache_l1_data_purge(cache_line, ALT_CACHE_LINE_SIZE);

    /* Read out the data. The actual reading will cause the error to be reported. */
    iter = cache_line;
    for (i = 0; i < ALT_CACHE_LINE_SIZE; i += sizeof(*iter))
    {
        /* Use volatile here so the read operation will not be optimized away. */
        *(volatile uint32_t *)iter;
        ++iter;
    }

    return ALT_E_SUCCESS;
}

ALT_STATUS_CODE socfpga_eccl2_inject_serr(void * cache_line)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    /* Verify [cache_line] is cache aligned. */
    if ((uintptr_t)cache_line & (ALT_CACHE_LINE_SIZE - 1))
    {
        return ALT_E_BAD_ARG;
    }

    if (status == ALT_E_SUCCESS)
    {
        status = socfpga_eccl2_inject_common_pre(cache_line);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_ecc_serr_inject(ALT_ECC_RAM_L2_DATA);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = socfpga_eccl2_inject_common_post(cache_line);
    }

    return status;
}

ALT_STATUS_CODE socfpga_eccl2_inject_derr(void * cache_line)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    /* Verify [cache_line] is cache aligned. */
    if ((uintptr_t)cache_line & (ALT_CACHE_LINE_SIZE - 1))
    {
        return ALT_E_BAD_ARG;
    }

    if (status == ALT_E_SUCCESS)
    {
        status = socfpga_eccl2_inject_common_pre(cache_line);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_ecc_derr_inject(ALT_ECC_RAM_L2_DATA);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = socfpga_eccl2_inject_common_post(cache_line);
    }

    return status;
}
