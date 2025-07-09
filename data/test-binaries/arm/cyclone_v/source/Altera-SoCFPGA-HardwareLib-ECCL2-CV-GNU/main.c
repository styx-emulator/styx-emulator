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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-ECCL2-CV-GNU/main.c#1 $
 */

#include <stdio.h>
#include <inttypes.h>
#include "alt_cache.h"
#include "alt_mmu.h"
#include "socfpga_eccl2.h"
#include "socfpga_int.h"
#include "socfpga_pagetable.h"
#include "alt_printf.h"

/* enable semihosting with gcc by defining an __auto_semihosting symbol */
#if !defined(__ARMCC_VERSION) && !defined(PRINTF_UART)
int __auto_semihosting;
#endif

#if defined(__ARMCC_VERSION) && defined(PRINTF_UART)
#pragma import(__use_no_semihosting)

void _sys_exit(int return_code)
{
    while(1);
}
#endif

//
/////

ALT_STATUS_CODE socfpga_cache_setup(void)
{
    ALT_PRINTF("INFO: Setup L1 and L2 caches.\n");

    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    if (status == ALT_E_SUCCESS)
    {
        status = alt_cache_system_disable();
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_cache_l1_data_enable();
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_cache_l2_init();
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_cache_l2_enable();
    }

    return status;
}

void socfpga_cache_cleanup(void)
{
    ALT_PRINTF("INFO: Cleanup L1 and L2 caches.\n");

    alt_cache_l2_disable();
    alt_cache_l2_uninit();
    alt_cache_l1_data_disable();
}

//
// Prototype function used to obtain the address and size of the ECC scratch
// RAM. This is one of the memory segments that needs to be cacheable to enable
// this example.
//
ALT_STATUS_CODE alt_ecc_scratch_ram_get(void ** pblock, size_t * psize);

//
// Callback of the L2 ECC SERR event.
//
void notify_serr(void * context)
{
    ALT_PRINTF("INFO [ISR]: SERR detected. Incrementing count.\n");
    ++(*(volatile int *)context);
}

//
// Callback of the L2 ECC DERR event.
//
void notify_derr(void * context)
{
    ALT_PRINTF("INFO [ISR]: DERR detected. Incrementing count.\n");
    ++(*(volatile int *)context);
}

//
// Memory buffer used for SERR / DERR error injection. It is cached.
//
uint32_t buffer[ALT_MMU_SMALL_PAGE_SIZE / sizeof(uint32_t)] __attribute__ ((aligned (ALT_MMU_SMALL_PAGE_SIZE)));

int main(int argc, char** argv)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    //
    // Context data for the ECC L2 system.
    //
    SOCFPGA_ECCL2_DATA_t data;

    //
    // Track the number of SERR and DERR events.
    //
    volatile int serr_count = 0;
    volatile int derr_count = 0;

    /////

    if (status == ALT_E_SUCCESS)
    {
        //
        // Initialize the common (global and CPU) interrupt items.
        //

        status = socfpga_int_setup_common();
    }

    if (status == ALT_E_SUCCESS)
    {
        //
        // Page the ECC scratch RAM and error injection buffer.
        //

        void * block;
        size_t size;
        alt_ecc_scratch_ram_get(&block, &size);

        SOCFPGA_PAGETABLE_SEGMENT_t segments[2];

        // Order the two buffers before paging them.
        if ((uintptr_t)block < (uintptr_t)buffer)
        {
            ALT_PRINTF("INFO: Segment[0]: scratch at %p, size = 0x%x.\n", block,  size);
            ALT_PRINTF("INFO: Segment[1]: buffer  at %p, size = 0x%x.\n", buffer, sizeof(buffer));

            segments[0] = (SOCFPGA_PAGETABLE_SEGMENT_t)
            {
                .addr = block,
                .size = size
            };
            segments[1] = (SOCFPGA_PAGETABLE_SEGMENT_t)
            {
                .addr = buffer,
                .size = sizeof(buffer)
            };
        }
        else
        {
            ALT_PRINTF("INFO: Segment[0]: buffer  at %p, size = 0x%x.\n", buffer, sizeof(buffer));
            ALT_PRINTF("INFO: Segment[1]: scratch at %p, size = 0x%x.\n", block,  size);

            segments[0] = (SOCFPGA_PAGETABLE_SEGMENT_t)
            {
                .addr = buffer,
                .size = sizeof(buffer)
            };
            segments[1] = (SOCFPGA_PAGETABLE_SEGMENT_t)
            {
                .addr = block,
                .size = size
            };
        }

        status = socfpga_pagetable_setup(segments, 2);
    }

    if (status == ALT_E_SUCCESS)
    {
        //
        // Enable L1 data and L2 caches. L2 must be enabled before L2 ECC can be started.
        //

        status = socfpga_cache_setup();
    }

    if (status == ALT_E_SUCCESS)
    {
        //
        // Setup the ECC L2 system. See socfpga_eccl2.c for more details.
        //

        socfpga_eccl2_setup(&data,
                            notify_serr, (void *)&serr_count,
                            notify_derr, (void *)&derr_count);
    }

    /////

    if (status == ALT_E_SUCCESS)
    {
        //
        // Inject a SERR error. The error should be corrected automatically.
        //

        ALT_PRINTF("\n");
        ALT_PRINTF("INFO: Injecting SERR ...\n");
        status = socfpga_eccl2_inject_serr(buffer);

        if (serr_count == 0)
        {
            ALT_PRINTF("ERROR: L2 ECC did not report any SERR events.\n");
            status = ALT_E_ERROR;
        }
        else
        {
            ALT_PRINTF("INFO: L2 ECC reported %d SERR event(s).\n", serr_count);
        }
    }

    if (status == ALT_E_SUCCESS)
    {
        //
        // Inject a DERR error. The error should be reported multiple times.
        // Because the error is in an isolated portion of memory, it is not
        // catastrophic for this example.
        //

        ALT_PRINTF("\n");
        ALT_PRINTF("INFO: Injecting DERR ...\n");
        status = socfpga_eccl2_inject_derr(buffer);

        if (derr_count == 0)
        {
            ALT_PRINTF("ERROR: L2 ECC did not report any DERR events.\n");
            status = ALT_E_ERROR;
        }
        else
        {
            ALT_PRINTF("INFO: L2 ECC reported %d DERR event(s).\n", derr_count);
        }
    }

    /////

    ALT_PRINTF("\n");

    //
    // Cleanup operations.
    //

    socfpga_eccl2_cleanup();
    socfpga_cache_cleanup();
    socfpga_pagetable_cleanup();
    socfpga_int_cleanup_common();

    ALT_PRINTF("\n");

    if (status == ALT_E_SUCCESS)
    {
        ALT_PRINTF("RESULT: Example completed successfully.\n");
        return 0;
    }
    else
    {
        ALT_PRINTF("RESULT: Some failures detected.\n");
        return 1;
    }
}
