/*****************************************************************************
*
* Copyright 2013 Altera Corporation. All Rights Reserved.
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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-FPGA-CV-GNU/main.c#1 $
 */

#include <stdio.h>
#include <inttypes.h>
#include "alt_address_space.h"
#include "alt_bridge_manager.h"
#include "alt_clock_manager.h"
#include "alt_dma.h"
#include "alt_fpga_manager.h"
#include "socal/socal.h"

#include "alt_hps_detect.h"
#include "alt_printf.h"

/* enable semihosting with gcc by defining an __auto_semihosting symbol */
int __auto_semihosting;

ALT_STATUS_CODE socfpga_dma_setup(ALT_DMA_CHANNEL_t * allocated)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    ALT_PRINTF("INFO: Setup DMA System ...\n");

    if (status == ALT_E_SUCCESS)
    {
        /* Configure everything as defaults. */
        ALT_DMA_CFG_t dma_config;
        int i;

        dma_config.manager_sec = ALT_DMA_SECURITY_DEFAULT;
        for (i = 0; i < 8; ++i)
        {
            dma_config.irq_sec[i] = ALT_DMA_SECURITY_DEFAULT;
        }
        for (i = 0; i < 32; ++i)
        {
            dma_config.periph_sec[i] = ALT_DMA_SECURITY_DEFAULT;
        }
        for (i = 0; i < 4; ++i)
        {
            dma_config.periph_mux[i] = ALT_DMA_PERIPH_MUX_DEFAULT;
        }

        status = alt_dma_init(&dma_config);
        if (status != ALT_E_SUCCESS)
        {
            ALT_PRINTF("ERROR: alt_dma_init() failed.\n");
        }
    }

    /* Allocate the DMA channel */

    if (status == ALT_E_SUCCESS)
    {
        status = alt_dma_channel_alloc_any(allocated);
        if (status != ALT_E_SUCCESS)
        {
            ALT_PRINTF("ERROR: alt_dma_channel_alloc_any() failed.\n");
        }
        else
        {
            ALT_PRINTF("INFO: Channel %d allocated.\n", *allocated);
        }
    }

    /* Verify channel state */

    if (status == ALT_E_SUCCESS)
    {
        ALT_DMA_CHANNEL_STATE_t state;
        status = alt_dma_channel_state_get(*allocated, &state);
        if (status == ALT_E_SUCCESS)
        {
            if (state != ALT_DMA_CHANNEL_STATE_STOPPED)
            {
                ALT_PRINTF("ERROR: Bad initial channel state.\n");
                status = ALT_E_ERROR;
            }
        }
    }

    if (status == ALT_E_SUCCESS)
    {
        ALT_PRINTF("INFO: Setup of DMA successful.\n\n");
    }
    else
    {
        ALT_PRINTF("ERROR: Setup of DMA failed. [status = %" PRIi32 "].\n\n", status);
    }

    return status;
}

void socfpga_dma_cleanup(ALT_DMA_CHANNEL_t channel)
{
    ALT_PRINTF("INFO: Cleaning up DMA System ...\n");

    if (alt_dma_channel_free(channel) != ALT_E_SUCCESS)
    {
        ALT_PRINTF("WARN: alt_dma_channel_free() returned non-SUCCESS.\n");
    }

    if (alt_dma_uninit() != ALT_E_SUCCESS)
    {
        ALT_PRINTF("WARN: alt_dma_uninit() returned non-SUCCESS.\n");
    }
}

ALT_STATUS_CODE socfpga_fpga_setup_dma(const void * fpga_image, size_t fpga_image_size,
                                       ALT_DMA_CHANNEL_t dma_channel)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    ALT_PRINTF("INFO: Setup FPGA System ...\n");

    if (status == ALT_E_SUCCESS)
    {
        status = alt_fpga_init();
    }

    /* Verify power is on */
    if (status == ALT_E_SUCCESS)
    {
        if (alt_fpga_state_get() == ALT_FPGA_STATE_POWER_OFF)
        {
            ALT_PRINTF("ERROR: FPGA Monitor reports FPGA is powered off.\n");
            status = ALT_E_ERROR;
        }
    }

    /* Take control of the FPGA CB */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_fpga_control_enable();
    }

    /* Verify the MSELs are appropriate for the type of image we're using. */
    if (status == ALT_E_SUCCESS)
    {
        /* From experimentation, a compressed image is ~2.3 MiB an uncompressed is ~6.8 MiB.
         * Thus if it's smaller than 3 MiB, consider it compressed. */
        bool compressed = (fpga_image_size < 3 * 1024 * 1024);

        ALT_FPGA_CFG_MODE_t mode = alt_fpga_cfg_mode_get();
        switch (mode)
        {
            /* Compressed image modes */
        case ALT_FPGA_CFG_MODE_PP32_FAST_AESOPT_DC:
        case ALT_FPGA_CFG_MODE_PP32_SLOW_AESOPT_DC:
        case ALT_FPGA_CFG_MODE_PP16_FAST_AESOPT_DC:
        case ALT_FPGA_CFG_MODE_PP16_SLOW_AESOPT_DC:
            if (compressed)
            {
                ALT_PRINTF("INFO: MSEL [%d] configured correctly for compressed FPGA image.\n", mode);
            }
            else
            {
                ALT_PRINTF("WARNING: MSEL [%d] likely configured incorrectly for uncompressed FPGA image.\n", mode);
                ALT_PRINTF("WARNING: Because of this, FPGA programming will probably fail.\n");
            }
            break;

            /* Uncompressed image modes */
        case ALT_FPGA_CFG_MODE_PP16_FAST_NOAES_NODC:
        case ALT_FPGA_CFG_MODE_PP16_FAST_AES_NODC:
        case ALT_FPGA_CFG_MODE_PP16_SLOW_NOAES_NODC:
        case ALT_FPGA_CFG_MODE_PP16_SLOW_AES_NODC:
        case ALT_FPGA_CFG_MODE_PP32_FAST_NOAES_NODC:
        case ALT_FPGA_CFG_MODE_PP32_FAST_AES_NODC:
        case ALT_FPGA_CFG_MODE_PP32_SLOW_NOAES_NODC:
        case ALT_FPGA_CFG_MODE_PP32_SLOW_AES_NODC:
            if (compressed)
            {
                ALT_PRINTF("WARNING: MSEL [%d] likely configured incorrectly for compressed FPGA image.\n", mode);
                ALT_PRINTF("WARNING: Because of this, FPGA programming will probably fail.\n");
            }
            else
            {
                ALT_PRINTF("INFO: MSEL [%d] configured correctly for uncompressed FPGA image.\n", mode);
            }
            break;

            /* Invalid modes */
        default:
            ALT_PRINTF("ERROR: Incompatible MSEL [%d] set. Cannot continue with FPGA programming.\n", mode);
            status = ALT_E_ERROR;
            break;
        }
    }

    /* Program the FPGA */
    if (status == ALT_E_SUCCESS)
    {
        /* Try the full configuration a few times. */
        const uint32_t full_config_retry = 5;
        uint32_t i;
        for (i = 0; i < full_config_retry; ++i)
        {
            status = alt_fpga_configure_dma(fpga_image, fpga_image_size, dma_channel);
            if (status == ALT_E_SUCCESS)
            {
                break;
            }
        }
    }

    if (status == ALT_E_SUCCESS)
    {
        ALT_PRINTF("INFO: Setup of FPGA successful.\n\n");
    }
    else
    {
        ALT_PRINTF("ERROR: Setup of FPGA failed. [status = %" PRIi32 "].\n\n", status);
    }

    return status;
}

void socfpga_fpga_cleanup(void)
{
    ALT_PRINTF("INFO: Cleanup of FPGA ...\n");

    if (alt_fpga_control_disable() != ALT_E_SUCCESS)
    {
        ALT_PRINTF("WARN: alt_fpga_control_disable() returned non-SUCCESS.\n");
    }

    if (alt_fpga_uninit() != ALT_E_SUCCESS)
    {
        ALT_PRINTF("WARN: alt_fpga_uninit() returned non-SUCCESS.\n");
    }
}

ALT_STATUS_CODE socfpga_bridge_setup(ALT_BRIDGE_t bridge)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    ALT_PRINTF("INFO: Setup Bridge [%d] ...\n", bridge);

    if (status == ALT_E_SUCCESS)
    {
        status = alt_bridge_init(bridge, NULL, NULL);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_addr_space_remap(ALT_ADDR_SPACE_MPU_ZERO_AT_BOOTROM,
                                      ALT_ADDR_SPACE_NONMPU_ZERO_AT_OCRAM,
                                      ALT_ADDR_SPACE_H2F_ACCESSIBLE,
                                      ALT_ADDR_SPACE_LWH2F_ACCESSIBLE);
    }

    if (status == ALT_E_SUCCESS)
    {
        ALT_PRINTF("INFO: Setup of Bridge [%d] successful.\n\n", bridge);
    }
    else
    {
        ALT_PRINTF("ERROR: Setup of Bridge [%d] failed. [status = %" PRIi32 "].\n\n", bridge, status);
    }

    return status;
}

void socfpga_bridge_cleanup(ALT_BRIDGE_t bridge)
{
    ALT_PRINTF("INFO: Cleanup of Bridge [%d] ...\n", bridge);

    if (alt_bridge_uninit(bridge, NULL, NULL) != ALT_E_SUCCESS)
    {
        ALT_PRINTF("WARN: alt_bridge_uninit() returned non-SUCCESS.\n");
    }
}

ALT_STATUS_CODE socfpga_bridge_io(void)
{
    const uint32_t ALT_LWFPGA_BASE         = 0xFF200000;
    const uint32_t ALT_LWFPGA_SYSID_OFFSET = 0x00060008;
    const uint32_t ALT_LWFPGA_LED_OFFSET   = 0x00060040;

    /* Attempt to read the system ID peripheral */
    uint32_t sysid = alt_read_word(ALT_LWFPGA_BASE + ALT_LWFPGA_SYSID_OFFSET);
    /* Attempt to toggle the 4 LEDs */
    const uint32_t bits = 4;
    uint32_t i, j;

    ALT_PRINTF("INFO: LWFPGA Slave => System ID Peripheral value = 0x%" PRIx32 ".\n", sysid);

    ALT_PRINTF("INFO: Demostrating IO across bridge ...\n");

    ALT_PRINTF("INFO: Toggling LEDs ...\n");
    for (i = 0; i < (1 << bits); ++i)
    {
        /* Use Gray code ... for fun!
         * http://en.wikipedia.org/wiki/Gray_code */
        uint32_t gray = (i >> 1) ^ i;

        alt_write_word(ALT_LWFPGA_BASE + ALT_LWFPGA_LED_OFFSET, gray);

        ALT_PRINTF("INFO: Gray code(i=0x%x) => 0x%x [", (unsigned int)i, (unsigned int)gray);

        for (j = 0; j < bits; ++j)
        {
            ALT_PRINTF("%c", (gray & (1 << (bits - j - 1))) ? '1' : '0');
        }

        ALT_PRINTF("].\n");
    }

    /* Reset the LEDs to all on */
    alt_write_word(ALT_LWFPGA_BASE + ALT_LWFPGA_LED_OFFSET, 0);

    ALT_PRINTF("INFO: LEDs should have blinked.\n\n");

    return ALT_E_SUCCESS;
}

int main(int argc, char** argv)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;
    ALT_DMA_CHANNEL_t channel;

    /* This example only works on the Cyclone 5. */
    if (!alt_hps_detect_is_cyclone5())
    {
        printf("ERROR: FPGA example is specific to Cyclone 5 SoCFPGA.\n");
        printf(" -> Please visit http://www.altera.com/ for more SoCFPGA examples.\n");
        return 1;
    }

    if (status == ALT_E_SUCCESS)
    {
        status = socfpga_dma_setup(&channel);
    }

    if (status == ALT_E_SUCCESS)
    {
        /* This is the symbol name for the SOF file contents linked in. */
        extern char _binary_soc_system_dc_rbf_start;
        extern char _binary_soc_system_dc_rbf_end;

        /* Use the above symbols to extract the FPGA image information. */
        const char *   fpga_image      = &_binary_soc_system_dc_rbf_start;
        const uint32_t fpga_image_size = &_binary_soc_system_dc_rbf_end - &_binary_soc_system_dc_rbf_start;

        /* Trace the FPGA image information. */
        ALT_PRINTF("INFO: FPGA Image binary at %p.\n", fpga_image);
        ALT_PRINTF("INFO: FPGA Image size is %" PRIu32 " bytes.\n", fpga_image_size);

        status = socfpga_fpga_setup_dma(fpga_image, fpga_image_size, channel);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = socfpga_bridge_setup(ALT_BRIDGE_LWH2F);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = socfpga_bridge_io();
    }

    socfpga_bridge_cleanup(ALT_BRIDGE_LWH2F);
    socfpga_fpga_cleanup();
    socfpga_dma_cleanup(channel);
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
