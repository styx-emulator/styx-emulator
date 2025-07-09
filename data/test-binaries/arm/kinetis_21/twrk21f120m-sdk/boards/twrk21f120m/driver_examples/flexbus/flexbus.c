/*
 * The Clear BSD License
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016-2017 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted (subject to the limitations in the disclaimer below) provided
 * that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this list
 *   of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * o Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY THIS LICENSE.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "fsl_debug_console.h"
#include "fsl_flexbus.h"
#include "board.h"

#include "fsl_common.h"
#include "pin_mux.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define MRAM_START_ADDRESS 0x60000000U

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
* @brief Main function
*/
int main(void)
{
    /* Variables */
    volatile uint32_t j;
    /* Data to write to MRAM */
    const uint32_t wdata = 0xDDCCBBAAU;
    /* Variable to read MRAM */
    uint32_t rdata;
    uint32_t n;
    int32_t *p_mram = (int32_t *)MRAM_START_ADDRESS;
    bool result = true;
    /* FlexBus configuration structure */
    flexbus_config_t flexbusUserConfig;

    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();
    PRINTF("\r\nFLEXBUS Example.\r\n");

    /*
     * Initialize configurations for MRAM.
     * Refer application note: AN4393.
     */
    /* Get default config */
    /*
     * flexbusUserConfig.writeProtect = 0;
     * flexbusUserConfig.burstWrite = 0;
     * flexbusUserConfig.burstRead = 0;
     * flexbusUserConfig.byteEnableMode = 0;
     * flexbusUserConfig.autoAcknowledge = true;
     * flexbusUserConfig.extendTransferAddress = 0;
     * flexbusUserConfig.secondaryWaitStates = 0;
     * flexbusUserConfig.byteLaneShift = kFLEXBUS_NotShifted;
     * flexbusUserConfig.writeAddressHold = kFLEXBUS_Hold1Cycle;
     * flexbusUserConfig.readAddressHold = kFLEXBUS_Hold1Or0Cycles;
     * flexbusUserConfig.addressSetup = kFLEXBUS_FirstRisingEdge;
     * flexbusUserConfig.portSize = kFLEXBUS_1Byte;
     * flexbusUserConfig.group1MultiplexControl = kFLEXBUS_MultiplexGroup1_FB_ALE;
     * flexbusUserConfig.group2MultiplexControl = kFLEXBUS_MultiplexGroup2_FB_CS4;
     * flexbusUserConfig.group3MultiplexControl = kFLEXBUS_MultiplexGroup3_FB_CS5;
     * flexbusUserConfig.group4MultiplexControl = kFLEXBUS_MultiplexGroup4_FB_TBST;
     * flexbusUserConfig.group5MultiplexControl = kFLEXBUS_MultiplexGroup5_FB_TA;
     */
    FLEXBUS_GetDefaultConfig(&flexbusUserConfig);
    /* Configure some parameters when using MRAM */
    flexbusUserConfig.waitStates = 2U;                      /* Wait 2 states */
    flexbusUserConfig.chipBaseAddress = MRAM_START_ADDRESS; /* MRAM address for using FlexBus */
    flexbusUserConfig.chipBaseAddressMask = 7U;             /* 512 Kbytes memory size */

    PRINTF("\r\nInitialize FLEXBUS.\r\n");
    /* Initialize and configure FLEXBUS module */
    FLEXBUS_Init(FB, &flexbusUserConfig);

    PRINTF("\r\nStart write/read MRAM.\r\n");

    /* Waiting some times */
    for (j = 0; j < 0xFFFFFFU; j++)
    {
        __NOP();
    }

    for (n = 0x0; n < 0xFU; n++)
    {
        /* Write data to MRAM */
        *(p_mram + n) = wdata;
    }
    /* Waiting some times */
    for (j = 0; j < 0xFFFFU; j++)
    {
        __NOP();
    }
    for (n = 0x0; n < 0xFU; n++)
    {
        /* Read data back from MRAM */
        rdata = *(p_mram + n);
        /* Verify that rdata equals to wdata */
        if (rdata != wdata)
        {
            result = false;
            break;
        }
    }
    if (result)
    {
        PRINTF("\r\nFLEXBUS (MRAM) test: succeed.\r\n");
    }
    else
    {
        PRINTF("\r\nFLEXBUS (MRAM) test: failed.\r\n");
    }

    FLEXBUS_Deinit(FB);

    while (1)
    {
    }
}
