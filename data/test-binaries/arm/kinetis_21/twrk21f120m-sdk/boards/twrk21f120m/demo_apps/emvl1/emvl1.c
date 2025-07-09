/*
 * The Clear BSD License
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
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

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "board.h"
#include "emvl1_core.h"
#include "emvl1_adapter_sdk.h"

#if defined(FSL_FEATURE_SOC_EMVSIM_COUNT) && FSL_FEATURE_SOC_EMVSIM_COUNT
#include "fsl_smartcard_emvsim.h"
#else
#include "fsl_smartcard_uart.h"
#endif

#include "fsl_smartcard_phy.h"

#include "pin_mux.h"
#include "fsl_port.h"
#include <stdbool.h>
#include "clock_config.h"
/*******************************************************************************
* Definitions
******************************************************************************/
#define CORE_CLK_FREQ CLOCK_GetFreq(kCLOCK_CoreSysClk)
#define EMVL1_ATR_BUFF_SIZE (100u)
#define MAX_AFL (16u)
#define AID_ENTRIES (7u)
#define DESIRED_CARD_INFO_TAGS (3u)
#define CARDHOLDER_NAME_LEN (64u)
#define APP_EXP_DATE_LEN (64u)
#define PRIMARY_ACCOUNT_NUMBER_LEN (64u)
/*! @brief Defines of smartcard payment types. */
typedef enum
{
    kCardMastercard = 0x00,
    kCardVisa,
    kCardVisaElectron,
    kCardAmex,
    kCardEuropay,
    kCardUnionPayDebit,
    kCardUnionPayCredit,
    kCardUnsupported = 0xFF,
} card_type_t;
/*******************************************************************************
* Prototypes
******************************************************************************/
static void wait_for_card_presence(smartcard_context_t *context);
static bool smartcard_emvl1_t0_test(smartcard_core_params_t *coreParams);
static bool smartcard_emvl1_t1_test(smartcard_core_params_t *coreParams);
static int8_t smartcard_tc_check_testresult(smartcard_core_params_t *coreParams);
static void smartcard_init_user_config(smartcard_context_t *context);
void installTimeDelay(smartcard_context_t *context);
void timeDelay(uint32_t miliseconds);
void smartcard_interrupts_config(void);
int extract_afl_list(uint8_t list[MAX_AFL][4], uint8_t *src);
smartcard_core_error_t send_command(smartcard_core_params_t *coreParams,
                                    uint8_t p1,
                                    uint8_t p2,
                                    smartcard_tal_cmd_t *cmd,
                                    smartcard_tal_resp_t *resp,
                                    card_type_t type);

/*******************************************************************************
 * Variables
 ******************************************************************************/
#if defined(FSL_FEATURE_SOC_EMVSIM_COUNT) && FSL_FEATURE_SOC_EMVSIM_COUNT
static EMVSIM_Type *base = BOARD_SMARTCARD_MODULE;
#else
static UART_Type *base = BOARD_SMARTCARD_MODULE;
#endif

smartcard_context_t *g_smartcardContext;
uint8_t txBuff[EMVL1_MAX_TRANSFER_SIZE] = {0u};
uint8_t rxBuff[EMVL1_MAX_TRANSFER_SIZE] = {0u};
uint8_t prim_account_num[PRIMARY_ACCOUNT_NUMBER_LEN] = {0u};
uint8_t expir_date[APP_EXP_DATE_LEN] = {0u};
uint8_t card_holder[CARDHOLDER_NAME_LEN] = {0u};
uint8_t *card_items[DESIRED_CARD_INFO_TAGS] = {&prim_account_num[0], &expir_date[0], &card_holder[0]};
bool cardItem_found[DESIRED_CARD_INFO_TAGS];

/*! @brief EMV Application Identifiers */
const uint8_t g_emvMastercardAid[] = {0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10};
const uint8_t g_emvVisaAid[] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10};
const uint8_t g_emvVisaElectronAid[] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10};
const uint8_t g_emvAmexAid[] = {0xA0, 0x00, 0x00, 0x00, 0x25, 0x01};
const uint8_t g_emvEuropayAid[] = {0xA0, 0x00, 0x00, 0x00, 0x10, 0x10, 0x30};
const uint8_t g_emvUnionPayDebitAid[] = {0xA0, 0x00, 0x00, 0x03, 0x33, 0x01, 0x01, 0x01};
const uint8_t g_emvUnionPayCreditAid[] = {0xA0, 0x00, 0x00, 0x03, 0x33, 0x01, 0x01, 0x02};

const uint32_t g_aidTable[AID_ENTRIES][2] = {
    {(uint32_t)&g_emvMastercardAid, sizeof(g_emvMastercardAid)},
    {(uint32_t)&g_emvVisaAid, sizeof(g_emvVisaAid)},
    {(uint32_t)&g_emvVisaElectronAid, sizeof(g_emvVisaElectronAid)},
    {(uint32_t)&g_emvAmexAid, sizeof(g_emvAmexAid)},
    {(uint32_t)&g_emvEuropayAid, sizeof(g_emvEuropayAid)},
    {(uint32_t)&g_emvUnionPayDebitAid, sizeof(g_emvUnionPayDebitAid)},
    {(uint32_t)&g_emvUnionPayCreditAid, sizeof(g_emvUnionPayCreditAid)},
};

/*! @brief EMV(book 3) Data elements */
const uint8_t g_desiredTags[DESIRED_CARD_INFO_TAGS][2] = {
    {0x5A, 0x00}, /*!< Application Primary account number (PAN) */
    {0x5F, 0x24}, /*!< Application expiration date */
    {0x5F, 0x20}, /*!< Cardholder name */
};
/*******************************************************************************
* Code
******************************************************************************/

/* IRQ handler for uart */
void UART0_RX_TX_IRQHandler(void)
{
    SMARTCARD_UART_IRQHandler(BOARD_SMARTCARD_MODULE, g_smartcardContext);
    /* Add for ARM errata 838869, affects Cortex-M4, Cortex-M4F Store immediate overlapping
    exception return operation might vector to incorrect interrupt */
    __DSB();
}
/* Error IRQ handler for uart */
void UART0_ERR_IRQHandler(void)
{
    SMARTCARD_UART_ErrIRQHandler(BOARD_SMARTCARD_MODULE, g_smartcardContext);
    /* Add for ARM errata 838869, affects Cortex-M4, Cortex-M4F Store immediate overlapping
    exception return operation might vector to incorrect interrupt */
    __DSB();
}
/* Pit timer channel 0 IRQ handler */
void PIT0_IRQHandler(void)
{
    SMARTCARD_UART_TSExpiryCallback(BOARD_SMARTCARD_MODULE, g_smartcardContext);
    /* Add for ARM errata 838869, affects Cortex-M4, Cortex-M4F Store immediate overlapping
    exception return operation might vector to incorrect interrupt */
    __DSB();
}
/* IRQ handler for card presence detection */
void PORTD_IRQHandler(void)
{
    /* Clear interrupt status flags */
    PORT_ClearPinsInterruptFlags(PORTD, 1u << 14u);
    SMARTCARD_PHY_IRQHandler(BOARD_SMARTCARD_MODULE, g_smartcardContext);
    /* Add for ARM errata 838869, affects Cortex-M4, Cortex-M4F Store immediate overlapping
    exception return operation might vector to incorrect interrupt */
    __DSB();
}
/*!
 * @brief Time delay required by smartcard test and smartcard driver. Function
 * waits desired time.
 */
void timeDelay(uint32_t microseconds)
{
    microseconds++;
    /* Wait desired time */
    while (microseconds > 0)
    {
        if (SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk)
        {
            microseconds--;
        }
    }
}

/*!
 * @brief Function initializes time delay for smartcard driver
 */
void installTimeDelay(smartcard_context_t *context)
{
    /* Disable SysTick timer */
    SysTick->CTRL &= ~SysTick_CTRL_ENABLE_Msk;
    /* Initialize Reload value to 1us */
    SysTick->LOAD = CORE_CLK_FREQ / 1000000;
    /* Set clock source to processor clock */
    SysTick->CTRL |= SysTick_CTRL_CLKSOURCE_Msk;
    /* Enable SysTick timer */
    SysTick->CTRL |= SysTick_CTRL_ENABLE_Msk;
    /* Store time delay function to smartcard context */
    context->timeDelay = timeDelay;
}

/*!
 * @brief Function initializes time delay for smartcard driver
 */
void smartcard_interrupts_config(void)
{
    /* Set smartcard communication peripheral interrupt priority */
    NVIC_SetPriority(BOARD_SMARTCARD_MODULE_IRQ, 8u);
#if defined(BOARD_SMARTCARD_MODULE_ERRIRQ)
    NVIC_SetPriority(BOARD_SMARTCARD_MODULE_ERRIRQ, 6u);
#endif
/* Set smartcard presence detect gpio pin interrupt priority */
#if defined(USING_PHY_TDA8035)
    NVIC_SetPriority(BOARD_SMARTCARD_IRQ_PIN_IRQ, 6u);
#endif /* USING_TDA8035_INTERFACE */
       /* Set external PIT timer interrupt priority
        * (used for initial TS char detection time-out) */
#if !(defined(FSL_FEATURE_SOC_EMVSIM_COUNT) && (FSL_FEATURE_SOC_EMVSIM_COUNT))
#if !defined(BOARD_SMARTCARD_TS_TIMER_IRQ)
#error "Please specify external PIT timer interrupt !"
#else
    NVIC_SetPriority(BOARD_SMARTCARD_TS_TIMER_IRQ, 6u);
#endif
#endif
}

/*!
 * @brief This function initialize smartcard_user_config_t structure. Enables configuration
 * of most common settings of the UART peripheral, smartcard clock, smartcard interface configuration,
 * interface instance number, slot number, operating voltage ...
 */
void smartcard_init_user_config(smartcard_context_t *context)
{
    /* Initialize interface configuration structure to default values */
    SMARTCARD_PHY_GET_DEFAULT_CONFIG(&context->interfaceConfig);
    context->interfaceConfig.smartCardClock = BOARD_SMARTCARD_CLOCK_VALUE;
    context->interfaceConfig.vcc = kSMARTCARD_VoltageClassB3_3V;
    context->interfaceConfig.clockModule = BOARD_SMARTCARD_CLOCK_MODULE;
    context->interfaceConfig.clockModuleChannel = BOARD_SMARTCARD_CLOCK_MODULE_CHANNEL;
    context->interfaceConfig.clockModuleSourceClock = BOARD_SMARTCARD_CLOCK_MODULE_SOURCE_CLK;
    context->interfaceConfig.controlPort = BOARD_SMARTCARD_CONTROL_PORT;
    context->interfaceConfig.controlPin = BOARD_SMARTCARD_CONTROL_PIN;
#if defined(BOARD_SMARTCARD_IRQ_PORT)
    context->interfaceConfig.irqPort = BOARD_SMARTCARD_IRQ_PORT;
    context->interfaceConfig.irqPin = BOARD_SMARTCARD_IRQ_PIN;
#endif
    context->interfaceConfig.resetPort = BOARD_SMARTCARD_RST_PORT;
    context->interfaceConfig.resetPin = BOARD_SMARTCARD_RST_PIN;
#if defined(USING_PHY_TDA8035)
    context->interfaceConfig.vsel0Port = BOARD_SMARTCARD_VSEL0_PORT;
    context->interfaceConfig.vsel0Pin = BOARD_SMARTCARD_VSEL0_PIN;
    context->interfaceConfig.vsel1Port = BOARD_SMARTCARD_VSEL1_PORT;
    context->interfaceConfig.vsel1Pin = BOARD_SMARTCARD_VSEL1_PIN;
#endif
#if defined(BOARD_SMARTCARD_TS_TIMER_ID)
    context->interfaceConfig.tsTimerId = BOARD_SMARTCARD_TS_TIMER_ID;
#endif
}

/*!
 * @brief Callback function for the Smartcard interface/PHY IC ISR
 */
void smartcard_interface_callback_function(void *base, void *g_smartcardState)
{
    /* Smartcard insertion/removal event occur */
    /* Put your code here */
}

/*!
 * @brief This function waits for card insertion/detection
 */
void wait_for_card_presence(smartcard_context_t *context)
{
    smartcard_interface_control_t interfaceControl = kSMARTCARD_InterfaceReadStatus;

    /* Putting delay as few boards has de-bouncing cap in card slot presence detect pin */
    timeDelay(1000 * 1000);
    /* clear present flag */
    context->cardParams.present = 0;
    /* Read card presence status */
    SMARTCARD_PHY_CONTROL(context, interfaceControl, 0);
    /* Check if a card is already inserted */
    if (!context->cardParams.present)
    {
        PRINTF("Please insert a smart card to test\r\n");
    }
    /* Wait until card is present */
    while (true)
    {
        /* Read card presence status */
        SMARTCARD_PHY_CONTROL(context, interfaceControl, 0);
        /* Return if card is present/inserted */
        if (context->cardParams.present)
        {
            break;
        }
    }
}

/*!
 * @brief Function search for appropriate card AID from hard-coded table.
 */
card_type_t scan_aid(smartcard_core_params_t *coreParams, smartcard_tal_cmd_t *cmd, smartcard_tal_resp_t *resp)
{
    smartcard_core_error_t status;
    uint32_t i;

    for (i = 0; i < AID_ENTRIES; i++)
    {
        txBuff[0] = 0x00u;
        txBuff[1] = 0xA4u;
        txBuff[2] = 0x04u;
        txBuff[3] = 0x00u;
        txBuff[4] = g_aidTable[i][1];

        memcpy(&txBuff[5u], (uint8_t *)g_aidTable[i][0u], g_aidTable[i][1u]);
        txBuff[5u + g_aidTable[i][1u]] = 0x00u;
        cmd->length = 5u + g_aidTable[i][1u] + 1u;

        status = smartcard_tal_send_cmd(coreParams, cmd, resp);

        smartcard_context_t *drvCtx = (smartcard_context_t *)coreParams->x_context;

        uint8_t sw1 = drvCtx->statusBytes[0u];
        uint8_t sw2 = drvCtx->statusBytes[1u];
        /* Check status bytes, 0x6A 0x82 - File not found */
        if ((status == kSCCoreSuccess) && !(sw1 == 0x6A && sw2 == 0x82))
        {
            /* Match found. */
            switch (i)
            {
                case 0u:
                    return kCardMastercard;
                case 1u:
                    return kCardVisa;
                case 2u:
                    return kCardVisaElectron;
                case 3u:
                    return kCardAmex;
                case 4u:
                    return kCardEuropay;
                case 5u:
                    return kCardUnionPayDebit;
                case 6u:
                    return kCardUnionPayCredit;
            }
        }
    }
    /* No match. */
    return kCardUnsupported;
}

/*!
 * @brief Function sends EMV commands (Get processing options or read of specific record) to ICC.
 */
smartcard_core_error_t send_command(smartcard_core_params_t *coreParams,
                                    uint8_t p1,
                                    uint8_t p2,
                                    smartcard_tal_cmd_t *cmd,
                                    smartcard_tal_resp_t *resp,
                                    card_type_t type)
{
    /* Sending Get processing information */
    if ((0u == p1) && (0u == p2))
    {
        if (type == kCardUnsupported)
        {
            return kSCCoreInvalidInputParameter;
        }
        /* Union Pay cards require to send PDOL from terminal as command data (additional informative tag),
         * according AID file selection response. */
        if ((type == kCardUnionPayDebit) || (type == kCardUnionPayCredit))
        {
            cmd->apdu[0u] = 0x80u; /* Command class */
            cmd->apdu[1u] = 0xA8u; /* INS byte */
            cmd->apdu[2u] = 0x00u; /* P1 */
            cmd->apdu[3u] = 0x00u; /* P2 */
            cmd->apdu[4u] = 0x0Bu; /* Lc = 0x0B */
            /* Lc data */
            cmd->apdu[5u] =
                0x83u; /* Tag indicating requested PDOL objects parsed from AID selection file command response. */
            cmd->apdu[6u] = 0x09u; /* Length of PDOL data. (Data is send without tags.) */
            /* Hard-coded PDOL objects without objects tags. */
            /* VLP Terminal Support Indicator */
            cmd->apdu[7u] = 0x00u;
            /* Amount, Authorised (Numeric) */
            cmd->apdu[8u] = 0x00u;
            cmd->apdu[9u] = 0x00u;
            cmd->apdu[10u] = 0x00u;
            cmd->apdu[11u] = 0x00u;
            cmd->apdu[12u] = 0x01u;
            cmd->apdu[13u] = 0x00u;
            /* Transaction Currency code */
            cmd->apdu[14u] = 0x01u; /* China CNY */
            cmd->apdu[15u] = 0x56u; /* China CNY */
            cmd->apdu[16u] = 0u;    /* Le = 0 */
            cmd->length = 17u;
        }
        else
        { /* Most of MASTER and VISA cards doesn't require sending terminal PDOL tags.
           * Get processing options is send without PDOL tags.*/
            cmd->apdu[0u] = 0x80u;
            cmd->apdu[1u] = 0xA8u;
            cmd->apdu[2u] = 0x00u;
            cmd->apdu[3u] = 0x00u;
            cmd->apdu[4u] = 0x02u;
            cmd->apdu[5u] = 0x83u;
            cmd->apdu[6u] = 0x00u;
            cmd->apdu[7u] = 0x00u;
            cmd->length = 8u;
        }
    }
    else
    {                               /* Read record command to get specific data. */
        cmd->apdu[0u] = 0x00u;      /* Command class */
        cmd->apdu[1u] = 0xB2u;      /* INS - read record */
        cmd->apdu[2u] = p1;         /* P1 */
        cmd->apdu[3u] = p2 | 0x04u; /* P2 */
        cmd->apdu[4u] = 0x00u;      /* Lc = 0 */
        cmd->length = 5u;
    }
    return smartcard_tal_send_cmd(coreParams, cmd, resp);
}

/*!
 * @briefExtract AFL list from GET_PROCESSING_OPTIONS response.
 */
int extract_afl_list(uint8_t list[MAX_AFL][4], uint8_t *src)
{
    uint32_t i;
    uint32_t size = 0u;

    /* Format is tag '80' */
    if (src[0u] == 0x80u)
    {
        /* Subtract 2 from the size (the two bytes being ignored are the AIP. */
        size = src[1u] - 2u;
        if ((size / 4u) > MAX_AFL)
        {
            return 0u;
        }
        for (i = 0u; i < (size / 4u); i++)
        {
            list[i][0u] = src[4u + (i * 4u)];
            list[i][1u] = src[5u + (i * 4u)];
            list[i][2u] = src[6u + (i * 4u)];
            list[i][3u] = src[7u + (i * 4u)];
        }
    }
    /* Format is tag '77' */
    else if (src[0u] == 0x77u)
    {
        /* The size is embedded a bit deeper into the frame. */
        size = src[7u];
        if ((size / 4u) > MAX_AFL)
        {
            return 0u;
        }
        for (i = 0u; i < (size / 4u); i++)
        {
            list[i][0u] = src[8u + (i * 4u)];
            list[i][1u] = src[9u + (i * 4u)];
            list[i][2u] = src[10u + (i * 4u)];
            list[i][3u] = src[11u + (i * 4u)];
        }
    }
    return size / 4u;
}

/*!
 * @brief Parse a READ_RECORD response and extract card info.
 */
int extract_card_info(uint8_t *src)
{
    uint32_t i, itemStart, itemSize, itemNum;

    for (itemNum = 0u; itemNum < DESIRED_CARD_INFO_TAGS; itemNum++)
    {
        if (cardItem_found[itemNum])
        {
            continue;
        }
        /* Find the starting point of the searched item. */
        i = 0;
        itemSize = 0u;
        while (!((src[i] == 0x90u) && (src[i + 1u] == 0x00u)))
        {
            if ((src[i] == g_desiredTags[itemNum][0u]) &&
                ((g_desiredTags[itemNum][1u] == 0u) || (src[i + 1u] == g_desiredTags[itemNum][1u])))
            {
                if ((g_desiredTags[itemNum][0u] == 0x5A) && (src[i + 1u] > 10u))
                {
                    i++;
                    continue;
                }
                if (0u == g_desiredTags[itemNum][1u])
                {
                    itemStart = i + 2u;
                    itemSize = src[i + 1u];
                }
                else
                {
                    itemStart = i + 3u;
                    itemSize = src[i + 2u];
                }
                break;
            }
            i++;
        }
        /* Extract the data element body field.*/
        if (itemSize)
        {
            i = 0u;
            while (i < itemSize)
            {
                card_items[itemNum][i] = src[itemStart + i];
                if (itemNum == 0x02u && (src[itemStart + i] == 0x20u) && (src[itemStart + i + 1u] == 0x20u))
                { /* Terminate the string.*/
                    card_items[itemNum][i] = 0x00u;
                    break;
                }
                i++;
            }
            /* If we reached the end without having two spaces, terminate the string. */
            if (itemNum == 0x02u && i == itemSize)
            {
                card_items[itemNum][i] = 0x00u;
            }
            cardItem_found[itemNum] = true;
        }
    }
    for (itemNum = 0u; itemNum < DESIRED_CARD_INFO_TAGS; itemNum++)
    {
        if (!cardItem_found[itemNum])
        {
            return -1;
        }
    }
    return 0;
}

/*!
 * @brief Function checks error code of last smartcard transfer.
 */
static int8_t smartcard_tc_check_testresult(smartcard_core_params_t *coreParams)
{
    if (coreParams->errCode == kSCCoreSuccess)
    {
        PRINTF("TEST PASSED.\r\n");
    }
    else
    {
        PRINTF("TEST FAILED.\r\n");
    }
    PRINTF("Returned Status Bytes = 0x%2X, 0x%2X\r\n", ((smartcard_context_t *)coreParams->x_context)->statusBytes[0],
           ((smartcard_context_t *)coreParams->x_context)->statusBytes[1]);

    return (coreParams->errCode);
}

/*!
 * @brief T=0 protocol test using EMV Level 1 APIs.
 */
static bool smartcard_emvl1_t0_test(smartcard_core_params_t *coreParams)
{
    uint32_t i, j;
    smartcard_tal_cmd_t talCmd = {0};
    smartcard_tal_resp_t talResp = {0};
    card_type_t type;
    uint8_t aflList[MAX_AFL][4u];
    uint32_t aflListSize = 0u;
    uint8_t number = 0u;
    bool found = false;

    talResp.resp = rxBuff;
    talCmd.apdu = txBuff;
    PRINTF("==========================================\r\n");
    PRINTF("Protocol T=0 test started!\r\n");

    memset(rxBuff, 0, EMVL1_MAX_TRANSFER_SIZE);
    /* T=0 transport test */
    smartcard_setup_t0(coreParams);
    /* Search smartcard AID */
    type = scan_aid(coreParams, &talCmd, &talResp);
    if (kCardUnsupported == type)
    {
        return false;
    }
    memset(rxBuff, 0u, EMVL1_MAX_TRANSFER_SIZE);
    /* Obtain processing options to read card additional information from records */
    if (kSCCoreSuccess != send_command(coreParams, 0u, 0u, &talCmd, &talResp, type))
    {
        PRINTF("Obtaining processing options failed.\r\n");
        return false;
    }
    aflListSize = extract_afl_list(aflList, talResp.resp);
    if (0u == aflListSize)
    {
        PRINTF("Parsing received AFL list failed. \r\n");
        return false;
    }
    /* Read card records to get wanted card info */
    PRINTF("Reading card records to get required data. \r\n");
    /* 'i' is for the list of AFLs present. */
    for (i = 0u; i < aflListSize; i++)
    { /* 'j' is for the number of records in each AFL. */
        for (j = aflList[i][1u]; j <= aflList[i][2u]; j++)
        { /* Send READ_RECORD. */
            if (kSCCoreSuccess != send_command(coreParams, j, aflList[i][0u], &talCmd, &talResp, kCardUnsupported))
            { /* Give up and start a new iteration of the loop. */
                continue;
            }
            /* Parse read record for required data */
            if (0u == extract_card_info(talResp.resp))
            {
                found = true;
                break;
            }
        }
        /* Break when found. */
        if (found)
        {
            break;
        }
    }
    PRINTF("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \r\n");
    PRINTF("Card info:\r\n");
    /* Check if PAN was found */
    if (cardItem_found[0])
    {
        PRINTF("          Primary account number: ");
        for (i = 0u; i < PRIMARY_ACCOUNT_NUMBER_LEN; i++)
        {
            if ((0x00u == card_items[0u][i]) && (0x00u == card_items[0u][i + 1u]))
            {
                break;
            }
            number = (uint8_t)(card_items[0u][i] >> 4u) + 0x30u;
            if (number > 0x39u)
            {
                break;
            }
            PRINTF("%c", number);
            number = (uint8_t)(card_items[0u][i] & 0xFu) + 0x30u;
            if (number > 0x39u)
            {
                break;
            }
            PRINTF("%c ", number);
        }
        PRINTF("\r\n");
    }
    /* Check if Application expiration date was found */
    if (cardItem_found[1u])
    {
        PRINTF("          Application expiration date: ");
        for (i = APP_EXP_DATE_LEN; i > 0u; i--)
        {
            if (0u == card_items[1][i - 1])
            {
                continue;
            }
            PRINTF("%c%c", (uint8_t)(card_items[1][i - 1] >> 4u) + 0x30u,
                   (uint8_t)(card_items[1u][i - 1] & 0x0Fu) + 0x30u);
            if (0u != (i - 1u))
            {
                PRINTF("/");
            }
        }
        PRINTF("\r\n");
    }
    /* Check if Cardholder name was found */
    if (cardItem_found[2u])
    {
        /* Check if cardholder name is valid */
        bool valid = false;
        for (i = 0; i < CARDHOLDER_NAME_LEN; i++)
        {
            if ((0x00u != card_items[2u][i]) || (0x20 != card_items[2u][i]))
            {
                valid = true;
            }
        }
        if (valid)
        {
            PRINTF("          Cardholder name: ");
            for (i = 0; i < CARDHOLDER_NAME_LEN; i++)
            {
                if (((0x20u == card_items[2u][i]) && (0x20u == card_items[2u][i + 1u])) || (0x00u == card_items[2u][i]))
                {
                    break;
                }
                PRINTF("%c", card_items[2u][i]);
            }
            PRINTF("\r\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \r\n");
        }
    }

    return true;
}

/*!
 * @brief T=1 protocol test using EMV Level 1 APIs
 */
static bool smartcard_emvl1_t1_test(smartcard_core_params_t *coreParams)
{
    int length;
    int i;
    int increment = 1;
    smartcard_tal_cmd_t talCmd;
    smartcard_tal_resp_t talResp;

    PRINTF("==========================================\r\n");
    PRINTF("Protocol T=1 test started!\r\n");

    /******************* Setup for T=0 transfer *******************/
    smartcard_setup_t0(coreParams);
    /* send a PPS indicating T=1 protocol */
    txBuff[0u] = 0xFFu;
    txBuff[1u] = 0x01u;
    txBuff[2u] = 0x00u;

    for (i = 0u; i < 2u; i++)
    {
        txBuff[2u] ^= txBuff[i];
    }

    memset(rxBuff, 0, EMVL1_MAX_TRANSFER_SIZE);
    smartcard_send_pps(coreParams, txBuff, rxBuff, 3);

    /* T=1 protocol test */
    length = 16u; /* payload */
    /* APDU */
    txBuff[0u] = 0xC0u;
    txBuff[1u] = 0x14u;     /* instruction code (0x14 for ECHO) */
    txBuff[2u] = increment; /* increment value - P1 */
    txBuff[3u] = 0u;        /* P2 */
    txBuff[4u] = length;    /* P3 = Lc */

    for (i = 0u; i < length; i++)
    {
        txBuff[i + 5u] = i;
    }

    /* last byte is the data length again */
    txBuff[length + 5u] = length;
    /******************* Setup for T=1 transfer *******************/
    smartcard_setup_t1(coreParams);

    talResp.resp = rxBuff;
    talCmd.apdu = txBuff;
    talCmd.length = (4u + 1u + txBuff[4u] + 1u);
    talResp.length = 0u;
    smartcard_tal_send_cmd(coreParams, &talCmd, &talResp);

    /* payload length */
    if (talResp.length != (length + 2))
    {
        return false;
    }

    for (i = 0u; i < length; i++)
    {
        if ((txBuff[i + 5u] + increment) != rxBuff[i])
        {
            PRINTF("Echo test Failed.\r\n");
            return false;
        }
    }
    PRINTF("Echo data matched!\r\n");

    return (kSCCoreSuccess == smartcard_tc_check_testresult(coreParams));
}

/*!
 * @brief This test will use EMV Level 1 APIs from emvlib and do protocol tests for T=0 using a
 * smartcard credit cards.
 */
void smartcard_emvl1_test(uint32_t param)
{
    uint8_t atrBuff[EMVL1_ATR_BUFF_SIZE];
    uint32_t atrLength = 0u;
    smartcard_core_params_t coreParams;
    smartcard_context_t context = {0};
    g_smartcardContext = &context;
    bool testT0done = false;
    bool testT1done = false;
    bool testPassed = false;

    memset(&coreParams, 0u, sizeof(smartcard_core_params_t));
    memset(&context, 0u, sizeof(smartcard_context_t));
    /* initialize EMV Level 1 core library */

    /* app must set EMVL1 in structure smartcard_core_params_t to 1 for emvl1, or 0 for 7816 */
    coreParams.EMVL1 = 1;

    coreParams.x_context = &context;
    /* Initialize smartcard interrupts */
    smartcard_interrupts_config();
    /* Install time delay defined in application to smartcard driver. */
    installTimeDelay(&context);
    /* Fill-in smartcard config structure with init data */
    smartcard_init_user_config(&context);
    /* Print welcome string */
    PRINTF("........................... EMVL1 demo ..............................\r\n");
    /* Initialize the smartcard module with base address and configuration structure */
    SMARTCARD_INIT(base, &context, BOARD_SMARTCARD_CLOCK_MODULE_CLK_FREQ);
    SMARTCARD_PHY_INIT(base, &context.interfaceConfig, BOARD_SMARTCARD_CLOCK_MODULE_CLK_FREQ);
    /* Install test/application callback function */
    context.interfaceCallback = smartcard_interface_callback_function;
    /* Wait for a card inserted */
    wait_for_card_presence(&context);
    PRINTF("Card inserted.\r\n");
    /* Deactivate the card */
    PRINTF("Deactivating card...");
    SMARTCARD_PHY_DEACTIVATE(&context);
    PRINTF("Done!\r\n");

    do
    {
        /* Invalidate ATR buffer first */
        memset(atrBuff, 0, EMVL1_ATR_BUFF_SIZE);
        /* Deactivate the card */
        PRINTF("Resetting/Activating card...");
        /* get ATR */
        atrLength = 0u;
        if (smartcard_reset_handle_atr(&coreParams, atrBuff, kSMARTCARD_ColdReset, kSMARTCARD_NoWarmReset,
                                       &atrLength) == kSCCoreFail)
        {
            PRINTF("Invalid ATR received!\r\n");
            break;
        }
        PRINTF("Done!\r\n");
        if (context.cardParams.t0Indicated && !testT0done)
        { /* Invoke T=0 protocol specific test */
            testPassed = smartcard_emvl1_t0_test(&coreParams);
            testT0done = true;
            if (!testPassed)
            {
                PRINTF("Unsupported card inserted.\r\n");
                PRINTF("Received status bytes: 0x%.2X, 0x%.2X \r\n", context.statusBytes[0u], context.statusBytes[1u]);
            }
        }
        else if (context.cardParams.t1Indicated && !testT1done)
        { /* Invoke T=1 protocol specific test */
            testPassed = smartcard_emvl1_t1_test(&coreParams);
            testT1done = true;
            if (!testPassed)
            {
                PRINTF("Unsupported card inserted.\r\n");
            }
        }
        /* Deactivate the card */
        PRINTF("Deactivating card...");
        SMARTCARD_PHY_DEACTIVATE(coreParams.x_context);
        PRINTF("Done!\r\n");
        if (testT1done || !context.cardParams.t1Indicated)
        {
            break;
        }
    } while (1);
    /* De-initialize smartcard driver */
    SMARTCARD_PHY_DEINIT(base, &context.interfaceConfig);
    SMARTCARD_DEINIT(base);

    PRINTF("***** EMVL1 Demo End *****\r\n\r\n");
}

int main(void)
{
    /* Initialize board hardware */
    BOARD_InitPins();

    /* Initialize pin interrupt */
    PORT_SetPinInterruptConfig(PORTD, 14u, kPORT_InterruptEitherEdge);

    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();
    /* Run emvl1 functionality check */
    smartcard_emvl1_test(0u);

    while (1)
    {
    }
}
