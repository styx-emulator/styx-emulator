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
#include "fsl_smartcard.h"
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
#define SMARTCARD_Control(base, handle, control, param) SMARTCARD_UART_Control(base, handle, control, 0)
#define SMARTCARD_TransferNonBlocking(base, handle, xfer) SMARTCARD_UART_TransferNonBlocking(base, handle, xfer)
#define SMARTCARD_Init(base, handle, sourceClockHz) SMARTCARD_UART_Init(base, handle, sourceClockHz)
#define SMARTCARD_Deinit(base) SMARTCARD_UART_Deinit(base)
#define SMARTCARD_GetTransferRemainingBytes(base, handle) SMARTCARD_UART_GetTransferRemainingBytes(base, handle)
#define SMARTCARD_AbortTransfer(base, handle) SMARTCARD_UART_AbortTransfer(base, handle)

#define CORE_CLK_FREQ CLOCK_GetFreq(kCLOCK_CoreSysClk)
#define MAX_TRANSFER_SIZE (258u)
#define EMVL1_ATR_BUFF_SIZE (100u)
/*! @brief Smartcard instruction codes */
#define READ_BINARY 0xB0u  /*!< Command to read binary data from smartcard */
#define SELECT 0xA4u       /*!< Select command */
#define GET_RESPONSE 0xC0u /*!< Get response command */

#define ICC_ID_LENGTH 0x0Au   /*!< ICC-ID binary length */
#define COMMAND_SUCCESS 0x90u /*!< Smartcard command success status code */
#define GSM_CLA 0xA0u         /*!< GSM CLA code */

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
#if !defined(USING_PHY_GPIO)
static void wait_for_card_presence(smartcard_context_t *context);
#endif
static int16_t receive_atr(smartcard_context_t *context, uint8_t *buf, uint16_t length);
void smartcard_interface_callback_function(void *context, void *param);
static void smartcard_installTimeDelay(smartcard_context_t *context);
void timeDelay(uint32_t microseconds);
static void smartcard_interrupts_config(void);
static int smartcard_test(void);
static int smartcard_parse_atr(smartcard_context_t *context, uint8_t *buff, uint8_t length);
static uint16_t receive_data(smartcard_context_t *context, uint8_t *buff, uint16_t length);
static void send_data(smartcard_context_t *context, uint8_t *buff, uint16_t length);

/*******************************************************************************
 * Variables
 ******************************************************************************/
#if defined(FSL_FEATURE_SOC_EMVSIM_COUNT) && FSL_FEATURE_SOC_EMVSIM_COUNT
static EMVSIM_Type *base = BOARD_SMARTCARD_MODULE;
#else
static UART_Type *base = BOARD_SMARTCARD_MODULE;
#endif
/*! @brief Smartcard driver context structure */
smartcard_context_t *g_smartcardContext;
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
/*
 * This example will example the efficiency of the transmit/receive drivers with
 * using non-blocking/async methods. Transfer data between board and GSM(SIM) cards.
 * The example will read ICC-ID (Integrated circuit identifier).
 */

/*!
 * @brief Function configures interrupt priorities for modules used in this example.
 */
static void smartcard_interrupts_config(void)
{
    /* Set smartcard communication peripheral interrupt priority */
    NVIC_SetPriority(BOARD_SMARTCARD_MODULE_IRQ, 8u);
#if defined(BOARD_SMARTCARD_MODULE_ERRIRQ)
    NVIC_SetPriority(BOARD_SMARTCARD_MODULE_ERRIRQ, 8u);
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
 * @brief Time delay required by smartcard test and smartcard driver. Function
 * waits desired time with accuracy 1us.
 */
void timeDelay(uint32_t microseconds)
{
    microseconds++;
    /* Wait desired time */
    while (microseconds > 0u)
    {
        if (SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk)
        {
            microseconds--;
        }
    }
}
/*! @brief Function initializes time delay for smartcard driver */
static void smartcard_installTimeDelay(smartcard_context_t *context)
{
    /* Disable SysTick timer */
    SysTick->CTRL &= ~SysTick_CTRL_ENABLE_Msk;
    /* Initialize Reload value to 1us */
    SysTick->LOAD = CORE_CLK_FREQ / 1000000u;
    /* Set clock source to processor clock */
    SysTick->CTRL |= SysTick_CTRL_CLKSOURCE_Msk;
    /* Disable SysTick exception request */
    SysTick->CTRL &= ~(SysTick_CTRL_TICKINT_Msk);
    /* Enable SysTick timer */
    SysTick->CTRL |= SysTick_CTRL_ENABLE_Msk;
    /* Store time delay function to smartcard context */
    context->timeDelay = timeDelay;
}
#if !defined(USING_PHY_GPIO)
/*!
 * @brief This function waits for card insertion/detection
 */
static void wait_for_card_presence(smartcard_context_t *context)
{
    smartcard_interface_control_t interfaceControl = kSMARTCARD_InterfaceReadStatus;

    /* Putting delay as few boards has de-bouncing cap in card slot presence detect pin */
    timeDelay(1000 * 1000);
    /* Read card presence status */
    SMARTCARD_PHY_Control(base, context, interfaceControl, 0u);
    /* Check if a card is already inserted */
    if (false == context->cardParams.present)
    {
        PRINTF("Please insert a smart card to test \r\n");
    }
    do
    { /* Read card presence status */
        SMARTCARD_PHY_Control(base, context, interfaceControl, 0u);
    } while (context->cardParams.present == false);
}
#endif

/*!
 * @brief Callback function for the Smartcard interface/PHY IC ISR
 */
void smartcard_interface_callback_function(void *context, void *param)
{
    /* Insertion/removal action occur.
     * Do whatever you want */
}

/*!
 * @brief This function receives the ATR bytes.
 */
static int16_t receive_atr(smartcard_context_t *context, uint8_t *buf, uint16_t length)
{
    smartcard_xfer_t xfer;

    /* Set the correct context */
    context->transferState = kSMARTCARD_ReceivingState;
    xfer.size = length;
    xfer.buff = buf;
    xfer.direction = kSMARTCARD_Receive;
    /* Receive ATR bytes using non-blocking API */
    SMARTCARD_TransferNonBlocking(base, context, &xfer);
    /* Wait for transfer to finish */
    while (0 != SMARTCARD_GetTransferRemainingBytes(base, context))
    {
    }
    /* Return number of read bytes */
    return (length - context->xSize);
}

/*!
 * @brief Function sends data using smartcard driver API.
*/
static void send_data(smartcard_context_t *context, uint8_t *buff, uint16_t length)
{
    smartcard_xfer_t xfer;

    /* Initialize transfer structure */
    xfer.size = length;
    xfer.buff = buff;
    xfer.direction = kSMARTCARD_Transmit;
    /* Wait until previous transfer is completed */
    while (0 != SMARTCARD_GetTransferRemainingBytes(base, context))
    {
    }
    /* Send data to card */
    if (kStatus_SMARTCARD_Success != SMARTCARD_TransferNonBlocking(base, context, &xfer))
    {
        return;
    }
    /* Wait until transfer is completed */
    while (0 != SMARTCARD_GetTransferRemainingBytes(base, context))
    {
    }
}

/*!
 * @brief Function receives data using smartcard driver API and returns received num. of bytes.
 */
static uint16_t receive_data(smartcard_context_t *context, uint8_t *buff, uint16_t length)
{
    smartcard_xfer_t xfer;

    /* Fill transfer structure */
    xfer.direction = kSMARTCARD_Receive;
    xfer.buff = buff;
    xfer.size = length;
    /* wait until previous transfer is finished */
    while (0 != SMARTCARD_GetTransferRemainingBytes(base, context))
    {
    }
    /* Receive ATR bytes */
    SMARTCARD_TransferNonBlocking(base, context, &xfer);
    /* Wait until transfer is completed */
    while (0 != SMARTCARD_GetTransferRemainingBytes(base, context))
    {
    }

    return (length - context->xSize);
}

/*!
 * @brief Function parse received ATR(gets only Fi/Di parameters) and set card parameters.
 */
static int smartcard_parse_atr(smartcard_context_t *context, uint8_t *buff, uint8_t length)
{
    uint16_t Fi;
    uint8_t ch;
    uint16_t i;
    uint8_t TCK = 0u;
    uint8_t Y1;
    uint8_t Y2;
    uint8_t historicalBytes = 0u;
    smartcard_card_params_t *cardParams = &context->cardParams;

    cardParams->modeNegotiable = true;
    cardParams->atrComplete = true;
    cardParams->atrValid = true;

    for (i = 0u; i < length; i++)
    {
        TCK ^= buff[i];
    }

    if (length == 0u)
    {
        cardParams->atrComplete = false;
        return -1;
    }
    /* parsing data */
    i = 0u;
    /* STORING y1 TO CHECK WHICH COMPONENTS ARE AVAILABLE */
    ch = buff[i];
    Y1 = ch >> 4u;
    historicalBytes = ch & 0x0fu;
    length -= historicalBytes;
    i++;
    if (Y1 & 0x1u)
    {
        /* TA1 present */
        if (i >= length)
        {
            /* TA1 not found,hence generate error */
            cardParams->atrComplete = false;
            return -1;
        }
        ch = buff[i];
        Fi = ch >> 4u;
        /* switch to the real Fi value, according to the table of Spec-3, chapter 8.3 */
        switch (Fi)
        {
/*Fi = 1 is only allowed value*/
#if defined(ISO7816_CARD_SUPPORT)
            case 0u:
                cardParams->Fi = 372u;
                cardParams->fMax = 4u;
                break;
#endif
            case 1u:
                cardParams->Fi = 372u;
                cardParams->fMax = 5u;
                break;
#if defined(ISO7816_CARD_SUPPORT)
            case 2u:
                cardParams->Fi = 558u;
                cardParams->fMax = 6u;
                break;
            case 3u:
                cardParams->Fi = 744u;
                cardParams->fMax = 8u;
                break;
            case 4u:
                cardParams->Fi = 1116u;
                cardParams->fMax = 12u;
                break;
            case 5u:
                cardParams->Fi = 1488u;
                cardParams->fMax = 16u;
                break;
            case 6u:
                cardParams->Fi = 1860u;
                cardParams->fMax = 20u;
                break;
            case 9u:
                cardParams->Fi = 512u;
                cardParams->fMax = 5u;
                break;
            case 10u:
                cardParams->Fi = 768u;
                cardParams->fMax = 7u;
                break;
            case 11u:
                cardParams->Fi = 1024u;
                cardParams->fMax = 10u;
                break;
            case 12u:
                cardParams->Fi = 1536u;
                cardParams->fMax = 15u;
                break;
            case 13u:
                cardParams->Fi = 2048u;
                cardParams->fMax = 20u;
                break;
#endif
            default:
                cardParams->Fi = 372u;
                cardParams->fMax = 5u;
                cardParams->atrValid = false;
                return -1;
        }
        cardParams->Di = ch & 0xfu;
        switch (cardParams->Di)
        {
            /* Di = 4 is only allowed value */
            case 1u:
                cardParams->Di = 1u;
                break;
            case 2u:
                cardParams->Di = 2u;
                break;
            case 3u:
                cardParams->Di = 4u;
                break;
#if defined(ISO7816_CARD_SUPPORT)
            case 4u:
                cardParams->Di = 8u;
                break;
            case 5u:
                cardParams->Di = 16u;
                break;
            case 6u:
                cardParams->Di = 32u;
                break;
            case 7u:
                cardParams->Di = 64u;
                break;
            case 8u:
                cardParams->Di = 12u;
                break;
            case 9u:
                cardParams->Di = 20u;
                break;
#endif
            default:
                cardParams->Di = 1;
                cardParams->atrValid = false;
                return -1;
        }
        i++;
    }
    else
    {
        cardParams->Fi = 372u;
        cardParams->fMax = 5u;
        cardParams->Di = 1u;
    }
    if (Y1 & 0x2u)
    {
        /* TB1 present */
        if (i >= length)
        {
            /* TB1 not found,hence generate error */
            cardParams->atrComplete = false;
            return -1;
        }
        ch = buff[i];
        if ((context->resetType == kSMARTCARD_ColdReset) && (ch > 0x00u))
        {
            cardParams->atrValid = false;
            return -1;
        }
        i++;
    }
#if !defined(ISO7816_CARD_SUPPORT)
    else
    {
        if (context->resetType == kSMARTCARD_ColdReset)
        {
            /* TB1 must be explicitly null in a COLD ATR */
            cardParams->atrValid = false;
            return -1;
        }
    }
#endif
    if (Y1 & 0x4u)
    { /* TC1 present */
        if (i >= length)
        {
            /* TC1 not found,hence generate error */
            cardParams->atrComplete = false;
            return -1;
        }
        ch = buff[i];
        if (ch == 0xffu)
        {
            cardParams->GTN = 0xFFu;
        }
        else
        {
            cardParams->GTN = ch;
        }
        i++;
    }
    else
    {
        cardParams->GTN = 0x00u;
    }
    if (Y1 & 0x8u)
    { /* TD1 present */
        if (i >= length)
        {
            /* TD1 not found,hence generate error */
            cardParams->atrComplete = false;
            return -1;
        }
        ch = buff[i];
        if ((buff[i] & 0xfu) == 0u)
        { /* T=0 is first offered protocol and hence must be used until TD2 is present
            indicating presence of T=1 and TA2 is absent indicating negotiable mode */
            cardParams->t0Indicated = true;
            cardParams->t1Indicated = false;
        }
        else if ((buff[i] & 0xfu) == 1u)
        { /* T=1 is first offered protocol and hence must be used
            TA2 is absent indicating negotiable mode */
            cardParams->t1Indicated = true;
            cardParams->t0Indicated = false;
        }
        else
        {
            cardParams->atrValid = false;
            return -1;
        }
        Y2 = ch >> 4u;
        i++;
    }
    else
    { /* TD1 absent,meaning only T= 0 has to be used*/
        cardParams->t0Indicated = true;
        cardParams->t1Indicated = false;
        Y2 = 0u;
    }
    if (Y2 & 0x1u)
    {
        /* TA2 present */
        if (i >= length)
        { /* TA2 not found,hence generate error */
            cardParams->atrComplete = false;
            return -1;
        }
        cardParams->modeNegotiable = false;
        ch = buff[i];
        if ((ch & 0x0fu) == 0u)
        { /* T = 0 specific mode */
            cardParams->t0Indicated = true;
            cardParams->t1Indicated = false;
        }
        else if ((ch & 0x0fu) == 1u)
        { /* T = 1 specific mode */
            if (!cardParams->t1Indicated)
            {
                cardParams->atrValid = false;
                return -1;
            }
            else
            {
                cardParams->t0Indicated = false;
            }
        }
        else
        { /* Unsupported Protocol type*/
            cardParams->atrValid = false;
            return -1;
        }
        if (ch & 0x10u)
        {
            cardParams->atrValid = false;
            /* b5 should be zero;hence generate error */
            return -1;
        }
        i++;
    }
    else
    { /* TA2 absent */
        cardParams->modeNegotiable = true;
    }
    if (Y2 & 0x2u)
    { /* TB2 present */
        if (i >= length)
        {
            /*TB2 not found,hence generate error*/
            cardParams->atrComplete = false;
            return -1;
        }
        i++;
        /* TB2 is not supported by EMV ;hence generate error */
        cardParams->atrValid = false;
        return -1;
    }
    if (Y2 & 0x4u)
    { /* TC2 present */
        if (i >= length)
        {
            /* TC2 not found,hence generate error */
            cardParams->atrComplete = false;
            return -1;
        }
        /* ch contains temp value of WI sent by ICC */
        ch = buff[i];
        if (ch == 0u)
        { /* WI can't be zero */
            cardParams->atrValid = false;
            return -1;
        }
        else
        {
            cardParams->WI = ch;
        }
        i++;
    }
    else
    { /* TC2 absent;hence WI = 0x0A ; default value */
        cardParams->WI = 0x0Au;
    }

    return 0;
}

/*!
 * @brief Demonstration of smartcard driver.
 * Function read ICC-ID from GSM smartcards.
 */
static int smartcard_test(void)
{
    uint8_t atrBuff[EMVL1_ATR_BUFF_SIZE];
    uint16_t i;
    uint32_t rcvLength = 0;
    smartcard_context_t context = {0};
    g_smartcardContext = &context;
    uint8_t txBuff[MAX_TRANSFER_SIZE] = {0};
    uint8_t rxBuff[MAX_TRANSFER_SIZE] = {0};

    memset(&context, 0, sizeof(smartcard_context_t));

    /* Initialize smartcard interrupts */
    smartcard_interrupts_config();
    /* Initialize interface configuration structure to default values */
    SMARTCARD_PHY_GetDefaultConfig(&context.interfaceConfig);
    /* Fill in SMARTCARD driver user configuration data */
    context.interfaceConfig.smartCardClock = BOARD_SMARTCARD_CLOCK_VALUE;
    context.interfaceConfig.vcc = kSMARTCARD_VoltageClassB3_3V;

#if (defined(USING_PHY_GPIO) || defined(USING_PHY_TDA8035))
    context.interfaceConfig.clockModule = BOARD_SMARTCARD_CLOCK_MODULE;
    context.interfaceConfig.clockModuleChannel = BOARD_SMARTCARD_CLOCK_MODULE_CHANNEL;
    context.interfaceConfig.clockModuleSourceClock = BOARD_SMARTCARD_CLOCK_MODULE_SOURCE_CLK;
    context.interfaceConfig.controlPort = BOARD_SMARTCARD_CONTROL_PORT;
    context.interfaceConfig.controlPin = BOARD_SMARTCARD_CONTROL_PIN;
    context.interfaceConfig.resetPort = BOARD_SMARTCARD_RST_PORT;
    context.interfaceConfig.resetPin = BOARD_SMARTCARD_RST_PIN;
#endif

#if defined(BOARD_SMARTCARD_IRQ_PORT)
    context.interfaceConfig.irqPort = BOARD_SMARTCARD_IRQ_PORT;
    context.interfaceConfig.irqPin = BOARD_SMARTCARD_IRQ_PIN;
#endif

#if defined(USING_PHY_TDA8035)
    context.interfaceConfig.vsel0Port = BOARD_SMARTCARD_VSEL0_PORT;
    context.interfaceConfig.vsel0Pin = BOARD_SMARTCARD_VSEL0_PIN;
    context.interfaceConfig.vsel1Port = BOARD_SMARTCARD_VSEL1_PORT;
    context.interfaceConfig.vsel1Pin = BOARD_SMARTCARD_VSEL1_PIN;
#endif

#if defined(USING_PHY_GPIO)
    context.interfaceConfig.dataPort = BOARD_SMARTCARD_DATA_PORT;
    context.interfaceConfig.dataPin = BOARD_SMARTCARD_DATA_PIN;
    context.interfaceConfig.dataPinMux = BOARD_SMARTCARD_DATA_PIN_MUX;
#endif

/* Setup the numerical id for TS detection timer */
#if defined(BOARD_SMARTCARD_TS_TIMER_ID)
    context.interfaceConfig.tsTimerId = BOARD_SMARTCARD_TS_TIMER_ID;
#endif

    /* Install time delay defined in application to smartcard driver. */
    smartcard_installTimeDelay(&context);
    PRINTF("\r\n***** SMARTCARD Driver Send Receive functionality example *****\r\n\r\n");
    /* Initialize the smartcard module with base address and config structure*/
    SMARTCARD_Init(base, &context, BOARD_SMARTCARD_CLOCK_MODULE_CLK_FREQ);
    SMARTCARD_PHY_Init(base, &context.interfaceConfig, BOARD_SMARTCARD_CLOCK_MODULE_CLK_FREQ);
    /* Install test/application callback function */
    context.interfaceCallback = smartcard_interface_callback_function;
#if !defined(USING_PHY_GPIO)
    /* Wait for a card inserted */
    wait_for_card_presence(&context);
    PRINTF("Card inserted.\r\n");
#endif
    /* Deactivate the card */
    PRINTF("Deactivating card...");
    SMARTCARD_PHY_Deactivate(base, &context);
    PRINTF("Done!\r\n");
    /* Invalidate ATR buffer first */
    memset(atrBuff, 0, EMVL1_ATR_BUFF_SIZE);
    /* Activate the card */
    PRINTF("Resetting/Activating card...");
    /* Enable Initial character detection first */
    SMARTCARD_Control(base, &context, kSMARTCARD_EnableInitDetect, 0u);
    /* Invoke SMARTCARD IP specific function to activate the card */
    SMARTCARD_PHY_Activate(base, &context, kSMARTCARD_ColdReset);
    /* Enable receiver */
    SMARTCARD_Control(base, &context, kSMARTCARD_EnableReceiverMode, 0u);
    /* Clear timers status flags */
    context.timersState.adtExpired = false;
    context.timersState.wwtExpired = false;
    /* Enable ATR timer and disable wait timer */
    SMARTCARD_Control(base, &context, kSMARTCARD_EnableADT, 0u);
    SMARTCARD_Control(base, &context, kSMARTCARD_DisableWWT, 0u);
    /* Set internal driver context to receive initial TS character */
    context.transferState = kSMARTCARD_WaitingForTSState;
    context.xIsBusy = true;
    /* Wait for Initial character. In case wrong Initial character is received, reject the card
    */
    while ((context.xIsBusy == true) && (context.transferState == kSMARTCARD_WaitingForTSState))
    { /* Wait until all the data is received, or error occurs */
    }
    if (context.transferState == kSMARTCARD_InvalidTSDetecetedState || context.timersState.initCharTimerExpired)
    { /* Reject the card */
        PRINTF("INVALID ATR received.... \r\nCard Rejected !\r\n");
        return -1;
    }
    /* Start WWT,CWT and ADT timer */
    context.timersState.wwtExpired = false;
    context.timersState.cwtExpired = false;
    /* Enable WWT and ADT timer before starting T=0 transport */
    SMARTCARD_Control(base, &context, kSMARTCARD_ResetWWT, 0u);
    SMARTCARD_Control(base, &context, kSMARTCARD_EnableWWT, 0u);
    /* Receiving cold ATR */
    /* Disable NACK while receiving ATR */
    SMARTCARD_Control(base, &context, kSMARTCARD_DisableAnack, 0u);
    receive_atr(&context, atrBuff, EMVL1_ATR_BUFF_SIZE);
    /* Enable the NACK after receiving ATR */
    SMARTCARD_Control(base, &context, kSMARTCARD_EnableAnack, 0u);
    /* Disable ATR & WorkWait timers */
    SMARTCARD_Control(base, &context, kSMARTCARD_DisableADT, 0u);
    SMARTCARD_Control(base, &context, kSMARTCARD_DisableWWT, 0u);
    /* Initialize card known ATR parameters */
    if (0u != smartcard_parse_atr(&context, atrBuff, EMVL1_ATR_BUFF_SIZE))
    {
        PRINTF("Parsing received ATR failed.\r\n");
        return -1;
    }
    PRINTF("Done!\r\n======================================================\r\n");
    /* Check if baud rate tune up is allowed */
    if (!context.cardParams.modeNegotiable)
    {
        context.cardParams.currentD = context.cardParams.Di;
        /* Update baud rate according received ATR */
        SMARTCARD_Control(base, &context, kSMARTCARD_ConfigureBaudrate, 0u);
    }
    /******************* Setup for T=0 transfer *******************/
    SMARTCARD_Control(base, &context, kSMARTCARD_SetupT0Mode, 0u);
    /* Initialize timer states in driver */
    context.timersState.wwtExpired = false;
    context.timersState.cwtExpired = false;
    context.timersState.bwtExpired = false;
    /* Reset WWT timer */
    SMARTCARD_Control(base, &context, kSMARTCARD_ResetWWT, 0u);
    /* Enable WWT timer before starting T=0 transport */
    SMARTCARD_Control(base, &context, kSMARTCARD_EnableWWT, 0u);

    /* Send a PPS for T=0 mode */
    /* send a PPS indicating T=1 protocol */
    txBuff[0u] = 0xFFu;
    txBuff[1u] = 0x00u;
    txBuff[2u] = 0x00u;
    /* Calculate CRC value */
    for (i = 0u; i < 2u; i++)
    {
        txBuff[2u] ^= txBuff[i];
    }
    /* Send PPS */
    send_data(&context, txBuff, 3u);
    /* Receive response on PPS command */
    receive_data(&context, rxBuff, 3u);

    /* SELECT GSM MASTER ROOT FILE */
    PRINTF("Selecting Master root file.\r\n");
    txBuff[0u] = GSM_CLA; /* CLA: GSM command class */
    txBuff[1u] = SELECT;  /* Instruction code Select file */
    txBuff[2u] = 0x00u;   /* P1 */
    txBuff[3u] = 0x00u;   /* P2 */
    txBuff[4u] = 0x02u;   /* P3 = Lc */
    txBuff[5u] = 0x3Fu;   /* Master root file */
    txBuff[6u] = 0x00u;   /* Master root file */
    /* SEND COMMAND HEADER AT FIRST */
    /* Start WWT timer */
    context.timersState.wwtExpired = false;
    context.timersState.cwtExpired = false;
    context.timersState.bwtExpired = false;
    /* Reset WWT timer */
    SMARTCARD_Control(base, &context, kSMARTCARD_ResetWWT, 0u);
    /* Enable WWT timer before starting T=0 transport */
    SMARTCARD_Control(base, &context, kSMARTCARD_EnableWWT, 0u);
    /* Send command header */
    send_data(&context, txBuff, 5u);
    /* Wait for INS byte */
    receive_data(&context, &context.statusBytes[0u], 1u);
    /* Check received response on command header */
    if (context.statusBytes[0u] != SELECT)
    {
        PRINTF("Getting INS select file byte failed.\r\n");
        return -1;
    }

    /* SEND T-APDU COMMAND PAYLOAD */
    /* Start WWT timer */
    context.timersState.wwtExpired = false;
    context.timersState.cwtExpired = false;
    context.timersState.bwtExpired = false;
    /* Reset WWT timer */
    SMARTCARD_Control(base, &context, kSMARTCARD_ResetWWT, 0u);
    /* Enable WWT timer before starting T=0 transport */
    SMARTCARD_Control(base, &context, kSMARTCARD_EnableWWT, 0u);
    /* Send command data */
    send_data(&context, txBuff + 5u, 2u);
    /* Wait for Status bytes using */
    receive_data(&context, &context.statusBytes[0u], 2u);
    /* Check status bytes
     *(expecting 0x9F == ME shall use the GET RESPONSE command to get the response data ) */
    if (context.statusBytes[0u] != 0x9Fu)
    {
        PRINTF("GSM file selection failed. \r\n ");
        return -1;
    }
    /* Second status byte inform about length of data will be send on get response command */
    rcvLength = context.statusBytes[1u];
    memset(rxBuff, 0u, MAX_TRANSFER_SIZE);
    context.statusBytes[0u] = 0u;
    context.statusBytes[1u] = 0u;

    /* Get response on file selection command. Second status byte is Le for
     * get response command */
    PRINTF("Getting response of selection command.\r\n");
    txBuff[0u] = GSM_CLA;      /* GSM CLA command */
    txBuff[1u] = GET_RESPONSE; /* INS: Get response */
    txBuff[2u] = 0x00u;        /* P1 */
    txBuff[3u] = 0x00u;        /* P2 */
    txBuff[4u] = rcvLength;    /* Le */
    /* SEND COMMAND HEADER */
    /* Start WWT timer */
    context.timersState.wwtExpired = false;
    context.timersState.cwtExpired = false;
    context.timersState.bwtExpired = false;
    /* Reset WWT timer */
    SMARTCARD_Control(base, &context, kSMARTCARD_ResetWWT, 0u);
    /* Enable WWT timer before starting T=0 transport */
    SMARTCARD_Control(base, &context, kSMARTCARD_EnableWWT, 0u);
    /* Send Command header */
    send_data(&context, txBuff, 5u);
    /* Wait for INS byte using non-blocking API */
    receive_data(&context, &context.statusBytes[0u], 1u);
    /* Check if sent INS byte was received correctly */
    if (GET_RESPONSE != context.statusBytes[0])
    {
        PRINTF("Getting INS get response byte failed.\r\n");
        return -1;
    }
    /* RECEIVE DATA OF GET RESPONSE COMMAND */
    receive_data(&context, rxBuff, rcvLength);
    /* receive status bytes */
    receive_data(&context, &context.statusBytes[0u], 2u);
    /* Check if received status bytes is success */
    if (((context.statusBytes[0u] != COMMAND_SUCCESS) || (context.statusBytes[1u] != 0x00u)))
    {
        PRINTF("Get response for GSM11 file selection command failed.\r\n");
        return -1;
    }
    memset(rxBuff, 0u, MAX_TRANSFER_SIZE);
    context.statusBytes[0u] = 0u;
    context.statusBytes[1u] = 0u;

    /* SELECT ICC-ID FILE */
    PRINTF("Selecting ICC-ID file.\r\n");
    /* Start WWT timer */
    context.timersState.wwtExpired = false;
    context.timersState.cwtExpired = false;
    context.timersState.bwtExpired = false;
    /* Reset WWT timer */
    SMARTCARD_Control(base, &context, kSMARTCARD_ResetWWT, 0u);
    /* Enable WWT timer before starting T=0 transport */
    SMARTCARD_Control(base, &context, kSMARTCARD_EnableWWT, 0u);
    txBuff[0u] = GSM_CLA; /* CLA: GSM command */
    txBuff[1u] = SELECT;  /* Instruction code Select file */
    txBuff[2u] = 0x00u;   /* P1 */
    txBuff[3u] = 0x00u;   /* P2 */
    txBuff[4u] = 0x02u;   /* P3 = Lc */
    txBuff[5u] = 0x2Fu;   /* ICCID file */
    txBuff[6u] = 0xE2u;   /* ICCID file */
    /* Send command header at first */
    send_data(&context, txBuff, 5u);
    /* Wait for INS byte */
    receive_data(&context, &context.statusBytes[0u], 1u);
    /* Check received response on command header */
    if (context.statusBytes[0u] != SELECT)
    {
        PRINTF("Getting INS select file byte failed.\r\n");
        return -1;
    }
    /* SEND T-APDU COMMAND PAYLOAD */
    /* Start WWT timer */
    context.timersState.wwtExpired = false;
    context.timersState.cwtExpired = false;
    context.timersState.bwtExpired = false;
    /* Reset WWT timer */
    SMARTCARD_Control(base, &context, kSMARTCARD_ResetWWT, 0u);
    /* Enable WWT timer before starting T=0 transport */
    SMARTCARD_Control(base, &context, kSMARTCARD_EnableWWT, 0u);
    /* Send command data */
    send_data(&context, txBuff + 5u, 2u);
    /* Wait for Status bytes using */
    receive_data(&context, &context.statusBytes[0u], 2u);
    /* Check received status bytes */
    if (context.statusBytes[0u] != 0x9Fu)
    {
        PRINTF("ICC-ID file selection failed.\r\n");
        return -1;
    }
    memset(rxBuff, 0u, MAX_TRANSFER_SIZE);
    context.statusBytes[0u] = 0u;
    context.statusBytes[1u] = 0u;

    /* READ BINARY ICC-ID */
    PRINTF("Reading binary ICC-ID.\r\n");
    /* Start WWT timer */
    context.timersState.wwtExpired = false;
    context.timersState.cwtExpired = false;
    context.timersState.bwtExpired = false;
    /* Reset WWT timer */
    SMARTCARD_Control(base, &context, kSMARTCARD_ResetWWT, 0u);
    /* Enable WWT timer before starting T=0 transport */
    SMARTCARD_Control(base, &context, kSMARTCARD_EnableWWT, 0u);
    txBuff[0u] = GSM_CLA;       /* GSM CLA command */
    txBuff[1u] = READ_BINARY;   /* INS: Read binary */
    txBuff[2u] = 0x00u;         /* P1 */
    txBuff[3u] = 0x00u;         /* P2 */
    txBuff[4u] = ICC_ID_LENGTH; /* Le */
    /* Send command header */
    send_data(&context, txBuff, 5u);
    /* Wait for INS byte using non-blocking API */
    receive_data(&context, &context.statusBytes[0u], 1u);
    /* Check if sent INS byte was received correctly */
    if (READ_BINARY != context.statusBytes[0u])
    {
        PRINTF("Getting INS get response byte failed.\r\n");
        return -1;
    }
    /* RECEIVE DATA OF GET RESPONSE COMMAND */
    receive_data(&context, rxBuff, 10u);
    /* receive status bytes */
    receive_data(&context, &context.statusBytes[0u], 2u);
    /* Check if received status bytes is success */
    if (COMMAND_SUCCESS != context.statusBytes[0u])
    {
        PRINTF("Get response command failed.\r\n ");
        return -1;
    }
    PRINTF("Received smartcard ICC-IC: ");
    uint8_t digit = 0u;
    for (i = 0u; i < ICC_ID_LENGTH - 1; i++)
    {
        digit = rxBuff[i] & 0x0Fu;
        PRINTF("%c", digit + 0x30u);
        digit = (uint8_t)(rxBuff[i] >> 4u);
        PRINTF("%c", digit + 0x30u);
    }
    PRINTF("\r\n");
    PRINTF("======================================================\r\n");
    PRINTF("\r\nSmartcard functionality example finished successfully !\r\n");

    return 0;
}

/*!
 * @brief Main function
 */
int main(void)
{
    /* Initialize board hardware */
    BOARD_InitPins();

    /* Initialize pin interrupt */
    PORT_SetPinInterruptConfig(PORTD, 14u, kPORT_InterruptEitherEdge);

    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();
    /* Call smartcard driver demonstration example */
    if (0u != smartcard_test())
    {
        PRINTF("Command status bytes 0x%.2X 0x%.2X.\r\n", g_smartcardContext->statusBytes[0],
               g_smartcardContext->statusBytes[1u]);
        PRINTF("Example ends with unexpectedly. Please try another card.\r\n");
    }
    /* De-initialize smartcard phy driver */
    SMARTCARD_PHY_Deinit(base, &g_smartcardContext->interfaceConfig);
    /* De-initialize smartcard driver */
    SMARTCARD_Deinit(base);

    while (1u)
    {
    }
}
