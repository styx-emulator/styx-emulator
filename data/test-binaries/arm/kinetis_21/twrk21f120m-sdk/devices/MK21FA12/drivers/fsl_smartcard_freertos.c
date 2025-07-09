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

#include "fsl_smartcard_freertos.h"

#define REMOVE_SYNC // os sync is only need in the beginning of  the T0/T1 cmd, rather than this place

/* Returns non zero value if the controller is in ISR */
#define IS_IRQ_CONTEXT() (SCB->ICSR & SCB_ICSR_VECTACTIVE_Msk)

/*******************************************************************************
* Variables
******************************************************************************/

/*******************************************************************************
* Prototypes
******************************************************************************/

/*******************************************************************************
* Code
******************************************************************************/
/*! @brief Function is executed from ISR */
static void SMARTCARD_RTOS_Callback(void *handle, void *param)
{
    rtos_smartcard_context_t *ctx = (rtos_smartcard_context_t *)param;
    BaseType_t reschedule;

    if (IS_IRQ_CONTEXT())
    {
        xSemaphoreGiveFromISR(ctx->x_event, &reschedule);
        portYIELD_FROM_ISR(reschedule);
    }
    else
    {
        xSemaphoreGive(ctx->x_event);
    }
}

int SMARTCARD_RTOS_Init(void *base, rtos_smartcard_context_t *ctx, uint32_t sourceClockHz)
{
    if ((NULL == ctx) || (0 == sourceClockHz) || (NULL == base))
    {
        return kStatus_InvalidArgument;
    }

    /* Allocate RTOS synchronization objects */
    ctx->x_sem = xSemaphoreCreateMutex();
    if ((NULL == ctx->x_sem))
    {
        return kStatus_Fail;
    }
    ctx->x_event = xSemaphoreCreateBinary();
    if ((NULL == ctx->x_event))
    {
        vSemaphoreDelete(ctx->x_sem);
        return kStatus_Fail;
    }
    /* Get default driver configuration */
    SMARTCARD_GetDefaultConfig(&ctx->x_context.cardParams);
    SMARTCARD_PHY_GetDefaultConfig(&ctx->x_context.interfaceConfig);
    /* Initialize and configure smartcard peripheral driver */
    if (kStatus_SMARTCARD_Success != (smartcard_status_t)SMARTCARD_Init(base, &ctx->x_context, sourceClockHz))
    {
        vSemaphoreDelete(ctx->x_event);
        vSemaphoreDelete(ctx->x_sem);
        return kStatus_Fail;
    }
    /* Initialize and configure smartcard PHY driver */
    if (kStatus_SMARTCARD_Success !=
        (smartcard_status_t)SMARTCARD_PHY_Init(base, &ctx->x_context.interfaceConfig, sourceClockHz))
    {
        vSemaphoreDelete(ctx->x_event);
        vSemaphoreDelete(ctx->x_sem);
        return kStatus_Fail;
    }
    /* Set transfer callback */
    ctx->x_context.transferCallback = SMARTCARD_RTOS_Callback;
    ctx->x_context.transferCallbackParam = (void *)ctx;

    return kStatus_Success;
}

int SMARTCARD_RTOS_Deinit(rtos_smartcard_context_t *ctx)
{
    if ((NULL == ctx))
    {
        return kStatus_InvalidArgument;
    }
    if ((ctx->x_context.base == NULL) || (ctx->x_event == NULL) || (ctx->x_sem == NULL))
    {
        return kStatus_Fail;
    }
    /* De-initialize SMARTCARD PHY driver */
    SMARTCARD_PHY_Deinit(ctx->x_context.base, &ctx->x_context.interfaceConfig);
    /* De-initialize SMARTCARD driver */
    SMARTCARD_Deinit(ctx->x_context.base);
    /* Free allocated RTOS synchronization objects */
    vSemaphoreDelete(ctx->x_event);
    /* Give the semaphore. This is for functional safety */
    xSemaphoreGive(ctx->x_sem);
    vSemaphoreDelete(ctx->x_sem);

    return kStatus_Success;
}

int SMARTCARD_RTOS_Transfer(rtos_smartcard_context_t *ctx, smartcard_xfer_t *xfer)
{
    int retval = kStatus_Success;

    if ((NULL == ctx) || (NULL == xfer))
    {
        return kStatus_InvalidArgument;
    }
    if ((0u == xfer->size))
    {
        return kStatus_Success;
    }

#ifndef REMOVE_SYNC
    /* Try to take semaphore */
    if ((pdFALSE == xSemaphoreTake(ctx->x_sem, 0)))
    { /* We could not take the semaphore, exit with 0 data received */
        return kStatus_Fail;
    }
#endif
    /* Non-blocking call */
    if (kStatus_SMARTCARD_Success != SMARTCARD_Transfer(ctx->x_context.base, &ctx->x_context, xfer))
    {
        retval = kStatus_Fail;
    }
    if (kStatus_Success == retval)
    {
        /* Wait until all bytes are transferred */
        xSemaphoreTake(ctx->x_event, portMAX_DELAY);
    }

#ifndef REMOVE_SYNC
    if (pdFALSE == xSemaphoreGive(ctx->x_sem))
    { /* We could not release the semaphore, exit with error */
        retval = kStatus_Fail;
    }
#endif
    return retval;
}

int SMARTCARD_RTOS_AbortTransfer(rtos_smartcard_context_t *ctx)
{
    if ((NULL == ctx))
    {
        return kStatus_InvalidArgument;
    }

    SMARTCARD_AbortTransfer(ctx->x_context.base, &ctx->x_context);

    return kStatus_Success;
}

int SMARTCARD_RTOS_WaitForXevent(rtos_smartcard_context_t *ctx)
{
    int retval = kStatus_Success;

    if ((NULL == ctx))
    {
        return kStatus_InvalidArgument;
    }

#ifndef REMOVE_SYNC
    /* Try to take semaphore */
    if ((pdFALSE == xSemaphoreTake(ctx->x_sem, 0)))
    { /* We could not take the semaphore, exit with 0 data received */
        return kStatus_Fail;
    }
#endif

    /* Wait until all bytes are transferred */
    xSemaphoreTake(ctx->x_event, portMAX_DELAY);

#ifndef REMOVE_SYNC
    if (pdFALSE == xSemaphoreGive(ctx->x_sem))
    { /* We could not release the semaphore, exit with error */
        retval = kStatus_Fail;
    }
#endif

    return retval;
}

int SMARTCARD_RTOS_Control(rtos_smartcard_context_t *ctx, smartcard_control_t control, uint32_t param)
{
    int retval = kStatus_Success;

    if ((NULL == ctx))
    {
        return kStatus_InvalidArgument;
    }

#ifndef REMOVE_SYNC
    /* Try to take semaphore */
    if ((pdFALSE == xSemaphoreTake(ctx->x_sem, 0)))
    { /* We could not take the semaphore, exit with 0 data received */
        return kStatus_Fail;
    }
#endif

    /* Call SMARTCARD PHY control function */
    if (kStatus_SMARTCARD_Success !=
        (smartcard_status_t)SMARTCARD_Control(ctx->x_context.base, &ctx->x_context, control, param))
    {
        retval = kStatus_Fail;
    }

#ifndef REMOVE_SYNC
    /* Try to give semaphore */
    if (pdFALSE == xSemaphoreGive(ctx->x_sem))
    { /* We could not release the semaphore, exit with error */
        retval = kStatus_Fail;
    }
#endif
    return retval;
}

int SMARTCARD_RTOS_PHY_Control(rtos_smartcard_context_t *ctx, smartcard_interface_control_t control, uint32_t param)
{
    int retval = kStatus_Success;

    if ((NULL == ctx))
    {
        return kStatus_InvalidArgument;
    }

#ifndef REMOVE_SYNC
    /* Try to take semaphore */
    if ((pdFALSE == xSemaphoreTake(ctx->x_sem, 0)))
    { /* We could not take the semaphore, exit with 0 data received */
        return kStatus_Fail;
    }
#endif

    /* Call SMARTCARD PHY control function */
    if (kStatus_SMARTCARD_Success !=
        (smartcard_status_t)SMARTCARD_PHY_Control(ctx->x_context.base, &ctx->x_context, control, param))
    {
        retval = kStatus_Fail;
    }

#ifndef REMOVE_SYNC
    /* Try to give semaphore */
    if (pdFALSE == xSemaphoreGive(ctx->x_sem))
    { /* We could not release the semaphore, exit with error */
        retval = kStatus_Fail;
    }
#endif

    return retval;
}

int SMARTCARD_RTOS_PHY_Activate(rtos_smartcard_context_t *ctx, smartcard_reset_type_t resetType)
{
    int retval = kStatus_Success;

    if ((NULL == ctx))
    {
        return kStatus_InvalidArgument;
    }

#ifndef REMOVE_SYNC
    /* Try to take semaphore */
    if ((pdFALSE == xSemaphoreTake(ctx->x_sem, 0)))
    { /* We could not take the semaphore, exit with 0 data received */
        return kStatus_Fail;
    }
#endif
    /* Call SMARTCARD PHY activate function */
    if (kStatus_SMARTCARD_Success !=
        (smartcard_status_t)SMARTCARD_PHY_Activate(ctx->x_context.base, &ctx->x_context, resetType))
    {
        retval = kStatus_Fail;
    }
#ifndef REMOVE_SYNC
    /* Try to give semaphore */
    if (pdFALSE == xSemaphoreGive(ctx->x_sem))
    { /* We could not release the semaphore, exit with error */
        retval = kStatus_Fail;
    }
#endif

    return retval;
}

int SMARTCARD_RTOS_PHY_Deactivate(rtos_smartcard_context_t *ctx)
{
    int retval = kStatus_Success;

    if ((NULL == ctx))
    {
        return kStatus_InvalidArgument;
    }

#ifndef REMOVE_SYNC
    /* Try to take semaphore */
    if ((pdFALSE == xSemaphoreTake(ctx->x_sem, 0)))
    { /* We could not take the semaphore, exit with 0 data received */
        return kStatus_Fail;
    }
#endif

    /* Call SMARTCARD PHY deactivate function */
    if (kStatus_SMARTCARD_Success != (smartcard_status_t)SMARTCARD_PHY_Deactivate(ctx->x_context.base, &ctx->x_context))
    {
        retval = kStatus_Fail;
    }

#ifndef REMOVE_SYNC
    /* Try to give semaphore */
    if (pdFALSE == xSemaphoreGive(ctx->x_sem))
    { /* We could not release the semaphore, exit with error */
        retval = kStatus_Fail;
    }
#endif

    return retval;
}
