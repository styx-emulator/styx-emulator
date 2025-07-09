/*
 * The Clear BSD License
 * Copyright (c) 2013-2015, Freescale Semiconductor, Inc.
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

#include "fsl_mma.h"

/******************************************************************************
 * Code
 ******************************************************************************/
#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && (FSL_FEATURE_SOC_LPI2C_COUNT)
volatile static bool g_completionFlag = false;
volatile static bool g_nakFlag = false;

void MMA_master_callback(LPI2C_Type *base, lpi2c_master_handle_t *handle, status_t status, void *userData)
{
    /* Signal transfer success when received success status. */
    if (status == kStatus_Success)
    {
        g_completionFlag = true;
    }
    /* Signal transfer success when received success status. */
    if (status == kStatus_LPI2C_Nak)
    {
        g_nakFlag = true;
    }
}
#endif

status_t MMA_Init(mma_handle_t *handle)
{
    uint8_t val = 0;

    /* Reset sensor */
    if(MMA_ReadReg(handle, kMMA8451_CTRL_REG2, &val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    val &= (uint8_t)(~(1 >> 7));
    if(MMA_WriteReg(handle, kMMA8451_CTRL_REG2, val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    /* Put the mma8451 into standby mode */
    if(MMA_ReadReg(handle, kMMA8451_CTRL_REG1, &val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    val &= (uint8_t)(~(0x01));
    if(MMA_WriteReg(handle, kMMA8451_CTRL_REG1, val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    /* Set the range, -4g to 4g */
    if(MMA_ReadReg(handle, kMMA8451_XYZ_DATA_CFG, &val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    val &= (uint8_t)(~0x03);
    val |= 0x01;
    if(MMA_WriteReg(handle, kMMA8451_XYZ_DATA_CFG, val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    /* Set the F_MODE, disable FIFO */
    if(MMA_ReadReg(handle, kMMA8451_F_SETUP, &val) != kStatus_Success)
    {
        return kStatus_Fail;
    }

    val &= 0x3F;
    if(MMA_WriteReg(handle, kMMA8451_F_SETUP, val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    /* Put the mma8451 into active mode */
    if(MMA_ReadReg(handle, kMMA8451_CTRL_REG1, &val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    val |= 0x01;
    val &= (uint8_t)(~0x02); /* set F_READ to 0 */
    if(MMA_WriteReg(handle, kMMA8451_CTRL_REG1, val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    return kStatus_Success;
}

status_t MMA_ReadSensorData(mma_handle_t *handle, mma_data_t *accel)
{
    uint8_t val = 0U;
    uint8_t ucStatus = 0;

    do
    {
        if(MMA_ReadReg(handle, kMMA8451_STATUS, &ucStatus) != kStatus_Success)
        {
            return kStatus_Fail;
        }
    } while (!(ucStatus & 0x08));

    if(MMA_ReadReg(handle, kMMA8451_OUT_X_MSB, &val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    accel->accelXMSB = val;
    if(MMA_ReadReg(handle, kMMA8451_OUT_X_LSB, &val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    accel->accelXLSB = val;

    if(MMA_ReadReg(handle, kMMA8451_OUT_Y_MSB, &val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    accel->accelYMSB = val;
    if(MMA_ReadReg(handle, kMMA8451_OUT_Y_LSB, &val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    accel->accelYLSB = val;

    if(MMA_ReadReg(handle, kMMA8451_OUT_Z_MSB, &val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    accel->accelZMSB = val;
    if(MMA_ReadReg(handle, kMMA8451_OUT_Z_LSB, &val) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    accel->accelZLSB = val;

    return kStatus_Success;
}

status_t MMA_ReadReg(mma_handle_t *handle, uint8_t reg, uint8_t *val)
{
    status_t status = kStatus_Success;

    /* Configure I2C xfer */
    handle->xfer.subaddress = (uint32_t)reg;
    handle->xfer.subaddressSize = 1U;
    handle->xfer.data = val;
    handle->xfer.dataSize = 1U;
#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && (FSL_FEATURE_SOC_LPI2C_COUNT)
    handle->xfer.direction = kLPI2C_Read;
    handle->xfer.flags = kLPI2C_TransferDefaultFlag;
#else
    handle->xfer.direction = kI2C_Read;
    handle->xfer.flags = kI2C_TransferDefaultFlag;
#endif

#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && (FSL_FEATURE_SOC_LPI2C_COUNT)
    if(LPI2C_MasterTransferNonBlocking(handle->base, handle->i2cHandle, &handle->xfer) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    /*  wait for transfer completed. */
    while ((!g_nakFlag) && (!g_completionFlag))
    {
    }

    g_nakFlag = false;

    if (g_completionFlag == true)
    {
        g_completionFlag = false;
    }
    else
    {
        status = kStatus_Fail;
    }
#else
    status = I2C_MasterTransferBlocking(handle->base, &handle->xfer);
#endif

    return status;
}

status_t MMA_WriteReg(mma_handle_t *handle, uint8_t reg, uint8_t val)
{
    status_t status = kStatus_Success;
    uint8_t buff[1];

    buff[0] = val;
    /* Set I2C xfer structure */
    handle->xfer.subaddress = (uint32_t)reg;
    handle->xfer.subaddressSize = 1U;
    handle->xfer.data = buff;
    handle->xfer.dataSize = 1U;
#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && (FSL_FEATURE_SOC_LPI2C_COUNT)
    handle->xfer.direction = kLPI2C_Write;
    handle->xfer.flags = kLPI2C_TransferDefaultFlag;
#else
    handle->xfer.direction = kI2C_Write;
    handle->xfer.flags = kI2C_TransferDefaultFlag;
#endif

#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && (FSL_FEATURE_SOC_LPI2C_COUNT)
    if(LPI2C_MasterTransferNonBlocking(handle->base, handle->i2cHandle, &handle->xfer) != kStatus_Success)
    {
        return kStatus_Fail;
    }
    /*  wait for transfer completed. */
    while ((!g_nakFlag) && (!g_completionFlag))
    {
    }

    g_nakFlag = false;

    if (g_completionFlag == true)
    {
        g_completionFlag = false;
    }
    else
    {
        status = kStatus_Fail;
    }
#else
    status = I2C_MasterTransferBlocking(handle->base, &handle->xfer);
#endif

    return status;
}
