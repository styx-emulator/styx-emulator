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

#ifndef _FSL_MMA8451Q_H_
#define _FSL_MMA8451Q_H_

#include "fsl_common.h"
#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && (FSL_FEATURE_SOC_LPI2C_COUNT > 0)
#include "fsl_lpi2c.h"
#else
#include "fsl_i2c.h"
#endif

/*!
 * @brief Register definitions for the MMA8451.
 */
enum _mma8451_constants
{
    kMMA8451_STATUS = 0x00,
    kMMA8451_OUT_X_MSB = 0x01,
    kMMA8451_OUT_X_LSB = 0x02,
    kMMA8451_OUT_Y_MSB = 0x03,
    kMMA8451_OUT_Y_LSB = 0x04,
    kMMA8451_OUT_Z_MSB = 0x05,
    kMMA8451_OUT_Z_LSB = 0x06,
    kMMA8451_F_SETUP = 0x09,
    kMMA8451_TRIG_CFG = 0x0a,
    kMMA8451_SYSMOD = 0x0b,
    kMMA8451_INT_SOURCE = 0x0c,
    kMMA8451_WHO_AM_I = 0x0d,
    kMMA8451_WHO_AM_I_Device_ID = 0x1a,
    kMMA8451_XYZ_DATA_CFG = 0x0e,
    kMMA8451_CTRL_REG1 = 0x2a,
    kMMA8451_CTRL_REG2 = 0x2b,
    kMMA8451_CTRL_REG3 = 0x2c,
    kMMA8451_CTRL_REG4 = 0x2d,
    kMMA8451_CTRL_REG5 = 0x2e
};

typedef struct _mma_data
{
    uint8_t accelXMSB;
    uint8_t accelXLSB;
    uint8_t accelYMSB;
    uint8_t accelYLSB;
    uint8_t accelZMSB;
    uint8_t accelZLSB;
} mma_data_t;

/*! @brief mma8451q configure definition. This structure should be global.*/
typedef struct _mma_handle
{
#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && (FSL_FEATURE_SOC_LPI2C_COUNT)
    LPI2C_Type *base;
    lpi2c_master_transfer_t xfer;
    lpi2c_master_handle_t *i2cHandle;
#else
    I2C_Type *base;                 /*!< I2C base. */
    i2c_master_handle_t *i2cHandle; /*!< I2C master transfer context */
    i2c_master_transfer_t xfer;     /*!< I2C master xfer */
#endif
} mma_handle_t;

/*******************************************************************************
 * API
 ******************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @brief Initialize the MMA8451 driver instance.
 *
 * @param accel_device Device driver state structure that will be filled in by this function.
 *      It is the responsibility of the caller to provide storage for this structure, and
 *      to free that storage when the driver is no longer needed.
 *
 * @return kStatus_Success if success or kStatus_Fail if error.
 */
status_t MMA_Init(mma_handle_t *handle);

/*!
 * @brief Read the current acceleration values.
 *
 * @param handle Pointer to a valid accel_device instance structure.
 * @param accel Pointer to a structure that will be filled in with the current acceleration
 *      values for all three axes.
 *
 * @return kStatus_Success if success or kStatus_Fail if error.
 */
status_t MMA_ReadSensorData(mma_handle_t *handle, mma_data_t *accel);

/*!
 * @brief Read the value of register in accelerometer.
 *
 * @param handle Pointer to a valid accel_device instance structure.
 * @param reg variable store address of register
 * @param val pointer store return value.
 *
 * @return kStatus_Success if success or kStatus_Fail if error.
 */
status_t MMA_ReadReg(mma_handle_t *handle, uint8_t reg, uint8_t *val);

/*!
 * @brief Write the value to register of accelerometer.
 *
 * @param handle Pointer to a valid accel_device instance structure.
 * @param reg variable store address of register
 * @param val pointer store value which is writen to accelerometer.
 *
 * @return kStatus_Success if success or kStatus_Fail if error.
 */
status_t MMA_WriteReg(mma_handle_t *handle, uint8_t reg, uint8_t val);

#if defined(__cplusplus)
}
#endif

#endif /* _FSL_MMA8451Q_H_ */
