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

#include "fsl_sgtl5000.h"

/*******************************************************************************
 * Definitations
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
void SGTL_Init(sgtl_handle_t *handle, sgtl_config_t *config)
{
    handle->xfer.slaveAddress = SGTL5000_I2C_ADDR;
    volatile uint32_t i = 0;

    /* NULL pointer means default setting. */
    if (config == NULL)
    {
        /* Power up Inputs/Outputs/Digital Blocks
           Power up LINEOUT, HP, ADC, DAC. */
        SGTL_WriteReg(handle, CHIP_ANA_POWER, 0x6AFFU);

        /* Power up desired digital blocks.
        I2S_IN (bit 0), I2S_OUT (bit 1), DAP (bit 4), DAC (bit 5), ADC (bit 6) are powered on */
        SGTL_WriteReg(handle, CHIP_DIG_POWER, 0x0063U);

        /* Configure SYS_FS clock to 48kHz, MCLK_FREQ to 256*Fs. */
        SGTL_ModifyReg(handle, CHIP_CLK_CTRL, 0xFFC8U, 0x0008U);

        /* Configure the I2S clocks in slave mode.
           I2S LRCLK is same as the system sample clock.
           Data length = 16 bits. */
        SGTL_WriteReg(handle, CHIP_I2S_CTRL, 0x0130U);

        /* I2S_IN -> DAC -> HP_OUT, Route I2S_IN to DAC */
        SGTL_ModifyReg(handle, CHIP_SSS_CTRL, 0xFFDFU, 0x0010U);

        /* Select DAC as the input to HP_OUT */
        SGTL_ModifyReg(handle, CHIP_ANA_CTRL, 0xFFBFU, 0x0000U);

        /* LINE_IN -> ADC -> I2S_OUT. Set ADC input to LINE_IN. */
        SGTL_ModifyReg(handle, CHIP_ANA_CTRL, 0xFFFFU, 0x0004U);

        /* Route ADC to I2S_OUT */
        SGTL_ModifyReg(handle, CHIP_SSS_CTRL, 0xFFFCU, 0x0000U);

        /* Default using I2S left format. */
        SGTL_SetProtocol(handle, kSGTL_BusLeftJustified);
    }
    else
    {
        SGTL_WriteReg(handle, CHIP_ANA_POWER, 0x6AFF);

        /* Set the data route */
        SGTL_SetDataRoute(handle, config->route);

        /* Set the audio format */
        SGTL_SetProtocol(handle, config->bus);

        /* Set sgtl5000 to master or slave */
        SGTL_SetMasterSlave(handle, config->master_slave);
    }

    /* Input Volume Control
    Configure ADC left and right analog volume to desired default.
    Example shows volume of 0dB. */
    SGTL_WriteReg(handle, CHIP_ANA_ADC_CTRL, 0x0000U);

    /* Volume and Mute Control
       Configure HP_OUT left and right volume to minimum, unmute.
       HP_OUT and ramp the volume up to desired volume.*/
    SGTL_WriteReg(handle, CHIP_ANA_HP_CTRL, 0x1818U);
    SGTL_ModifyReg(handle, CHIP_ANA_CTRL, 0xFFEFU, 0x0000U);

    /* LINEOUT and DAC volume control */
    SGTL_ModifyReg(handle, CHIP_ANA_CTRL, 0xFEFFU, 0x0000U);

    /* Configure DAC left and right digital volume */
    SGTL_WriteReg(handle, CHIP_DAC_VOL, 0x5C5CU);

    /* Configure ADC volume, reduce 6db. */
    SGTL_WriteReg(handle, CHIP_ANA_ADC_CTRL, 0x0100U);

    /* Unmute DAC */
    SGTL_ModifyReg(handle, CHIP_ADCDAC_CTRL, 0xFFFBU, 0x0000U);
    SGTL_ModifyReg(handle, CHIP_ADCDAC_CTRL, 0xFFF7U, 0x0000U);

    /* Unmute ADC */
    SGTL_ModifyReg(handle, CHIP_ANA_CTRL, 0xFFFEU, 0x0000U);

    /* Delay for some seconds */
    for (i = 0; i < 3000000; i++)
    {
        __ASM("nop");
    }
}

void SGTL_Deinit(sgtl_handle_t *handle)
{
    SGTL_DisableModule(handle, kSGTL_ModuleADC);
    SGTL_DisableModule(handle, kSGTL_ModuleDAC);
    SGTL_DisableModule(handle, kSGTL_ModuleDAP);
    SGTL_DisableModule(handle, kSGTL_ModuleI2SIN);
    SGTL_DisableModule(handle, kSGTL_ModuleI2SOUT);
    SGTL_DisableModule(handle, kSGTL_ModuleLineOut);
}

void SGTL_SetMasterSlave(sgtl_handle_t *handle, bool master)
{
    if (master == 1)
    {
        SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_MS_CLR_MASK, SGTL5000_I2S_MASTER);
    }
    else
    {
        SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_MS_CLR_MASK, SGTL5000_I2S_SLAVE);
    }
}

status_t SGTL_EnableModule(sgtl_handle_t *handle, sgtl_module_t module)
{
    status_t ret = kStatus_Success;
    switch (module)
    {
        case kSGTL_ModuleADC:
            SGTL_ModifyReg(handle, CHIP_DIG_POWER, SGTL5000_ADC_ENABLE_CLR_MASK,
                           ((uint16_t)1U << SGTL5000_ADC_ENABLE_SHIFT));
            SGTL_ModifyReg(handle, CHIP_ANA_POWER, SGTL5000_ADC_POWERUP_CLR_MASK,
                           ((uint16_t)1U << SGTL5000_ADC_POWERUP_SHIFT));
            break;
        case kSGTL_ModuleDAC:
            SGTL_ModifyReg(handle, CHIP_DIG_POWER, SGTL5000_DAC_ENABLE_CLR_MASK,
                           ((uint16_t)1U << SGTL5000_DAC_ENABLE_SHIFT));
            SGTL_ModifyReg(handle, CHIP_ANA_POWER, SGTL5000_DAC_POWERUP_CLR_MASK,
                           ((uint16_t)1U << SGTL5000_DAC_POWERUP_SHIFT));
            break;
        case kSGTL_ModuleDAP:
            SGTL_ModifyReg(handle, CHIP_DIG_POWER, SGTL5000_DAP_ENABLE_CLR_MASK,
                           ((uint16_t)1U << SGTL5000_DAP_ENABLE_SHIFT));
            SGTL_ModifyReg(handle, SGTL5000_DAP_CONTROL, SGTL5000_DAP_CONTROL_DAP_EN_CLR_MASK,
                           ((uint16_t)1U << SGTL5000_DAP_CONTROL_DAP_EN_SHIFT));
            break;
        case kSGTL_ModuleI2SIN:
            SGTL_ModifyReg(handle, CHIP_DIG_POWER, SGTL5000_I2S_IN_ENABLE_CLR_MASK,
                           ((uint16_t)1U << SGTL5000_I2S_IN_ENABLE_SHIFT));
            break;
        case kSGTL_ModuleI2SOUT:
            SGTL_ModifyReg(handle, CHIP_DIG_POWER, SGTL5000_I2S_OUT_ENABLE_CLR_MASK,
                           ((uint16_t)1U << SGTL5000_I2S_OUT_ENABLE_SHIFT));
            break;
        case kSGTL_ModuleHP:
            SGTL_ModifyReg(handle, CHIP_ANA_POWER, SGTL5000_HEADPHONE_POWERUP_CLR_MASK,
                           ((uint16_t)1U << SGTL5000_HEADPHONE_POWERUP_SHIFT));
            break;
        case kSGTL_ModuleLineOut:
            SGTL_ModifyReg(handle, CHIP_ANA_POWER, SGTL5000_LINEOUT_POWERUP_CLR_MASK,
                           ((uint16_t)1U << SGTL5000_LINEOUT_POWERUP_SHIFT));
            break;
        default:
            ret = kStatus_InvalidArgument;
            break;
    }
    return ret;
}

status_t SGTL_DisableModule(sgtl_handle_t *handle, sgtl_module_t module)
{
    status_t ret = kStatus_Success;
    switch (module)
    {
        case kSGTL_ModuleADC:
            SGTL_ModifyReg(handle, CHIP_DIG_POWER, SGTL5000_ADC_ENABLE_CLR_MASK,
                           ((uint16_t)0U << SGTL5000_ADC_ENABLE_SHIFT));
            SGTL_ModifyReg(handle, CHIP_ANA_POWER, SGTL5000_ADC_POWERUP_CLR_MASK,
                           ((uint16_t)0U << SGTL5000_ADC_POWERUP_SHIFT));
            break;
        case kSGTL_ModuleDAC:
            SGTL_ModifyReg(handle, CHIP_DIG_POWER, SGTL5000_DAC_ENABLE_CLR_MASK,
                           ((uint16_t)0U << SGTL5000_DAC_ENABLE_SHIFT));
            SGTL_ModifyReg(handle, CHIP_ANA_POWER, SGTL5000_DAC_POWERUP_CLR_MASK,
                           ((uint16_t)0U << SGTL5000_DAC_POWERUP_SHIFT));
            break;
        case kSGTL_ModuleDAP:
            SGTL_ModifyReg(handle, CHIP_DIG_POWER, SGTL5000_DAP_ENABLE_CLR_MASK,
                           ((uint16_t)0U << SGTL5000_DAP_ENABLE_SHIFT));
            SGTL_ModifyReg(handle, SGTL5000_DAP_CONTROL, SGTL5000_DAP_CONTROL_DAP_EN_CLR_MASK,
                           ((uint16_t)0U << SGTL5000_DAP_CONTROL_DAP_EN_SHIFT));
            break;
        case kSGTL_ModuleI2SIN:
            SGTL_ModifyReg(handle, CHIP_DIG_POWER, SGTL5000_I2S_IN_ENABLE_CLR_MASK,
                           ((uint16_t)0U << SGTL5000_I2S_IN_ENABLE_SHIFT));
            break;
        case kSGTL_ModuleI2SOUT:
            SGTL_ModifyReg(handle, CHIP_DIG_POWER, SGTL5000_I2S_OUT_ENABLE_CLR_MASK,
                           ((uint16_t)0U << SGTL5000_I2S_OUT_ENABLE_SHIFT));
            break;
        case kSGTL_ModuleHP:
            SGTL_ModifyReg(handle, CHIP_ANA_POWER, SGTL5000_HEADPHONE_POWERUP_CLR_MASK,
                           ((uint16_t)0U << SGTL5000_HEADPHONE_POWERUP_SHIFT));
            break;
        case kSGTL_ModuleLineOut:
            SGTL_ModifyReg(handle, CHIP_ANA_POWER, SGTL5000_LINEOUT_POWERUP_CLR_MASK,
                           ((uint16_t)0U << SGTL5000_LINEOUT_POWERUP_SHIFT));
            break;
        default:
            ret = kStatus_InvalidArgument;
            break;
    }
    return ret;
}

status_t SGTL_SetDataRoute(sgtl_handle_t *handle, sgtl_route_t route)
{
    status_t ret = kStatus_Success;
    switch (route)
    {
        case kSGTL_RouteBypass:
            /* Bypass means from line-in to HP*/
            SGTL_WriteReg(handle, CHIP_DIG_POWER, 0x0000);
            SGTL_EnableModule(handle, kSGTL_ModuleHP);
            SGTL_ModifyReg(handle, CHIP_ANA_CTRL, SGTL5000_SEL_HP_CLR_MASK, SGTL5000_SEL_HP_LINEIN);
            break;
        case kSGTL_RoutePlayback:
            /* Data route I2S_IN-> DAC-> HP */
            SGTL_EnableModule(handle, kSGTL_ModuleHP);
            SGTL_EnableModule(handle, kSGTL_ModuleDAC);
            SGTL_EnableModule(handle, kSGTL_ModuleI2SIN);
            SGTL_ModifyReg(handle, CHIP_SSS_CTRL, SGTL5000_DAC_SEL_CLR_MASK, SGTL5000_DAC_SEL_I2S_IN);
            SGTL_ModifyReg(handle, CHIP_ANA_CTRL, SGTL5000_SEL_HP_CLR_MASK, SGTL5000_SEL_HP_DAC);
            break;
        case kSGTL_RoutePlaybackandRecord:
            /* I2S IN->DAC->HP  LINE_IN->ADC->I2S_OUT */
            SGTL_EnableModule(handle, kSGTL_ModuleHP);
            SGTL_EnableModule(handle, kSGTL_ModuleDAC);
            SGTL_EnableModule(handle, kSGTL_ModuleI2SIN);
            SGTL_EnableModule(handle, kSGTL_ModuleI2SOUT);
            SGTL_EnableModule(handle, kSGTL_ModuleADC);
            SGTL_ModifyReg(handle, CHIP_SSS_CTRL, SGTL5000_DAC_SEL_CLR_MASK, SGTL5000_DAC_SEL_I2S_IN);
            SGTL_ModifyReg(handle, CHIP_ANA_CTRL, SGTL5000_SEL_HP_CLR_MASK, SGTL5000_SEL_HP_DAC);
            SGTL_ModifyReg(handle, CHIP_ANA_CTRL, SGTL5000_SEL_ADC_CLR_MASK, SGTL5000_SEL_ADC_LINEIN);
            SGTL_ModifyReg(handle, CHIP_SSS_CTRL, SGTL5000_I2S_OUT_SEL_CLR_MASK, SGTL5000_I2S_OUT_SEL_ADC);
            break;
        case kSGTL_RoutePlaybackwithDAP:
            /* I2S_IN->DAP->DAC->HP */
            SGTL_EnableModule(handle, kSGTL_ModuleHP);
            SGTL_EnableModule(handle, kSGTL_ModuleDAC);
            SGTL_EnableModule(handle, kSGTL_ModuleI2SIN);
            SGTL_EnableModule(handle, kSGTL_ModuleDAP);
            SGTL_ModifyReg(handle, CHIP_SSS_CTRL, SGTL5000_DAP_SEL_CLR_MASK, SGTL5000_DAP_SEL_I2S_IN);
            SGTL_ModifyReg(handle, CHIP_SSS_CTRL, SGTL5000_DAC_SEL_CLR_MASK, SGTL5000_DAC_SEL_DAP);
            SGTL_ModifyReg(handle, CHIP_ANA_CTRL, SGTL5000_SEL_HP_CLR_MASK, SGTL5000_SEL_HP_DAC);
            break;
        case kSGTL_RoutePlaybackwithDAPandRecord:
            /* I2S_IN->DAP->DAC->HP,  LINE_IN->ADC->I2S_OUT */
            SGTL_EnableModule(handle, kSGTL_ModuleHP);
            SGTL_EnableModule(handle, kSGTL_ModuleDAC);
            SGTL_EnableModule(handle, kSGTL_ModuleI2SIN);
            SGTL_EnableModule(handle, kSGTL_ModuleI2SOUT);
            SGTL_EnableModule(handle, kSGTL_ModuleADC);
            SGTL_EnableModule(handle, kSGTL_ModuleDAP);
            SGTL_ModifyReg(handle, SGTL5000_DAP_CONTROL, SGTL5000_DAP_CONTROL_DAP_EN_CLR_MASK, 0x0001);
            SGTL_ModifyReg(handle, CHIP_SSS_CTRL, SGTL5000_DAP_SEL_CLR_MASK, SGTL5000_DAP_SEL_I2S_IN);
            SGTL_ModifyReg(handle, CHIP_SSS_CTRL, SGTL5000_DAC_SEL_CLR_MASK, SGTL5000_DAC_SEL_DAP);
            SGTL_ModifyReg(handle, CHIP_ANA_CTRL, SGTL5000_SEL_HP_CLR_MASK, SGTL5000_SEL_HP_DAC);
            SGTL_ModifyReg(handle, CHIP_ANA_CTRL, SGTL5000_SEL_ADC_CLR_MASK, SGTL5000_SEL_ADC_LINEIN);
            SGTL_ModifyReg(handle, CHIP_SSS_CTRL, SGTL5000_I2S_OUT_SEL_CLR_MASK, SGTL5000_I2S_OUT_SEL_ADC);
            break;
        case kSGTL_RouteRecord:
            /* LINE_IN->ADC->I2S_OUT */
            SGTL_EnableModule(handle, kSGTL_ModuleI2SOUT);
            SGTL_EnableModule(handle, kSGTL_ModuleADC);
            SGTL_ModifyReg(handle, CHIP_ANA_CTRL, SGTL5000_SEL_ADC_CLR_MASK, SGTL5000_SEL_ADC_LINEIN);
            SGTL_ModifyReg(handle, CHIP_SSS_CTRL, SGTL5000_I2S_OUT_SEL_CLR_MASK, SGTL5000_I2S_OUT_SEL_ADC);
            break;
        default:
            ret = kStatus_InvalidArgument;
            break;
    }
    return ret;
}

status_t SGTL_SetProtocol(sgtl_handle_t *handle, sgtl_protocol_t protocol)
{
    status_t ret = kStatus_Success;
    switch (protocol)
    {
        case kSGTL_BusI2S:
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_MODE_CLR_MASK, SGTL5000_I2S_MODE_I2S_LJ);
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_LRALIGN_CLR_MASK, SGTL5000_I2S_ONE_BIT_DELAY);
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_SCLK_INV_CLR_MASK, SGTL5000_I2S_VAILD_RISING_EDGE);
            break;
        case kSGTL_BusLeftJustified:
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_MODE_CLR_MASK, SGTL5000_I2S_MODE_I2S_LJ);
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_LRALIGN_CLR_MASK, SGTL5000_I2S_NO_DELAY);
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_SCLK_INV_CLR_MASK, SGTL5000_I2S_VAILD_RISING_EDGE);
            break;
        case kSGTL_BusRightJustified:
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_MODE_CLR_MASK, SGTL5000_I2S_MODE_RJ);
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_SCLK_INV_CLR_MASK, SGTL5000_I2S_VAILD_RISING_EDGE);
            break;
        case kSGTL_BusPCMA:
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_MODE_CLR_MASK, SGTL5000_I2S_MODE_PCM);
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_LRALIGN_CLR_MASK, SGTL5000_I2S_ONE_BIT_DELAY);
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_SCLK_INV_CLR_MASK, SGTL5000_I2S_VAILD_FALLING_EDGE);
            break;
        case kSGTL_BusPCMB:
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_MODE_CLR_MASK, SGTL5000_I2S_MODE_PCM);
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_LRALIGN_CLR_MASK, SGTL5000_I2S_NO_DELAY);
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_SCLK_INV_CLR_MASK, SGTL5000_I2S_VAILD_FALLING_EDGE);
            break;
        default:
            ret = kStatus_InvalidArgument;
            break;
    }
    return ret;
}

status_t SGTL_SetVolume(sgtl_handle_t *handle, sgtl_module_t module, uint32_t volume)
{
    uint16_t vol = 0;
    status_t ret = kStatus_Success;
    switch (module)
    {
        case kSGTL_ModuleADC:
            vol = volume | (volume << 4U);
            ret = SGTL_ModifyReg(handle, CHIP_ANA_ADC_CTRL,
                                 SGTL5000_ADC_VOL_LEFT_CLR_MASK & SGTL5000_ADC_VOL_RIGHT_CLR_MASK, vol);
            break;
        case kSGTL_ModuleDAC:
            vol = volume | (volume << 8U);
            ret = SGTL_WriteReg(handle, CHIP_DAC_VOL, vol);
            break;
        case kSGTL_ModuleHP:
            vol = volume | (volume << 8U);
            ret = SGTL_WriteReg(handle, CHIP_ANA_HP_CTRL, vol);
            break;
        case kSGTL_ModuleLineOut:
            vol = volume | (volume << 8U);
            ret = SGTL_WriteReg(handle, CHIP_LINE_OUT_VOL, vol);
            break;
        default:
            ret = kStatus_InvalidArgument;
            break;
    }
    return ret;
}

uint32_t SGTL_GetVolume(sgtl_handle_t *handle, sgtl_module_t module)
{
    uint16_t vol = 0;
    switch (module)
    {
        case kSGTL_ModuleADC:
            SGTL_ReadReg(handle, CHIP_ANA_ADC_CTRL, &vol);
            vol = (vol & (uint16_t)SGTL5000_ADC_VOL_LEFT_GET_MASK) >> SGTL5000_ADC_VOL_LEFT_SHIFT;
            break;
        case kSGTL_ModuleDAC:
            SGTL_ReadReg(handle, CHIP_DAC_VOL, &vol);
            vol = (vol & (uint16_t)SGTL5000_DAC_VOL_LEFT_GET_MASK) >> SGTL5000_DAC_VOL_LEFT_SHIFT;
            break;
        case kSGTL_ModuleHP:
            SGTL_ReadReg(handle, CHIP_ANA_HP_CTRL, &vol);
            vol = (vol & (uint16_t)SGTL5000_HP_VOL_LEFT_GET_MASK) >> SGTL5000_HP_VOL_LEFT_SHIFT;
            break;
        case kSGTL_ModuleLineOut:
            SGTL_ReadReg(handle, CHIP_LINE_OUT_VOL, &vol);
            vol = (vol & (uint16_t)SGTL5000_LINE_OUT_VOL_LEFT_GET_MASK) >> SGTL5000_LINE_OUT_VOL_LEFT_SHIFT;
            break;
        default:
            vol = 0;
            break;
    }
    return vol;
}

status_t SGTL_SetMute(sgtl_handle_t *handle, sgtl_module_t module, bool mute)
{
    status_t ret = kStatus_Success;
    switch (module)
    {
        case kSGTL_ModuleADC:
            SGTL_ModifyReg(handle, CHIP_ANA_CTRL, SGTL5000_MUTE_ADC_CLR_MASK, mute);
            break;
        case kSGTL_ModuleDAC:
            if (mute)
            {
                SGTL_ModifyReg(handle, CHIP_ADCDAC_CTRL,
                               SGTL5000_DAC_MUTE_LEFT_CLR_MASK & SGTL5000_DAC_MUTE_RIGHT_CLR_MASK, 0x000C);
            }
            else
            {
                SGTL_ModifyReg(handle, CHIP_ADCDAC_CTRL,
                               SGTL5000_DAC_MUTE_LEFT_CLR_MASK & SGTL5000_DAC_MUTE_RIGHT_CLR_MASK, 0x0000);
            }
            break;
        case kSGTL_ModuleHP:
            SGTL_ModifyReg(handle, CHIP_ANA_CTRL, SGTL5000_MUTE_HP_CLR_MASK,
                           ((uint16_t)mute << SGTL5000_MUTE_HP_SHIFT));
            break;
        case kSGTL_ModuleLineOut:
            SGTL_ModifyReg(handle, CHIP_ANA_CTRL, SGTL5000_MUTE_LO_CLR_MASK,
                           ((uint16_t)mute << SGTL5000_MUTE_LO_SHIFT));
            break;
        default:
            ret = kStatus_InvalidArgument;
            break;
    }
    return ret;
}

status_t SGTL_ConfigDataFormat(sgtl_handle_t *handle, uint32_t mclk, uint32_t sample_rate, uint8_t bits)
{
    uint16_t val = 0;
    uint16_t regVal = 0;
    status_t retval = kStatus_Success;
    uint16_t mul_clk = 0U;
    uint32_t sysFs = 0U;

    /* Over sample rate can only up to 512, the least to 8k */
    if ((mclk / (MIN(sample_rate * 6U, 96000U)) > 512U) || (mclk / sample_rate < 256U))
    {
        return kStatus_InvalidArgument;
    }

    /* Configure the sample rate */
    switch (sample_rate)
    {
        case 8000:
            if (mclk > 32000U * 512U)
            {
                val = 0x0038;
                sysFs = 48000;
            }
            else
            {
                val = 0x0020;
                sysFs = 32000;
            }
            break;
        case 11025:
            val = 0x0024;
            sysFs = 44100;
            break;
        case 12000:
            val = 0x0028;
            sysFs = 48000;
            break;
        case 16000:
            if (mclk > 32000U * 512U)
            {
                val = 0x003C;
                sysFs = 96000;
            }
            else
            {
                val = 0x0010;
                sysFs = 32000;
            }
            break;
        case 22050:
            val = 0x0014;
            sysFs = 44100;
            break;
        case 24000:
            if (mclk > 48000U * 512U)
            {
                val = 0x002C;
                sysFs = 96000;
            }
            else
            {
                val = 0x0018;
                sysFs = 48000;
            }
            break;
        case 32000:
            val = 0x0000;
            sysFs = 32000;
            break;
        case 44100:
            val = 0x0004;
            sysFs = 44100;
            break;
        case 48000:
            if (mclk > 48000U * 512U)
            {
                val = 0x001C;
                sysFs = 96000;
            }
            else
            {
                val = 0x0008;
                sysFs = 48000;
            }
            break;
        case 96000:
            val = 0x000C;
            sysFs = 96000;
            break;
        default:
            retval = kStatus_InvalidArgument;
            break;
    }

    SGTL_ReadReg(handle, CHIP_I2S_CTRL, &regVal);

    /* While as slave, Fs is input */
    if ((regVal & SGTL5000_I2S_MS_GET_MASK) == 0U)
    {
        sysFs = sample_rate;
    }
    mul_clk = mclk / sysFs;
    /* Configure the mul_clk. Sgtl-5000 only support 256, 384 and 512 oversample rate */
    if ((mul_clk / 128U - 2U) > 2U)
    {
        return kStatus_InvalidArgument;
    }
    else
    {
        val |= (mul_clk / 128U - 2U);
    }
    SGTL_WriteReg(handle, CHIP_CLK_CTRL, val);

    /* Data bits configure,sgtl supports 16bit, 20bit 24bit, 32bit */
    SGTL_ModifyReg(handle, CHIP_I2S_CTRL, 0xFEFF, SGTL5000_I2S_SCLKFREQ_64FS);
    switch (bits)
    {
        case 16:
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_DLEN_CLR_MASK, SGTL5000_I2S_DLEN_16);
            break;
        case 20:
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_DLEN_CLR_MASK, SGTL5000_I2S_DLEN_20);
            break;
        case 24:
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_DLEN_CLR_MASK, SGTL5000_I2S_DLEN_24);
            break;
        case 32:
            SGTL_ModifyReg(handle, CHIP_I2S_CTRL, SGTL5000_I2S_DLEN_CLR_MASK, SGTL5000_I2S_DLEN_32);
            break;
        default:
            retval = kStatus_InvalidArgument;
            break;
    }

    return retval;
}

status_t SGTL_WriteReg(sgtl_handle_t *handle, uint16_t reg, uint16_t val)
{
    uint8_t buff[2];
    status_t retval = 0;

    /* Data copied to buff*/
    buff[0] = (val & 0xFF00U) >> 8U;
    buff[1] = val & 0xFF;

#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && (FSL_FEATURE_SOC_LPI2C_COUNT)
    uint8_t data[4] = {0};
    data[0] = (reg & 0xFF00U) >> 8U;
    data[1] = reg & 0xFFU;
    data[2] = buff[0];
    data[3] = buff[1];
    retval = LPI2C_MasterStart(handle->base, SGTL5000_I2C_ADDR, kLPI2C_Write);
    retval = LPI2C_MasterSend(handle->base, data, 4);
    retval = LPI2C_MasterStop(handle->base);
#else
    /* Set I2C xfer structure */
    handle->xfer.direction = kI2C_Write;
    handle->xfer.subaddress = (uint32_t)reg;
    handle->xfer.subaddressSize = 2U;
    handle->xfer.data = buff;
    handle->xfer.dataSize = 2U;

    retval = I2C_MasterTransferBlocking(handle->base, &handle->xfer);
#endif

    return retval;
}

status_t SGTL_ReadReg(sgtl_handle_t *handle, uint16_t reg, uint16_t *val)
{
    uint8_t data[2];
    status_t retval = 0;

#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && (FSL_FEATURE_SOC_LPI2C_COUNT)
    uint8_t buff[2] = {0};
    buff[0] = (reg & 0xFF00U) >> 8U;
    buff[1] = reg & 0xFFU;
    retval = LPI2C_MasterStart(handle->base, SGTL5000_I2C_ADDR, kLPI2C_Write);
    retval = LPI2C_MasterSend(handle->base, buff, 2);
    retval = LPI2C_MasterStart(handle->base, SGTL5000_I2C_ADDR, kLPI2C_Read);
    retval = LPI2C_MasterReceive(handle->base, data, 2);
    retval = LPI2C_MasterStop(handle->base);
#else
    /* Configure I2C xfer */
    handle->xfer.direction = kI2C_Read;
    handle->xfer.subaddress = (uint32_t)reg;
    handle->xfer.subaddressSize = 2U;
    handle->xfer.data = data;
    handle->xfer.dataSize = 2U;

    retval = I2C_MasterTransferBlocking(handle->base, &handle->xfer);
#endif

    /* Handle the return data */
    *val = (uint16_t)(((uint32_t)data[0] << 8U) | (uint32_t)data[1]);

    return retval;
}

status_t SGTL_ModifyReg(sgtl_handle_t *handle, uint16_t reg, uint16_t clr_mask, uint16_t val)
{
    status_t retval = 0;
    uint16_t reg_val;

    /* Read the register value out */
    retval = SGTL_ReadReg(handle, reg, &reg_val);
    if (retval != kStatus_Success)
    {
        return kStatus_Fail;
    }

    /* Modify the value */
    reg_val &= clr_mask;
    reg_val |= val;

    /* Write the data to register */
    retval = SGTL_WriteReg(handle, reg, reg_val);
    if (retval != kStatus_Success)
    {
        return kStatus_Fail;
    }

    return kStatus_Success;
}
