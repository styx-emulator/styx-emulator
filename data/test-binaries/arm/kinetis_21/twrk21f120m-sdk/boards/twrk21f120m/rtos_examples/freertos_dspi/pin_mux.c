/*
 * The Clear BSD License
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
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

/* clang-format off */
/*
 * TEXT BELOW IS USED AS SETTING FOR TOOLS *************************************
!!GlobalInfo
product: Pins v3.0
processor: MK21FN1M0Axxx12
package_id: MK21FN1M0AVMC12
mcu_data: ksdk2_0
processor_version: 0.0.8
 * BE CAREFUL MODIFYING THIS COMMENT - IT IS YAML SETTINGS FOR TOOLS ***********
 */
/* clang-format on */

#include "fsl_common.h"
#include "fsl_port.h"
#include "pin_mux.h"



/* clang-format off */
/*
 * TEXT BELOW IS USED AS SETTING FOR TOOLS *************************************
BOARD_InitPins:
- options: {callFromInitBoot: 'true', coreID: core0, enableClock: 'true'}
- pin_list:
  - {pin_num: A10, peripheral: UART5, signal: RX, pin_signal: PTD8/I2C0_SCL/UART5_RX/FBa_A16}
  - {pin_num: A9, peripheral: UART5, signal: TX, pin_signal: PTD9/I2C0_SDA/UART5_TX/FBa_A17}
  - {pin_num: D4, peripheral: SPI0, signal: PCS0_SS, pin_signal: PTD0/LLWU_P12/SPI0_PCS0/UART2_RTS_b/FTM3_CH0/FBa_ALE/FBa_CS1_b/FBa_TS_b}
  - {pin_num: D3, peripheral: SPI0, signal: SCK, pin_signal: ADC0_SE5b/PTD1/SPI0_SCK/UART2_CTS_b/FTM3_CH1/FBa_CS0_b}
  - {pin_num: C3, peripheral: SPI0, signal: SOUT, pin_signal: PTD2/LLWU_P13/SPI0_SOUT/UART2_RX/FTM3_CH2/FBa_AD4/I2C0_SCL}
  - {pin_num: B3, peripheral: SPI0, signal: SIN, pin_signal: PTD3/SPI0_SIN/UART2_TX/FTM3_CH3/FBa_AD3/I2C0_SDA}
  - {pin_num: D10, peripheral: SPI1, signal: PCS0_SS, pin_signal: ADC1_SE14/PTB10/SPI1_PCS0/UART3_RX/FBa_AD19/FTM0_FLT1}
  - {pin_num: C10, peripheral: SPI1, signal: SCK, pin_signal: ADC1_SE15/PTB11/SPI1_SCK/UART3_TX/FBa_AD18/FTM0_FLT2}
  - {pin_num: B10, peripheral: SPI1, signal: SOUT, pin_signal: PTB16/SPI1_SOUT/UART0_RX/FTM_CLKIN0/FBa_AD17/EWM_IN}
  - {pin_num: E9, peripheral: SPI1, signal: SIN, pin_signal: PTB17/SPI1_SIN/UART0_TX/FTM_CLKIN1/FBa_AD16/EWM_OUT_b}
 * BE CAREFUL MODIFYING THIS COMMENT - IT IS YAML SETTINGS FOR TOOLS ***********
 */
/* clang-format on */

/* FUNCTION ************************************************************************************************************
 *
 * Function Name : BOARD_InitPins
 * Description   : Configures pin routing and optionally pin electrical features.
 *
 * END ****************************************************************************************************************/
void BOARD_InitPins(void)
{
    /* Port B Clock Gate Control: Clock enabled */
    CLOCK_EnableClock(kCLOCK_PortB);
    /* Port D Clock Gate Control: Clock enabled */
    CLOCK_EnableClock(kCLOCK_PortD);

    /* PORTB10 (pin D10) is configured as SPI1_PCS0 */
    PORT_SetPinMux(PORTB, 10U, kPORT_MuxAlt2);

    /* PORTB11 (pin C10) is configured as SPI1_SCK */
    PORT_SetPinMux(PORTB, 11U, kPORT_MuxAlt2);

    /* PORTB16 (pin B10) is configured as SPI1_SOUT */
    PORT_SetPinMux(PORTB, 16U, kPORT_MuxAlt2);

    /* PORTB17 (pin E9) is configured as SPI1_SIN */
    PORT_SetPinMux(PORTB, 17U, kPORT_MuxAlt2);

    /* PORTD0 (pin D4) is configured as SPI0_PCS0 */
    PORT_SetPinMux(PORTD, 0U, kPORT_MuxAlt2);

    /* PORTD1 (pin D3) is configured as SPI0_SCK */
    PORT_SetPinMux(PORTD, 1U, kPORT_MuxAlt2);

    /* PORTD2 (pin C3) is configured as SPI0_SOUT */
    PORT_SetPinMux(PORTD, 2U, kPORT_MuxAlt2);

    /* PORTD3 (pin B3) is configured as SPI0_SIN */
    PORT_SetPinMux(PORTD, 3U, kPORT_MuxAlt2);

    /* PORTD8 (pin A10) is configured as UART5_RX */
    PORT_SetPinMux(PORTD, 8U, kPORT_MuxAlt3);

    /* PORTD9 (pin A9) is configured as UART5_TX */
    PORT_SetPinMux(PORTD, 9U, kPORT_MuxAlt3);
}
/***********************************************************************************************************************
 * EOF
 **********************************************************************************************************************/
