/*****************************************************************************
Copyright (c), 2009 - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.
******************************************************************************

$RCSfile: adi_adp5520.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Title:       ADP5520 Backlight Driver with I/O Expander

Description: This is the primary include file for ADP5520 Backlight Driver
             with I/O Expander.  The software driver supports Device access
             commands to access ADP5520 registers.

Notes:       Access to the ADP5520 control registers is over the TWI port
             using the Device Access Service.

             Although the software driver enables use of all the ADP5520's
             features the ADSP-BF527 EZ-Kit only uses the keypad decoder.

*****************************************************************************/

#ifndef __ADI_ADP5520_H__
#define __ADI_ADP5520_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*=============  I N C L U D E S   =============*/

#include <drivers/adi_dev.h>


/*==============  D E F I N E S  ===============*/

/*
**
** ADP5520 Register Map
**
** The ADP5520 has 38 registers, numbered 0x00 - 0x25.  Each register
** is 8-bits wide and most are subdivided into bit-fields.  In the
** following preprocessor definitions the number associated with
** each field name is the bit position of the least significant (or
** only) bit of the field.  The fields of a register are listed left-
** to-right (that is from the most significant end of the register
** down to the least significant).
**
*/

/* 0x00 - MODE_STATUS
**        Sets device operating mode.
**        Contains enables for backlight on/dim.
**        Contains top-level interrupt status bits.
**
** Fields:
**  [7]   nSTNBY   - 0 => only TWI, GPIO and key scanning available
**                   1 => backlight, aux LEDs and light sensor also available
**  [6]   BL_EN    - 1 => backlight driver enabled
**  [5]   DIM_EN   - 1 => dim mode enabled
**  [4]   OVP_INT  - 1 => over-voltage protection condition detected
**  [3]   CMPR_INT - 1 => an ambient light sensor comparator has triggered
**  [2]   GPI_INT  - 1 => GPIO input interrupt condition has occurred
**  [1]   KR_INT   - 1 => key release detected
**  [0]   KP_INT   - 1 => key press detected
*/
#define ADP5520_REG_MODE_STATUS 0x00u
  #define ADP5520_POS_nSTNBY   7u
  #define ADP5520_POS_BL_EN    6u
  #define ADP5520_POS_DIM_EN   5u
  #define ADP5520_POS_OVP_INT  4u
  #define ADP5520_POS_CMPR_INT 3u
  #define ADP5520_POS_GPI_INT  2u
  #define ADP5520_POS_KR_INT   1u
  #define ADP5520_POS_KP_INT   0u

  #define ADP5520_VAL_nSTNBY_STNBY 0u
  #define ADP5520_VAL_nSTNBY_OPER  1u

  #define ADP5520_VAL_BL_EN_OFF    0u
  #define ADP5520_VAL_BL_EN_ON     1u

  #define ADP5520_VAL_DIM_EN_OFF   0u
  #define ADP5520_VAL_DIM_EN_ON    1u

  #define ADP5520_VAL_OVP_INT      1u
  #define ADP5520_VAL_CMPR_INT     1u
  #define ADP5520_VAL_GPI_INT      1u
  #define ADP5520_VAL_KR_INT       1u
  #define ADP5520_VAL_KP_INT       1u

/* 0x01 - INTERRUPT_ENABLE
**        Contains enables for allowing interrupts to assert nINT.
**
** Fields:
**  [7:5] Unused
**  [4]   AUTO_LD_EN - 1 => autoload enabled (dummy 1mA load)
**  [3]   CMPR_IEN   - 1 => ambient light sensor interrupt enabled
**  [2]   OVP_IEN    - 1 => over-voltage protection interrupt enabled
**  [1]   KR_IEN     - 1 => key release interrupt enabled
**  [0]   KP_IEN     - 1 => key press interrupt enabled
*/
#define ADP5520_REG_INTERRUPT_ENABLE 0x01u
  #define ADP5520_POS_AUTO_LD_EN 4u
  #define ADP5520_POS_CMPR_IEN   3u
  #define ADP5520_POS_OVP_IEN    2u
  #define ADP5520_POS_KR_IEN     1u
  #define ADP5520_POS_KP_IEN     0u

  #define ADP5520_VAL_AUTO_LD_EN 1u
  #define ADP5520_VAL_CMPR_IEN   1u
  #define ADP5520_VAL_OVP_IEN    1u
  #define ADP5520_VAL_KR_IEN     1u
  #define ADP5520_VAL_KP_IEN     1u

  #define ADP5520_MSK_CMPR_IEN   (1u << ADP5520_POS_CMPR_IEN)
  #define ADP5520_MSK_OVP_IEN    (1u << ADP5520_POS_OVP_IEN)
  #define ADP5520_MSK_KR_IEN     (1u << ADP5520_POS_KR_IEN)
  #define ADP5520_MSK_KP_IEN     (1u << ADP5520_POS_KP_IEN)

/* 0x02 - BL_CONTROL
**        Sets parameters relating to backlight control.
**
** Fields:
**  [7:6] BL_LVL      - backlight brightness level
**  [5:4] BL_LAW      - backlight fade on/off characteristic
**  [3]   BL_AUTO_ADJ - 1 => light sensor adjusts backlight level
**  [2]   OVP_EN      - 1 => backlight ramp down during over-load protection
**  [1]   FOVR        - 1 => backlight fade override enabled
**  [0]   KP_BL_EN    - 1 => a keypress turns on backlight
*/
#define ADP5520_REG_BL_CONTROL 0x02u
  #define ADP5520_POS_BL_LVL      6u
  #define ADP5520_POS_BL_LAW      4u
  #define ADP5520_POS_BL_AUTO_ADJ 3u
  #define ADP5520_POS_OVP_EN      2u
  #define ADP5520_POS_FOVR        1u
  #define ADP5520_POS_KP_BL_EN    0u

  #define ADP5520_VAL_BL_LVL_L1   0
  #define ADP5520_VAL_BL_LVL_L2   1
  #define ADP5520_VAL_BL_LVL_L3   2

  #define ADP5520_VAL_BL_LAW_LIN  0
  #define ADP5520_VAL_BL_LAW_SQR  1
  #define ADP5520_VAL_BL_LAW_CU1  2
  #define ADP5520_VAL_BL_LAW_CU2  3

  #define ADP5520_VAL_BL_AUTO_ADJ_OFF 0u
  #define ADP5520_VAL_BL_AUTO_ADJ_ON  1u

  #define ADP5520_VAL_OVP_EN_OFF 0u
  #define ADP5520_VAL_OVP_EN_ON  1u

  #define ADP5520_VAL_FOVR_OFF 0u
  #define ADP5520_VAL_FOVR_ON  1u

  #define ADP5520_VAL_KP_BL_EN_OFF 0u
  #define ADP5520_VAL_KP_BL_EN_ON  1u

/* 0x03 - BL_TIME
**        Contains backlight off and dim timers.
**
** Fields:
**  [7:4] BL_OFFT - backlight off timer value
**  [3:0] BL_DIMT - backlight dim timer value
*/
#define ADP5520_REG_BL_TIME 0x03u
  #define ADP5520_POS_BL_OFFT 4u
  #define ADP5520_POS_BL_DIMT 0u

  #define ADP5520_BL_TIME_DISABLED  0u
  #define ADP5520_BL_TIME_10_SEC    1u
  #define ADP5520_BL_TIME_15_SEC    2u
  #define ADP5520_BL_TIME_20_SEC    3u
  #define ADP5520_BL_TIME_25_SEC    4u
  #define ADP5520_BL_TIME_30_SEC    5u
  #define ADP5520_BL_TIME_35_SEC    6u
  #define ADP5520_BL_TIME_40_SEC    7u
  #define ADP5520_BL_TIME_50_SEC    8u
  #define ADP5520_BL_TIME_60_SEC    9u
  #define ADP5520_BL_TIME_70_SEC   10u
  #define ADP5520_BL_TIME_80_SEC   11u
  #define ADP5520_BL_TIME_90_SEC   12u
  #define ADP5520_BL_TIME_100_SEC  13u
  #define ADP5520_BL_TIME_110_SEC  14u
  #define ADP5520_BL_TIME_120_SEC  15u

/* 0x04 - BL_FADE
**        Contains backlight fade-in and fade-out timers.
**
** Fields:
**  [7:4] BL_FO - backlight fade-out timer value
**  [3:0] BL_FI - backlight fade-in timer value
*/
#define ADP5520_REG_BL_FADE 0x04u
  #define ADP5520_POS_BL_FO 4u
  #define ADP5520_POS_BL_FI 0u

  #define ADP5520_VAL_FADE_DISABLED  0u
  #define ADP5520_VAL_FADE_0p3_SEC   1u
  #define ADP5520_VAL_FADE_0p6_SEC   2u
  #define ADP5520_VAL_FADE_0p9_SEC   3u
  #define ADP5520_VAL_FADE_1p2_SEC   4u
  #define ADP5520_VAL_FADE_1p5_SEC   5u
  #define ADP5520_VAL_FADE_1p8_SEC   6u
  #define ADP5520_VAL_FADE_2p1_SEC   7u
  #define ADP5520_VAL_FADE_2p4_SEC   8u
  #define ADP5520_VAL_FADE_2p7_SEC   9u
  #define ADP5520_VAL_FADE_3p0_SEC  10u
  #define ADP5520_VAL_FADE_3p5_SEC  11u
  #define ADP5520_VAL_FADE_4p0_SEC  12u
  #define ADP5520_VAL_FADE_4p5_SEC  13u
  #define ADP5520_VAL_FADE_5p0_SEC  14u
  #define ADP5520_VAL_FADE_5p5_SEC  15u

/* 0x05 - DAYLIGHT_MAX
**        Sets daylight (L1) maximum current.
**
** Fields:
**  [7]   Unused
**  [6:0] DAYLIGHT_MAX - max backlight current at level 1 (daylight)
*/
#define ADP5520_REG_DAYLIGHT_MAX 0x05u
  #define ADP5520_POS_DAYLIGHT_MAX 0u

/* 0x06 - DAYLIGHT_DIM
**        Sets daylight (L1) dim current.
**
** Fields:
**  [7]   Unused
**  [6:0] DAYLIGHT_DIM - dim backlight current at level 1 (daylight)
*/
#define ADP5520_REG_DAYLIGHT_DIM 0x06u
  #define ADP5520_POS_DAYLIGHT_DIM 0u

/* 0x07 - OFFICE_MAX
**        Sets office (L2) maximum current.
**
** Fields:
**  [7]   Unused
**  [6:0] OFFICE_MAX - max backlight current at level 2 (office)
*/
#define ADP5520_REG_OFFICE_MAX 0x07u
  #define ADP5520_POS_OFFICE_MAX 0u

/* 0x08 - OFFICE_DIM
**        Sets office (L2) dim current.
**
** Fields:
**  [7]   Unused
**  [6:0] OFFICE_DIM - dim backlight current at level 2 (office)
*/
#define ADP5520_REG_OFFICE_DIM 0x08u
  #define ADP5520_POS_OFFICE_DIM 0u

/* 0x09 - DARK_MAX
**        Sets dark (L3) maximum current.
**
** Fields:
**  [7]   Unused
**  [6:0] DARK_MAX - max backlight current at level 3 (dark)
*/
#define ADP5520_REG_DARK_MAX 0x09u
  #define ADP5520_POS_DARK_MAX 0u

/* 0x0A - DARK_DIM
**        Sets dark (L3) dim current.
**
** Fields:
**  [7]   Unused
**  [6:0] DARK_DIM - dim backlight current at level 3 (dark)
*/
#define ADP5520_REG_DARK_DIM 0x0Au
  #define ADP5520_POS_DARK_DIM 0u

/* 0x0B - BL_VALUE
**        Read-only register of what the backlight is presently set to.
**
** Fields:
**  [7]   Unused
**  [6:0] BL_VALUE - value of backlight current setting at present
*/
#define ADP5520_REG_BL_VALUE 0x0Bu
  #define ADP5520_POS_BL_VALUE 0u

/* 0x0C - ALS_CMPR_CFG
**        Sets enables and filters for ambient light sensor comparators.
**        Contains comparator output status bits.
**
** Fields:
**  [7:5] FILT     - light sensor filter time
**  [4]   FORCE_RD - 1 => force comparator to do a single comparison
**  [3]   L3_OUT   - 0 => ambient light is greater than L3 (dark)
**                   1 => change detected from L2 (office) to L3 (dark)
**  [2]   L2_OUT   - 0 => ambient light is greater than L2 (office)
**                   1 => change detected from L1 (daylight) to L2 (office)
**  [1]   L3_EN    - 1 => enable comparator L3_CMPR
**  [0]   L2_EN    - 1 => enable comparator L2_CMPR
*/
#define ADP5520_REG_ALS_CMPR_CFG 0x0Cu
  #define ADP5520_POS_FILT     5u
  #define ADP5520_POS_FORCE_RD 4u
  #define ADP5520_POS_L3_OUT   3u
  #define ADP5520_POS_L2_OUT   2u
  #define ADP5520_POS_L3_EN    1u
  #define ADP5520_POS_L2_EN    0u

  #define ADP5520_VAL_FILT_0p08_SEC  0u
  #define ADP5520_VAL_FILT_0p16_SEC  1u
  #define ADP5520_VAL_FILT_0p32_SEC  2u
  #define ADP5520_VAL_FILT_0p64_SEC  3u
  #define ADP5520_VAL_FILT_1p28_SEC  4u
  #define ADP5520_VAL_FILT_2p56_SEC  5u
  #define ADP5520_VAL_FILT_5p12_SEC  6u
  #define ADP5520_VAL_FILT_10p24_SEC 7u

  #define ADP5520_VAL_L3_EN_OFF 0u
  #define ADP5520_VAL_L3_EN_ON  1u

  #define ADP5520_VAL_L2_EN_OFF 0u
  #define ADP5520_VAL_L2_EN_ON  1u

/* 0x0D - L2_TRIP
**        Sets the light sensor comparator (L2_CMPR) threshold point.
**
** Fields:
**  [7:0] L2_TRIP - if ambient light falls below this level then L2_OUT is set
*/
#define ADP5520_REG_L2_TRIP 0x0Du
  #define ADP5520_POS_L2_TRIP 0u

/* 0x0E - L2_HYS
**        Sets the light sensor comparator (L2_CMPR hysteresis.
**
** Fields:
**  [7:0] L2_HYS - if light rises above L2_TRIP + L2_HYS then L2_OUT is cleared
*/
#define ADP5520_REG_L2_HYS 0x0Eu
  #define ADP5520_POS_L2_HYS 0u

/* 0x0F - L3_TRIP
**        Sets the light sensor comparator (L3_CMPR) threshold point.
**
** Fields:
**  [7:0] L3_TRIP - if ambient light falls below this level then L3_OUT is set
*/
#define ADP5520_REG_L3_TRIP 0x0Fu
  #define ADP5520_POS_L3_TRIP 0u

/* 0x10 - L3_HYS
**        Sets the light sensor comparator (L3_CMPR) hysteresis.
**
** Fields:
**  [7:0] L3_HYS - if light rises above L3_TRIP + L3_HYS then L3_OUT is cleared
*/
#define ADP5520_REG_L3_HYS 0x10u
  #define ADP5520_POS_L3_HYS 0u

/* 0x11 - LED_CONTROL
**        Contains enables and configuration for the three auxiliary LED
**        current sinks.
**
** Fields:
**  [7:6] Unused
**  [5]   R3_MODE - 0 => R3 is configured as a current sink (LED3)
**                  1 => R3 is configured as a GPIO (D3)
**  [4]   C3_MODE - 0 => C3 is configured as a current sink (LED2)
**                  1 => C3 is configured as a GPIO (D7)
**  [3]   LED_LAW - LED fade-on/off characteristic is linear (0) or square (1)
**  [2]   LED3_EN - 1 => LED3 is enabled
**  [1]   LED2_EN - 1 => LED2 is enabled
**  [0]   LED1_EN - 1 => LED1 is enabled
*/
#define ADP5520_REG_LED_CONTROL 0x11u
  #define ADP5520_POS_R3_MODE 5u
  #define ADP5520_POS_C3_MODE 4u
  #define ADP5520_POS_LED_LAW 3u
  #define ADP5520_POS_LED3_EN 2u
  #define ADP5520_POS_LED2_EN 1u
  #define ADP5520_POS_LED1_EN 0u

  #define ADP5520_VAL_R3_MODE_LED  0u
  #define ADP5520_VAL_R3_MODE_GPIO 1u

  #define ADP5520_VAL_C3_MODE_LED  0u
  #define ADP5520_VAL_C3_MODE_GPIO 1u

  #define ADP5520_VAL_LED_LAW_LIN 0u
  #define ADP5520_VAL_LED_LAW_SQR 1u

  #define ADP5520_VAL_LED3_EN_OFF 0u
  #define ADP5520_VAL_LED3_EN_ON  1u

  #define ADP5520_VAL_LED2_EN_OFF 0u
  #define ADP5520_VAL_LED2_EN_ON  1u

  #define ADP5520_VAL_LED1_EN_OFF 0u
  #define ADP5520_VAL_LED1_EN_ON  1u

/* 0x12 - LED_TIME
**        Contains the on and off timers for the three auxiliary LED
**        current sinks.
**
** Fields:
**  [7:6] LED_ONT   - LED blink 'on' time (common)
**  [5:4] LED3_OFFT - LED3 blink 'off' time (0 => continuously 'on')
**  [3:2] LED2_OFFT - LED2 blink 'off' time (0 => continuously 'on')
**  [1:0] LED1_OFFT - LED1 blink 'off' time (0 => continuously 'on')
*/
#define ADP5520_REG_LED_TIME 0x12u
  #define ADP5520_POS_LED_ONT   6u
  #define ADP5520_POS_LED3_OFFT 4u
  #define ADP5520_POS_LED2_OFFT 2u
  #define ADP5520_POS_LED1_OFFT 0u

  #define ADP5520_VAL_LED_ONT_0p2_SEC 0u
  #define ADP5520_VAL_LED_ONT_0p6_SEC 1u
  #define ADP5520_VAL_LED_ONT_0p8_SEC 2u
  #define ADP5520_VAL_LED_ONT_1p2_SEC 3u

  #define ADP5520_POS_LED_OFFT_DISABLED 0u
  #define ADP5520_VAL_LED_OFFT_0p6_SEC  1u
  #define ADP5520_VAL_LED_OFFT_0p8_SEC  2u
  #define ADP5520_VAL_LED_OFFT_1p2_SEC  3u

/* 0x13 - LED_FADE
**        Contains the fade-in and fade-out timers for the three auxiliary
**        LED current sinks.
**
** Fields:
**  [7:4] LED_FO - LED fade-out timer (0 => timer disabled)
**  [3:0] LED_FI - LED fade-in timer (0 => timer disabled)
*/
#define ADP5520_REG_LED_FADE 0x13u
  #define ADP5520_POS_LED_FO 4u
  #define ADP5520_POS_LED_FI 0u

  /* Use ADP5520_VAL_FADE_xxx_SEC (above) for fade out/in values. */

/* 0x14 - LED1_CURRENT
**        Sets the LED 1 (ILED) sink current.
**
** Fields:
**  [7:6] Unused
**  [5:0] LED1_CURRENT - LED1 sink current setting
*/
#define ADP5520_REG_LED1_CURRENT 0x14u
  #define ADP5520_POS_LED1_CURRENT 0u

/* 0x15 - LED2_CURRENT
**        Sets the LED 2 (C3) sink current.
**
** Fields:
**  [7:6] Unused
**  [5:0] LED2_CURRENT - LED2 sink current setting
*/
#define ADP5520_REG_LED2_CURRENT 0x15u
  #define ADP5520_POS_LED2_CURRENT 0u

/* 0x16 - LED3_CURRENT
**        Sets the LED 3 (R3) sink current.
**
** Fields:
**  [7:6] Unused
**  [5:0] LED3_CURRENT - LED3 sink current setting
*/
#define ADP5520_REG_LED3_CURRENT 0x16u
  #define ADP5520_POS_LED3_CURRENT 0u

/* 0x17 - GPIO_CFG_1
**        Configuration for I/O pins. (GPIOs or keypad matrix)
**
** Fields:
**  [7]   C3_CONFIG - C3 configured as GPIO D7 (0) or keypad column 3 (1)
**  [6]   C2_CONFIG - C2 configured as GPIO D6 (0) or keypad column 2 (1)
**  [5]   C1_CONFIG - C1 configured as GPIO D5 (0) or keypad column 1 (1)
**  [4]   C0_CONFIG - C0 configured as GPIO D4 (0) or keypad column 0 (1)
**  [3]   R3_CONFIG - R3 configured as GPIO D3 (0) or keypad row 3 (1)
**  [2]   R2_CONFIG - R2 configured as GPIO D2 (0) or keypad row 2 (1)
**  [1]   R1_CONFIG - R1 configured as GPIO D1 (0) or keypad row 1 (1)
**  [0]   R0_CONFIG - R0 configured as GPIO D0 (0) or keypad row 0 (1)
*/
#define ADP5520_REG_GPIO_CFG_1 0x17u
  #define ADP5520_POS_C3_CONFIG 7u
  #define ADP5520_POS_C2_CONFIG 6u
  #define ADP5520_POS_C1_CONFIG 5u
  #define ADP5520_POS_C0_CONFIG 4u
  #define ADP5520_POS_R3_CONFIG 3u
  #define ADP5520_POS_R2_CONFIG 2u
  #define ADP5520_POS_R1_CONFIG 1u
  #define ADP5520_POS_R0_CONFIG 0u

  #define ADP5520_VAL_GPIO_CFG_GPIO   0u
  #define ADP5520_VAL_GPIO_CFG_KEYPAD 1u

/* 0x18 - GPIO_CFG_2
**        Configuration for I/O pins. (GPIO direction, input or output)
**
** Fields:          For each pin, 0 => it is an input and 1 => it is an output
**  [7]   D7_DIR
**  [6]   D6_DIR
**  [5]   D5_DIR
**  [4]   D4_DIR
**  [3]   D3_DIR
**  [2]   D2_DIR
**  [1]   D1_DIR
**  [0]   D0_DIR
*/
#define ADP5520_REG_GPIO_CFG_2 0x18u
  #define ADP5520_POS_D7_DIR 7u
  #define ADP5520_POS_D6_DIR 6u
  #define ADP5520_POS_D5_DIR 5u
  #define ADP5520_POS_D4_DIR 4u
  #define ADP5520_POS_D3_DIR 3u
  #define ADP5520_POS_D2_DIR 2u
  #define ADP5520_POS_D1_DIR 1u
  #define ADP5520_POS_D0_DIR 0u

  #define ADP5520_VAL_GPIO_IN  0u
  #define ADP5520_VAL_GPIO_OUT 1u

/* 0x19 - GPIO_IN
**        Read-only register. Reflects the logic state of GPIO inputs.
**
** Fields:      For each pin, 0 => input is low and 1 => input is high
**  [7]   D7_IN
**  [6]   D6_IN
**  [5]   D5_IN
**  [4]   D4_IN
**  [3]   D3_IN
**  [2]   D2_IN
**  [1]   D1_IN
**  [0]   D0_IN
*/
#define ADP5520_REG_GPIO_IN 0x19u
  #define ADP5520_POS_D7_IN 7u
  #define ADP5520_POS_D6_IN 6u
  #define ADP5520_POS_D5_IN 5u
  #define ADP5520_POS_D4_IN 4u
  #define ADP5520_POS_D3_IN 3u
  #define ADP5520_POS_D2_IN 2u
  #define ADP5520_POS_D1_IN 1u
  #define ADP5520_POS_D0_IN 0u

  #define ADP5520_VAL_GPIO_IN_LOW  0u
  #define ADP5520_VAL_GPIO_IN_HIGH 1u

/* 0x1A - GPIO_OUT
**        Sets GPIO output logic drive level.
**
** Fields:          For each pin, 0 => set output low and 1 => set output high
**  [7]   D7_OUT
**  [6]   D6_OUT
**  [5]   D5_OUT
**  [4]   D4_OUT
**  [3]   D3_OUT
**  [2]   D2_OUT
**  [1]   D1_OUT
**  [0]   D0_OUT
*/
#define ADP5520_REG_GPIO_OUT 0x1Au
  #define ADP5520_POS_D7_OUT 7u
  #define ADP5520_POS_D6_OUT 6u
  #define ADP5520_POS_D5_OUT 5u
  #define ADP5520_POS_D4_OUT 4u
  #define ADP5520_POS_D3_OUT 3u
  #define ADP5520_POS_D2_OUT 2u
  #define ADP5520_POS_D1_OUT 1u
  #define ADP5520_POS_D0_OUT 0u

  #define ADP5520_VAL_GPIO_OUT_LOW  0u
  #define ADP5520_VAL_GPIO_OUT_HIGH 1u

/* 0x1B - GPIO_INT_EN
**        GPIO input interrupt enable.
**
** Fields:          For each pin, 0 => interrupt disabled and 1 => enabled
**  [7]   D7_IN_IEN
**  [6]   D6_IN_IEN
**  [5]   D5_IN_IEN
**  [4]   D4_IN_IEN
**  [3]   D3_IN_IEN
**  [2]   D2_IN_IEN
**  [1]   D1_IN_IEN
**  [0]   D0_IN_IEN
*/
#define ADP5520_REG_GPIO_INT_EN 0x1Bu
  #define ADP5520_POS_D7_IN_IEN 7u
  #define ADP5520_POS_D6_IN_IEN 6u
  #define ADP5520_POS_D5_IN_IEN 5u
  #define ADP5520_POS_D4_IN_IEN 4u
  #define ADP5520_POS_D3_IN_IEN 3u
  #define ADP5520_POS_D2_IN_IEN 2u
  #define ADP5520_POS_D1_IN_IEN 1u
  #define ADP5520_POS_D0_IN_IEN 0u

  #define ADP5520_VAL_GPIO_IN_INT_EN_OFF 0u
  #define ADP5520_VAL_GPIO_IN_INT_EN_ON  1u

/* 0x1C - GPIO_INT_STAT
**        GPIO input interrupt status. Read-only: read twice to clear.
**
** Fields:          For each pin, 0 => no interrupt and 1 => interrupt
**  [7]   D7_IN_ISTAT
**  [6]   D6_IN_ISTAT
**  [5]   D5_IN_ISTAT
**  [4]   D4_IN_ISTAT
**  [3]   D3_IN_ISTAT
**  [2]   D2_IN_ISTAT
**  [1]   D1_IN_ISTAT
**  [0]   D0_IN_ISTAT
*/
#define ADP5520_REG_GPIO_INT_STAT 0x1Cu
  #define ADP5520_POS_D7_IN_ISTAT 7u
  #define ADP5520_POS_D6_IN_ISTAT 6u
  #define ADP5520_POS_D5_IN_ISTAT 5u
  #define ADP5520_POS_D4_IN_ISTAT 4u
  #define ADP5520_POS_D3_IN_ISTAT 3u
  #define ADP5520_POS_D2_IN_ISTAT 2u
  #define ADP5520_POS_D1_IN_ISTAT 1u
  #define ADP5520_POS_D0_IN_ISTAT 0u

  #define ADP5520_VAL_GPIO_IN_INT_CLR 0u
  #define ADP5520_VAL_GPIO_IN_INT_SET 1u

/* 0x1D - GPIO_INT_LVL
**        Configures the GPIO input interrupt level that causes an
**        interrupt (active high or low).
**
** Fields:          For each pin, 0 => interrupt when low and 1 => when high
**  [7]   D7_ILVL
**  [6]   D6_ILVL
**  [5]   D5_ILVL
**  [4]   D4_ILVL
**  [3]   D3_ILVL
**  [2]   D2_ILVL
**  [1]   D1_ILVL
**  [0]   D0_ILVL
*/
#define ADP5520_REG_GPIO_INT_LVL 0x1Du
  #define ADP5520_POS_D7_ILVL 7u
  #define ADP5520_POS_D6_ILVL 6u
  #define ADP5520_POS_D5_ILVL 5u
  #define ADP5520_POS_D4_ILVL 4u
  #define ADP5520_POS_D3_ILVL 3u
  #define ADP5520_POS_D2_ILVL 2u
  #define ADP5520_POS_D1_ILVL 1u
  #define ADP5520_POS_D0_ILVL 0u

  #define ADP5520_VAL_GPIO_INT_LVL_LOW  0u
  #define ADP5520_VAL_GPIO_INT_LVL_HIGH 1u

/* 0x1E - GPIO_DEBOUNCE
**        GPIO input debounce enable/disable.
**
** Fields:          For each pin, 0 => debounce enabled and 1 => disabled
**  [7]   D7_IN_DBNC
**  [6]   D6_IN_DBNC
**  [5]   D5_IN_DBNC
**  [4]   D4_IN_DBNC
**  [3]   D3_IN_DBNC
**  [2]   D2_IN_DBNC
**  [1]   D1_IN_DBNC
**  [0]   D0_IN_DBNC
*/
#define ADP5520_REG_GPIO_DEBOUNCE 0x1Eu
  #define ADP5520_POS_D7_IN_DBNC 7u
  #define ADP5520_POS_D6_IN_DBNC 6u
  #define ADP5520_POS_D5_IN_DBNC 5u
  #define ADP5520_POS_D4_IN_DBNC 4u
  #define ADP5520_POS_D3_IN_DBNC 3u
  #define ADP5520_POS_D2_IN_DBNC 2u
  #define ADP5520_POS_D1_IN_DBNC 1u
  #define ADP5520_POS_D0_IN_DBNC 0u

  #define ADP5520_VAL_GPIO_DEBOUNCE_ON  0u
  #define ADP5520_VAL_GPIO_DEBOUNCE_OFF 1u

/* 0x1F - GPIO_PULLUP
**        GPIO pull-up enable/disable.
**
** Fields:          For each pin, 0 => input pull-up disabled and 1 => enabled
**  [7]   D7_PULL
**  [6]   D6_PULL
**  [5]   D5_PULL
**  [4]   D4_PULL
**  [3]   D3_PULL
**  [2]   D2_PULL
**  [1]   D1_PULL
**  [0]   D0_PULL
*/
#define ADP5520_REG_GPIO_PULLUP 0x1Fu
  #define ADP5520_POS_D7_PULL 7u
  #define ADP5520_POS_D6_PULL 6u
  #define ADP5520_POS_D5_PULL 5u
  #define ADP5520_POS_D4_PULL 4u
  #define ADP5520_POS_D3_PULL 3u
  #define ADP5520_POS_D2_PULL 2u
  #define ADP5520_POS_D1_PULL 1u
  #define ADP5520_POS_D0_PULL 0u

  #define ADP5520_VAL_GPIO_PULLUP_OFF 0u
  #define ADP5520_VAL_GPIO_PULLUP_ON  1u

/* 0x20 - KP_INT_STAT_1
**        Read only register.
**        Contains interrupt status information for key presses on keys A-H.
**        Cleared on read.
**
** Fields:          For each key, 0 => no interrupt and 1 => keypress interrupt
**  [7]   KP_A_ISTAT
**  [6]   KP_B_ISTAT
**  [5]   KP_C_ISTAT
**  [4]   KP_D_ISTAT
**  [3]   KP_E_ISTAT
**  [2]   KP_F_ISTAT
**  [1]   KP_G_ISTAT
**  [0]   KP_H_ISTAT
*/
#define ADP5520_REG_KP_INT_STAT_1 0x20u
  #define ADP5520_POS_KP_A_ISTAT 7u
  #define ADP5520_POS_KP_B_ISTAT 6u
  #define ADP5520_POS_KP_C_ISTAT 5u
  #define ADP5520_POS_KP_D_ISTAT 4u
  #define ADP5520_POS_KP_E_ISTAT 3u
  #define ADP5520_POS_KP_F_ISTAT 2u
  #define ADP5520_POS_KP_G_ISTAT 1u
  #define ADP5520_POS_KP_H_ISTAT 0u

  #define ADP5520_VAL_KP_INT_CLR 0u
  #define ADP5520_VAL_KP_INT_SET 1u

/* 0x21 - KP_INT_STAT_2
**        Read-only register.
**        Contains interrupt status information for key presses on keys I-P.
**        Cleared on read.
**
** Fields:          For each key, 0 => no interrupt and 1 => keypress interrupt
**  [7]   KP_I_ISTAT
**  [6]   KP_J_ISTAT
**  [5]   KP_K_ISTAT
**  [4]   KP_L_ISTAT
**  [3]   KP_M_ISTAT
**  [2]   KP_N_ISTAT
**  [1]   KP_O_ISTAT
**  [0]   KP_P_ISTAT
*/
#define ADP5520_REG_KP_INT_STAT_2 0x21u
  #define ADP5520_POS_KP_I_ISTAT 7u
  #define ADP5520_POS_KP_J_ISTAT 6u
  #define ADP5520_POS_KP_K_ISTAT 5u
  #define ADP5520_POS_KP_L_ISTAT 4u
  #define ADP5520_POS_KP_M_ISTAT 3u
  #define ADP5520_POS_KP_N_ISTAT 2u
  #define ADP5520_POS_KP_O_ISTAT 1u
  #define ADP5520_POS_KP_P_ISTAT 0u

/* 0x22 - KR_INT_STAT_1
**        Read-only register.
**        Contains interrupt status information for key releases on keys A-H.
**        Cleared on read.
**
** Fields:          For each key, 0 => no interrupt and 1 => release interrupt
**  [7]   KR_A_ISTAT
**  [6]   KR_B_ISTAT
**  [5]   KR_C_ISTAT
**  [4]   KR_D_ISTAT
**  [3]   KR_E_ISTAT
**  [2]   KR_F_ISTAT
**  [1]   KR_G_ISTAT
**  [0]   KR_H_ISTAT
*/
#define ADP5520_REG_KR_INT_STAT_1 0x22u
  #define ADP5520_POS_KR_A_ISTAT 7u
  #define ADP5520_POS_KR_B_ISTAT 6u
  #define ADP5520_POS_KR_C_ISTAT 5u
  #define ADP5520_POS_KR_D_ISTAT 4u
  #define ADP5520_POS_KR_E_ISTAT 3u
  #define ADP5520_POS_KR_F_ISTAT 2u
  #define ADP5520_POS_KR_G_ISTAT 1u
  #define ADP5520_POS_KR_H_ISTAT 0u

  #define ADP5520_VAL_KR_INT_CLR 0u
  #define ADP5520_VAL_KR_INT_SET 1u

/* 0x23 - KR_INT_STAT_2
**        Read-only register.
**        Contains interrupt status information for key releases on keys I-P.
**        Cleared on read.
**
** Fields:          For each key, 0 => no interrupt and 1 => release interrupt
**  [7]   KR_I_ISTAT
**  [6]   KR_J_ISTAT
**  [5]   KR_K_ISTAT
**  [4]   KR_L_ISTAT
**  [3]   KR_M_ISTAT
**  [2]   KR_N_ISTAT
**  [1]   KR_O_ISTAT
**  [0]   KR_P_ISTAT
*/
#define ADP5520_REG_KR_INT_STAT_2 0x23u
  #define ADP5520_POS_KR_I_ISTAT 7u
  #define ADP5520_POS_KR_J_ISTAT 6u
  #define ADP5520_POS_KR_K_ISTAT 5u
  #define ADP5520_POS_KR_L_ISTAT 4u
  #define ADP5520_POS_KR_M_ISTAT 3u
  #define ADP5520_POS_KR_N_ISTAT 2u
  #define ADP5520_POS_KR_O_ISTAT 1u
  #define ADP5520_POS_KR_P_ISTAT 0u

/* 0x24 - KEY_STAT_1
**        Read-only register.
**        Reflects the present state of Key A through Key H.
**
** Fields:          For each key, 0 => key currently released and 1 => pressed
**  [7]   KEY_A_STAT
**  [6]   KEY_B_STAT
**  [5]   KEY_C_STAT
**  [4]   KEY_D_STAT
**  [3]   KEY_E_STAT
**  [2]   KEY_F_STAT
**  [1]   KEY_G_STAT
**  [0]   KEY_H_STAT
*/
#define ADP5520_REG_KEY_STAT_1 0x24u
  #define ADP5520_POS_KEY_A_STAT 7u
  #define ADP5520_POS_KEY_B_STAT 6u
  #define ADP5520_POS_KEY_C_STAT 5u
  #define ADP5520_POS_KEY_D_STAT 4u
  #define ADP5520_POS_KEY_E_STAT 3u
  #define ADP5520_POS_KEY_F_STAT 2u
  #define ADP5520_POS_KEY_G_STAT 1u
  #define ADP5520_POS_KEY_H_STAT 0u

  #define ADP5520_VAL_KEY_RELEASED 0u
  #define ADP5520_VAL_KEY_PRESSED  1u

/* 0x25 - KEY_STAT_2
**        Read-only register.
**        Reflects the present state of Key I through Key P.
**
** Fields:          For each key, 0 => key currently released and 1 => pressed
**  [7]   KEY_I_STAT
**  [6]   KEY_J_STAT
**  [5]   KEY_K_STAT
**  [4]   KEY_L_STAT
**  [3]   KEY_M_STAT
**  [2]   KEY_N_STAT
**  [1]   KEY_O_STAT
**  [0]   KEY_P_STAT
*/
#define ADP5520_REG_KEY_STAT_2 0x25u
  #define ADP5520_POS_KEY_I_STAT 7u
  #define ADP5520_POS_KEY_J_STAT 6u
  #define ADP5520_POS_KEY_K_STAT 5u
  #define ADP5520_POS_KEY_L_STAT 4u
  #define ADP5520_POS_KEY_M_STAT 3u
  #define ADP5520_POS_KEY_N_STAT 2u
  #define ADP5520_POS_KEY_O_STAT 1u
  #define ADP5520_POS_KEY_P_STAT 0u

/*
** End of register map
*/

/*
** The ADP5520's built-in TWI address.  Note that the Device Access
** Service appends a 0-bit to the address for write accesses and a
** 1-bit for read accesses.
*/
#define ADP5520_TWI_DEVICE_ADDRESS 0x32u

/*
** How to specify which keypad events are required.
*/
#define ADI_ADP5520_WANT_KEY_PRESSES   1
#define ADI_ADP5520_WANT_KEY_RELEASES  2

/*
**
** Enumerations of ADP5520 driver-specific commands
**
*/
enum
{
    /* 0x40320000 - ADP5520 driver enumeration start  */
    ADI_ADP5520_CMD_START = ADI_ADP5520_ENUMERATION_START,

    /*
    ** TWI related commands
    */

    /* 0x40320001 */    ADI_ADP5520_CMD_SET_TWI_DEVICE_NUMBER,
    /* Sets TWI Device Number to use to access ADP5520 registers

       Value   = u32 (TWI Device number to use)
       Default = 0
    */

    /* 0x40320002 */    ADI_ADP5520_CMD_SET_TWI_CONFIG_TABLE,
    /* Sets TWI Configuration table specific to the application

       Value   = pointer to ADI_DEV_CMD_VALUE_PAIR
       Default = pointer to a minimal set of commands that sets the dataflow
                 method to ADI_DEV_MODE_SEQ_CHAINED and then enables dataflow.
    */

    /* 0x40320003 */    ADI_ADP5520_CMD_SET_TWI_DEVICE_ADDRESS,
    /* Sets TWI Device Address specific to the HW platform

       Value   = u32 (TWI Device address to use)
       Default = ADP5520_TWI_DEVICE_ADDRESS
    */

    /*
    ** Interrupt related commands
    */

    /* 0x40320004 */    ADI_ADP5520_CMD_ENABLE_INTERRUPTS,
    /* Specifies which ADP5520 interrupts are to be enabled and which processor
       flag receives the ADP5520's nINT signals.  The ADP5520 interrupt enable
       bits are set first and then the processor flag is opened and configured
       and then its processor interrupt is enabled.

       Value = ADI_ADP5520_INTERRUPT_INFO*
    */

    /* 0x40320005 */    ADI_ADP5520_CMD_DISABLE_INTERRUPTS,
    /* Specifies which, if any, ADP5520 interrupts are to be disabled and
       whether the processor flag interrupt is to be disabled and the flag
       closed.  '1' bits in the 'interruptMask' field represent ADP5520
       interrupts that are to be disabled.  A value of ADI_FLAG_UNDEFINED
       in the 'flagId' field means that processor interrupts from the ADP5520
       are to be disabled and the corresponding processor flag closed.
       Other values are ignored and processor interrupts remain enabled.

       Value = ADI_ADP5520_INTERRUPT_INFO*
    */

    /* 0x40320006 */    ADI_ADP5520_CMD_BLOCK_INTERRUPT,
    /* Blocks the processor interrupt associated with nINT.

       Value = none
    */

    /* 0x40320007 */    ADI_ADP5520_CMD_UNBLOCK_INTERRUPT,
    /* Unblocks the processor interrupt associated with nINT.

       Value = none
    */


    /*
    ** The following are 'macro' commands to enable and disable various ADP5520
    ** features in standard configurations.  The description of each command
    ** includes details of the configuration used for it.
    **
    ** Note that because of multiplexing within the ADP5520 device, not all of
    ** these features can be simultaneously enabled: for example, the command
    ** that enables key press and release detection assumes a 4 x 4 keypad
    ** matrix and so the commands that enable LED2, LED3 and the GPIO lines
    ** cannot be used while keypad access is enabled.
    **
    ** Applications for which the driver's standard feature configurations are
    ** inappropriate can set up their own configurations by programming the
    ** ADP5520's registers using the usual register access commands defined in
    ** include file adi_dev.h (for example, ADI_DEV_CMD_REGISTER_WRITE).  The
    ** datasheet for the ADP5520 contains descriptions of all the device's
    ** registers and information about their use.
    */

    /* 0x40320008 */    ADI_ADP5520_CMD_ENABLE_KEYPAD,
    /* Enable the keypad scanner in the ADP5520 and start the delivery of key
       press and/or release events to the callback handler.

       Value = u32 (ADI_ADP5520_WANT_KEY_PRESSES, ADI_ADP5520_WANT_KEY_RELEASES
                   or these two values 'ORed' together.)

       This command will be rejected if the GPIO or LED2/LED3 facilities are
       currently enabled.  Otherwise, it will set up the ADP5520 to scan a 4 x 4
       key matrix and to generate interrupts when key presses and/or releases
       are detected (depending on the value of the command's parameter).

       If the device is in standby mode before this command is issued then it
       will still be in standby mode when it completes since key scanning is
       available in standby mode (assuming a suitable VDDIO level).

       If the ADP5520's backlight feature is enabled before this command is
       issued then a keypress when the backlight is off will automatically turn
       it on again.
    */

    /* 0x40320009 */    ADI_ADP5520_CMD_DISABLE_KEYPAD
    /* Disable the ADP5520's keypad scanner and stop delivery of key press and
       release events.

       Value = none
    */
};

/*
**
** Enumerations of ADP5520 driver specific events
**
*/

enum
{
    /* 0x40320000 - ADP5520 driver enumeration start  */
    ADI_ADP5520_EVENT_START = ADI_ADP5520_ENUMERATION_START,

    /* 0x40320001 */    ADI_ADP5520_EVENT_KEYPAD_PRESS,
    /* One or more of the keypad keys has raised a 'pressed' interrupt.

       The event argument is a u32 value holding a 16-bit mask in bits 15:0.
       Each 1-bit represents a key that has raised a 'pressed' interrupt:

         Bit Key Row Col
         15  'A'  R0  C0
         14  'B'  R0  C1
         13  'C'  R0  C2
         ...
          1  'O'  R3  C2
          0  'P'  R3  C3
    */

    /* 0x40320002 */    ADI_ADP5520_EVENT_KEYPAD_RELEASE,
    /* One or more of the keypad keys has raised a 'released' interrupt.

       The event argument is a u32 value holding a 16-bit mask in bits 15:0.
       Each 1-bit represents a key that has raised a 'released' interrupt:

         Bit Key Row Col
         15  'A'  R0  C0
         14  'B'  R0  C1
         13  'C'  R0  C2
         ...
          1  'O'  R3  C2
          0  'P'  R3  C3
    */

    /* 0x40320003 */    ADI_ADP5520_EVENT_LIGHT_SENSOR_TRIGGER,
    /* The ambient light sensor comparators have signalled a change.

       The event argument is a u32 value holding the current values of the
       L3_OUT and L2_OUT status bits from the ADP5520's ALS_CMPR_CFG register.
       The status bit values occupy positions ADP5520_POS_L3_OUT and
       ADP5520_POS_L2_OUT respectively in the event argument.
    */

    /* 0x40320004 */    ADI_ADP5520_EVENT_OVERVOLTAGE_TRIGGER,
    /* The overvoltage protection circuit has raised an interrupt.

       There is no associated event argument.
    */

    /* 0x40320005 */    ADI_ADP5520_EVENT_GPIO_INPUT
    /* One or more GPIO input pins has raised an interrupt.

       The event argument is a u32 item holding the current value of the
       ADP5520's GPIO_INT_STAT register in bits 7-0.
    */
};

/*
**
** Enumerations of ADP5520 driver specific Return codes
**
*/

enum
{
    /* 0x40320000 - ADP5520 driver enumeration start  */
    ADI_ADP5520_RESULT_START = ADI_ADP5520_ENUMERATION_START,

    /* 0x40320001 */    ADI_ADP5520_RESULT_CMD_NOT_SUPPORTED,
    /* Returned when client issues a command that is not supported by this
       driver.
    */

    /* 0x40320002 */    ADI_ADP5520_RESULT_FEATURE_CONFLICT,
    /* The requested feature conflicts with an already-enabled feature.
       Due to multiplexing within the ADP5520, not all features can be active
       simultaneously.
    */

    /* 0x40320003 */    ADI_ADP5520_RESULT_INVALID_KEY_REQUIREMENT
    /* Notification of neither keypad presses nor releases was requested when
       enabling the keypad.
    */
};

/*=============  E X T E R N A L S  ============*/

/*
**
**  External Data section
**
*/
/*
** ADIADP5520EntryPoint
**  - Device Manager Entry point for ADP5520 driver
**
*/
extern ADI_DEV_PDD_ENTRY_POINT      ADIADP5520EntryPoint;

/*=============  D A T A    T Y P E S   =============*/

#if defined(_LANGUAGE_C)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* C-specific definitions  */

/*
**
**  Data structures
**
*/


/*
** ADI_ADP5520_INTERRUPT_INFO
** Structure specifying which ADP5520 interrupts are to be enabled and which
** Blackfin FLAG is connected to the ADP5520's nINT signal.
**
** This data structure is used with the ADI_ADP5520_CMD_ENABLE_INTERRUPTS
** command which configures the driver to monitor the nINT interrupt and
** use the callback mechanism to pass significant events back to the
** application.
**
** The 'interruptMask' field should hold a mask specifying which of the
** interrupt enable bits of the ADP5520's INTERRUPT_ENABLE register are
** to be set: 'or' together the appropriate combination of
** ADP5520_MSK_CMPR_IEN, ADP5520_MSK_OVP_IEN, ADP5520_MSK_KR_IEN and
** ADP5520_MSK_KP_IEN.
**
** The 'flagId' field should hold the Blackfin processor Flag ID connected
** to the nINT interrupt signal and the 'flagIntId' field should hold the
** Peripheral Interrupt ID of the corresponding flag.
**
** The structure is also used with the ADI_ADP5520_CMD_DISABLE_INTERRUPTS
** command, in which case the 'interruptMask' field specifies which ADP5520
** interrupt conditions are to be disabled and a value of ADI_FLAG_UNDEFINED
** in 'flagId' means that processor interrupts from the flag connected to
** nINT are to be disabled.
*/
typedef struct __AdiAdp5520InterruptInfo
{
    u8                      interruptMask;
    ADI_FLAG_ID             flagId;
    ADI_INT_PERIPHERAL_ID   flagIntId;

} ADI_ADP5520_INTERRUPT_INFO;

/*=======  P U B L I C   P R O T O T Y P E S  ========*/
/*            (globally-scoped functions)             */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#else /* not _LANGUAGE_C */

/* Assembler-specific */

#endif /* not _LANGUAGE_C */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_ADP5520_H__ */

/*****/
