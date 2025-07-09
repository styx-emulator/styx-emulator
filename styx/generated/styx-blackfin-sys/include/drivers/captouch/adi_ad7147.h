/*****************************************************************************
Copyright (c), 2002-2009 - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.
******************************************************************************

$RCSfile: adi_ad7147.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Title: AD7147 Capacitance Converter Controller Driver

Description: This is the primary include file for AD7147 Capacitance Converter
             Controller Driver.  The driver supports Device access commands
             to access AD7147 registers

Notes: Access to the AD7147 control registers is over the TWI port.


*****************************************************************************/

#ifndef __ADI_AD7147_H__
#define __ADI_AD7147_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*=============  I N C L U D E S   =============*/

/* TWI driver includes */
#include <drivers/twi/adi_twi.h>


/*==============  D E F I N E S  ===============*/

/*********************************************************************

Entry point to the AD7147 device driver

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADIAD7147EntryPoint;

/*
**
** AD7147 Register Map
**
** The AD7147 address space is divided into three register banks.
**
** BANK 1 registers contain control registers, CDC conversion control registers,
** interrupt enable registers, interrupt status registers, CDC 16-bit conversion data registers,
** device ID registers, and proximity status registers.
**
** BANK 2 registers contain the configuration registers used to configure
** the individual CINx inputs for each conversion stage.
**
** BANK 3 registers contain the results of each conversion stage.
**
*/

/*
** REGISTER BANK 1
**  - Read/Write Type Registers
*/

/*
** AD7147_REG_PWR_CONTROL
**  - RW    Power & conversion control
*/
#define AD7147_REG_PWR_CONTROL                  0x00
/*
** AD7147_REG_STAGE_CAL_EN
**  - RW    Calibration enable register
*/
#define AD7147_REG_STAGE_CAL_EN                 0x01
/*
** AD7147_REG_AMB_COMP_CTRL0
** RW   Ambient compensation control register 0
*/
#define AD7147_REG_AMB_COMP_CTRL0               0x02
/*
** AD7147_REG_AMB_COMP_CTRL1
**  - RW    Ambient compensation control register 1
*/
#define AD7147_REG_AMB_COMP_CTRL1               0x03
/*
** AD7147_REG_AMB_COMP_CTRL2
**  - RW    Ambient compensation control register 2
*/
#define AD7147_REG_AMB_COMP_CTRL2               0x04
/*
** AD7147_REG_STAGE_LOW_INT_EN
**  - RW    Low Limit Interrupt enable register
*/
#define AD7147_REG_STAGE_LOW_INT_EN             0x05
/*
** AD7147_REG_STAGE_HIGH_INT_EN
**  - RW    High Limit Interrupt enable register
*/
#define AD7147_REG_STAGE_HIGH_INT_EN            0x06
/*
** AD7147_REG_STAGE_COMPLETE_INT_EN
**  - RW    Conversion Interrupt enable register
*/
#define AD7147_REG_STAGE_COMPLETE_INT_EN        0x07
/*
** AD7147_REG_STAGE_LOW_INT_STATUS
**  - R Low limit interrupt status register
*/
#define AD7147_REG_STAGE_LOW_INT_STATUS         0x08
/*
** AD7147_REG_STAGE_HIGH_INT_STATUS
**  - R High limit interrupt status register
*/
#define AD7147_REG_STAGE_HIGH_INT_STATUS        0x09
/*
** AD7147_REG_STAGE_COMPLETE_INT_STATUS
**  - R Conversion Interrupt status register
*/
#define AD7147_REG_STAGE_COMPLETE_INT_STATUS    0x0A
/*
** AD7147_REG_CDCRESULT_S0
**  - R CDC stage 0 result
*/
#define AD7147_REG_CDCRESULT_S0                 0x0B
/*
** AD7147_REG_CDCRESULT_S1
**  - R CDC stage 1 result
*/
#define AD7147_REG_CDCRESULT_S1                 0x0C
/*
** AD7147_REG_CDCRESULT_S2
**  - R CDC stage 2 result
*/
#define AD7147_REG_CDCRESULT_S2                 0x0D
/*
** AD7147_REG_CDCRESULT_S3
**  - R CDC stage 3 result
*/
#define AD7147_REG_CDCRESULT_S3                 0x0E
/*
** AD7147_REG_CDCRESULT_S4
**  - R CDC stage 4 result
*/
#define AD7147_REG_CDCRESULT_S4                 0x0F
/*
** AD7147_REG_CDCRESULT_S5
**  - R CDC stage 5 result
*/
#define AD7147_REG_CDCRESULT_S5                 0x10
/*
** AD7147_REG_CDCRESULT_S6
**  - R CDC stage 6 result
*/
#define AD7147_REG_CDCRESULT_S6                 0x11
/*
** AD7147_REG_CDCRESULT_S7
**  - R CDC stage 7 result
*/
#define AD7147_REG_CDCRESULT_S7                 0x12
/*
** AD7147_REG_CDCRESULT_S8
**  - R CDC stage 8 result
*/
#define AD7147_REG_CDCRESULT_S8                 0x13
/*
** AD7147_REG_CDCRESULT_S9
**  - R CDC stage 9 result
*/
#define AD7147_REG_CDCRESULT_S9                 0x14
/*
** AD7147_REG_CDCRESULT_S10
**  - R CDC stage 10 result
*/
#define AD7147_REG_CDCRESULT_S10                0x15
/*
** AD7147_REG_CDCRESULT_S11
**  - R CDC stage 11 result
*/
#define AD7147_REG_CDCRESULT_S11                0x16
/*
** AD7147_REG_DEVID
**  - R Device I.D. Register
*/
#define AD7147_REG_DEVID                        0x17
/*
** AD7147_REG_PROX_STAT_REG
**  - R Proximity status register
*/
#define AD7147_REG_PROX_STATUS                  0x42


#define ADI_AD7147_END_REG_ADDR                 0x28FU


/*
**
** AD7147 Register field definitions
**  - Power Control Register field definitions (AD7147_REG_PWR_CONTROL)
**
*/

/*
** AD7147_RFLD_CDCBIAS
**  - CDC bias current control (bits 14-15)
*/
#define     AD7147_RFLD_CDCBIAS             14U
/*
** AD7147_RFLD_EXCSOURCE
**  - Excitation source control (bit 12)
*/
#define     AD7147_RFLD_EXCSOURCE           12U
/*
** AD7147_RFLD_INTPOL
**  - Interrupt polarity control (bit 11)
*/
#define     AD7147_RFLD_INTPOL              11U
/*
** AD7147_RFLD_SWRESET
**  - Software reset control (bit 10)
*/
#define     AD7147_RFLD_SWRESET             10U
/*
** AD7147_RFLD_DECIMATION
**  - ADC decimation factor (bits 8-9)
*/
#define     AD7147_RFLD_DECIMATION          8U
/*
** AD7147_RFLD_SEQSTGNUM
**  - Number of stages in sequence (bits 4-7)
*/
#define     AD7147_RFLD_SEQSTGNUM           4U
/*
** AD7147_RFLD_LPCONVDEL
**  - Low power mode conversion delay (bits 2-3)
*/
#define     AD7147_RFLD_LPCONVDEL           2U
/*
** AD7147_RFLD_POWERMODE
**  - Operating modes (bits 0-1)
*/
#define     AD7147_RFLD_POWERMODE           0U


/*
**
** AD7147 Register field definitions
**  - STAGE calibration enable Register field definitions (AD7147_REG_STAGE_CAL_EN)
**
*/

/*
** AD7147_RFLD_LPSKIP
**  - Low power mode skip control (bits 14-15)
*/
#define     AD7147_RFLD_LPSKIP             14U
/*
** AD7147_RFLD_FPSKIP
**  - Full power mode skip control (bits 12-13)
*/
#define     AD7147_RFLD_FPSKIP             12U
/*
** AD7147_RFLD_STAGE11_CALEN
**  - STAGE11 calibration enable (bit 11)
*/
#define     AD7147_RFLD_STAGE11_CALEN       11U
/*
** AD7147_RFLD_STAGE10_CALEN
**  - STAGE10 calibration enable (bit 10)
*/
#define     AD7147_RFLD_STAGE10_CALEN       10U
/*
** AD7147_RFLD_STAGE9_CALEN
**  - STAGE9 calibration enable (bit 9)
*/
#define     AD7147_RFLD_STAGE9_CALEN        9U
/*
** AD7147_RFLD_STAGE8_CALEN
**  - STAGE8 calibration enable (bit 8)
*/
#define     AD7147_RFLD_STAGE8_CALEN        8U
/*
** AD7147_RFLD_STAGE7_CALEN
**  - STAGE7 calibration enable (bit 7)
*/
#define     AD7147_RFLD_STAGE7_CALEN        7U
/*
** AD7147_RFLD_STAGE6_CALEN
**  - STAGE6 calibration enable (bit 6)
*/
#define     AD7147_RFLD_STAGE6_CALEN        6U
/*
** AD7147_RFLD_STAGE5_CALEN
**  - STAGE5 calibration enable (bit 5)
*/
#define     AD7147_RFLD_STAGE5_CALEN        5U
/*
** AD7147_RFLD_STAGE4_CALEN
**  - STAGE4 calibration enable (bit 4)
*/
#define     AD7147_RFLD_STAGE4_CALEN        4U
/*
** AD7147_RFLD_STAGE3_CALEN
**  - STAGE3 calibration enable (bit 3)
*/
#define     AD7147_RFLD_STAGE3_CALEN        3U
/*
** AD7147_RFLD_STAGE2_CALEN
**  - STAGE2 calibration enable (bit 2)
*/
#define     AD7147_RFLD_STAGE2_CALEN        2U
/*
** AD7147_RFLD_STAGE1_CALEN
**  - STAGE1 calibration enable (bit 1)
*/
#define     AD7147_RFLD_STAGE1_CALEN        1U
/*
** AD7147_RFLD_STAGE0_CALEN
**  - STAGE0 calibration enable (bit 0)
*/
#define     AD7147_RFLD_STAGE0_CALEN        0U

/*
**
** AD7147 Register field definitions
**  - Ambient compensation controller 0 Register field definitions (AD7147_REG_AMB_COMP_CTRL0)
**
*/

/*
** AD7147_RFLD_CONV_RESET
**  - Conversion reset control (bit15)
*/
#define     AD7147_RFLD_CONV_RESET             15U
/*
** AD7147_RFLD_FORCED_CAL
**  - Forced calibration control (bit14)
*/
#define     AD7147_RFLD_FORCED_CAL             14U
/*
** AD7147_RFLD_PWR_DOWN_TMO
**  - Full power to low power mode timeout control (bits 12-13)
*/
#define     AD7147_RFLD_PWR_DOWN_TMO           12U
/*
** AD7147_RFLD_LP_PROX_CNT
**  - Calibration disable period in low power mode (bits 8-11)
*/
#define     AD7147_RFLD_LP_PROX_CNT            8U
/*
** AD7147_RFLD_FP_PROX_CNT
**  - Calibration disable period in full power mode (bits 4-7)
*/
#define     AD7147_RFLD_FP_PROX_CNT            4U
/*
** AD7147_RFLD_FF_SKIP_CNT
**  - Fast filter skip control (bits 0-3)
*/
#define     AD7147_RFLD_FF_SKIP_CNT            0U


/*
**
** AD7147 Register field definitions
**  - Ambient compensation controller 1 Register field definitions (AD7147_REG_AMB_COMP_CTRL1)
**
*/

/*
** AD7147_RFLD_CONV_RESET
**  - Slow filter update level (bit14-15)
*/
#define     AD7147_RFLD_SLOW_FIL_UPD_LVL        14U
/*
** AD7147_RFLD_PROX_DET_RATE
**  - Proximity detection rate.(bit8-13)
*/
#define     AD7147_RFLD_PROX_DET_RATE           8U
/*
** AD7147_RFLD_PROX_RECAL_LVL
**  - Proximity recalibration level (bit0-7)
*/
#define     AD7147_RFLD_PROX_RECAL_LVL          0U

/*
**
** AD7147 Register field definitions
**  - Ambient compensation controller 2 Register field definitions (AD7147_REG_AMB_COMP_CTRL2)
**
*/

/*
** AD7147_RFLD_LP_PROX_RECAL
**  - Low power mode proximity recalibration time control (bit10-15)
*/
#define     AD7147_RFLD_LP_PROX_RECAL           10U
/*
** AD7147_RFLD_FP_PROX_RECAL
**  - Full power mode proximity recalibration time control (bit0-9)
*/
#define     AD7147_RFLD_FP_PROX_RECAL           0U

/*
**
** AD7147 Register field definitions
**  - Low limit interrupt enable Register field definitions (AD7147_REG_STAGE_LOW_INT_EN)
**
*/

/*
** AD7147_RFLD_GPIO_INCONFIG
**  - GPIO input configuration (bit14-15)
*/
#define     AD7147_RFLD_GPIO_INCONFIG           14U
/*
** AD7147_RFLD_GPIO_SETUP
**  - GPIO setup (bit12-13)
*/
#define     AD7147_RFLD_GPIO_SETUP              12U
/*
** AD7147_RFLD_STAGE11_LINT_EN
**  - STAGE11 low interrupt enable (bit11)
*/
#define     AD7147_RFLD_STAGE11_LINT_EN         11U
/*
** AD7147_RFLD_STAGE10_LINT_EN
**  - STAGE10 low interrupt enable (bit10)
*/
#define     AD7147_RFLD_STAGE10_LINT_EN         10U
/*
** AD7147_RFLD_STAGE9_LINT_EN
**  - STAGE9 low interrupt enable (bit9)
*/
#define     AD7147_RFLD_STAGE9_LINT_EN           9U
/*
** AD7147_RFLD_STAGE8_LINT_EN
**  - STAGE8 low interrupt enable (bit8)
*/
#define     AD7147_RFLD_STAGE8_LINT_EN           8U
/*
** AD7147_RFLD_STAGE7_LINT_EN
**  - STAGE7 low interrupt enable (bit7)
*/
#define     AD7147_RFLD_STAGE7_LINT_EN           7U
/*
** AD7147_RFLD_STAGE6_LINT_EN
**  - STAGE6 low interrupt enable (bit6)
*/
#define     AD7147_RFLD_STAGE6_LINT_EN           6U
/*
** AD7147_RFLD_STAGE5_LINT_EN
**  - STAGE5 low interrupt enable (bit5)
*/
#define     AD7147_RFLD_STAGE5_LINT_EN           5U
/*
** AD7147_RFLD_STAGE4_LINT_EN
**  - STAGE4 low interrupt enable (bit4)
*/
#define     AD7147_RFLD_STAGE4_LINT_EN           4U
/*
** AD7147_RFLD_STAGE3_LINT_EN
**  - STAGE3 low interrupt enable (bit3)
*/
#define     AD7147_RFLD_STAGE3_LINT_EN           3U
/*
** AD7147_RFLD_STAGE2_LINT_EN
**  - STAGE2 low interrupt enable (bit2)
*/
#define     AD7147_RFLD_STAGE2_LINT_EN           2U
/*
** AD7147_RFLD_STAGE1_LINT_EN
**  - STAGE1 low interrupt enable (bit1)
*/
#define     AD7147_RFLD_STAGE1_LINT_EN           1U
/*
** AD7147_RFLD_STAGE0_LINT_EN
**  - STAGE0 low interrupt enable (bit0)
*/
#define     AD7147_RFLD_STAGE0_LINT_EN           0U


/*
**
** AD7147 Register field definitions
**  - High limit interrupt enable Register field definitions (AD7147_REG_STAGE_HIGH_INT_EN)
**
*/

/*
** AD7147_RFLD_STAGE11_HINT_EN
**  - STAGE11 low interrupt enable (bit11)
*/
#define     AD7147_RFLD_STAGE11_HINT_EN         11U
/*
** AD7147_RFLD_STAGE10_LINT_EN
**  - STAGE10 low interrupt enable (bit10)
*/
#define     AD7147_RFLD_STAGE10_HINT_EN         10U
/*
** AD7147_RFLD_STAGE9_HINT_EN
**  - STAGE9 low interrupt enable (bit9)
*/
#define     AD7147_RFLD_STAGE9_HINT_EN           9U
/*
** AD7147_RFLD_STAGE8_HINT_EN
**  - STAGE8 low interrupt enable (bit8)
*/
#define     AD7147_RFLD_STAGE8_HINT_EN           8U
/*
** AD7147_RFLD_STAGE7_HINT_EN
**  - STAGE7 low interrupt enable (bit7)
*/
#define     AD7147_RFLD_STAGE7_HINT_EN           7U
/*
** AD7147_RFLD_STAGE6_HINT_EN
**  - STAGE6 low interrupt enable (bit6)
*/
#define     AD7147_RFLD_STAGE6_HINT_EN           6U
/*
** AD7147_RFLD_STAGE5_HINT_EN
**  - STAGE5 low interrupt enable (bit5)
*/
#define     AD7147_RFLD_STAGE5_HINT_EN           5U
/*
** AD7147_RFLD_STAGE4_HINT_EN
**  - STAGE4 low interrupt enable (bit4)
*/
#define     AD7147_RFLD_STAGE4_HINT_EN           4U
/*
** AD7147_RFLD_STAGE3_HINT_EN
**  - STAGE3 low interrupt enable (bit3)
*/
#define     AD7147_RFLD_STAGE3_HINT_EN           3U
/*
** AD7147_RFLD_STAGE2_HINT_EN
**  - STAGE2 low interrupt enable (bit2)
*/
#define     AD7147_RFLD_STAGE2_HINT_EN           2U
/*
** AD7147_RFLD_STAGE1_HINT_EN
**  - STAGE1 low interrupt enable (bit1)
*/
#define     AD7147_RFLD_STAGE1_HINT_EN           1U
/*
** AD7147_RFLD_STAGE0_HINT_EN
**  - STAGE0 low interrupt enable (bit0)
*/
#define     AD7147_RFLD_STAGE0_HINT_EN           0U


/*
**
** AD7147 Register field definitions
**  - Low limit interrupt enable Register field definitions (AD7147_REG_STAGE_COMPLETE_INT_EN)
**
*/

/*
** AD7147_RFLD_GPIO_INT_EN
**  - Interrupt control when GPIO input pin changes level (bit12)
*/
#define     AD7147_RFLD_GPIO_SETUP              12U
/*
** AD7147_RFLD_STAGE11_COMP_INT_EN
**  - STAGE11 complete interrupt enable (bit11)
*/
#define     AD7147_RFLD_STAGE11_COMP_INT_EN         11U
/*
** AD7147_RFLD_STAGE10_COMP_INT_EN
**  - STAGE10 complete interrupt enable (bit10)
*/
#define     AD7147_RFLD_STAGE10_COMP_INT_EN         10U
/*
** AD7147_RFLD_STAGE9_LINT_EN
**  - STAGE9 complete interrupt enable (bit9)
*/
#define     AD7147_RFLD_STAGE9_COMP_INT_EN           9U
/*
** AD7147_RFLD_STAGE8_LINT_EN
**  - STAGE8 complete interrupt enable (bit8)
*/
#define     AD7147_RFLD_STAGE8_COMP_INT_EN           8U
/*
** AD7147_RFLD_STAGE7_LINT_EN
**  - STAGE7 complete interrupt enable (bit7)
*/
#define     AD7147_RFLD_STAGE7_COMP_INT_EN           7U
/*
** AD7147_RFLD_STAGE6_LINT_EN
**  - STAGE6 complete interrupt enable (bit6)
*/
#define     AD7147_RFLD_STAGE6_COMP_INT_EN           6U
/*
** AD7147_RFLD_STAGE5_COMP_INT_EN
**  - STAGE5 complete interrupt enable (bit5)
*/
#define     AD7147_RFLD_STAGE5_COMP_INT_EN           5U
/*
** AD7147_RFLD_STAGE4_COMP_INT_EN
**  - STAGE4 complete interrupt enable (bit4)
*/
#define     AD7147_RFLD_STAGE4_COMP_INT_EN           4U
/*
** AD7147_RFLD_STAGE3_COMP_INT_EN
**  - STAGE3 complete interrupt enable (bit3)
*/
#define     AD7147_RFLD_STAGE3_COMP_INT_EN           3U
/*
** AD7147_RFLD_STAGE2_COMP_INT_EN
**  - STAGE2 complete interrupt enable (bit2)
*/
#define     AD7147_RFLD_STAGE2_COMP_INT_EN           2U
/*
** AD7147_RFLD_STAGE1_COMP_INT_EN
**  - STAGE1 complete interrupt enable (bit1)
*/
#define     AD7147_RFLD_STAGE1_COMP_INT_EN           1U
/*
** AD7147_RFLD_STAGE0_COMP_INT_EN
**  - STAGE0 complete interrupt enable (bit0)
*/
#define     AD7147_RFLD_STAGE0_COMP_INT_EN           0U


/*
**
** AD7147 Register field definitions
**  - Low interrupt status Register field definitions (AD7147_REG_STAGE_LOW_INT_STATUS)
**
*/

/*
** AD7147_RFLD_STAGE11_LINT_STATUS
**  - STAGE11 low interrupt status (bit11)
*/
#define     AD7147_RFLD_STAGE11_LINT_STATUS         11U
/*
** AD7147_RFLD_STAGE10_LINT_STATUS
**  - STAGE10 low interrupt enable (bit10)
*/
#define     AD7147_RFLD_STAGE10_LINT_STATUS         10U
/*
** AD7147_RFLD_STAGE9_LINT_STATUS
**  - STAGE9 low interrupt status (bit9)
*/
#define     AD7147_RFLD_STAGE9_LINT_STATUS           9U
/*
** AD7147_RFLD_STAGE8_LINT_STATUS
**  - STAGE8 low interrupt status (bit8)
*/
#define     AD7147_RFLD_STAGE8_LINT_STATUS           8U
/*
** AD7147_RFLD_STAGE7_LINT_STATUS
**  - STAGE7 low interrupt status (bit7)
*/
#define     AD7147_RFLD_STAGE7_LINT_STATUS           7U
/*
** AD7147_RFLD_STAGE6_LINT_STATUS
**  - STAGE6 low interrupt status (bit6)
*/
#define     AD7147_RFLD_STAGE6_LINT_STATUS           6U
/*
** AD7147_RFLD_STAGE5_LINT_STATUS
**  - STAGE5 low interrupt status (bit5)
*/
#define     AD7147_RFLD_STAGE5_LINT_STATUS           5U
/*
** AD7147_RFLD_STAGE4_LINT_STATUS
**  - STAGE4 low interrupt status (bit4)
*/
#define     AD7147_RFLD_STAGE4_LINT_STATUS           4U
/*
** AD7147_RFLD_STAGE3_LINT_STATUS
**  - STAGE3 low interrupt status (bit3)
*/
#define     AD7147_RFLD_STAGE3_LINT_STATUS           3U
/*
** AD7147_RFLD_STAGE2_LINT_STATUS
**  - STAGE2 low interrupt status (bit2)
*/
#define     AD7147_RFLD_STAGE2_LINT_STATUS           2U
/*
** AD7147_RFLD_STAGE1_LINT_STATUS
**  - STAGE1 low interrupt status (bit1)
*/
#define     AD7147_RFLD_STAGE1_LINT_STATUS           1U
/*
** AD7147_RFLD_STAGE0_LINT_STATUS
**  - STAGE0 low interrupt status (bit0)
*/
#define     AD7147_RFLD_STAGE0_LINT_STATUS           0U


/*
**
** AD7147 Register field definitions
**  - High interrupt status Register field definitions (AD7147_REG_STAGE_HIGH_INT_STATUS)
**
*/

/*
** AD7147_RFLD_STAGE11_HINT_STATUS
**  - STAGE11 high interrupt status (bit11)
*/
#define     AD7147_RFLD_STAGE11_HINT_STATUS         11U
/*
** AD7147_RFLD_STAGE10_HINT_STATUS
**  - STAGE10 high interrupt enable (bit10)
*/
#define     AD7147_RFLD_STAGE10_HINT_STATUS         10U
/*
** AD7147_RFLD_STAGE9_HINT_STATUS
**  - STAGE9 high interrupt status (bit9)
*/
#define     AD7147_RFLD_STAGE9_HINT_STATUS           9U
/*
** AD7147_RFLD_STAGE8_HINT_STATUS
**  - STAGE8 high interrupt status (bit8)
*/
#define     AD7147_RFLD_STAGE8_HINT_STATUS           8U
/*
** AD7147_RFLD_STAGE7_HINT_STATUS
**  - STAGE7 high interrupt status (bit7)
*/
#define     AD7147_RFLD_STAGE7_HINT_STATUS           7U
/*
** AD7147_RFLD_STAGE6_HINT_STATUS
**  - STAGE6 high interrupt status (bit6)
*/
#define     AD7147_RFLD_STAGE6_HINT_STATUS           6U
/*
** AD7147_RFLD_STAGE5_HINT_STATUS
**  - STAGE5 high interrupt status (bit5)
*/
#define     AD7147_RFLD_STAGE5_HINT_STATUS           5U
/*
** AD7147_RFLD_STAGE4_HINT_STATUS
**  - STAGE4 high interrupt status (bit4)
*/
#define     AD7147_RFLD_STAGE4_HINT_STATUS           4U
/*
** AD7147_RFLD_STAGE3_HINT_STATUS
**  - STAGE3 high interrupt status (bit3)
*/
#define     AD7147_RFLD_STAGE3_HINT_STATUS           3U
/*
** AD7147_RFLD_STAGE2_HINT_STATUS
**  - STAGE2 high interrupt status (bit2)
*/
#define     AD7147_RFLD_STAGE2_HINT_STATUS           2U
/*
** AD7147_RFLD_STAGE1_HINT_STATUS
**  - STAGE1 high interrupt status (bit1)
*/
#define     AD7147_RFLD_STAGE1_HINT_STATUS           1U
/*
** AD7147_RFLD_STAGE0_HINT_STATUS
**  - STAGE0 high interrupt status (bit0)
*/
#define     AD7147_RFLD_STAGE0_HINT_STATUS           0U


/*
**
** AD7147 Register field definitions
**  - Complete interrupt status Register field definitions (AD7147_REG_STAGE_COMPLETE_INT_STATUS)
**
*/

/*
** AD7147_RFLD_STAGE11_COMP_INT_STATUS
**  - STAGE11 conversion complete interrupt status (bit11)
*/
#define     AD7147_RFLD_STAGE11_COMP_INT_STATUS         11U
/*
** AD7147_RFLD_STAGE10_COMP_INT_STATUS
**  - STAGE10 conversion complete interrupt enable (bit10)
*/
#define     AD7147_RFLD_STAGE10_COMP_INT_STATUS         10U
/*
** AD7147_RFLD_STAGE9_COMP_INT_STATUS
**  - STAGE9 conversion complete interrupt status (bit9)
*/
#define     AD7147_RFLD_STAGE9_COMP_INT_STATUS           9U
/*
** AD7147_RFLD_STAGE8_COMP_INT_STATUS
**  - STAGE8 conversion complete interrupt status (bit8)
*/
#define     AD7147_RFLD_STAGE8_COMP_INT_STATUS           8U
/*
** AD7147_RFLD_STAGE7_COMP_INT_STATUS
**  - STAGE7 conversion complete interrupt status (bit7)
*/
#define     AD7147_RFLD_STAGE7_COMP_INT_STATUS           7U
/*
** AD7147_RFLD_STAGE6_COMP_INT_STATUS
**  - STAGE6 conversion complete interrupt status (bit6)
*/
#define     AD7147_RFLD_STAGE6_COMP_INT_STATUS           6U
/*
** AD7147_RFLD_STAGE5_COMP_INT_STATUS
**  - STAGE5 conversion complete interrupt status (bit5)
*/
#define     AD7147_RFLD_STAGE5_COMP_INT_STATUS           5U
/*
** AD7147_RFLD_STAGE4_COMP_INT_STATUS
**  - STAGE4 conversion complete interrupt status (bit4)
*/
#define     AD7147_RFLD_STAGE4_COMP_INT_STATUS           4U
/*
** AD7147_RFLD_STAGE3_COMP_INT_STATUS
**  - STAGE3 conversion complete interrupt status (bit3)
*/
#define     AD7147_RFLD_STAGE3_COMP_INT_STATUS           3U
/*
** AD7147_RFLD_STAGE2_COMP_INT_STATUS
**  - STAGE2 conversion complete interrupt status (bit2)
*/
#define     AD7147_RFLD_STAGE2_COMP_INT_STATUS           2U
/*
** AD7147_RFLD_STAGE1_COMP_INT_STATUS
**  - STAGE1 conversion complete interrupt status (bit1)
*/
#define     AD7147_RFLD_STAGE1_COMP_INT_STATUS           1U
/*
** AD7147_RFLD_STAGE0_COMP_INT_STATUS
**  - STAGE0 conversion complete interrupt status (bit0)
*/
#define     AD7147_RFLD_STAGE0_COMP_INT_STATUS           0U


/*
**
** AD7147 Register field definitions
**  - Device ID Register field definitions (AD7147_REG_DEVID)
**
*/

/*
** AD7147_RFLD_DEVID
**  - Device ID (bit4-15)
*/
#define     AD7147_RFLD_DEVID           4U
/*
** AD7147_RFLD_REV_CODE
**  - Revision code (bit0-3)
*/
#define     AD7147_RFLD_REV_CODE            0U


/*
**
** AD7147 Register field definitions
**  - Proximity Status Register field definitions (AD7147_REG_PROX_STATUS)
**
*/

/*
** AD7147_RFLD_STAGE11_PROX_STATUS
**  - STAGE11 proximity status (bit11)
*/
#define     AD7147_RFLD_STAGE11_PROX_STATUS         11U
/*
** AD7147_RFLD_STAGE10_PROX_STATUS
**  - STAGE10 proximity status (bit10)
*/
#define     AD7147_RFLD_STAGE10_PROX_STATUS         10U
/*
** AD7147_RFLD_STAGE9_PROX_STATUS
**  - STAGE9 proximity status (bit9)
*/
#define     AD7147_RFLD_STAGE9_PROX_STATUS           9U
/*
** AD7147_RFLD_STAGE8_PROX_STATUS
**  - STAGE8 proximity status (bit8)
*/
#define     AD7147_RFLD_STAGE8_PROX_STATUS           8U
/*
** AD7147_RFLD_STAGE7_PROX_STATUS
**  - STAGE7 proximity status (bit7)
*/
#define     AD7147_RFLD_STAGE7_PROX_STATUS           7U
/*
** AD7147_RFLD_STAGE6_PROX_STATUS
**  - STAGE6 proximity status (bit6)
*/
#define     AD7147_RFLD_STAGE6_PROX_STATUS           6U
/*
** AD7147_RFLD_STAGE5_PROX_STATUS
**  - STAGE5 proximity status (bit5)
*/
#define     AD7147_RFLD_STAGE5_PROX_STATUS           5U
/*
** AD7147_RFLD_STAGE4_PROX_STATUS
**  - STAGE4 proximity status (bit4)
*/
#define     AD7147_RFLD_STAGE4_PROX_STATUS           4U
/*
** AD7147_RFLD_STAGE3_PROX_STATUS
**  - STAGE3 proximity status (bit3)
*/
#define     AD7147_RFLD_STAGE3_PROX_STATUS           3U
/*
** AD7147_RFLD_STAGE2_PROX_STATUS
**  - STAGE2 proximity status (bit2)
*/
#define     AD7147_RFLD_STAGE2_PROX_STATUS           2U
/*
** AD7147_RFLD_STAGE1_PROX_STATUS
**  - STAGE1 proximity status (bit1)
*/
#define     AD7147_RFLD_STAGE1_PROX_STATUS           1U
/*
** AD7147_RFLD_STAGE0_PROX_STATUS
**  - STAGE0 proximity status (bit0)
*/
#define     AD7147_RFLD_STAGE0_PROX_STATUS           0U



/*
** REGISTER BANK 2
**  - Read/Write Type Registers
*/

/*
** AD7147_REG_STAGE0_CONFIG
**  - RW    STAGE0 Configuration Registers
*/
#define AD7147_REG_STG0_CIN0_6_SETUP        0x080U
#define AD7147_REG_STG0_CIN7_12_SETUP       0x081U
#define AD7147_REG_STG0_AFE_OFFSET          0x082U
#define AD7147_REG_STG0_SENSITIVITY         0x083U
#define AD7147_REG_STG0_OFFSET_LOW          0x084U
#define AD7147_REG_STG0_OFFSET_HIGH         0x085U
#define AD7147_REG_STG0_OFFSET_HIGH_CLAMP   0x086U
#define AD7147_REG_STG0_OFFSET_LOW_CLAMP    0x087U
/*
** AD7147_REG_STAGE1_CONFIG
**  - RW    STAGE1 Configuration Registers
*/
#define AD7147_REG_STG1_CIN0_6_SETUP        0x088U
#define AD7147_REG_STG1_CIN7_12_SETUP       0x089U
#define AD7147_REG_STG1_AFE_OFFSET          0x08AU
#define AD7147_REG_STG1_SENSITIVITY         0x08BU
#define AD7147_REG_STG1_OFFSET_LOW          0x08CU
#define AD7147_REG_STG1_OFFSET_HIGH         0x08DU
#define AD7147_REG_STG1_OFFSET_HIGH_CLAMP   0x08EU
#define AD7147_REG_STG1_OFFSET_LOW_CLAMP    0x08FU
/*
** AD7147_REG_STAGE2_CONFIG
**  - RW    STAGE2 Configuration Registers
*/
#define AD7147_REG_STG2_CIN0_6_SETUP        0x090U
#define AD7147_REG_STG2_CIN7_12_SETUP       0x091U
#define AD7147_REG_STG2_AFE_OFFSET          0x092U
#define AD7147_REG_STG2_SENSITIVITY         0x093U
#define AD7147_REG_STG2_OFFSET_LOW          0x094U
#define AD7147_REG_STG2_OFFSET_HIGH         0x095U
#define AD7147_REG_STG2_OFFSET_HIGH_CLAMP   0x096U
#define AD7147_REG_STG2_OFFSET_LOW_CLAMP    0x097U
/*
** AD7147_REG_STAGE3_CONFIG
**  - RW    STAGE3 Configuration Registers
*/
#define AD7147_REG_STG3_CIN0_6_SETUP        0x098U
#define AD7147_REG_STG3_CIN7_12_SETUP       0x099U
#define AD7147_REG_STG3_AFE_OFFSET          0x09AU
#define AD7147_REG_STG3_SENSITIVITY         0x09BU
#define AD7147_REG_STG3_OFFSET_LOW          0x09CU
#define AD7147_REG_STG3_OFFSET_HIGH         0x09DU
#define AD7147_REG_STG3_OFFSET_HIGH_CLAMP   0x09EU
#define AD7147_REG_STG3_OFFSET_LOW_CLAMP    0x09FU
/*
** AD7147_REG_STAGE4_CONFIG
**  - RW    STAGE4 Configuration Registers
*/
#define AD7147_REG_STG4_CIN0_6_SETUP        0x0A0U
#define AD7147_REG_STG4_CIN7_12_SETUP       0x0A1U
#define AD7147_REG_STG4_AFE_OFFSET          0x0A2U
#define AD7147_REG_STG4_SENSITIVITY         0x0A3U
#define AD7147_REG_STG4_OFFSET_LOW          0x0A4U
#define AD7147_REG_STG4_OFFSET_HIGH         0x0A5U
#define AD7147_REG_STG4_OFFSET_HIGH_CLAMP   0x0A6U
#define AD7147_REG_STG4_OFFSET_LOW_CLAMP    0x0A7U
/*
** AD7147_REG_STAGE5_CONFIG
**  - RW    STAGE4 Configuration Registers
*/
#define AD7147_REG_STG5_CIN0_6_SETUP        0x0A8U
#define AD7147_REG_STG5_CIN7_12_SETUP       0x0A9U
#define AD7147_REG_STG5_AFE_OFFSET          0x0AAU
#define AD7147_REG_STG5_SENSITIVITY         0x0ABU
#define AD7147_REG_STG5_OFFSET_LOW          0x0ACU
#define AD7147_REG_STG5_OFFSET_HIGH         0x0ADU
#define AD7147_REG_STG5_OFFSET_HIGH_CLAMP   0x0AEU
#define AD7147_REG_STG5_OFFSET_LOW_CLAMP    0x0AFU
/*
** AD7147_REG_STAGE6_CONFIG
**  - RW    STAGE6 Configuration Registers
*/
#define AD7147_REG_STG6_CIN0_6_SETUP        0x0B0U
#define AD7147_REG_STG6_CIN7_12_SETUP       0x0B1U
#define AD7147_REG_STG6_AFE_OFFSET          0x0B2U
#define AD7147_REG_STG6_SENSITIVITY         0x0B3U
#define AD7147_REG_STG6_OFFSET_LOW          0x0B4U
#define AD7147_REG_STG6_OFFSET_HIGH         0x0B5U
#define AD7147_REG_STG6_OFFSET_HIGH_CLAMP   0x0B6U
#define AD7147_REG_STG6_OFFSET_LOW_CLAMP    0x0B7U
/*
** AD7147_REG_STAGE7_CONFIG
**  - RW    STAGE7 Configuration Registers
*/
#define AD7147_REG_STG7_CIN0_6_SETUP        0x0B8U
#define AD7147_REG_STG7_CIN7_12_SETUP       0x0B9U
#define AD7147_REG_STG7_AFE_OFFSET          0x0BAU
#define AD7147_REG_STG7_SENSITIVITY         0x0BBU
#define AD7147_REG_STG7_OFFSET_LOW          0x0BCU
#define AD7147_REG_STG7_OFFSET_HIGH         0x0BDU
#define AD7147_REG_STG7_OFFSET_HIGH_CLAMP   0x0BEU
#define AD7147_REG_STG7_OFFSET_LOW_CLAMP    0x0BFU
/*
** AD7147_REG_STAGE8_CONFIG
**  - RW    STAGE8 Configuration Registers
*/
#define AD7147_REG_STG8_CIN0_6_SETUP        0x0C0U
#define AD7147_REG_STG8_CIN7_12_SETUP       0x0C1U
#define AD7147_REG_STG8_AFE_OFFSET          0x0C2U
#define AD7147_REG_STG8_SENSITIVITY         0x0C3U
#define AD7147_REG_STG8_OFFSET_LOW          0x0C4U
#define AD7147_REG_STG8_OFFSET_HIGH         0x0C5U
#define AD7147_REG_STG8_OFFSET_HIGH_CLAMP   0x0C6U
#define AD7147_REG_STG8_OFFSET_LOW_CLAMP    0x0C7U
/*
** AD7147_REG_STAGE9_CONFIG
**  - RW    STAGE9 Configuration Registers
*/
#define AD7147_REG_STG9_CIN0_6_SETUP        0x0C8U
#define AD7147_REG_STG9_CIN7_12_SETUP       0x0C9U
#define AD7147_REG_STG9_AFE_OFFSET          0x0CAU
#define AD7147_REG_STG9_SENSITIVITY         0x0CBU
#define AD7147_REG_STG9_OFFSET_LOW          0x0CCU
#define AD7147_REG_STG9_OFFSET_HIGH         0x0CDU
#define AD7147_REG_STG9_OFFSET_HIGH_CLAMP   0x0CEU
#define AD7147_REG_STG9_OFFSET_LOW_CLAMP    0x0CFU
/*
** AD7147_REG_STAGE10_CONFIG
**  - RW    STAGE10 Configuration Registers
*/
#define AD7147_REG_STG10_CIN0_6_SETUP       0x0D0U
#define AD7147_REG_STG10_CIN7_12_SETUP      0x0D1U
#define AD7147_REG_STG10_AFE_OFFSET         0x0D2U
#define AD7147_REG_STG10_SENSITIVITY        0x0D3U
#define AD7147_REG_STG10_OFFSET_LOW         0x0D4U
#define AD7147_REG_STG10_OFFSET_HIGH        0x0D5U
#define AD7147_REG_STG10_OFFSET_HIGH_CLAMP  0x0D6U
#define AD7147_REG_STG10_OFFSET_LOW_CLAMP   0x0D7U
/*
** AD7147_REG_STAGE11_CONFIG
**  - RW    STAGE11 Configuration Registers
*/
#define AD7147_REG_STG11_CIN0_6_SETUP       0x0D8U
#define AD7147_REG_STG11_CIN7_12_SETUP      0x0D9U
#define AD7147_REG_STG11_AFE_OFFSET         0x0DAU
#define AD7147_REG_STG11_SENSITIVITY        0x0DBU
#define AD7147_REG_STG11_OFFSET_LOW         0x0DCU
#define AD7147_REG_STG11_OFFSET_HIGH        0x0DDU
#define AD7147_REG_STG11_OFFSET_HIGH_CLAMP  0x0DEU
#define AD7147_REG_STG11_OFFSET_LOW_CLAMP   0x0DFU

/*
**
** AD7147 Register field definitions for following registers
**  AD7147_REG_STG0_CIN0_6_SETUP
**  AD7147_REG_STG0_CIN7_12_SETUP
**  AD7147_REG_STG0_AFE_OFFSET
**  AD7147_REG_STG0_SENSITIVITY
*/

/*
** AD7147_REG_STG0_CIN0_6_SETUP
**  - STAGE0 CIN0 to CIN6 Connection setup
*/
#define     AD7147_RFLD_STG0_CIN6_CONN_SETUP    12U
#define     AD7147_RFLD_STG0_CIN5_CONN_SETUP    10U
#define     AD7147_RFLD_STG0_CIN4_CONN_SETUP    8U
#define     AD7147_RFLD_STG0_CIN3_CONN_SETUP    6U
#define     AD7147_RFLD_STG0_CIN2_CONN_SETUP    4U
#define     AD7147_RFLD_STG0_CIN1_CONN_SETUP    2U
#define     AD7147_RFLD_STG0_CIN0_CONN_SETUP    0U
/*
** AD7147_REG_STG0_CIN7_12_SETUP
**  - STAGE0 CIN7 to CIN12 Connection setup
*/
#define     AD7147_RFLD_STG0_POS_AFE_OFFSET_DIS 15U
#define     AD7147_RFLD_STG0_NEG_AFE_OFFSET_DIS 14U
#define     AD7147_RFLD_STG0_SE_CONN_SETUP      12U
#define     AD7147_RFLD_STG0_CIN12_CONN_SETUP   10U
#define     AD7147_RFLD_STG0_CIN11_CONN_SETUP   8U
#define     AD7147_RFLD_STG0_CIN10_CONN_SETUP   6U
#define     AD7147_RFLD_STG0_CIN9_CONN_SETUP    4U
#define     AD7147_RFLD_STG0_CIN8_CONN_SETUP    2U
#define     AD7147_RFLD_STG0_CIN7_CONN_SETUP    0U
/*
** AD7147_REG_STG0_AFE_OFFSET
**  - STAGE0 AFE offset
*/
#define     AD7147_RFLD_STG0_POS_AFE_OFFSET_SWAP    15U
#define     AD7147_RFLD_STG0_POS_AFE_OFFSET         8U
#define     AD7147_RFLD_STG0_NEG_AFE_OFFSET_SWAP    7U
#define     AD7147_RFLD_STG0_NEG_AFE_OFFSET         0U
/*
** AD7147_REG_STG0_SENSITIVITY
**  - STAGE0 Sensitivity
*/
#define     AD7147_RFLD_STG0_POS_PEAK_DETECT        12U
#define     AD7147_RFLD_STG0_POS_THOLD_SEN          8U
#define     AD7147_RFLD_STG0_NEG_PEAK_DETECT        4U
#define     AD7147_RFLD_STG0_NEG_THOLD_SEN          0U

/*
**
** AD7147 Register field definitions for following registers
**  AD7147_REG_STG1_CIN0_6_SETUP
**  AD7147_REG_STG1_CIN7_12_SETUP
**  AD7147_REG_STG1_AFE_OFFSET
**  AD7147_REG_STG1_SENSITIVITY
*/

/*
** AD7147_REG_STG1_CIN0_6_SETUP
**  - STAGE1 CIN0 to CIN6 Connection setup
*/
#define     AD7147_RFLD_STG1_CIN6_CONN_SETUP    12U
#define     AD7147_RFLD_STG1_CIN5_CONN_SETUP    10U
#define     AD7147_RFLD_STG1_CIN4_CONN_SETUP    8U
#define     AD7147_RFLD_STG1_CIN3_CONN_SETUP    6U
#define     AD7147_RFLD_STG1_CIN2_CONN_SETUP    4U
#define     AD7147_RFLD_STG1_CIN1_CONN_SETUP    2U
#define     AD7147_RFLD_STG1_CIN0_CONN_SETUP    0U
/*
** AD7147_REG_STG1_CIN7_12_SETUP
**  - STAGE1 CIN7 to CIN12 Connection setup
*/
#define     AD7147_RFLD_STG1_POS_AFE_OFFSET_DIS 15U
#define     AD7147_RFLD_STG1_NEG_AFE_OFFSET_DIS 14U
#define     AD7147_RFLD_STG1_SE_CONN_SETUP      12U
#define     AD7147_RFLD_STG1_CIN12_CONN_SETUP   10U
#define     AD7147_RFLD_STG1_CIN11_CONN_SETUP   8U
#define     AD7147_RFLD_STG1_CIN10_CONN_SETUP   6U
#define     AD7147_RFLD_STG1_CIN9_CONN_SETUP    4U
#define     AD7147_RFLD_STG1_CIN8_CONN_SETUP    2U
#define     AD7147_RFLD_STG1_CIN7_CONN_SETUP    0U
/*
** AD7147_REG_STG1_AFE_OFFSET
**  - STAGE1 AFE offset
*/
#define     AD7147_RFLD_STG1_POS_AFE_OFFSET_SWAP    15U
#define     AD7147_RFLD_STG1_POS_AFE_OFFSET         8U
#define     AD7147_RFLD_STG1_NEG_AFE_OFFSET_SWAP    7U
#define     AD7147_RFLD_STG1_NEG_AFE_OFFSET         0U
/*
** AD7147_REG_STG1_SENSITIVITY
**  - STAGE1 Sensitivity
*/
#define     AD7147_RFLD_STG1_POS_PEAK_DETECT        12U
#define     AD7147_RFLD_STG1_POS_THOLD_SEN          8U
#define     AD7147_RFLD_STG1_NEG_PEAK_DETECT        4U
#define     AD7147_RFLD_STG1_NEG_THOLD_SEN          0U
/*
**
** AD7147 Register field definitions for following registers
**  AD7147_REG_STG2_CIN0_6_SETUP
**  AD7147_REG_STG2_CIN7_12_SETUP
**  AD7147_REG_STG2_AFE_OFFSET
**  AD7147_REG_STG2_SENSITIVITY
*/

/*
** AD7147_REG_STG2_CIN0_6_SETUP
**  - STAGE2 CIN0 to CIN6 Connection setup
*/
#define     AD7147_RFLD_STG2_CIN6_CONN_SETUP    12U
#define     AD7147_RFLD_STG2_CIN5_CONN_SETUP    10U
#define     AD7147_RFLD_STG2_CIN4_CONN_SETUP    8U
#define     AD7147_RFLD_STG2_CIN3_CONN_SETUP    6U
#define     AD7147_RFLD_STG2_CIN2_CONN_SETUP    4U
#define     AD7147_RFLD_STG2_CIN1_CONN_SETUP    2U
#define     AD7147_RFLD_STG2_CIN0_CONN_SETUP    0U
/*
** AD7147_REG_STG2_CIN7_12_SETUP
**  - STAGE2 CIN7 to CIN12 Connection setup
*/
#define     AD7147_RFLD_STG2_POS_AFE_OFFSET_DIS 15U
#define     AD7147_RFLD_STG2_NEG_AFE_OFFSET_DIS 14U
#define     AD7147_RFLD_STG2_SE_CONN_SETUP      12U
#define     AD7147_RFLD_STG2_CIN12_CONN_SETUP   10U
#define     AD7147_RFLD_STG2_CIN11_CONN_SETUP   8U
#define     AD7147_RFLD_STG2_CIN10_CONN_SETUP   6U
#define     AD7147_RFLD_STG2_CIN9_CONN_SETUP    4U
#define     AD7147_RFLD_STG2_CIN8_CONN_SETUP    2U
#define     AD7147_RFLD_STG2_CIN7_CONN_SETUP    0U
/*
** AD7147_REG_STG2_AFE_OFFSET
**  - STAGE2 AFE offset
*/
#define     AD7147_RFLD_STG2_POS_AFE_OFFSET_SWAP    15U
#define     AD7147_RFLD_STG2_POS_AFE_OFFSET         8U
#define     AD7147_RFLD_STG2_NEG_AFE_OFFSET_SWAP    7U
#define     AD7147_RFLD_STG2_NEG_AFE_OFFSET         0U
/*
** AD7147_REG_STG2_SENSITIVITY
**  - STAGE2 Sensitivity
*/
#define     AD7147_RFLD_STG2_POS_PEAK_DETECT        12U
#define     AD7147_RFLD_STG2_POS_THOLD_SEN          8U
#define     AD7147_RFLD_STG2_NEG_PEAK_DETECT        4U
#define     AD7147_RFLD_STG2_NEG_THOLD_SEN          0U

/*
**
** AD7147 Register field definitions for following registers
**  AD7147_REG_STG3_CIN0_6_SETUP
**  AD7147_REG_STG3_CIN7_12_SETUP
**  AD7147_REG_STG3_AFE_OFFSET
**  AD7147_REG_STG3_SENSITIVITY
*/

/*
** AD7147_REG_STG3_CIN0_6_SETUP
**  - STAGE3 CIN0 to CIN6 Connection setup
*/
#define     AD7147_RFLD_STG3_CIN6_CONN_SETUP    12U
#define     AD7147_RFLD_STG3_CIN5_CONN_SETUP    10U
#define     AD7147_RFLD_STG3_CIN4_CONN_SETUP    8U
#define     AD7147_RFLD_STG3_CIN3_CONN_SETUP    6U
#define     AD7147_RFLD_STG3_CIN2_CONN_SETUP    4U
#define     AD7147_RFLD_STG3_CIN1_CONN_SETUP    2U
#define     AD7147_RFLD_STG3_CIN0_CONN_SETUP    0U
/*
** AD7147_REG_STG3_CIN7_12_SETUP
**  - STAGE3 CIN7 to CIN12 Connection setup
*/
#define     AD7147_RFLD_STG3_POS_AFE_OFFSET_DIS 15U
#define     AD7147_RFLD_STG3_NEG_AFE_OFFSET_DIS 14U
#define     AD7147_RFLD_STG3_SE_CONN_SETUP      12U
#define     AD7147_RFLD_STG3_CIN12_CONN_SETUP   10U
#define     AD7147_RFLD_STG3_CIN11_CONN_SETUP   8U
#define     AD7147_RFLD_STG3_CIN10_CONN_SETUP   6U
#define     AD7147_RFLD_STG3_CIN9_CONN_SETUP    4U
#define     AD7147_RFLD_STG3_CIN8_CONN_SETUP    2U
#define     AD7147_RFLD_STG3_CIN7_CONN_SETUP    0U
/*
** AD7147_REG_STG3_AFE_OFFSET
**  - STAGE3 AFE offset
*/
#define     AD7147_RFLD_STG3_POS_AFE_OFFSET_SWAP    15U
#define     AD7147_RFLD_STG3_POS_AFE_OFFSET         8U
#define     AD7147_RFLD_STG3_NEG_AFE_OFFSET_SWAP    7U
#define     AD7147_RFLD_STG3_NEG_AFE_OFFSET         0U
/*
** AD7147_REG_STG3_SENSITIVITY
**  - STAGE3 Sensitivity
*/
#define     AD7147_RFLD_STG3_POS_PEAK_DETECT        12U
#define     AD7147_RFLD_STG3_POS_THOLD_SEN          8U
#define     AD7147_RFLD_STG3_NEG_PEAK_DETECT        4U
#define     AD7147_RFLD_STG3_NEG_THOLD_SEN          0U
/*
**
** AD7147 Register field definitions for following registers
**  AD7147_REG_STG4_CIN0_6_SETUP
**  AD7147_REG_STG4_CIN7_12_SETUP
**  AD7147_REG_STG4_AFE_OFFSET
**  AD7147_REG_STG4_SENSITIVITY
*/

/*
** AD7147_REG_STG4_CIN0_6_SETUP
**  - STAGE4 CIN0 to CIN6 Connection setup
*/
#define     AD7147_RFLD_STG4_CIN6_CONN_SETUP    12U
#define     AD7147_RFLD_STG4_CIN5_CONN_SETUP    10U
#define     AD7147_RFLD_STG4_CIN4_CONN_SETUP    8U
#define     AD7147_RFLD_STG4_CIN3_CONN_SETUP    6U
#define     AD7147_RFLD_STG4_CIN2_CONN_SETUP    4U
#define     AD7147_RFLD_STG4_CIN1_CONN_SETUP    2U
#define     AD7147_RFLD_STG4_CIN0_CONN_SETUP    0U
/*
** AD7147_REG_STG4_CIN7_12_SETUP
**  - STAGE4 CIN7 to CIN12 Connection setup
*/
#define     AD7147_RFLD_STG4_POS_AFE_OFFSET_DIS 15U
#define     AD7147_RFLD_STG4_NEG_AFE_OFFSET_DIS 14U
#define     AD7147_RFLD_STG4_SE_CONN_SETUP      12U
#define     AD7147_RFLD_STG4_CIN12_CONN_SETUP   10U
#define     AD7147_RFLD_STG4_CIN11_CONN_SETUP   8U
#define     AD7147_RFLD_STG4_CIN10_CONN_SETUP   6U
#define     AD7147_RFLD_STG4_CIN9_CONN_SETUP    4U
#define     AD7147_RFLD_STG4_CIN8_CONN_SETUP    2U
#define     AD7147_RFLD_STG4_CIN7_CONN_SETUP    0U
/*
** AD7147_REG_STG4_AFE_OFFSET
**  - STAGE4 AFE offset
*/
#define     AD7147_RFLD_STG4_POS_AFE_OFFSET_SWAP    15U
#define     AD7147_RFLD_STG4_POS_AFE_OFFSET         8U
#define     AD7147_RFLD_STG4_NEG_AFE_OFFSET_SWAP    7U
#define     AD7147_RFLD_STG4_NEG_AFE_OFFSET         0U
/*
** AD7147_REG_STG4_SENSITIVITY
**  - STAGE4 Sensitivity
*/
#define     AD7147_RFLD_STG4_POS_PEAK_DETECT        12U
#define     AD7147_RFLD_STG4_POS_THOLD_SEN          8U
#define     AD7147_RFLD_STG4_NEG_PEAK_DETECT        4U
#define     AD7147_RFLD_STG4_NEG_THOLD_SEN          0U
/*
**
** AD7147 Register field definitions for following registers
**  AD7147_REG_STG5_CIN0_6_SETUP
**  AD7147_REG_STG5_CIN7_12_SETUP
**  AD7147_REG_STG5_AFE_OFFSET
**  AD7147_REG_STG5_SENSITIVITY
*/

/*
** AD7147_REG_STG5_CIN0_6_SETUP
**  - STAGE5 CIN0 to CIN6 Connection setup
*/
#define     AD7147_RFLD_STG5_CIN6_CONN_SETUP    12U
#define     AD7147_RFLD_STG5_CIN5_CONN_SETUP    10U
#define     AD7147_RFLD_STG5_CIN4_CONN_SETUP    8U
#define     AD7147_RFLD_STG5_CIN3_CONN_SETUP    6U
#define     AD7147_RFLD_STG5_CIN2_CONN_SETUP    4U
#define     AD7147_RFLD_STG5_CIN1_CONN_SETUP    2U
#define     AD7147_RFLD_STG5_CIN0_CONN_SETUP    0U
/*
** AD7147_REG_STG5_CIN7_12_SETUP
**  - STAGE5 CIN7 to CIN12 Connection setup
*/
#define     AD7147_RFLD_STG5_POS_AFE_OFFSET_DIS 15U
#define     AD7147_RFLD_STG5_NEG_AFE_OFFSET_DIS 14U
#define     AD7147_RFLD_STG5_SE_CONN_SETUP      12U
#define     AD7147_RFLD_STG5_CIN12_CONN_SETUP   10U
#define     AD7147_RFLD_STG5_CIN11_CONN_SETUP   8U
#define     AD7147_RFLD_STG5_CIN10_CONN_SETUP   6U
#define     AD7147_RFLD_STG5_CIN9_CONN_SETUP    4U
#define     AD7147_RFLD_STG5_CIN8_CONN_SETUP    2U
#define     AD7147_RFLD_STG5_CIN7_CONN_SETUP    0U
/*
** AD7147_REG_STG5_AFE_OFFSET
**  - STAGE5 AFE offset
*/
#define     AD7147_RFLD_STG5_POS_AFE_OFFSET_SWAP    15U
#define     AD7147_RFLD_STG5_POS_AFE_OFFSET         8U
#define     AD7147_RFLD_STG5_NEG_AFE_OFFSET_SWAP    7U
#define     AD7147_RFLD_STG5_NEG_AFE_OFFSET         0U
/*
** AD7147_REG_STG5_SENSITIVITY
**  - STAGE5 Sensitivity
*/
#define     AD7147_RFLD_STG5_POS_PEAK_DETECT        12U
#define     AD7147_RFLD_STG5_POS_THOLD_SEN          8U
#define     AD7147_RFLD_STG5_NEG_PEAK_DETECT        4U
#define     AD7147_RFLD_STG5_NEG_THOLD_SEN          0U
/*
**
** AD7147 Register field definitions for following registers
**  AD7147_REG_STG6_CIN0_6_SETUP
**  AD7147_REG_STG6_CIN7_12_SETUP
**  AD7147_REG_STG6_AFE_OFFSET
**  AD7147_REG_STG6_SENSITIVITY
*/

/*
** AD7147_REG_STG6_CIN0_6_SETUP
**  - STAGE6 CIN0 to CIN6 Connection setup
*/
#define     AD7147_RFLD_STG6_CIN6_CONN_SETUP    12U
#define     AD7147_RFLD_STG6_CIN5_CONN_SETUP    10U
#define     AD7147_RFLD_STG6_CIN4_CONN_SETUP    8U
#define     AD7147_RFLD_STG6_CIN3_CONN_SETUP    6U
#define     AD7147_RFLD_STG6_CIN2_CONN_SETUP    4U
#define     AD7147_RFLD_STG6_CIN1_CONN_SETUP    2U
#define     AD7147_RFLD_STG6_CIN0_CONN_SETUP    0U
/*
** AD7147_REG_STG6_CIN7_12_SETUP
**  - STAGE6 CIN7 to CIN12 Connection setup
*/
#define     AD7147_RFLD_STG6_POS_AFE_OFFSET_DIS 15U
#define     AD7147_RFLD_STG6_NEG_AFE_OFFSET_DIS 14U
#define     AD7147_RFLD_STG6_SE_CONN_SETUP      12U
#define     AD7147_RFLD_STG6_CIN12_CONN_SETUP   10U
#define     AD7147_RFLD_STG6_CIN11_CONN_SETUP   8U
#define     AD7147_RFLD_STG6_CIN10_CONN_SETUP   6U
#define     AD7147_RFLD_STG6_CIN9_CONN_SETUP    4U
#define     AD7147_RFLD_STG6_CIN8_CONN_SETUP    2U
#define     AD7147_RFLD_STG6_CIN7_CONN_SETUP    0U
/*
** AD7147_REG_STG6_AFE_OFFSET
**  - STAGE6 AFE offset
*/
#define     AD7147_RFLD_STG6_POS_AFE_OFFSET_SWAP    15U
#define     AD7147_RFLD_STG6_POS_AFE_OFFSET         8U
#define     AD7147_RFLD_STG6_NEG_AFE_OFFSET_SWAP    7U
#define     AD7147_RFLD_STG6_NEG_AFE_OFFSET         0U
/*
** AD7147_REG_STG6_SENSITIVITY
**  - STAGE6 Sensitivity
*/
#define     AD7147_RFLD_STG6_POS_PEAK_DETECT        12U
#define     AD7147_RFLD_STG6_POS_THOLD_SEN          8U
#define     AD7147_RFLD_STG6_NEG_PEAK_DETECT        4U
#define     AD7147_RFLD_STG6_NEG_THOLD_SEN          0U
/*
**
** AD7147 Register field definitions for following registers
**  AD7147_REG_STG7_CIN0_6_SETUP
**  AD7147_REG_STG7_CIN7_12_SETUP
**  AD7147_REG_STG7_AFE_OFFSET
**  AD7147_REG_STG7_SENSITIVITY
*/

/*
** AD7147_REG_STG7_CIN0_6_SETUP
**  - STAGE7 CIN0 to CIN6 Connection setup
*/
#define     AD7147_RFLD_STG7_CIN6_CONN_SETUP    12U
#define     AD7147_RFLD_STG7_CIN5_CONN_SETUP    10U
#define     AD7147_RFLD_STG7_CIN4_CONN_SETUP    8U
#define     AD7147_RFLD_STG7_CIN3_CONN_SETUP    6U
#define     AD7147_RFLD_STG7_CIN2_CONN_SETUP    4U
#define     AD7147_RFLD_STG7_CIN1_CONN_SETUP    2U
#define     AD7147_RFLD_STG7_CIN0_CONN_SETUP    0U
/*
** AD7147_REG_STG7_CIN7_12_SETUP
**  - STAGE7 CIN7 to CIN12 Connection setup
*/
#define     AD7147_RFLD_STG7_POS_AFE_OFFSET_DIS 15U
#define     AD7147_RFLD_STG7_NEG_AFE_OFFSET_DIS 14U
#define     AD7147_RFLD_STG7_SE_CONN_SETUP      12U
#define     AD7147_RFLD_STG7_CIN12_CONN_SETUP   10U
#define     AD7147_RFLD_STG7_CIN11_CONN_SETUP   8U
#define     AD7147_RFLD_STG7_CIN10_CONN_SETUP   6U
#define     AD7147_RFLD_STG7_CIN9_CONN_SETUP    4U
#define     AD7147_RFLD_STG7_CIN8_CONN_SETUP    2U
#define     AD7147_RFLD_STG7_CIN7_CONN_SETUP    0U
/*
** AD7147_REG_STG7_AFE_OFFSET
**  - STAGE7 AFE offset
*/
#define     AD7147_RFLD_STG7_POS_AFE_OFFSET_SWAP    15U
#define     AD7147_RFLD_STG7_POS_AFE_OFFSET         8U
#define     AD7147_RFLD_STG7_NEG_AFE_OFFSET_SWAP    7U
#define     AD7147_RFLD_STG7_NEG_AFE_OFFSET         0U
/*
** AD7147_REG_STG7_SENSITIVITY
**  - STAGE7 Sensitivity
*/
#define     AD7147_RFLD_STG7_POS_PEAK_DETECT        12U
#define     AD7147_RFLD_STG7_POS_THOLD_SEN          8U
#define     AD7147_RFLD_STG7_NEG_PEAK_DETECT        4U
#define     AD7147_RFLD_STG7_NEG_THOLD_SEN          0U
/*
**
** AD7147 Register field definitions for following registers
**  AD7147_REG_STG8_CIN0_6_SETUP
**  AD7147_REG_STG8_CIN7_12_SETUP
**  AD7147_REG_STG8_AFE_OFFSET
**  AD7147_REG_STG8_SENSITIVITY
*/

/*
** AD7147_REG_STG8_CIN0_6_SETUP
**  - STAGE8 CIN0 to CIN6 Connection setup
*/
#define     AD7147_RFLD_STG8_CIN6_CONN_SETUP    12U
#define     AD7147_RFLD_STG8_CIN5_CONN_SETUP    10U
#define     AD7147_RFLD_STG8_CIN4_CONN_SETUP    8U
#define     AD7147_RFLD_STG8_CIN3_CONN_SETUP    6U
#define     AD7147_RFLD_STG8_CIN2_CONN_SETUP    4U
#define     AD7147_RFLD_STG8_CIN1_CONN_SETUP    2U
#define     AD7147_RFLD_STG8_CIN0_CONN_SETUP    0U
/*
** AD7147_REG_STG8_CIN7_12_SETUP
**  - STAGE8 CIN7 to CIN12 Connection setup
*/
#define     AD7147_RFLD_STG8_POS_AFE_OFFSET_DIS 15U
#define     AD7147_RFLD_STG8_NEG_AFE_OFFSET_DIS 14U
#define     AD7147_RFLD_STG8_SE_CONN_SETUP      12U
#define     AD7147_RFLD_STG8_CIN12_CONN_SETUP   10U
#define     AD7147_RFLD_STG8_CIN11_CONN_SETUP   8U
#define     AD7147_RFLD_STG8_CIN10_CONN_SETUP   6U
#define     AD7147_RFLD_STG8_CIN9_CONN_SETUP    4U
#define     AD7147_RFLD_STG8_CIN8_CONN_SETUP    2U
#define     AD7147_RFLD_STG8_CIN7_CONN_SETUP    0U
/*
** AD7147_REG_STG8_AFE_OFFSET
**  - STAGE8 AFE offset
*/
#define     AD7147_RFLD_STG8_POS_AFE_OFFSET_SWAP    15U
#define     AD7147_RFLD_STG8_POS_AFE_OFFSET         8U
#define     AD7147_RFLD_STG8_NEG_AFE_OFFSET_SWAP    7U
#define     AD7147_RFLD_STG8_NEG_AFE_OFFSET         0U
/*
** AD7147_REG_STG8_SENSITIVITY
**  - STAGE8 Sensitivity
*/
#define     AD7147_RFLD_STG8_POS_PEAK_DETECT        12U
#define     AD7147_RFLD_STG8_POS_THOLD_SEN          8U
#define     AD7147_RFLD_STG8_NEG_PEAK_DETECT        4U
#define     AD7147_RFLD_STG8_NEG_THOLD_SEN          0U
/*
**
** AD7147 Register field definitions for following registers
**  AD7147_REG_STG9_CIN0_6_SETUP
**  AD7147_REG_STG9_CIN7_12_SETUP
**  AD7147_REG_STG9_AFE_OFFSET
**  AD7147_REG_STG9_SENSITIVITY
*/

/*
** AD7147_REG_STG9_CIN0_6_SETUP
**  - STAGE9 CIN0 to CIN6 Connection setup
*/
#define     AD7147_RFLD_STG9_CIN6_CONN_SETUP    12U
#define     AD7147_RFLD_STG9_CIN5_CONN_SETUP    10U
#define     AD7147_RFLD_STG9_CIN4_CONN_SETUP    8U
#define     AD7147_RFLD_STG9_CIN3_CONN_SETUP    6U
#define     AD7147_RFLD_STG9_CIN2_CONN_SETUP    4U
#define     AD7147_RFLD_STG9_CIN1_CONN_SETUP    2U
#define     AD7147_RFLD_STG9_CIN0_CONN_SETUP    0U
/*
** AD7147_REG_STG9_CIN7_12_SETUP
**  - STAGE9 CIN7 to CIN12 Connection setup
*/
#define     AD7147_RFLD_STG9_POS_AFE_OFFSET_DIS 15U
#define     AD7147_RFLD_STG9_NEG_AFE_OFFSET_DIS 14U
#define     AD7147_RFLD_STG9_SE_CONN_SETUP      12U
#define     AD7147_RFLD_STG9_CIN12_CONN_SETUP   10U
#define     AD7147_RFLD_STG9_CIN11_CONN_SETUP   8U
#define     AD7147_RFLD_STG9_CIN10_CONN_SETUP   6U
#define     AD7147_RFLD_STG9_CIN9_CONN_SETUP    4U
#define     AD7147_RFLD_STG9_CIN8_CONN_SETUP    2U
#define     AD7147_RFLD_STG9_CIN7_CONN_SETUP    0U
/*
** AD7147_REG_STG9_AFE_OFFSET
**  - STAGE9 AFE offset
*/
#define     AD7147_RFLD_STG9_POS_AFE_OFFSET_SWAP    15U
#define     AD7147_RFLD_STG9_POS_AFE_OFFSET         8U
#define     AD7147_RFLD_STG9_NEG_AFE_OFFSET_SWAP    7U
#define     AD7147_RFLD_STG9_NEG_AFE_OFFSET         0U
/*
** AD7147_REG_STG9_SENSITIVITY
**  - STAGE9 Sensitivity
*/
#define     AD7147_RFLD_STG9_POS_PEAK_DETECT        12U
#define     AD7147_RFLD_STG9_POS_THOLD_SEN          8U
#define     AD7147_RFLD_STG9_NEG_PEAK_DETECT        4U
#define     AD7147_RFLD_STG9_NEG_THOLD_SEN          0U
/*
**
** AD7147 Register field definitions for following registers
**  AD7147_REG_STG10_CIN0_6_SETUP
**  AD7147_REG_STG10_CIN7_12_SETUP
**  AD7147_REG_STG10_AFE_OFFSET
**  AD7147_REG_STG10_SENSITIVITY
*/

/*
** AD7147_REG_STG10_CIN0_6_SETUP
**  - STAGE10 CIN0 to CIN6 Connection setup
*/
#define     AD7147_RFLD_STG10_CIN6_CONN_SETUP       12U
#define     AD7147_RFLD_STG10_CIN5_CONN_SETUP       10U
#define     AD7147_RFLD_STG10_CIN4_CONN_SETUP       8U
#define     AD7147_RFLD_STG10_CIN3_CONN_SETUP       6U
#define     AD7147_RFLD_STG10_CIN2_CONN_SETUP       4U
#define     AD7147_RFLD_STG10_CIN1_CONN_SETUP       2U
#define     AD7147_RFLD_STG10_CIN0_CONN_SETUP       0U
/*
** AD7147_REG_STG10_CIN7_12_SETUP
**  - STAGE10 CIN7 to CIN12 Connection setup
*/
#define     AD7147_RFLD_STG10_POS_AFE_OFFSET_DIS    15U
#define     AD7147_RFLD_STG10_NEG_AFE_OFFSET_DIS    14U
#define     AD7147_RFLD_STG10_SE_CONN_SETUP     12U
#define     AD7147_RFLD_STG10_CIN12_CONN_SETUP   10U
#define     AD7147_RFLD_STG10_CIN11_CONN_SETUP   8U
#define     AD7147_RFLD_STG10_CIN10_CONN_SETUP   6U
#define     AD7147_RFLD_STG10_CIN9_CONN_SETUP       4U
#define     AD7147_RFLD_STG10_CIN8_CONN_SETUP       2U
#define     AD7147_RFLD_STG10_CIN7_CONN_SETUP       0U
/*
** AD7147_REG_STG10_AFE_OFFSET
**  - STAGE10 AFE offset
*/
#define     AD7147_RFLD_STG10_POS_AFE_OFFSET_SWAP   15U
#define     AD7147_RFLD_STG10_POS_AFE_OFFSET            8U
#define     AD7147_RFLD_STG10_NEG_AFE_OFFSET_SWAP   7U
#define     AD7147_RFLD_STG10_NEG_AFE_OFFSET            0U
/*
** AD7147_REG_STG10_SENSITIVITY
**  - STAGE10 Sensitivity
*/
#define     AD7147_RFLD_STG10_POS_PEAK_DETECT       12U
#define     AD7147_RFLD_STG10_POS_THOLD_SEN         8U
#define     AD7147_RFLD_STG10_NEG_PEAK_DETECT       4U
#define     AD7147_RFLD_STG10_NEG_THOLD_SEN         0U
/*
**
** AD7147 Register field definitions for following registers
**  AD7147_REG_STG11_CIN0_6_SETUP
**  AD7147_REG_STG11_CIN7_12_SETUP
**  AD7147_REG_STG11_AFE_OFFSET
**  AD7147_REG_STG11_SENSITIVITY
*/

/*
** AD7147_REG_STG11_CIN0_6_SETUP
**  - STAGE11 CIN0 to CIN6 Connection setup
*/
#define     AD7147_RFLD_STG11_CIN6_CONN_SETUP       12U
#define     AD7147_RFLD_STG11_CIN5_CONN_SETUP       10U
#define     AD7147_RFLD_STG11_CIN4_CONN_SETUP       8U
#define     AD7147_RFLD_STG11_CIN3_CONN_SETUP       6U
#define     AD7147_RFLD_STG11_CIN2_CONN_SETUP       4U
#define     AD7147_RFLD_STG11_CIN1_CONN_SETUP       2U
#define     AD7147_RFLD_STG11_CIN0_CONN_SETUP       0U
/*
** AD7147_REG_STG11_CIN7_12_SETUP
**  - STAGE11 CIN7 to CIN12 Connection setup
*/
#define     AD7147_RFLD_STG11_POS_AFE_OFFSET_DIS    15U
#define     AD7147_RFLD_STG11_NEG_AFE_OFFSET_DIS    14U
#define     AD7147_RFLD_STG11_SE_CONN_SETUP     12U
#define     AD7147_RFLD_STG11_CIN12_CONN_SETUP   10U
#define     AD7147_RFLD_STG11_CIN11_CONN_SETUP   8U
#define     AD7147_RFLD_STG11_CIN10_CONN_SETUP   6U
#define     AD7147_RFLD_STG11_CIN9_CONN_SETUP       4U
#define     AD7147_RFLD_STG11_CIN8_CONN_SETUP       2U
#define     AD7147_RFLD_STG11_CIN7_CONN_SETUP       0U
/*
** AD7147_REG_STG11_AFE_OFFSET
**  - STAGE11 AFE offset
*/
#define     AD7147_RFLD_STG11_POS_AFE_OFFSET_SWAP   15U
#define     AD7147_RFLD_STG11_POS_AFE_OFFSET            8U
#define     AD7147_RFLD_STG11_NEG_AFE_OFFSET_SWAP   7U
#define     AD7147_RFLD_STG11_NEG_AFE_OFFSET            0U
/*
** AD7147_REG_STG11_SENSITIVITY
**  - STAGE11 Sensitivity
*/
#define     AD7147_RFLD_STG11_POS_PEAK_DETECT       12U
#define     AD7147_RFLD_STG11_POS_THOLD_SEN         8U
#define     AD7147_RFLD_STG11_NEG_PEAK_DETECT       4U
#define     AD7147_RFLD_STG11_NEG_THOLD_SEN         0U


/*
** REGISTER BANK 3
**  - Read/Write Type Registers
*/

/*
** AD7147_REG_STAGE0_RESULT
**  - RW    STAGE0 Results Register
*/
#define AD7147_REG_STG0_CONV_DATA           0x0E0U
#define AD7147_REG_STG0_FF_WORD0            0x0E1U
#define AD7147_REG_STG0_FF_WORD1            0x0E2U
#define AD7147_REG_STG0_FF_WORD2            0x0E3U
#define AD7147_REG_STG0_FF_WORD3            0x0E4U
#define AD7147_REG_STG0_FF_WORD4            0x0E5U
#define AD7147_REG_STG0_FF_WORD5            0x0E6U
#define AD7147_REG_STG0_FF_WORD6            0x0E7U
#define AD7147_REG_STG0_FF_WORD7            0x0E8U
#define AD7147_REG_STG0_SF_WORD0            0x0E9U
#define AD7147_REG_STG0_SF_WORD1            0x0EAU
#define AD7147_REG_STG0_SF_WORD2            0x0EBU
#define AD7147_REG_STG0_SF_WORD3            0x0ECU
#define AD7147_REG_STG0_SF_WORD4            0x0EDU
#define AD7147_REG_STG0_SF_WORD5            0x0EEU
#define AD7147_REG_STG0_SF_WORD6            0x0EFU
#define AD7147_REG_STG0_SF_WORD7            0x0F0U
#define AD7147_REG_STG0_SF_AMBIENT          0x0F1U
#define AD7147_REG_STG0_SF_AVG              0x0F2U
#define AD7147_REG_STG0_PEAK_DET_WORD0      0x0F3U
#define AD7147_REG_STG0_PEAK_DET_WORD1      0x0F4U
#define AD7147_REG_STG0_MAX_WORD0           0x0F5U
#define AD7147_REG_STG0_MAX_WORD1           0x0F6U
#define AD7147_REG_STG0_MAX_WORD2           0x0F7U
#define AD7147_REG_STG0_MAX_WORD3           0x0F8U
#define AD7147_REG_STG0_MAX_AVG             0x0F9U
#define AD7147_REG_STG0_HIGH_THRESHOLD      0x0FAU
#define AD7147_REG_STG0_MAX_TEMP            0x0FBU
#define AD7147_REG_STG0_MIN_WORD0           0x0FCU
#define AD7147_REG_STG0_MIN_WORD1           0x0FDU
#define AD7147_REG_STG0_MIN_WORD2           0x0FEU
#define AD7147_REG_STG0_MIN_WORD3           0x0FFU
#define AD7147_REG_STG0_MIN_AVG             0x0100U
#define AD7147_REG_STG0_LOW_THRESHOLD       0x0101U
#define AD7147_REG_STG0_MIN_TEMP            0x0102U
/*
** AD7147_REG_STAGE1_RESULT
**  - RW    STAGE1 Results Register
*/
#define AD7147_REG_STG1_CONV_DATA           0x0104U
#define AD7147_REG_STG1_FF_WORD0            0x0105U
#define AD7147_REG_STG1_FF_WORD1            0x0106U
#define AD7147_REG_STG1_FF_WORD2            0x0107U
#define AD7147_REG_STG1_FF_WORD3            0x0108U
#define AD7147_REG_STG1_FF_WORD4            0x0109U
#define AD7147_REG_STG1_FF_WORD5            0x010AU
#define AD7147_REG_STG1_FF_WORD6            0x010BU
#define AD7147_REG_STG1_FF_WORD7            0x010CU
#define AD7147_REG_STG1_SF_WORD0            0x010DU
#define AD7147_REG_STG1_SF_WORD1            0x010EU
#define AD7147_REG_STG1_SF_WORD2            0x010FU
#define AD7147_REG_STG1_SF_WORD3            0x0110U
#define AD7147_REG_STG1_SF_WORD4            0x0111U
#define AD7147_REG_STG1_SF_WORD5            0x0112U
#define AD7147_REG_STG1_SF_WORD6            0x0113U
#define AD7147_REG_STG1_SF_WORD7            0x0114U
#define AD7147_REG_STG1_SF_AMBIENT          0x0115U
#define AD7147_REG_STG1_SF_AVG              0x0116U
#define AD7147_REG_STG1_PEAK_DET_WORD0      0x0117U
#define AD7147_REG_STG1_PEAK_DET_WORD1      0x0118U
#define AD7147_REG_STG1_MAX_WORD0           0x0119U
#define AD7147_REG_STG1_MAX_WORD1           0x011AU
#define AD7147_REG_STG1_MAX_WORD2           0x011BU
#define AD7147_REG_STG1_MAX_WORD3           0x011CU
#define AD7147_REG_STG1_MAX_AVG             0x011DU
#define AD7147_REG_STG1_HIGH_THRESHOLD      0x011EU
#define AD7147_REG_STG1_MAX_TEMP            0x011FU
#define AD7147_REG_STG1_MIN_WORD0           0x0120U
#define AD7147_REG_STG1_MIN_WORD1           0x0121U
#define AD7147_REG_STG1_MIN_WORD2           0x0122U
#define AD7147_REG_STG1_MIN_WORD3           0x0123U
#define AD7147_REG_STG1_MIN_AVG             0x0124U
#define AD7147_REG_STG1_LOW_THRESHOLD       0x0125U
#define AD7147_REG_STG1_MIN_TEMP            0x0126U
/*
** AD7147_REG_STAGE2_RESULT
**  - RW    STAGE2 Results Register
*/
#define AD7147_REG_STG2_CONV_DATA           0x0128U
#define AD7147_REG_STG2_FF_WORD0            0x0129U
#define AD7147_REG_STG2_FF_WORD1            0x012AU
#define AD7147_REG_STG2_FF_WORD2            0x012BU
#define AD7147_REG_STG2_FF_WORD3            0x012CU
#define AD7147_REG_STG2_FF_WORD4            0x012DU
#define AD7147_REG_STG2_FF_WORD5            0x012EU
#define AD7147_REG_STG2_FF_WORD6            0x012FU
#define AD7147_REG_STG2_FF_WORD7            0x0130U
#define AD7147_REG_STG2_SF_WORD0            0x0131U
#define AD7147_REG_STG2_SF_WORD1            0x0132U
#define AD7147_REG_STG2_SF_WORD2            0x0133U
#define AD7147_REG_STG2_SF_WORD3            0x0134U
#define AD7147_REG_STG2_SF_WORD4            0x0135U
#define AD7147_REG_STG2_SF_WORD5            0x0136U
#define AD7147_REG_STG2_SF_WORD6            0x0137U
#define AD7147_REG_STG2_SF_WORD7            0x0138U
#define AD7147_REG_STG2_SF_AMBIENT          0x0139U
#define AD7147_REG_STG2_SF_AVG              0x013AU
#define AD7147_REG_STG2_PEAK_DET_WORD0      0x013BU
#define AD7147_REG_STG2_PEAK_DET_WORD1      0x013CU
#define AD7147_REG_STG2_MAX_WORD0           0x013DU
#define AD7147_REG_STG2_MAX_WORD1           0x013EU
#define AD7147_REG_STG2_MAX_WORD2           0x013FU
#define AD7147_REG_STG2_MAX_WORD3           0x0140U
#define AD7147_REG_STG2_MAX_AVG             0x0141U
#define AD7147_REG_STG2_HIGH_THRESHOLD      0x0142U
#define AD7147_REG_STG2_MAX_TEMP            0x0143U
#define AD7147_REG_STG2_MIN_WORD0           0x0144U
#define AD7147_REG_STG2_MIN_WORD1           0x0145U
#define AD7147_REG_STG2_MIN_WORD2           0x0146U
#define AD7147_REG_STG2_MIN_WORD3           0x0147U
#define AD7147_REG_STG2_MIN_AVG             0x0148U
#define AD7147_REG_STG2_LOW_THRESHOLD       0x0149U
#define AD7147_REG_STG2_MIN_TEMP            0x014AU
/*
** AD7147_REG_STAGE3_RESULT
**  - RW    STAGE3 Results Register
*/
#define AD7147_REG_STG3_CONV_DATA           0x014CU
#define AD7147_REG_STG3_FF_WORD0            0x014DU
#define AD7147_REG_STG3_FF_WORD1            0x014EU
#define AD7147_REG_STG3_FF_WORD2            0x014FU
#define AD7147_REG_STG3_FF_WORD3            0x0150U
#define AD7147_REG_STG3_FF_WORD4            0x0151U
#define AD7147_REG_STG3_FF_WORD5            0x0152U
#define AD7147_REG_STG3_FF_WORD6            0x0153U
#define AD7147_REG_STG3_FF_WORD7            0x0154U
#define AD7147_REG_STG3_SF_WORD0            0x0155U
#define AD7147_REG_STG3_SF_WORD1            0x0156U
#define AD7147_REG_STG3_SF_WORD2            0x0157U
#define AD7147_REG_STG3_SF_WORD3            0x0158U
#define AD7147_REG_STG3_SF_WORD4            0x0159U
#define AD7147_REG_STG3_SF_WORD5            0x015AU
#define AD7147_REG_STG3_SF_WORD6            0x015BU
#define AD7147_REG_STG3_SF_WORD7            0x015CU
#define AD7147_REG_STG3_SF_AMBIENT          0x015DU
#define AD7147_REG_STG3_SF_AVG              0x015EU
#define AD7147_REG_STG3_PEAK_DET_WORD0      0x015FU
#define AD7147_REG_STG3_PEAK_DET_WORD1      0x0160U
#define AD7147_REG_STG3_MAX_WORD0           0x0161U
#define AD7147_REG_STG3_MAX_WORD1           0x0162U
#define AD7147_REG_STG3_MAX_WORD2           0x0163U
#define AD7147_REG_STG3_MAX_WORD3           0x0164U
#define AD7147_REG_STG3_MAX_AVG             0x0165U
#define AD7147_REG_STG3_HIGH_THRESHOLD      0x0166U
#define AD7147_REG_STG3_MAX_TEMP            0x0167U
#define AD7147_REG_STG3_MIN_WORD0           0x0168U
#define AD7147_REG_STG3_MIN_WORD1           0x0169U
#define AD7147_REG_STG3_MIN_WORD2           0x016AU
#define AD7147_REG_STG3_MIN_WORD3           0x016BU
#define AD7147_REG_STG3_MIN_AVG             0x016CU
#define AD7147_REG_STG3_LOW_THRESHOLD       0x016DU
#define AD7147_REG_STG3_MIN_TEMP            0x016EU
/*
** AD7147_REG_STAGE4_RESULT
**  - RW    STAGE4 Results Register
*/
#define AD7147_REG_STG4_CONV_DATA           0x0170U
#define AD7147_REG_STG4_FF_WORD0            0x0171U
#define AD7147_REG_STG4_FF_WORD1            0x0172U
#define AD7147_REG_STG4_FF_WORD2            0x0173U
#define AD7147_REG_STG4_FF_WORD3            0x0174U
#define AD7147_REG_STG4_FF_WORD4            0x0175U
#define AD7147_REG_STG4_FF_WORD5            0x0176U
#define AD7147_REG_STG4_FF_WORD6            0x0177U
#define AD7147_REG_STG4_FF_WORD7            0x0178U
#define AD7147_REG_STG4_SF_WORD0            0x0179U
#define AD7147_REG_STG4_SF_WORD1            0x017AU
#define AD7147_REG_STG4_SF_WORD2            0x017BU
#define AD7147_REG_STG4_SF_WORD3            0x017CU
#define AD7147_REG_STG4_SF_WORD4            0x017DU
#define AD7147_REG_STG4_SF_WORD5            0x017EU
#define AD7147_REG_STG4_SF_WORD6            0x017FU
#define AD7147_REG_STG4_SF_WORD7            0x0180U
#define AD7147_REG_STG4_SF_AMBIENT          0x0181U
#define AD7147_REG_STG4_SF_AVG              0x0182U
#define AD7147_REG_STG4_PEAK_DET_WORD0      0x0183U
#define AD7147_REG_STG4_PEAK_DET_WORD1      0x0184U
#define AD7147_REG_STG4_MAX_WORD0           0x0185U
#define AD7147_REG_STG4_MAX_WORD1           0x0186U
#define AD7147_REG_STG4_MAX_WORD2           0x0187U
#define AD7147_REG_STG4_MAX_WORD3           0x0188U
#define AD7147_REG_STG4_MAX_AVG             0x0189U
#define AD7147_REG_STG4_HIGH_THRESHOLD      0x018AU
#define AD7147_REG_STG4_MAX_TEMP            0x018BU
#define AD7147_REG_STG4_MIN_WORD0           0x018CU
#define AD7147_REG_STG4_MIN_WORD1           0x018DU
#define AD7147_REG_STG4_MIN_WORD2           0x018EU
#define AD7147_REG_STG4_MIN_WORD3           0x018FU
#define AD7147_REG_STG4_MIN_AVG             0x0190U
#define AD7147_REG_STG4_LOW_THRESHOLD       0x0191U
#define AD7147_REG_STG4_MIN_TEMP            0x0192U
/*
** AD7147_REG_STAGE5_RESULT
**  - RW    STAGE5 Results Register
*/
#define AD7147_REG_STG5_CONV_DATA           0x0194U
#define AD7147_REG_STG5_FF_WORD0            0x0195U
#define AD7147_REG_STG5_FF_WORD1            0x0196U
#define AD7147_REG_STG5_FF_WORD2            0x0197U
#define AD7147_REG_STG5_FF_WORD3            0x0198U
#define AD7147_REG_STG5_FF_WORD4            0x0199U
#define AD7147_REG_STG5_FF_WORD5            0x019AU
#define AD7147_REG_STG5_FF_WORD6            0x019BU
#define AD7147_REG_STG5_FF_WORD7            0x019CU
#define AD7147_REG_STG5_SF_WORD0            0x019DU
#define AD7147_REG_STG5_SF_WORD1            0x019EU
#define AD7147_REG_STG5_SF_WORD2            0x019FU
#define AD7147_REG_STG5_SF_WORD3            0x01A0U
#define AD7147_REG_STG5_SF_WORD4            0x01A1U
#define AD7147_REG_STG5_SF_WORD5            0x01A2U
#define AD7147_REG_STG5_SF_WORD6            0x01A3U
#define AD7147_REG_STG5_SF_WORD7            0x01A4U
#define AD7147_REG_STG5_SF_AMBIENT          0x01A5U
#define AD7147_REG_STG5_SF_AVG              0x01A6U
#define AD7147_REG_STG5_PEAK_DET_WORD0      0x01A7U
#define AD7147_REG_STG5_PEAK_DET_WORD1      0x01A8U
#define AD7147_REG_STG5_MAX_WORD0           0x01A9U
#define AD7147_REG_STG5_MAX_WORD1           0x01AAU
#define AD7147_REG_STG5_MAX_WORD2           0x01ABU
#define AD7147_REG_STG5_MAX_WORD3           0x01ACU
#define AD7147_REG_STG5_MAX_AVG             0x01ADU
#define AD7147_REG_STG5_HIGH_THRESHOLD      0x01AEU
#define AD7147_REG_STG5_MAX_TEMP            0x01AFU
#define AD7147_REG_STG5_MIN_WORD0           0x01B0U
#define AD7147_REG_STG5_MIN_WORD1           0x01B1U
#define AD7147_REG_STG5_MIN_WORD2           0x01B2U
#define AD7147_REG_STG5_MIN_WORD3           0x01B3U
#define AD7147_REG_STG5_MIN_AVG             0x01B4U
#define AD7147_REG_STG5_LOW_THRESHOLD       0x01B5U
#define AD7147_REG_STG5_MIN_TEMP            0x01B6U
/*
** AD7147_REG_STAGE6_RESULT
**  - RW    STAGE6 Results Register
*/
#define AD7147_REG_STG6_CONV_DATA           0x01B8U
#define AD7147_REG_STG6_FF_WORD0            0x01B9U
#define AD7147_REG_STG6_FF_WORD1            0x01BAU
#define AD7147_REG_STG6_FF_WORD2            0x01BBU
#define AD7147_REG_STG6_FF_WORD3            0x01BCU
#define AD7147_REG_STG6_FF_WORD4            0x01BDU
#define AD7147_REG_STG6_FF_WORD5            0x01BEU
#define AD7147_REG_STG6_FF_WORD6            0x01BFU
#define AD7147_REG_STG6_FF_WORD7            0x01C0U
#define AD7147_REG_STG6_SF_WORD0            0x01C1U
#define AD7147_REG_STG6_SF_WORD1            0x01C2U
#define AD7147_REG_STG6_SF_WORD2            0x01C3U
#define AD7147_REG_STG6_SF_WORD3            0x01C4U
#define AD7147_REG_STG6_SF_WORD4            0x01C5U
#define AD7147_REG_STG6_SF_WORD5            0x01C6U
#define AD7147_REG_STG6_SF_WORD6            0x01C7U
#define AD7147_REG_STG6_SF_WORD7            0x01C8U
#define AD7147_REG_STG6_SF_AMBIENT          0x01C9U
#define AD7147_REG_STG6_SF_AVG              0x01CAU
#define AD7147_REG_STG6_PEAK_DET_WORD0      0x01CBU
#define AD7147_REG_STG6_PEAK_DET_WORD1      0x01CCU
#define AD7147_REG_STG6_MAX_WORD0           0x01CDU
#define AD7147_REG_STG6_MAX_WORD1           0x01CEU
#define AD7147_REG_STG6_MAX_WORD2           0x01CFU
#define AD7147_REG_STG6_MAX_WORD3           0x01D0U
#define AD7147_REG_STG6_MAX_AVG             0x01D1U
#define AD7147_REG_STG6_HIGH_THRESHOLD      0x01D2U
#define AD7147_REG_STG6_MAX_TEMP            0x01D3U
#define AD7147_REG_STG6_MIN_WORD0           0x01D4U
#define AD7147_REG_STG6_MIN_WORD1           0x01D5U
#define AD7147_REG_STG6_MIN_WORD2           0x01D6U
#define AD7147_REG_STG6_MIN_WORD3           0x01D7U
#define AD7147_REG_STG6_MIN_AVG             0x01D8U
#define AD7147_REG_STG6_LOW_THRESHOLD       0x01D9U
#define AD7147_REG_STG6_MIN_TEMP            0x01DAU
/*
** AD7147_REG_STAGE7_RESULT
**  - RW    STAGE7 Results Register
*/
#define AD7147_REG_STG7_CONV_DATA           0x01DCU
#define AD7147_REG_STG7_FF_WORD0            0x01DDU
#define AD7147_REG_STG7_FF_WORD1            0x01DEU
#define AD7147_REG_STG7_FF_WORD2            0x01DFU
#define AD7147_REG_STG7_FF_WORD3            0x01E0U
#define AD7147_REG_STG7_FF_WORD4            0x01E1U
#define AD7147_REG_STG7_FF_WORD5            0x01E2U
#define AD7147_REG_STG7_FF_WORD6            0x01E3U
#define AD7147_REG_STG7_FF_WORD7            0x01E4U
#define AD7147_REG_STG7_SF_WORD0            0x01E5U
#define AD7147_REG_STG7_SF_WORD1            0x01E6U
#define AD7147_REG_STG7_SF_WORD2            0x01E7U
#define AD7147_REG_STG7_SF_WORD3            0x01E8U
#define AD7147_REG_STG7_SF_WORD4            0x01E9U
#define AD7147_REG_STG7_SF_WORD5            0x01EAU
#define AD7147_REG_STG7_SF_WORD6            0x01EBU
#define AD7147_REG_STG7_SF_WORD7            0x01ECU
#define AD7147_REG_STG7_SF_AMBIENT          0x01EDU
#define AD7147_REG_STG7_SF_AVG              0x01EEU
#define AD7147_REG_STG7_PEAK_DET_WORD0      0x01EFU
#define AD7147_REG_STG7_PEAK_DET_WORD1      0x01F0U
#define AD7147_REG_STG7_MAX_WORD0           0x01F1U
#define AD7147_REG_STG7_MAX_WORD1           0x01F2U
#define AD7147_REG_STG7_MAX_WORD2           0x01F3U
#define AD7147_REG_STG7_MAX_WORD3           0x01F4U
#define AD7147_REG_STG7_MAX_AVG             0x01F5U
#define AD7147_REG_STG7_HIGH_THRESHOLD      0x01F6U
#define AD7147_REG_STG7_MAX_TEMP            0x01F7U
#define AD7147_REG_STG7_MIN_WORD0           0x01F8U
#define AD7147_REG_STG7_MIN_WORD1           0x01F9U
#define AD7147_REG_STG7_MIN_WORD2           0x01FAU
#define AD7147_REG_STG7_MIN_WORD3           0x01FBU
#define AD7147_REG_STG7_MIN_AVG             0x01FCU
#define AD7147_REG_STG7_LOW_THRESHOLD       0x01FDU
#define AD7147_REG_STG7_MIN_TEMP            0x01FEU
/*
** AD7147_REG_STAGE8_RESULT
**  - RW    STAGE8 Results Register
*/
#define AD7147_REG_STG8_CONV_DATA           0x0200U
#define AD7147_REG_STG8_FF_WORD0            0x0201U
#define AD7147_REG_STG8_FF_WORD1            0x0202U
#define AD7147_REG_STG8_FF_WORD2            0x0203U
#define AD7147_REG_STG8_FF_WORD3            0x0204U
#define AD7147_REG_STG8_FF_WORD4            0x0205U
#define AD7147_REG_STG8_FF_WORD5            0x0206U
#define AD7147_REG_STG8_FF_WORD6            0x0207U
#define AD7147_REG_STG8_FF_WORD7            0x0208U
#define AD7147_REG_STG8_SF_WORD0            0x0209U
#define AD7147_REG_STG8_SF_WORD1            0x020AU
#define AD7147_REG_STG8_SF_WORD2            0x020BU
#define AD7147_REG_STG8_SF_WORD3            0x020CU
#define AD7147_REG_STG8_SF_WORD4            0x020DU
#define AD7147_REG_STG8_SF_WORD5            0x020EU
#define AD7147_REG_STG8_SF_WORD6            0x020FU
#define AD7147_REG_STG8_SF_WORD7            0x0210U
#define AD7147_REG_STG8_SF_AMBIENT          0x0211U
#define AD7147_REG_STG8_SF_AVG              0x0212U
#define AD7147_REG_STG8_PEAK_DET_WORD0      0x0213U
#define AD7147_REG_STG8_PEAK_DET_WORD1      0x0214U
#define AD7147_REG_STG8_MAX_WORD0           0x0215U
#define AD7147_REG_STG8_MAX_WORD1           0x0216U
#define AD7147_REG_STG8_MAX_WORD2           0x0217U
#define AD7147_REG_STG8_MAX_WORD3           0x0218U
#define AD7147_REG_STG8_MAX_AVG             0x0219U
#define AD7147_REG_STG8_HIGH_THRESHOLD      0x021AU
#define AD7147_REG_STG8_MAX_TEMP            0x021BU
#define AD7147_REG_STG8_MIN_WORD0           0x021CU
#define AD7147_REG_STG8_MIN_WORD1           0x021DU
#define AD7147_REG_STG8_MIN_WORD2           0x021EU
#define AD7147_REG_STG8_MIN_WORD3           0x021FU
#define AD7147_REG_STG8_MIN_AVG             0x0220U
#define AD7147_REG_STG8_LOW_THRESHOLD       0x0221U
#define AD7147_REG_STG8_MIN_TEMP            0x0222U

/** AD7147_REG_STAGE9_RESULT
**  - RW    STAGE9 Results Register
*/
#define AD7147_REG_STG9_CONV_DATA           0x0224U
#define AD7147_REG_STG9_FF_WORD0            0x0225U
#define AD7147_REG_STG9_FF_WORD1            0x0226U
#define AD7147_REG_STG9_FF_WORD2            0x0227U
#define AD7147_REG_STG9_FF_WORD3            0x0228U
#define AD7147_REG_STG9_FF_WORD4            0x0229U
#define AD7147_REG_STG9_FF_WORD5            0x022AU
#define AD7147_REG_STG9_FF_WORD6            0x022BU
#define AD7147_REG_STG9_FF_WORD7            0x022CU
#define AD7147_REG_STG9_SF_WORD0            0x022DU
#define AD7147_REG_STG9_SF_WORD1            0x022EU
#define AD7147_REG_STG9_SF_WORD2            0x022FU
#define AD7147_REG_STG9_SF_WORD3            0x0230U
#define AD7147_REG_STG9_SF_WORD4            0x0231U
#define AD7147_REG_STG9_SF_WORD5            0x0232U
#define AD7147_REG_STG9_SF_WORD6            0x0233U
#define AD7147_REG_STG9_SF_WORD7            0x0234U
#define AD7147_REG_STG9_SF_AMBIENT          0x0235U
#define AD7147_REG_STG9_SF_AVG              0x0236U
#define AD7147_REG_STG9_PEAK_DET_WORD0      0x0237U
#define AD7147_REG_STG9_PEAK_DET_WORD1      0x0238U
#define AD7147_REG_STG9_MAX_WORD0           0x0239U
#define AD7147_REG_STG9_MAX_WORD1           0x023AU
#define AD7147_REG_STG9_MAX_WORD2           0x023BU
#define AD7147_REG_STG9_MAX_WORD3           0x023CU
#define AD7147_REG_STG9_MAX_AVG             0x023DU
#define AD7147_REG_STG9_HIGH_THRESHOLD      0x023EU
#define AD7147_REG_STG9_MAX_TEMP            0x023FU
#define AD7147_REG_STG9_MIN_WORD0           0x0240U
#define AD7147_REG_STG9_MIN_WORD1           0x0241U
#define AD7147_REG_STG9_MIN_WORD2           0x0242U
#define AD7147_REG_STG9_MIN_WORD3           0x0243U
#define AD7147_REG_STG9_MIN_AVG             0x0244U
#define AD7147_REG_STG9_LOW_THRESHOLD       0x0245U
#define AD7147_REG_STG9_MIN_TEMP            0x0246U
/*
** AD7147_REG_STAGE10_RESULT
**  - RW    STAGE10 Results Register
*/
#define AD7147_REG_STG10_CONV_DATA          0x0248U
#define AD7147_REG_STG10_FF_WORD0           0x0249U
#define AD7147_REG_STG10_FF_WORD1           0x024AU
#define AD7147_REG_STG10_FF_WORD2           0x024BU
#define AD7147_REG_STG10_FF_WORD3           0x024CU
#define AD7147_REG_STG10_FF_WORD4           0x024DU
#define AD7147_REG_STG10_FF_WORD5           0x024EU
#define AD7147_REG_STG10_FF_WORD6           0x024FU
#define AD7147_REG_STG10_FF_WORD7           0x0250U
#define AD7147_REG_STG10_SF_WORD0           0x0251U
#define AD7147_REG_STG10_SF_WORD1           0x0252U
#define AD7147_REG_STG10_SF_WORD2           0x0253U
#define AD7147_REG_STG10_SF_WORD3           0x0254U
#define AD7147_REG_STG10_SF_WORD4           0x0255U
#define AD7147_REG_STG10_SF_WORD5           0x0256U
#define AD7147_REG_STG10_SF_WORD6           0x0257U
#define AD7147_REG_STG10_SF_WORD7           0x0258U
#define AD7147_REG_STG10_SF_AMBIENT         0x0259U
#define AD7147_REG_STG10_SF_AVG             0x025AU
#define AD7147_REG_STG10_PEAK_DET_WORD0     0x025BU
#define AD7147_REG_STG10_PEAK_DET_WORD1     0x025CU
#define AD7147_REG_STG10_MAX_WORD0          0x025DU
#define AD7147_REG_STG10_MAX_WORD1          0x025EU
#define AD7147_REG_STG10_MAX_WORD2          0x025FU
#define AD7147_REG_STG10_MAX_WORD3          0x0260U
#define AD7147_REG_STG10_MAX_AVG            0x0261U
#define AD7147_REG_STG10_HIGH_THRESHOLD     0x0262U
#define AD7147_REG_STG10_MAX_TEMP           0x0263U
#define AD7147_REG_STG10_MIN_WORD0          0x0264U
#define AD7147_REG_STG10_MIN_WORD1          0x0265U
#define AD7147_REG_STG10_MIN_WORD2          0x0266U
#define AD7147_REG_STG10_MIN_WORD3          0x0267U
#define AD7147_REG_STG10_MIN_AVG            0x0268U
#define AD7147_REG_STG10_LOW_THRESHOLD      0x0269U
#define AD7147_REG_STG10_MIN_TEMP           0x026AU
/*
** AD7147_REG_STAGE11_RESULT
**  - RW    STAGE11 Results Register
*/
#define AD7147_REG_STG11_CONV_DATA          0x026CU
#define AD7147_REG_STG11_FF_WORD0           0x026DU
#define AD7147_REG_STG11_FF_WORD1           0x026EU
#define AD7147_REG_STG11_FF_WORD2           0x026FU
#define AD7147_REG_STG11_FF_WORD3           0x0270U
#define AD7147_REG_STG11_FF_WORD4           0x0271U
#define AD7147_REG_STG11_FF_WORD5           0x0272U
#define AD7147_REG_STG11_FF_WORD6           0x0273U
#define AD7147_REG_STG11_FF_WORD7           0x0274U
#define AD7147_REG_STG11_SF_WORD0           0x0275U
#define AD7147_REG_STG11_SF_WORD1           0x0276U
#define AD7147_REG_STG11_SF_WORD2           0x0277U
#define AD7147_REG_STG11_SF_WORD3           0x0278U
#define AD7147_REG_STG11_SF_WORD4           0x0279U
#define AD7147_REG_STG11_SF_WORD5           0x027AU
#define AD7147_REG_STG11_SF_WORD6           0x027BU
#define AD7147_REG_STG11_SF_WORD7           0x027CU
#define AD7147_REG_STG11_SF_AMBIENT         0x027DU
#define AD7147_REG_STG11_SF_AVG             0x027EU
#define AD7147_REG_STG11_PEAK_DET_WORD0     0x027FU
#define AD7147_REG_STG11_PEAK_DET_WORD1     0x0280U
#define AD7147_REG_STG11_MAX_WORD0          0x0281U
#define AD7147_REG_STG11_MAX_WORD1          0x0282U
#define AD7147_REG_STG11_MAX_WORD2          0x0283U
#define AD7147_REG_STG11_MAX_WORD3          0x0284U
#define AD7147_REG_STG11_MAX_AVG            0x0285U
#define AD7147_REG_STG11_HIGH_THRESHOLD     0x0286U
#define AD7147_REG_STG11_MAX_TEMP           0x0287U
#define AD7147_REG_STG11_MIN_WORD0          0x0288U
#define AD7147_REG_STG11_MIN_WORD1          0x0289U
#define AD7147_REG_STG11_MIN_WORD2          0x028AU
#define AD7147_REG_STG11_MIN_WORD3          0x028BU
#define AD7147_REG_STG11_MIN_AVG            0x028CU
#define AD7147_REG_STG11_LOW_THRESHOLD      0x028DU
#define AD7147_REG_STG11_MIN_TEMP           0x028EU





/*
**
** Enumerations of AD7147 driver specific commands
**
*/
enum
{
    /* 0x401B0000 - AD7147 driver enumeration start  */
    ADI_AD7147_CMD_START = ADI_AD7147_ENUMERATION_START,

    /*
    ** TWI related commands
    */

    /* 0x401B0001 - Sets TWI Device Number to use to access AD7147 registers
                    Value = u32 (TWI Device number to use)
                    Default = 0xFF (TWI device number invalid)              */
    ADI_AD7147_CMD_SET_TWI_DEVICE_NUMBER,
    /* 0x401B0002 - Sets TWI Configuration table specific to the application
                    Value = pointer to ADI_DEV_CMD_VALUE_PAIR
                    Default = NULL pointer                                  */
    ADI_AD7147_CMD_SET_TWI_CONFIG_TABLE,
    /* 0x401B0003 - Sets TWI Device Address specific to the HW setting
                    Value = u32 (TWI Device address to use)
                    Default = 0x00 (TWI device address invalid)              */
    ADI_AD7147_CMD_SET_TWI_DEVICE_ADDRESS,
    /*
    ** AD7147 Interrupt signals related commands
    */
    /* 0x401B0004 - Sets AD7147 driver to monitor INTIRQ interrupts
                    Value = ADI_AD7147_INTERRUPT_PORT
                    Default = Interrupt monitoring disabled                 */
    ADI_AD7147_CMD_INSTALL_INTIRQ,
    /* 0x401B0005 - Removes INTIRQ interrupt from being
                    monitored by AD7147 driver
                    Value = NULL                                            */
    ADI_AD7147_CMD_UNINSTALL_INTIRQ,
    /* 0x401B0006 - Disable INTIRQ interrupt from being
                    monitored by AD7147 driver
                    Value = NULL                                            */
    ADI_AD7147_CMD_DISABLE_INTIRQ,
    /* 0x401B0007 - Reenable INTIRQ interrupt from being
                    monitored by AD7147 driver
                    Value = NULL                                            */
    ADI_AD7147_CMD_REENABLE_INTIRQ

};

/*
**
** Enumerations of AD7147 driver specific events
**
*/

enum
{
    /* 0x401B0000 - AD7147 driver enumeration start  */
    ADI_AD7147_EVENT_START = ADI_AD7147_ENUMERATION_START,

    /* 0x401B0001 - Callback Event indicates that
                    INTIRQ has detected.
                    Callback Argument - points to NULL  */
    ADI_AD7147_EVENT_INT_IRQ
};

/*
**
** Enumerations of AD7147 driver specific Return codes
**
*/

enum
{
    /* 0x401B0000 - AD7147 driver enumeration start  */
    ADI_AD7147_RESULT_START = ADI_AD7147_ENUMERATION_START,
    /* 0x401B0001 - Occurs when client issues a command
                    that is not supported by this driver  */
    ADI_AD7147_RESULT_CMD_NOT_SUPPORTED,
    /* 0x401B0002 - Given TWI Device address is invalid   */
    ADI_AD7147_RESULT_TWI_ADDRESS_INVALID,
    /* 0x401B0003 - Given TWI Device number is invalid    */
    ADI_AD7147_RESULT_TWI_NUMBER_INVALID,
    /* 0x401B0004 - Given pointer to TWI configuration table is invalid   */
    ADI_AD7147_RESULT_TWI_CONFIG_TABLE_INVALID,
    /* 0x401B0005 - Results when client tries to write to an invalid
                    register address      */
    ADI_AD7147_RESULT_REGISTER_ADDR_INVALID,
    /* 0x401B0006 - Results when client tries to write to a read-only
                    register address      */
   ADI_AD7147_RESULT_REGISTER_ADDR_RO
};

/*=============  E X T E R N A L S  ============*/

/*
**
**  External Data section
**
*/
/*
** ADIAD7147EntryPoint
**  - Device Manager Entry point for AD7147 driver
**
*/
extern ADI_DEV_PDD_ENTRY_POINT      ADIAD7147EntryPoint;

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
** ADI_AD7147_INTERRUPT_PORT
**  - Structure to pass information on Blackfin flag pin connected to
**    This data structure can be used with
**    ADI_AD7147_CMD_ENABLE_INTERRUPT_PEN_INT_IRQ command that can be used to
**    configure the driver to monitor Data Available (INTIRQ)
**    interrupt signal. Allowing driver to monitor these interrupts will
**    reduce Application code overhead  */

typedef struct __AdiAd7147InterruptPort
{

    /* Variable: eFlagId
        - Flag ID connected to AD7147 interrupt signal */
    ADI_FLAG_ID             eFlagId;

    /* Variable: eFlagIntId
        - Peripheral Interrupt ID of the corresponding flag */
    ADI_INT_PERIPHERAL_ID   eFlagIntId;

} ADI_AD7147_INTERRUPT_PORT;

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

#endif /* __ADI_AD7147_H__ */

/*****/
