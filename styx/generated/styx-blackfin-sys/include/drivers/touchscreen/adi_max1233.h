#ifndef __ADI_MAX1233_H__
#define __ADI_MAX1233_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/**********************************************************************
Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_max1233.h,v $

Description:
    This is the primary include file for MAX1233 Touchscreen Controller.
    Use Device access commands to access MAX1233 device registers
    (refer to adi_dev.h)

References:
See Maxim "MAX1233/MAX1234" data sheet, revision "19-2512; Rev. 3; 8/05"

Description:
The MAX1233 is controlled by reading from and writing to registers over the SPI port.
These registers are addressed through a 16-bit command word:

+-------------------------------------------+
|       Command Word Bit Positions          |
+-------------------------------------------+
| R/W | Rserved Bits | Page Bit | Reg Addr  |
|-----|--------------|----------|-----------|
| 15  |     14:7     |     6    |    5:0    |
+-----+--------------+----------+-----------+

Following the 16-bit command word, the next 16-bits of data are read from or written
to the address specified in the command word.  After 32 clock cycles (one command word
followed by the first data word), the MAX1233 automatically increments its address pointer
and continues reading or writing data (without additional command words) until the rising
edge of CS (really, CS_BAR), or until it reaches the end of the active page (Bit6 of the
command word).

***********************************************************************/


/*****************************
MAX1233 Register Addresses
*****************************/

/* All registers are read/write, performing different functions */

/* The PAGE bit (Control Word Bit6) is treated as a 6th Address bit (0x40) */

/* Note: the register address space has the following reserved ranges:
    0x0C-0x0E, 0x12-0x1F, 0x43-0x4D, 0x52-0x5F */

/* Table numbers refer to MAX1233 data sheet */

/* Table 3.  MAX1233 Register Addresses                                                                             */
#define    MAX1233_REG_X               0x00    /* ADC data of X-position                                            */
#define    MAX1233_REG_Y               0x01    /* ADC data of Y-position                                            */
#define    MAX1233_REG_Z1              0x02    /* ADC data of Z1 touch pressure measure                             */
#define    MAX1233_REG_Z2              0x03    /* ADC data of Z2 touch pressure measure                             */
#define    MAX1233_REG_KPD             0x04    /* Keypad raw scan data                                              */
#define    MAX1233_REG_BAT1            0x05    /* ADC data of BAT1 analog input measure                             */
#define    MAX1233_REG_BAT2            0x06    /* ADC data of BAT2 analog input measure                             */
#define    MAX1233_REG_AUX1            0x07    /* ADC data of AUX1 analog input measure                             */
#define    MAX1233_REG_AUX2            0x08    /* ADC data of AUX2 analog input measure                             */
#define    MAX1233_REG_TEMP1           0x09    /* ADC data of single-ended temperature measure                      */
#define    MAX1233_REG_TEMP2           0x0A    /* ADC data of differential temperature measure                      */
#define    MAX1233_REG_DAC             0x0B    /* DAC data register                                                 */
#define    MAX1233_REG_GPIO            0x0F    /* GPIO data register                                                */
#define    MAX1233_REG_KPDATA1         0x10    /* Keypad pending scan data                                          */
#define    MAX1233_REG_KPDATA2         0x11    /* Keypad unmasked scan data                                         */
#define    MAX1233_REG_ADC             0x40    /* ADC control register                                              */
#define    MAX1233_REG_KEY             0x41    /* Keypad status/interrupt/debounce/hold-time                        */
#define    MAX1233_REG_DAC_CNTL        0x42    /* DAC control register                                              */
#define    MAX1233_REG_GPIO_PULL       0x4E    /* GPIO internal pullup disable                                      */
#define    MAX1233_REG_GPIO_CFG        0x4F    /* GPIO pin configuration                                            */
#define    MAX1233_REG_KEY_MASK        0x50    /* Keypad individual key mask                                        */
#define    MAX1233_REG_COL_MASK        0x51    /* Keypad column mask                                                */

/************************************
MAX1233 Register Bitfields and Values
************************************/

/* Table 4/5.  ADC Control Register Bitfields (sub-fields of the MAX1233_REG_ADC register)                          */
#define    MAX1233_POS_PENSTS            15    /* 1-bit field: read pen IR status / write touch-screen scan mode    */
#define    MAX1233_POS_ADSTS             14    /* 1-bit field: read ADC status / write to stop ADC                  */
#define    MAX1233_POS_AD                10    /* 4-bit field: ADC scan select                                      */
#define    MAX1233_POS_RES                8    /* 2-bit field: sets ADC resolution and power-up delay               */
#define    MAX1233_POS_AVG                6    /* 2-bit field: sets ADC averaging mode                              */
#define    MAX1233_POS_CNR                4    /* 2-bit field: sets ADC conversion rate                             */
#define    MAX1233_POS_ST                 1    /* 3-bit field: sets Touch-Screen settling time                      */
#define    MAX1233_POS_RFV                0    /* 1-bit field: selects ADC internal reference voltage source        */

/* Table 6.  ADSTS Bit Operations                     read function                    / write function             */
#define    MAX1233_VAL_ADSTS0             0    /* no-touch+scan in-progress        / start scan and wait            */
#define    MAX1233_VAL_ADSTS1             1    /* no-touch+scan complete           / stop scan and wait             */
#define    MAX1233_VAL_ADSTS2             2    /* touch detected+scan in-progress  / stop scan and wait             */
#define    MAX1233_VAL_ADSTS3             3    /* touch detected+scan complete     / stop scan and power-down       */

/* Table 7.  ADC Scan Select (Touch-Screen, Battery, Auxiliary Channels, and Temperature                            */
#define    MAX1233_VAL_AD_RES             0    /* Select ADC reference voltage with MAX1233_POS_ADC_RESOLUTION bits */
#define    MAX1233_VAL_AD_XY              1    /* Convert/store X/Y inputs                                          */
#define    MAX1233_VAL_AD_XYZ             2    /* Convert/store X/Y/Z1/Z2 inputs                                    */
#define    MAX1233_VAL_AD_X               3    /* Convert/store X input;                                            */
#define    MAX1233_VAL_AD_Y               4    /* Convert/store Y input                                             */
#define    MAX1233_VAL_AD_Z               5    /* Convert/store Z1/Z2 inputs                                        */
#define    MAX1233_VAL_AD_BAT1            6    /* Convert/store BAT1 input                                          */
#define    MAX1233_VAL_AD_BAT2            7    /* Convert/store BAT2 input                                          */
#define    MAX1233_VAL_AD_AUX1            8    /* Convert/store AUX1 input                                          */
#define    MAX1233_VAL_AD_AUX2            9    /* Convert/store AUX2 input                                          */
#define    MAX1233_VAL_AD_TEMP1          10    /* Convert/store TEMP1 input                                         */
#define    MAX1233_VAL_AD_ALT            11    /* Convert/store BAT1/BAT2/AUX1/AUX2/TEMP1 inputs                    */
#define    MAX1233_VAL_AD_TEMP2          12    /* Convert/store TEMP2 input                                         */
#define    MAX1233_VAL_AD_DRVYY          13    /* Drive Y+/Y- output pins                                           */
#define    MAX1233_VAL_AD_DRVXX          14    /* Drive X+/X- output pins                                           */
#define    MAX1233_VAL_AD_DRVYX          15    /* Drive Y+/X- output pins                                           */

/* Table 8.  ADC Resolution Control                                                                                 */
#define    MAX1233_VAL_RES0               0    /* use 8-bit conversions with 31us reference power-up delay          */
#define    MAX1233_VAL_RES8               1    /* use 8-bit conversions with 31us reference power-up delay          */
#define    MAX1233_VAL_RES10              2    /* use 10-bit conversions with 37us reference power-up delay         */
#define    MAX1233_VAL_RES12              3    /* use 12-bit conversions with 44us reference power-up delay         */

/* Table 9.  ADC Averaging Control                                                                                  */
#define    MAX1233_VAL_AVG0               0    /* no averaging                                                      */
#define    MAX1233_VAL_AVG4               1    /* average over 4 conversions                                        */
#define    MAX1233_VAL_AVG8               2    /* average over 8 conversions                                        */
#define    MAX1233_VAL_AVG16              3    /* average over 16 conversions                                       */

/* Table 10.  ADC Conversion Rate Control                                                                           */
#define    MAX1233_VAL_CNR3               1    /* use 3.5us/sample (1.5us acquisition + 2us conversion)             */
#define    MAX1233_VAL_CNR10              2    /* use 10us/sample (5us acquisition + 5us conversion)                */
#define    MAX1233_VAL_CNR100             3    /* use 100us/sample (95us acquisition + 5us conversion)              */

/* Table 11.  ADC Touch-Screen Settling Time Control                                                                */
#define    MAX1233_VAL_ST0                0    /* no delay between touch-detect and conversion                      */
#define    MAX1233_VAL_ST100US            1    /* 100us settling time                                               */
#define    MAX1233_VAL_ST500US            2    /* 500us settling time                                               */
#define    MAX1233_VAL_ST1MS              3    /*   1ms settling time                                               */
#define    MAX1233_VAL_ST5MS              4    /*   5ms settling time                                               */
#define    MAX1233_VAL_ST10MS             5    /*  10ms settling time                                               */
#define    MAX1233_VAL_ST50MS             6    /*  50ms settling time                                               */
#define    MAX1233_VAL_ST100MS            7    /* 100ms settling time                                               */

/* Table 12.  ADC Reference Control Bit                                                                             */
#define    MAX1233_VAL_RFV1               0    /* use +1.0V internal reference                                      */
#define    MAX1233_VAL_RFV25              1    /* use +2.5V internal reference                                      */

/* Table 13.  Internal ADC Reference Auto Power-Up Control                                                          */
/* This table describes an alternate use of the resolution control bits (MAX1233_POS_ADC_RES)                       */
#define    MAX1233_VAL_INT_AUTO           0    /* Select internal ADC reference in auto-on mode                     */
#define    MAX1233_VAL_INT_ON             1    /* Select internal ADC reference in always-on mode                   */
#define    MAX1233_VAL_EXT2               2    /* Select external ADC reference with internal reference always off  */
#define    MAX1233_VAL_EXT3               3    /* Select external ADC reference with internal reference always off  */

/* Table 14/15.  DAC Control Register Bitfield (sub-field of MAX1233_REG_DAC_CNTL register)                         */
#define    MAX1233_POS_DAC_CNTL_DAPD     15    /* 1-bit field: selects DAC power-down mode                          */

/* Table 16.  DAC Power-Down Bit                                                                                    */
#define    MAX1233_VAL_DAPD_ON            0    /* DAC powered up                                                    */
#define    MAX1233_VAL_DAPD_OFF           1    /* DAC powered down                                                  */

/* Table 17/18.  Keypad Control Register Bitfields (sub-fields of MAX1233_REG_KEY register)                         */
#define    MAX1233_POS_KEYSTS            14    /* 2-bit field: read ir & scan status / write scan start & stop      */
#define    MAX1233_POS_DBN               11    /* 3-bit field: sets keypad debounce time                            */
#define    MAX1233_POS_HLD                8    /* 3-bit field: sets keypad hold time                                */

/* Table 19.  KEYSTS1/KEYSTS0 Functions               read function                    / write function             */
#define    MAX1233_VAL_KEYSTS0            0    /* no-press+scan in-progress        / start scan and wait            */
#define    MAX1233_VAL_KEYSTS1            1    /* no-press+scan complete           / stop scan and wait             */
#define    MAX1233_VAL_KEYSTS2            2    /* press detected+scan in-progress  / stop scan and wait             */
#define    MAX1233_VAL_KEYSTS3            3    /* press detected+scan complete     / stop scan and porer-down       */

/* Table 20.  Keypad Debounce Time Control                                                                          */
#define    MAX1233_VAL_DBN2               0    /*   2ms keypad debounce time                                        */
#define    MAX1233_VAL_DBN10              1    /*  10ms keypad debounce time                                        */
#define    MAX1233_VAL_DBN20              2    /*  20ms keypad debounce time                                        */
#define    MAX1233_VAL_DBN50              3    /*  50ms keypad debounce time                                        */
#define    MAX1233_VAL_DBN60              4    /*  60ms keypad debounce time                                        */
#define    MAX1233_VAL_DBN80              5    /*  80ms keypad debounce time                                        */
#define    MAX1233_VAL_DBN100             6    /* 100ms keypad debounce time                                        */
#define    MAX1233_VAL_DBN120             7    /* 120ms keypad debounce time                                        */

/* Table 21.  Keypad Hold Time Control                                                                              */
#define    MAX1233_VAL_HLD0               0    /* if a button is held, wait 100us before next scan                  */
#define    MAX1233_VAL_HLD1               1    /* if a button is held, wait 1 debounce time before next scan        */
#define    MAX1233_VAL_HLD2               2    /* if a button is held, wait 2 debounce times before next scan       */
#define    MAX1233_VAL_HLD3               3    /* if a button is held, wait 3 debounce times before next scan       */
#define    MAX1233_VAL_HLD4               4    /* if a button is held, wait 4 debounce times before next scan       */
#define    MAX1233_VAL_HLD5               5    /* if a button is held, wait 5 debounce times before next scan       */
#define    MAX1233_VAL_HLD6               6    /* if a button is held, wait 6 debounce times before next scan       */
#define    MAX1233_VAL_HLD7               7    /* if a button is held, wait 7 debounce times before next scan       */

/* Table 22/23.  Keypad Individual Key Mask Control Register Bitfields (sub-fields of MAX1233_REG_KEY_MASK register) */
#define    MAX1233_POS_KM15               15    /* 1-bit field: mask key R4C4                                        */
#define    MAX1233_POS_KM14               14    /* 1-bit field: mask key R3C4                                        */
#define    MAX1233_POS_KM13               13    /* 1-bit field: mask key R2C4                                        */
#define    MAX1233_POS_KM12               12    /* 1-bit field: mask key R1C4                                        */
#define    MAX1233_POS_KM11               11    /* 1-bit field: mask key R4C3                                        */
#define    MAX1233_POS_KM10               10    /* 1-bit field: mask key R3C3                                        */
#define    MAX1233_POS_KM9                 9    /* 1-bit field: mask key R2C3                                        */
#define    MAX1233_POS_KM8                 8    /* 1-bit field: mask key R1C3                                        */
#define    MAX1233_POS_KM7                 7    /* 1-bit field: mask key R4C2                                        */
#define    MAX1233_POS_KM6                 6    /* 1-bit field: mask key R3C2                                        */
#define    MAX1233_POS_KM5                 5    /* 1-bit field: mask key R2C2                                        */
#define    MAX1233_POS_KM4                 4    /* 1-bit field: mask key R1C2                                        */
#define    MAX1233_POS_KM3                 3    /* 1-bit field: mask key R4C1                                        */
#define    MAX1233_POS_KM2                 2    /* 1-bit field: mask key R3C1                                        */
#define    MAX1233_POS_KM1                 1    /* 1-bit field: mask key R2C1                                        */
#define    MAX1233_POS_KM0                 0    /* 1-bit field: mask key R1C1                                        */

/* Table 24/25.  Kaypad Column Mask Conrtol Register Bitfields (sub-fields of MAX1233_REG_COL_MASK register)         */
#define    MAX1233_POS_CM4                15    /* 1-bit field: mask all keys in column 4                            */
#define    MAX1233_POS_CM3                14    /* 1-bit field: mask all keys in column 3                            */
#define    MAX1233_POS_CM2                13    /* 1-bit field: mask all keys in column 2                            */
#define    MAX1233_POS_CM1                12    /* 1-bit field: mask all keys in column 1                            */

/* Table 26/27.  GPIO Control Register Bitfields (sub-fields of MAX1233_REG_GPIO_CFG register)                       */
#define    MAX1233_POS_GP7                15    /* 1-bit field: configure pin C4 as GPIO bit 7                       */
#define    MAX1233_POS_GP6                14    /* 1-bit field: configure pin C3 as GPIO bit 6                       */
#define    MAX1233_POS_GP5                13    /* 1-bit field: configure pin C2 as GPIO bit 5                       */
#define    MAX1233_POS_GP4                12    /* 1-bit field: configure pin C1 as GPIO bit 4                       */
#define    MAX1233_POS_GP3                11    /* 1-bit field: configure pin R4 as GPIO bit 3                       */
#define    MAX1233_POS_GP2                10    /* 1-bit field: configure pin R3 as GPIO bit 2                       */
#define    MAX1233_POS_GP1                 9    /* 1-bit field: configure pin R2 as GPIO bit 1                       */
#define    MAX1233_POS_GP0                 8    /* 1-bit field: configure pin R1 as GPIO bit 0                       */
#define    MAX1233_POS_OE7                 7    /* 1-bit field: configure GPIO bit 7 for output                      */
#define    MAX1233_POS_OE6                 6    /* 1-bit field: configure GPIO bit 6 for output                      */
#define    MAX1233_POS_OE5                 5    /* 1-bit field: configure GPIO bit 5 for output                      */
#define    MAX1233_POS_OE4                 4    /* 1-bit field: configure GPIO bit 4 for output                      */
#define    MAX1233_POS_OE3                 3    /* 1-bit field: configure GPIO bit 3 for output                      */
#define    MAX1233_POS_OE2                 2    /* 1-bit field: configure GPIO bit 2 for output                      */
#define    MAX1233_POS_OE1                 1    /* 1-bit field: configure GPIO bit 1 for output                      */
#define    MAX1233_POS_OE0                 0    /* 1-bit field: configure GPIO bit 0 for output                      */

/* Table 28/29.  GPIO Pullup Disable Bitfields (sub-fields of MAX1233_REG_GPIO_PULL register)                        */
#define    MAX1233_POS_PU7                15    /* 1-bit field: float output on GPIO bit 7                           */
#define    MAX1233_POS_PU6                14    /* 1-bit field: float output on GPIO bit 6                           */
#define    MAX1233_POS_PU5                13    /* 1-bit field: float output on GPIO bit 5                           */
#define    MAX1233_POS_PU4                12    /* 1-bit field: float output on GPIO bit 4                           */
#define    MAX1233_POS_PU3                11    /* 1-bit field: float output on GPIO bit 3                           */
#define    MAX1233_POS_PU2                10    /* 1-bit field: float output on GPIO bit 2                           */
#define    MAX1233_POS_PU1                 9    /* 1-bit field: float output on GPIO bit 1                           */
#define    MAX1233_POS_PU0                 8    /* 1-bit field: float output on GPIO bit 0                           */



/*********************************************************************

Data Structures

*********************************************************************/


/*******************************************************************************************\
   Structure to set MAX1233 PENIRQ/KEYIRQ Interrupt Flag connected to Blackfin.

   This data structure can be used with ADI_MAX1233_CMD_ENABLE_INTERRUPT_PENIRQ and
   ADI_MAX1233_CMD_ENABLE_INTERRUPT_KEYIRQ commands.

   These commands can be used to configure this driver to monitor corresponding interrupt
   signals, which will reduce Application code overhead

   To enable MAX1233 PENIRQ or KEYIRQ interrupts, client must pass corresponding interrupt
   enable command with pointer to following structure as value.  The 'FlagId' field should
   hold the Blackfin processor Flag ID connected to the selected Interrupt signal and
   'FlagIntId' field should hold the Peripheral Interrupt ID of the corresponding flag.
 \*******************************************************************************************/
typedef struct
{
    ADI_FLAG_ID             FlagId;     /* Flag ID connected to MAX1233 interrupt signal     */
    ADI_INT_PERIPHERAL_ID   FlagIntId;  /* Peripheral Interrupt ID of the corresponding flag*/
} MAX1233_INTERRUPT_PORT;

/*********************************************************************

Extensible enumerations and defines

*********************************************************************/
#define ADI_MAX1233_FIRST_COMMAND_ID    ADI_MAX1233_ENUMERATION_START + 0               // 0x40290000 (from adi_dev.h)
#define ADI_MAX1233_FIRST_EVENT_ID      ADI_MAX1233_ENUMERATION_START + 0x1000          // event id offset
#define ADI_MAX1233_FIRST_RESULT_ID     ADI_MAX1233_ENUMERATION_START + 0x2000          // result id offset

/* MAX1233 driver Command IDs                                                                                       */
enum{
    ADI_MAX1233_CMD_START = ADI_MAX1233_FIRST_COMMAND_ID,

    ADI_MAX1233_CMD_SET_SPI_DEVICE_NUMBER,                  /* 0x40290001 - Set MAX1233 SPI Device Number to use
                                                               (SPI Device used for MAX1233 access) (value = u8)    */
    ADI_MAX1233_CMD_SET_SPI_CS,                             /* 0x40290002 - Set MAX1233 SPI Chipselect
                                                               (Blackfin SPI_FLG to select MAX1233) (value = u8)    */
    ADI_MAX1233_CMD_SET_SPI_SLAVE,                          /* 0x40290003 - Set MAX1233 SPI Slave Select ID
                                                               (Blackfin SPISSEL to select MAX1233) (value = u8)    */
    ADI_MAX1233_CMD_SET_SPI_BAUD,                           /* 0x40290004 - Set SPI Baud Rate Register ID
                                                               (Controls SPI symbol rate) (value = pointer to u32)  */
    ADI_MAX1233_CMD_INSTALL_PENIRQ,                         /* 0x40290005 - Sets MAX1233 driver to monitor PENIRQ
                                                               interrupt (value = ADI_MAX1233_INTERRUPT_PORT*)      */
    ADI_MAX1233_CMD_INSTALL_KEYIRQ,                         /* 0x40290006 - Sets MAX1233 driver to monitor KEYIRQ
                                                               interrupt (value = ADI_MAX1233_INTERRUPT_PORT*)      */
    ADI_MAX1233_CMD_UNINSTALL_PENIRQ,                       /* 0x40290007 - Removes PENIRQ interrupt from being
                                                               monitored by MAX1233 driver (value = NULL)           */
    ADI_MAX1233_CMD_UNINSTALL_KEYIRQ,                       /* 0x40290008 - Removes KEYIRQ interrupt from being
                                                               monitored by MAX1233 driver (value = NULL)           */
    ADI_MAX1233_CMD_REENABLE_PENIRQ,                        /* 0x40290009 - Removes PENIRQ interrupt from being
                                                               monitored by MAX1233 driver (value = NULL)           */
    ADI_MAX1233_CMD_REENABLE_KEYIRQ                         /* 0x4029000A - Removes KEYIRQ interrupt from being
                                                               monitored by MAX1233 driver (value = NULL)           */
};

/* MAX1233 driver Event IDs                                                                                         */
enum{
    ADI_MAX1233_EVENT_START=ADI_MAX1233_FIRST_EVENT_ID,     /* 0x40290007                                           */

    ADI_MAX1233_EVENT_PENIRQ_NOTIFICATION,                  /* 0x40291001 - Callback Event indicates that
                                                               PENIRQ has detected a screen touch event.
                                                               Callback Argument - points to NULL                   */
    ADI_MAX1233_EVENT_KEYIRQ_NOTIFICATION                   /* 0x40291002 - Callback Event indicates that
                                                               KEYIRQ has detected a key press event.
                                                               Callback Argument - points to NULL                   */
};

/* MAX1233 driver Return codes                                                                                      */
enum{
    ADI_MAX1233_RESULT_START=ADI_MAX1233_FIRST_RESULT_ID,   /* 0x40292000                                           */
    ADI_MAX1233_RESULT_CMD_BAD_BAUD_RATE,                   /* 0x40292001 - Occurs when client issues an invalid    */
                                                            /* ADI_MAX1233_CMD_SET_SPI_BAUD command                 */
    ADI_MAX1233_RESULT_CMD_NOT_SUPPORTED                    /* 0x40292002 - Occurs when client issues a
                                                               command not supported by this driver                 */
};


/*********************************************************************

Entry point to the MAX1233 device driver

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADIMAX1233EntryPoint;

/*********************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_MAX1233_H__ */
