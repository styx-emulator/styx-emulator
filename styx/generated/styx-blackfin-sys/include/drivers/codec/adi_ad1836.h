/*********************************************************************************

Copyright(c) 2005 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

Description:
            This is the include file for the AD1836 Audio Codec device driver.
            It uses adi_spi(to configure the ad1836) and adi_sport (for data
            processing)
*********************************************************************************/

#ifndef __ADI_AD1836_H__
#define __ADI_AD1836_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* integer typedefs - for all modules */
#include <services_types.h>

/* ****************************************************************************
 * OPERATION MODES
 * ****************************************************************************
 */

/* ****************************************************************************
 * RESULT CODES
 * ****************************************************************************
 */
enum {
    ADI_AD1836_RESULT_START=ADI_AD1836_ENUMERATION_START,// insure this order remains
    ADI_AD1836_RESULT_OPERATION_MODE_NOT_SET,
    ADI_AD1836_RESULT_OPERATION_MODE_NOT_SUPPORTED
};


/* ****************************************************************************
 * COMMAND CODES
 * ****************************************************************************
 */

//--------------------------------------------------------------------------//
// Symbolic constants                                                       //
//--------------------------------------------------------------------------//

// Names for codec registers with address fields preinitialized.
// bitwise or in the function bits, leaving the top 5 bits in tact
// as the address and direction for the spi port access of the codec
// register.
#define DAC_CONTROL_1       0x0000
#define DAC_CONTROL_2       0x1000
#define DAC_VOLUME_0        0x2000
#define DAC_VOLUME_1        0x3000
#define DAC_VOLUME_2        0x4000
#define DAC_VOLUME_3        0x5000
#define DAC_VOLUME_4        0x6000
#define DAC_VOLUME_5        0x7000
#define ADC_CONTROL_1       0xC000
#define ADC_CONTROL_2       0xD000
#define ADC_CONTROL_3       0xE000

// Access to the AD1836 control registers is over the SPI port.
// A 16 bit word is sent over SPI as data which is broken down
// as follows:
// +-------------------------------------------------+
// |Addr    | R/W   | RSVD   |   F u n c t i o n     |
// |-------------------------------------------------|
// | 15:12  |  11   |  xxx   |          9:0          |
// +-------------------------------------------------+
//
// See breakdown of control registers below or consult the
// data sheet for the AD1836 Multichannel 96 kHz Codec for
// function bits in each control register.
//
enum {
    ADI_AD1836_CMD_START=ADI_AD1836_ENUMERATION_START,  // 0x40050000
    ADI_AD1836_CMD_RESET,                               //0x0001 - Reset the AD1836 on the 533 ezkit        (NULL Value)
    ADI_AD1836_CMD_SET_OPERATION_MODE_I2S,              //0x0002 - I2S operation mode for codec and sport   (NULL value)
    ADI_AD1836_CMD_SET_OPERATION_MODE_TDM,              //0x0003 - TDM operation mode for codec and sport   (NULL value)
    ADI_AD1836_CMD_SET_AD1836_DAC_CONTROL_1,            //0x0004 - AD1836 DAC_CONTROL_1 register            (value = DAC_CONTROL_1 | 10 bit function code)
    ADI_AD1836_CMD_SET_AD1836_DAC_CONTROL_2,            //0x0005 - AD1836 DAC_CONTROL_2 register            (value = DAC_CONTROL_2 | 10 bit function code)
    ADI_AD1836_CMD_SET_AD1836_DAC_VOLUME_0,             //0x0006 - AD1836 DAC_VOLUME_0 register             (value = DAC_VOLUME_0 | 10 bit function code)
    ADI_AD1836_CMD_SET_AD1836_DAC_VOLUME_1,             //0x0007 - AD1836 DAC_VOLUME_1 register             (value = DAC_VOLUME_1 | 10 bit function code)
    ADI_AD1836_CMD_SET_AD1836_DAC_VOLUME_2,             //0x0008 - AD1836 DAC_VOLUME_2 register             (value = DAC_VOLUME_2 | 10 bit function code)
    ADI_AD1836_CMD_SET_AD1836_DAC_VOLUME_3,             //0x0009 - AD1836 DAC_VOLUME_3 register             (value = DAC_VOLUME_3 | 10 bit function code)
    ADI_AD1836_CMD_SET_AD1836_DAC_VOLUME_4,             //0x000a - AD1836 DAC_VOLUME_4 register             (value = DAC_VOLUME_4 | 10 bit function code)
    ADI_AD1836_CMD_SET_AD1836_DAC_VOLUME_5,             //0x000b - AD1836 DAC_VOLUME_5 register             (value = DAC_VOLUME_5 | 10 bit function code)
    ADI_AD1836_CMD_SET_AD1836_ADC_CONTROL_1,            //0x000c - AD1836 ADC_CONTROL_1 register            (value = ADC_CONTROL_1 | 10 bit function code)
    ADI_AD1836_CMD_SET_AD1836_ADC_CONTROL_2,            //0x000d - AD1836 ADC_CONTROL_2 register            (value = ADC_CONTROL_2 | 10 bit function code)
    ADI_AD1836_CMD_SET_AD1836_ADC_CONTROL_3,            //0x000e - AD1836 ADC_CONTROL_3 register            (value = ADC_CONTROL_3 | 10 bit function code)
    ADI_AD1836_CMD_SET_AD1836_SPI_SLAVE_SELECT,         //0x000f - AD1836 Slave Select                      (Slave Flag Value)

    // no longer used
    ADI_AD1836_CMD_SET_AD1836_SPI_Slave_Select = ADI_AD1836_CMD_SET_AD1836_SPI_SLAVE_SELECT
};

/*********************************************************************

Data Structures

*********************************************************************/
#pragma pack(2)         // needed to allow these to be 16 bit entries
typedef struct {
    //Function Code Begin
    volatile u16                    :1;
    volatile u16 interpolatormode   :1; //0=8x48kHz, 1=4x96kHz
    volatile u16 powerdownreset     :1; //0=normal, 1=pwrdwn
    volatile u16 datawordwidth      :2; //00=24, 01=20,10=16, 11=rsvd
    volatile u16 serialmode         :3; //000=i2s,rj,dsp,lj,pack256,pack128,rsvd,rsvd
    volatile u16 deemphasis         :2; //00=none, 01=44.1kHz, 10=32.0kHz, 11=48.0kHz
    //Function Code End
    volatile u16                    :1; //reserved
    volatile u16 rnw                :1; //access direction: 0=write, 1=read
    volatile u16 address            :4; //'address' of DAC_CONTROL_REGISTER1
} ADI_AD1836_DAC_CONTROL_REGISTER1;

typedef struct {
    volatile u16 mutedac0           :1; // 1=mute, 0=on
    volatile u16 mutedac1           :1;
    volatile u16 mutedac2           :1;
    volatile u16 mutedac3           :1;
    volatile u16 mutedac4           :1;
    volatile u16 mutedac5           :1;
    volatile u16                    :5;
    volatile u16 rnw                :1;
    volatile u16 address            :4;
} ADI_AD1836_DAC_CONTROL_REGISTER2;

typedef struct {
    volatile u16 volume             :10; // 0 - 1023 in linear steps
    volatile u16                    :1;
    volatile u16 rnw                :1;
    volatile u16 address            :4;
} ADI_AD1836_DAC_VOLUME_REGISTER;

typedef struct {
    volatile u16 rightgain      :3; //000=0dB,001=3dB,010=6dB,011=9dB,100=12dB
    volatile u16 leftgain       :3; //same as above
    volatile u16 samplerate     :1; //0=48kHz,1=96kHz
    volatile u16 powerdown      :1; //0=normal,1=pwrdown
    volatile u16 filter         :1; //0=DC,1=high-pass
    volatile u16                :2;
    volatile u16 rnw            :1;
    volatile u16 address        :4;
} ADI_AD1836_ADC_CONTROL_REGISTER1;

typedef struct {
    volatile u16 adcmute0           :1; //w/gain 0=on,1=mute
    volatile u16 adcmute1           :1; //w/gain
    volatile u16 adcmute2           :1; //0=on,1=mute
    volatile u16 adcmute3           :1; //0=on,1=mute
    volatile u16 wordwidth          :2; //00=24,01=20,10=16,11=invalid
    volatile u16 soutmode           :3; //000=i2s,rj,dsp,lj,pack256,pack128,pack,aux
    volatile u16 masterslaveauxmode :1; //0=slave,1=master
    volatile u16                    :1;
    volatile u16 rnw                :1;
    volatile u16 address            :4;
} ADI_AD1836_ADC_CONTROL_REGISTER2;

typedef struct {
    volatile u16 rightmuxipselect   :1; //0=i/p 0, 1=i/p 1
    volatile u16 rightmuxpgaenable  :1; //0=direct, 1=mux/pga
    volatile u16 leftmuxipselect    :1;
    volatile u16 leftmuxpgaenable   :1;
    volatile u16 rightdiffipselect  :1; //0=differential pga mode,
    volatile u16 leftdiffipselect   :1; //1=pga/mux mode (single ended input)
    volatile u16 clockmode          :2; //00=256 x fs, 01=512 x fs, 10=768 x fs
    volatile u16                    :3;
    volatile u16 rnw                :1;
    volatile u16 address            :4;
} ADI_AD1836_ADC_CONTROL_REGISTER3;

#pragma pack()

// entry point
extern ADI_DEV_PDD_ENTRY_POINT ADIAD1836EntryPoint;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_AD1836_H__ */
