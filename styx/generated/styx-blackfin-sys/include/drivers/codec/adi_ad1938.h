/*********************************************************************************

Copyright(c) 2005 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

Description:
        This is the include file for the AD1938 Audio Codec device driver.
                It uses adi_spi(to configure the AD1938) and adi_sport (for data
                processing)
*********************************************************************************/

#ifndef __ADI_AD1938_H__
#define __ADI_AD1938_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */



//--------------------------------------------------------------------------//
// Symbolic constants                                                       //
//--------------------------------------------------------------------------//

// Names for codec registers with address fields preinitialized.
// bitwise or in the function bits, leaving the top 5 bits in tact
// as the address and direction for the spi port access of the codec
// register.
#define PLL_CLOCK_CONTROL_0     0x00
#define PLL_CLOCK_CONTROL_1     0x01
#define DAC_CONTROL_0           0x02
#define DAC_CONTROL_1           0x03
#define DAC_CONTROL_2           0x04
#define DAC_IND_CHANNEL_MUTES   0x05
#define DAC_1LVOLUME_CONTROL    0x06
#define DAC_1RVOLUME_CONTROL    0x07
#define DAC_2LVOLUME_CONTROL    0x08
#define DAC_2RVOLUME_CONTROL    0x09
#define DAC_3LVOLUME_CONTROL    0x0a
#define DAC_3RVOLUME_CONTROL    0x0b
#define DAC_4LVOLUME_CONTROL    0x0c
#define DAC_4RVOLUME_CONTROL    0x0d
#define ADC_CONTROL_0           0x0e
#define ADC_CONTROL_1           0x0f
#define ADC_CONTROL_2           0x10

// Access to the AD1938 control registers is over the SPI port.
// A 24 bit frame is sent over SPI as data which is broken down
// as follows:
// +------------------------------------------------+
// |Glabal Addr | R/W | Register Addr |   Data      |
// |------------------------------------------------|
// | 23:17      |  16 |  15:8         |   7:0       |
// +------------------------------------------------+
//
// See breakdown of control registers below or consult the
// data sheet for the AD1938 Multichannel 192 kHz Codec for
// function bits in each control register.
//

/*********************************************************************
*
* Extensible enumerations for command IDs
*
*********************************************************************/

enum {
    ADI_AD1938_CMD_START=ADI_AD1938_ENUMERATION_START,
    ADI_AD1938_CMD_SET_OPERATION_MODE_I2S,          // - I2S operation mode for codec and sport (NULL value)
    ADI_AD1938_CMD_SET_OPERATION_MODE_TDM,          // - TDM operation mode for codec and sport (NULL value)
    //ADI_AD1938_CMD_SET_OPERATION_MODE_AUX,        // - AUX operation mode for codec and sport (NULL value)
    //ADI_AD1938_CMD_SET_OPERATION_MODE_DLTDM,      // - DualLine TDM operation mode for codec and sport (NULL value)

    // command to open SPI driver
    ADI_AD1938_CMD_OPEN_SPI,

    // command to open SPORT driver
    ADI_AD1938_CMD_OPEN_SPORT,

    // set SPI slave select command
    ADI_AD1938_CMD_SET_SPI_SLAVE_SELECT,

    // read active SPI slave select command
    ADI_AD1938_CMD_GET_SPI_SLAVE_SELECT,


    // write to register commands
    ADI_AD1938_CMD_SET_PLL_CLOCK_CONTROL_0,         // - AD1938 PLL_CLOCK_CONTROL_0 register
    ADI_AD1938_CMD_SET_PLL_CLOCK_CONTROL_1,         // - AD1938 PLL_CLOCK_CONTROL_1 register
    ADI_AD1938_CMD_SET_DAC_CONTROL_0,               // - AD1938 DAC_CONTROL_0 register
    ADI_AD1938_CMD_SET_DAC_CONTROL_1,               // - AD1938 DAC_CONTROL_1 register
    ADI_AD1938_CMD_SET_DAC_CONTROL_2,               // - AD1938 DAC_CONTROL_2 register
    ADI_AD1938_CMD_SET_DAC_CHANNEL_MUTES,           // - AD1938 DAC_IND_CHANNEL_MUTES register
    ADI_AD1938_CMD_SET_DAC_1LVOLUME_CONTROL,// -AD1938 DAC_1LVOLUME_CONTROL
    ADI_AD1938_CMD_SET_DAC_1RVOLUME_CONTROL,// -AD1938 DAC_1RVOLUME_CONTROL
    ADI_AD1938_CMD_SET_DAC_2LVOLUME_CONTROL,// -AD1938 DAC_2LVOLUME_CONTROL
    ADI_AD1938_CMD_SET_DAC_2RVOLUME_CONTROL,// -AD1938 DAC_2RVOLUME_CONTROL
    ADI_AD1938_CMD_SET_DAC_3LVOLUME_CONTROL,// -AD1938 DAC_3LVOLUME_CONTROL
    ADI_AD1938_CMD_SET_DAC_3RVOLUME_CONTROL,// -AD1938 DAC_3RVOLUME_CONTROL
    ADI_AD1938_CMD_SET_DAC_4LVOLUME_CONTROL,// -AD1938 DAC_4LVOLUME_CONTROL
    ADI_AD1938_CMD_SET_DAC_4RVOLUME_CONTROL,// -AD1938 DAC_4RVOLUME_CONTROL
    ADI_AD1938_CMD_SET_ADC_CONTROL_0,       // - AD1938 ADC_CONTROL_0 register
    ADI_AD1938_CMD_SET_ADC_CONTROL_1,       // - AD1938 ADC_CONTROL_1 register
    ADI_AD1938_CMD_SET_ADC_CONTROL_2,       // - AD1938 ADC_CONTROL_2 register

    // read from register commands
    ADI_AD1938_CMD_GET_PLL_CLOCK_CONTROL_0,         // - Read AD1938 PLL_CLOCK_CONTROL_0 register
    ADI_AD1938_CMD_GET_PLL_CLOCK_CONTROL_1,         // - Read AD1938 PLL_CLOCK_CONTROL_1 register
    ADI_AD1938_CMD_GET_DAC_CONTROL_0,               // - Read AD1938 DAC_CONTROL_0 register
    ADI_AD1938_CMD_GET_DAC_CONTROL_1,               // - Read AD1938 DAC_CONTROL_1 register
    ADI_AD1938_CMD_GET_DAC_CONTROL_2,               // - Read AD1938 DAC_CONTROL_2 register
    ADI_AD1938_CMD_GET_DAC_CHANNEL_MUTES,           // - Read AD1938 DAC_IND_CHANNEL_MUTES register
    ADI_AD1938_CMD_GET_DAC_VOLUME_CONTROLS,         // - Read AD1938 DAC_VOLUME_CONTROLS register
    ADI_AD1938_CMD_GET_DAC_1LVOLUME_CONTROL,// Read AD1938 DAC_1LVOLUME_CONTROL register
    ADI_AD1938_CMD_GET_DAC_1RVOLUME_CONTROL,// Read AD1938 DAC_1RVOLUME_CONTROL register
    ADI_AD1938_CMD_GET_DAC_2LVOLUME_CONTROL,// Read AD1938 DAC_2LVOLUME_CONTROL register
    ADI_AD1938_CMD_GET_DAC_2RVOLUME_CONTROL,// Read AD1938 DAC_2RVOLUME_CONTROL register
    ADI_AD1938_CMD_GET_DAC_3LVOLUME_CONTROL,// Read AD1938 DAC_3LVOLUME_CONTROL register
    ADI_AD1938_CMD_GET_DAC_3RVOLUME_CONTROL,// Read AD1938 DAC_3RVOLUME_CONTROL register
    ADI_AD1938_CMD_GET_DAC_4LVOLUME_CONTROL,// Read AD1938 DAC_4LVOLUME_CONTROL register
    ADI_AD1938_CMD_GET_DAC_4RVOLUME_CONTROL,// Read AD1938 DAC_4RVOLUME_CONTROL register

    ADI_AD1938_CMD_GET_ADC_CONTROL_0,       // - Read AD1938 ADC_CONTROL_0 register
    ADI_AD1938_CMD_GET_ADC_CONTROL_1,       // - Read AD1938 ADC_CONTROL_1 register
    ADI_AD1938_CMD_GET_ADC_CONTROL_2,       // - Read AD1938 ADC_CONTROL_2 register

    // PLL Control-0 set commands
    ADI_AD1938_CMD_SET_PLL_MODE,        // 0=normal operation   1=power down
    ADI_AD1938_CMD_SET_PLL_MCLK,        // 00=input 256(x44.1 or 48kHz) 01=input 384(x44.1 or 48kHz)
                                        // 10=input 512(x44.1 or 48kHz) 11=input 768(x44.1 or 48kHz)
    ADI_AD1938_CMD_SET_PLL_MCLK_O,      // 00=XTAL Osc enable 01=256xfs VCO output
                                        // 10=512xfs VCO output 11=off
    ADI_AD1938_CMD_SET_PLL_INPUT,       // 00=MCLK 01=DLRCLK 10=ALRCLK 11=reserved
    ADI_AD1938_CMD_SET_ADC_DAC_ACTIVE,  // 0=ADC&DAC idle   1=ADC&DAC active

    // PLL Control-0 get commands
    ADI_AD1938_CMD_GET_PLL_MODE,
    ADI_AD1938_CMD_GET_PLL_MCLK,
    ADI_AD1938_CMD_GET_PLL_MCLK_O,
    ADI_AD1938_CMD_GET_PLL_INPUT,
    ADI_AD1938_CMD_GET_ADC_DAC_ACTIVE,

    // PLL Control-1 set commands
    ADI_AD1938_CMD_SET_DAC_CLOCK_SOURCE,// 0=PLL clock  1=MCLK Select DAC clock source
    ADI_AD1938_CMD_SET_ADC_CLOCK_SOURCE,// 0=PLL clock  1=MCLK Select ADC clock source
    ADI_AD1938_CMD_SET_VOLTAGE_REFERENCE,// 0=enable    1=disable ;On-chip Volt Reference

    //PLL Control-1 get commands
    ADI_AD1938_CMD_GET_DAC_CLOCK_SOURCE,
    ADI_AD1938_CMD_GET_ADC_CLOCK_SOURCE,
    ADI_AD1938_CMD_GET_VOLTAGE_REFERENCE,
    ADI_AD1938_CMD_GET_PLL_LOCK_STATUS, // Read PLL lock indicator,0=not locked 1=locked

    // DAC set commands for Control_0 register
    ADI_AD1938_CMD_SET_DAC_MODE,        // 0=normal operation   1=power down
    ADI_AD1938_CMD_SET_DAC_SAMPLE_RATE, // 00=32/44.1/48kHz 01=64/88.2/96kHz
                                        // 10=128/176.4/192kHz 11= reserved
    ADI_AD1938_CMD_SET_DAC_SDATA_DELAY, // 000=1    001=0   010=8   011=12  100=16 (BCLK periods)
                                        // 101=reserved 110=reserved 111=reserved
    ADI_AD1938_CMD_SET_DAC_SERIAL_FORMAT,// 00=stereo   01=TDM  10=AUX  11=dual-line TDM

    // DAC get commands for Control_0 register
    ADI_AD1938_CMD_GET_DAC_MODE,
    ADI_AD1938_CMD_GET_DAC_SAMPLE_RATE,
    ADI_AD1938_CMD_GET_DAC_SDATA_DELAY,
    ADI_AD1938_CMD_GET_DAC_SERIAL_FORMAT,


    // DAC set commands for Control_1 register
    ADI_AD1938_CMD_SET_DAC_BCLK_ACTIVE_EDGE,// 0=latch in mid cycle 1=latch in at end of cycle
    ADI_AD1938_CMD_SET_DAC_NUMBER_OF_CHANNEL,//BCLKs per frame 00=64(2chan) 01=128(4chan)   10=256(8chan)   11=512(16chan)
    ADI_AD1938_CMD_SET_DAC_LRCLK_POLARITY,// 0=left low 1=left high
    ADI_AD1938_CMD_SET_DAC_LRCLK_MASTER_SLAVE,// 0=LRCLK slave  1=LRCLK master
    ADI_AD1938_CMD_SET_DAC_BCLK_MASTER_SLAVE,// 0=BCLK slave    1=BCLK master
    ADI_AD1938_CMD_SET_DAC_BCLK_SOURCE,// 0=DBCLK pin   1=internally generated
    ADI_AD1938_CMD_SET_DAC_BCLK_POLARITY,// 0=normal    1=inverted

    // DAC get commands for Control_1 register
    ADI_AD1938_CMD_GET_DAC_BCLK_ACTIVE_EDGE,
    ADI_AD1938_CMD_GET_DAC_NUMBER_OF_CHANNEL,
    ADI_AD1938_CMD_GET_DAC_LRCLK_POLARITY,
    ADI_AD1938_CMD_GET_DAC_LRCLK_MASTER_SLAVE,
    ADI_AD1938_CMD_GET_DAC_BCLK_MASTER_SLAVE,
    ADI_AD1938_CMD_GET_DAC_BCLK_SOURCE,
    ADI_AD1938_CMD_GET_DAC_BCLK_POLARITY,



    // DAC set commands for Control_2 register
    ADI_AD1938_CMD_SET_DAC_MASTER_MUTE,// 0=unmute  1=mute
    ADI_AD1938_CMD_SET_DAC_DEEMPHASIS_MODE,// 00=flat   01=48kHz curve  10=44.1kHz curve    11=32kHz curve
    ADI_AD1938_CMD_SET_DAC_WORD_WIDTH,// 00=24  01=20   10=reserved  11=16
    ADI_AD1938_CMD_SET_DAC_OUTPUT_POLARITY,// 0=non-inverted    1=inverted

    // DAC get commands for Control_2 register
    ADI_AD1938_CMD_GET_DAC_MASTER_MUTE,
    ADI_AD1938_CMD_GET_DAC_DEEMPHASIS_MODE,
    ADI_AD1938_CMD_GET_DAC_WORD_WIDTH,
    ADI_AD1938_CMD_GET_DAC_OUTPUT_POLARITY,


    // DAC set commands for Individual channel mutes register
    ADI_AD1938_CMD_SET_DAC_1LEFT_MUTE,// 0=unmute   1=mute
    ADI_AD1938_CMD_SET_DAC_1RIGHT_MUTE,// 0=unmute  1=mute
    ADI_AD1938_CMD_SET_DAC_2LEFT_MUTE,// 0=unmute   1=mute
    ADI_AD1938_CMD_SET_DAC_2RIGHT_MUTE,// 0=unmute  1=mute
    ADI_AD1938_CMD_SET_DAC_3LEFT_MUTE,// 0=unmute   1=mute
    ADI_AD1938_CMD_SET_DAC_3RIGHT_MUTE,// 0=unmute  1=mute
    ADI_AD1938_CMD_SET_DAC_4LEFT_MUTE,// 0=unmute   1=mute
    ADI_AD1938_CMD_SET_DAC_4RIGHT_MUTE,// 0=unmute  1=mute

    // DAC get commands for Individual channel mutes register
    ADI_AD1938_CMD_GET_DAC_1LEFT_MUTE,
    ADI_AD1938_CMD_GET_DAC_1RIGHT_MUTE,
    ADI_AD1938_CMD_GET_DAC_2LEFT_MUTE,
    ADI_AD1938_CMD_GET_DAC_2RIGHT_MUTE,
    ADI_AD1938_CMD_GET_DAC_3LEFT_MUTE,
    ADI_AD1938_CMD_GET_DAC_3RIGHT_MUTE,
    ADI_AD1938_CMD_GET_DAC_4LEFT_MUTE,
    ADI_AD1938_CMD_GET_DAC_4RIGHT_MUTE,

    // ADC set commands for Control_0 register
    ADI_AD1938_CMD_SET_ADC_MODE,        // 0=normal operation   1=power down
    ADI_AD1938_CMD_SET_ADC_HP_FILTER,   // 0=highpass filter off    1=highpass filter on
    ADI_AD1938_CMD_SET_ADC_1L_MUTE,     // 0=unmute 1=mute
    ADI_AD1938_CMD_SET_ADC_1R_MUTE,     // 0=unmute 1=mute
    ADI_AD1938_CMD_SET_ADC_2L_MUTE,     // 0=unmute 1=mute
    ADI_AD1938_CMD_SET_ADC_2R_MUTE,     // 0=unmute 1=mute
    ADI_AD1938_CMD_SET_ADC_SAMPLE_RATE,// 00=32/44.1/48     01=64/88.2/96

    // ADC get commands for Control_0 register
    ADI_AD1938_CMD_GET_ADC_MODE,
    ADI_AD1938_CMD_GET_ADC_HP_FILTER,
    ADI_AD1938_CMD_GET_ADC_1L_MUTE,
    ADI_AD1938_CMD_GET_ADC_1R_MUTE,
    ADI_AD1938_CMD_GET_ADC_2L_MUTE,
    ADI_AD1938_CMD_GET_ADC_2R_MUTE,
    ADI_AD1938_CMD_GET_ADC_SAMPLE_RATE,

    // ADC set commands for Control_1 register
    ADI_AD1938_CMD_SET_ADC_WORD_WIDTH,// 00=24  01=20   10=reserved     11=16
    ADI_AD1938_CMD_SET_ADC_SDATA_DELAY, // 000=1    001=0   010=8   011=12  100=16 (BCLK periods)
                                        // 101=reserved 110=reserved 111=reserved
    ADI_AD1938_CMD_SET_ADC_SERIAL_FORMAT,// 00=stereo   01=TDM  10=AUX  11=dual-line TDM
    ADI_AD1938_CMD_SET_ADC_BCLK_ACTIVE_EDGE,// 0=latch in mid cycle 1=latch in at end of cycle

    // ADC get commands for Control_1 register
    ADI_AD1938_CMD_GET_ADC_WORD_WIDTH,
    ADI_AD1938_CMD_GET_ADC_SDATA_DELAY,
    ADI_AD1938_CMD_GET_ADC_SERIAL_FORMAT,
    ADI_AD1938_CMD_GET_ADC_BCLK_ACTIVE_EDGE,

    // ADC set commands for Control_2 register
    ADI_AD1938_CMD_SET_ADC_LRCLK_FORMAT,// 0=50/50(allows 32/24/20/16 BCLK/channel)
                                        // 1=pulse(32 BCLK/channel)
    ADI_AD1938_CMD_SET_ADC_BCLK_POLARITY,// 0=drive out on falling edge
                                         // 1=inverted
    ADI_AD1938_CMD_SET_ADC_LRCLK_POLARITY,// 0=left low 1=left high
    ADI_AD1938_CMD_SET_ADC_LRCLK_MASTER_SLAVE,// 0=LRCLK slave  1=LRCLK master
    ADI_AD1938_CMD_SET_ADC_BCLKS_FRAME,// 00=64 01=128  10=256  11=512
    ADI_AD1938_CMD_SET_ADC_BCLK_MASTER_SLAVE,// 0=BCLK slave    1=BCLK master
    ADI_AD1938_CMD_SET_ADC_BCLK_SOURCE,// 0=ABCLK pin   1=internally generated


    // ADC get commands for Control_2 register
    ADI_AD1938_CMD_GET_ADC_LRCLK_FORMAT,
    ADI_AD1938_CMD_GET_ADC_BCLK_POLARITY,
    ADI_AD1938_CMD_GET_ADC_LRCLK_POLARITY,
    ADI_AD1938_CMD_GET_ADC_LRCLK_MASTER_SLAVE,
    ADI_AD1938_CMD_GET_ADC_BCLKS_FRAME,
    ADI_AD1938_CMD_GET_ADC_BCLK_MASTER_SLAVE,
    ADI_AD1938_CMD_GET_ADC_BCLK_SOURCE



};

/*********************************************************************
*
* Extensible enumerations for return codes
*
*********************************************************************/

enum {
    ADI_AD1938_RESULT_START=ADI_AD1938_ENUMERATION_START,// insure this order remains
    ADI_AD1938_RESULT_OPERATION_MODE_NOT_SET,
    ADI_AD1938_RESULT_OPERATION_MODE_NOT_SUPPORTED,//
    ADI_AD1938_RESULT_WRITE_REGISTER_FAILED,// failed to write into register
    ADI_AD1938_RESULT_READ_REGISTER_FAILED,// failed to read content of a register
    ADI_AD1938_RESULT_OPEN_SPI_FAILED,// failed to open SPI port
    ADI_AD1938_RESULT_SPI_CONFIG_FAILED,// failed to configure SPI
    ADI_AD1938_RESULT_BAD_SPI_SLAVE_NUMBER, //not valid SPI slave number(expect 1-7)
    ADI_AD1938_RESULT_BAD_SPI_DEVICE,// bad value for SPI device, Blackfin has only 1 SPI
    ADI_AD1938_RESULT_OPEN_SPORT_FAILED,// failed to open SPORT
    ADI_AD1938_RESULT_SPORT_CONFIG_FAILED,// failed to configure SPORT
    ADI_AD1938_RESULT_BAD_SPORT_DEVICE,// bad value for SPORT device, Blackfin has only 2 SPORTs
    ADI_AD1938_RESULT_SPI_SPORT_NOT_OPENED,// SPI or SPORT not active
    ADI_AD1938_RESULT_BAD_VALUE  //bad value passed in

};


/*********************************************************************

Data Structures

*********************************************************************/
typedef struct {
    volatile u8 globaladd_rnw;      //AD1938 global address=0x04(7bit) & 1bit readandwrite
    volatile u8 registeraddress; // AD1938 register address
    volatile u8 registerdata;    // AD1938 register data
} ADI_AD1938_CONTROL_PACKET;


typedef struct {
    volatile u8 pllpowerdown       :1;// PLL 0=normal 1=power down,
    volatile u8 mclkpinfunction   :2; //INPUT 00=256x44.1 01=384x44.1 10=512x44.1 11=768x44.1
    volatile u8 mclk_Opin          :2; //00=Xtal_Osc_enable 01=256xfs_VCO_Output 10=512xfs_VCO_Output 11=Off
    volatile u8 pllinput           :2; //00=MCLK, 01=DLRCLK,10=ALRCLK, 11=rsvd
    volatile u8 internalmclkenable :1; //0=Disable:ADC&DAC_Idle 1=Enable:ADC&DAC_Active
} ADI_AD1938_PLL_CONTROL_REGISTER0;

typedef struct {
    volatile u8 dacclocksource     :1;// 0=PLL_clock 1=MCLK
    volatile u8 adcclocksource     :1;// 0=PLL_clock 1=MCLK
    volatile u8 onchipvoltref      :1;// 0=enable 1=disable
    volatile u8 plllockindi        :1;// 0=not_locked 1=locked (read only)
    volatile u8 reserved           :4; //reserved
} ADI_AD1938_PLL_CONTROL_REGISTER1;


typedef struct {
    volatile u8 powerdown          :1;// 0=normal 1=powerdown
    volatile u8 samplerate         :2;// 00=32/44.1/48kHz 01=64/88.2/96kHz 10=128/176.4/192kHz 11=reserved
    volatile u8 sdatadelay         :3;// 000=1 001=0 010=8 011=12 100=16 101=reserved 110=reserved 111=reserved
    volatile u8 serialformat       :2;// 00=stereo 01=TDM 10=DAC_Aux_mode 11=Dual_lineTDM
} ADI_AD1938_DAC_CONTROL_REGISTER0;

typedef struct {
    volatile u8 bclkactiveedge     :1;// 0=latch in mid cycle 1=latch in at end of cycle
    volatile u8 bclkperframe       :2;// 00=64(2channels) 01=128(4channels) 10=256(8channels) 11=512(16channels)
    volatile u8 lrclkpolarity      :1;// 0=left low 1=left high
    volatile u8 lrclkmasterslave   :1;// 0=slave 1=master
    volatile u8 bclkmasterslave    :1;// 0=slave 1=master
    volatile u8 bclksource         :1;// 0=DBCLK pin 1=Internally generated
    volatile u8 bclkpolarity       :1;// 0=normal 1=inverted
} ADI_AD1938_DAC_CONTROL_REGISTER1;

typedef struct {
    volatile u8 mastermute        :1;// 0=unmute 1=mute
    volatile u8 deemphasis         :2;// 00=flat 01=48kHz Curve 10=44.1kHz Curve 11=32kHz Curve
    volatile u8 wordwidth          :2;// 00=24 01=20 10=reserved 11=16
    volatile u8 dacoutputpolarity  :1;// 0=Non-inverted 1=inverted
    volatile u8 reserved           :2;// reserved
} ADI_AD1938_DAC_CONTROL_REGISTER2;

typedef struct {
    volatile u8 dac1leftmute       :1;// 0=unmute 1=mute
    volatile u8 dac1rightmute      :1;// 0=unmute 1=mute
    volatile u8 dac2leftmute       :1;// 0=unmute 1=mute
    volatile u8 dac2rightmute      :1;// 0=unmute 1=mute
    volatile u8 dac3leftmute       :1;// 0=unmute 1=mute
    volatile u8 dac3rightmute      :1;// 0=unmute 1=mute
    volatile u8 dac4leftmute       :1;// 0=unmute 1=mute
    volatile u8 dac4rightmute      :1;// 0=unmute 1=mute
} ADI_AD1938_DAC_CHANNEL_MUTES_REGISTER;


typedef struct {
    volatile u8  dacvolumecontrol;   // 0= no attenuation 1-254=-3/8 dB per step 255=full attenuation
} ADI_AD1938_DAC_VOLUME_CONTROL_REGISTER;

typedef struct {
    volatile u8 powerdown          :1; //0=normal 1=powerdown
    volatile u8 highpassfilter     :1; //0=off 1=on
    volatile u8 adc1lmute          :1; //0=unmute 1=mute
    volatile u8 adc1rmute          :1; //0=unmute 1=mute
    volatile u8 adc2lmute          :1; //0=unmute 1=mute
    volatile u8 adc2rmute          :1; //0=unmute 1=mute
    volatile u8 outputsamplerate   :2; //00=32/44.1/48 01=64/88.2/96 10=128/176.4/192 11=reserved
} ADI_AD1938_ADC_CONTROL_REGISTER0;

typedef struct {
    volatile u8 wordwidth          :2; //00=24 01=20 10=reserved 11=16
    volatile u8 sdatadelay         :3; //000=1 001=0 010=8 011=12 100=16(BCLK periods) 101-111=reserved
    volatile u8 serialformat       :2; //00=stereo 01=TDM(daisy chain) 10=ADC Aux mode 11=reserved
    volatile u8 bclkactiveedge     :1; //0=latch in mid cycle 1= latch in at end of cycle
} ADI_AD1938_ADC_CONTROL_REGISTER1;

typedef struct {
    volatile u8 lrclkformat         :1; //0=50/50(allows 32/24/20/16 BCLK/channel) 1=pulse(32 BCLK/channel)
    volatile u8 bclkpolarity        :1; //0=drive out on falling edge(DEF)  1=drive out on rising edge
    volatile u8 lrclkpolarity       :1; //0=left low 1=left high
    volatile u8 lrclkmasterslave   :1; //0=slave 1=master
    volatile u8 bclkperframe        :2; //00=64 01=128 10=256 11=512
    volatile u8 bclkmasterslave     :1; //0=slave 1=master
    volatile u8 bclksource          :1; //0=ABCLK pin 1=internally generated
} ADI_AD1938_ADC_CONTROL_REGISTER2;


// entry point
extern ADI_DEV_PDD_ENTRY_POINT ADIAD1938EntryPoint;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_AD1938_H__ */
