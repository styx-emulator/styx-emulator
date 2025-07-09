/******************************************************************************
Copyright (c), 2010 - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.

$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Title: Analog Devices SSM2603 - Low Power Audio CODEC driver

Description:
    This is the primary include file for ADI SSM2603 Audio CODEC driver
    The file defines enumerations, data structures and commands
    supported by SSM2603 Audio CODEC driver

Note: Access to the SSM2603 control registers is over TWI or SPI port.
      A 16 bit frame is sent over TWI/SPI and the data is broken down as

    +----------------------------------+
    | Register Address | Register Data |
    |----------------------------------|
    |       15:9       |      9:0      |
    +----------------------------------+

*****************************************************************************/

#ifndef __ADI_SSM2603_H__
#define __ADI_SSM2603_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*=============  E X T E R N A L S  ============*/

/*
** Entry point to the SSM2603 device driver
*/
extern ADI_DEV_PDD_ENTRY_POINT      ADISSM2603EntryPoint;

/*==============  D E F I N E S  ===============*/

/*
**
** SSM2603 Register definitions
**
*/

/* Left ADC Volume Control */
#define     SSM2603_REG_LEFT_ADC_VOL            0x00U
/* Right ADC Volume Control */
#define     SSM2603_REG_RIGHT_ADC_VOL           0x01U
/* Left DAC Volume Control */
#define     SSM2603_REG_LEFT_DAC_VOL            0x02U
/* Right DAC Volume Control */
#define     SSM2603_REG_RIGHT_DAC_VOL           0x03U
/* Analogue Audio Path Control */
#define     SSM2603_REG_ANALOGUE_PATH           0x04U
/* Digital Audio Path Control */
#define     SSM2603_REG_DIGITAL_PATH            0x05U
/* Power Management */
#define     SSM2603_REG_POWER                   0x06U
/* Digital Audio Interface Format */
#define     SSM2603_REG_DIGITAL_IFACE           0x07U
/* Sampling Control */
#define     SSM2603_REG_SAMPLING_CTRL           0x08U
/* Active Control */
#define     SSM2603_REG_ACTIVE_CTRL             0x09U
/* Reset Register (write only) */
#define     SSM2603_REG_RESET                   0x0FU
/* Automatic Level Control 1 */
#define     SSM2603_REG_ALC_1                   0x10U
/* Automatic Level Control 2 */
#define     SSM2603_REG_ALC_2                   0x11U
/* Noise Gate */
#define     SSM2603_REG_NOISE_GATE              0x12U

/*
**
** SSM2603 Codec Register Field definitions
** (Mask value to extract the corresponding Register field)
**
*/

/*
** Left ADC Volume Control (SSM2603_REG_LEFT_ADC_VOL)
*/

/* Left Channel PGA Volume Control */
#define     SSM2603_RFLD_LIN_VOL                0x03FU
/* Left Channel Input Mute */
#define     SSM2603_RFLD_LIN_ENABLE_MUTE        0x080U
/* Left Channel Line Input Volume update */
#define     SSM2603_RFLD_LRIN_BOTH              0x100U

/*
** Right ADC Volume Control (SSM2603_REG_RIGHT_ADC_VOL)
*/

/* Right Channel PGA Volume control */
#define     SSM2603_RFLD_RIN_VOL                0x03FU
/* Right Channel Input Mute */
#define     SSM2603_RFLD_RIN_ENABLE_MUTE        0x080U
/* Right Channel Line Input Volume update */
#define     SSM2603_RFLD_RLIN_BOTH              0x100U

/*
** Left DAC Volume Control (SSM2603_REG_LEFT_DAC_VOL)
*/

/* Left Channel Headphone volume control */
#define     SSM2603_RFLD_LHP_VOL                0x07FU
/* Left Channel Zero cross detect enable */
#define     SSM2603_RFLD_ENABLE_LZC             0x080U
/* Left Channel Headphone volume update */
#define     SSM2603_RFLD_LRHP_BOTH              0x100U

/*
** Right DAC Volume Control (SSM2603_REG_RIGHT_DAC_VOL)
*/

/* Right Channel Headphone volume control */
#define     SSM2603_RFLD_RHP_VOL                0x07FU
/* Right Channel Zero cross detect enable */
#define     SSM2603_RFLD_ENABLE_RZC             0x080U
/* Right Channel Headphone volume update */
#define     SSM2603_RFLD_RLHP_BOTH              0x100U

/*
** Analogue Audio Path Control (SSM2603_REG_ANALOGUE_PATH)
*/

/* Primary Microphone Amplifier gain booster control */
#define     SSM2603_RFLD_ENABLE_MIC_BOOST       0x001U
   /* Microphone Mute Control */
#define     SSM2603_RFLD_ENABLE_MIC_MUTE        0x002U
/* Microphone/Line IN select to ADC (1=MIC, 0=Line In) */
#define     SSM2603_RFLD_ADC_IN_SELECT          0x004U
/* Line input bypass to line output */
#define     SSM2603_RFLD_ENABLE_BYPASS          0x008U
/* Select DAC (1=Select DAC, 0=Don't Select DAC) */
#define     SSM2603_RFLD_SELECT_DAC             0x010U
/* Enable/Disable Side Tone */
#define     SSM2603_RFLD_ENABLE_SIDETONE        0x020U
/* Side Tone Attenuation */
#define     SSM2603_RFLD_SIDETONE_ATTN          0x0C0U
/* Additional Microphone amplifier gain booster control */
#define     SSM2603_RFLD_ENABLE_MIC_BOOST_2     0x100U

/*
** Digital Audio Path Control (SSM2603_REG_DIGITAL_PATH)
*/

/* Enable/Disable ADC Highpass Filter */
#define     SSM2603_RFLD_ENABLE_ADC_HPF         0x001U
/* De-Emphasis Control */
#define     SSM2603_RFLD_DE_EMPHASIS            0x006U
/* DAC Mute Control */
#define     SSM2603_RFLD_ENABLE_DAC_MUTE        0x008U
/* Store/Clear DC offset when HPF is disabled */
#define     SSM2603_RFLD_STORE_OFFSET           0x010U

/*
** Power Down Control (SSM2603_REG_POWER)
**  (1=Enable PowerDown, 0=Disable PowerDown)
*/

/* Line Input Power Down */
#define     SSM2603_RFLD_LINE_IN_PDN            0x001U
/* Microphone Input & Bias Power Down */
#define     SSM2603_RFLD_MIC_PDN                0x002U
/* ADC Power Down */
#define     SSM2603_RFLD_ADC_PDN                0x004U
/* DAC Power Down */
#define     SSM2603_RFLD_DAC_PDN                0x008U
/* Outputs Power Down */
#define     SSM2603_RFLD_OUT_PDN                0x010U
/* Oscillator Power Down */
#define     SSM2603_RFLD_OSC_PDN                0x020U
/* CLKOUT Power Down */
#define     SSM2603_RFLD_CLK_OUT_PDN            0x040U
/* POWEROFF Mode */
#define     SSM2603_RFLD_POWER_OFF              0x080U

/*
** Digital Audio Interface Format (SSM2603_REG_DIGITAL_IFACE)
*/

/* Digital Audio input format control */
#define     SSM2603_RFLD_IFACE_FORMAT           0x003U
/* Audio Data word length control */
#define     SSM2603_RFLD_AUDIO_DATA_LEN         0x00CU
/* Polarity Control for clocks in RJ,LJ and I2S modes */
#define     SSM2603_RFLD_DAC_LR_POLARITY        0x010U
/* Swap DAC data control */
#define     SSM2603_RFLD_DAC_LR_SWAP            0x020U
/* Enable/Disable Master Mode */
#define     SSM2603_RFLD_ENABLE_MASTER          0x040U
/* Bit Clock Inversion control */
#define     SSM2603_RFLD_BCLK_INVERT            0x080U

/*
** Sampling Control (SSM2603_REG_SAMPLING_CTRL)
*/

/* Enable/Disable USB Mode */
#define     SSM2603_RFLD_ENABLE_USB_MODE        0x001U
/* Base Over-Sampling rate */
#define     SSM2603_RFLD_BOS_RATE               0x002U
/* Clock setting condition (Sampling rate control) */
#define     SSM2603_RFLD_SAMPLE_RATE            0x03CU
/* Core Clock divider select */
#define     SSM2603_RFLD_CORECLK_DIV2           0x040U
/* Clock Out divider select */
#define     SSM2603_RFLD_CLKOUT_DIV2            0x080U

/*
** Active Control (SSM2603_REG_ACTIVE_CTRL)
*/

/* Activate Codec Digital Audio Interface */
#define     SSM2603_RFLD_ACTIVATE_CODEC         0x001U

/*
** Automatic Level Control Register 1 (SSM2603_REG_ALC_1)
*/

/* Automatic Level Control Target level */
#define     SSM2603_RFLD_ALC_TARGET             0x00FU
/* Automatic Level Control - PGA maximum Gain */
#define     SSM2603_RFLD_PGA_MAX_GAIN           0x070U
/* Automatic Level Control Selection */
#define     SSM2603_RFLD_ALC_SELECT             0x180U

/*
** Automatic Level Control Register 2 (SSM2603_REG_ALC_2)
*/

/* Automatic Level Control - Attack time control */
#define     SSM2603_RFLD_ALC_ATTACK_TIME        0x00FU
/* Automatic Level Control - Decay time control */
#define     SSM2603_RFLD_ALC_DECAY_TIME         0x0F0U

/*
** Noise Gate (SSM2603_REG_NOISE_GATE)
*/

/* Enable/Disable Noise Gate */
#define     SSM2603_RFLD_ENABLE_NG              0x001U
/* Noise Gate Type */
#define     SSM2603_RFLD_NG_TYPE                0x006U
/* Noise Gate Threshold */
#define     SSM2603_RFLD_NG_THRESHOLD           0x0F8U

/*=============  D A T A    T Y P E S   =============*/

/* IF (Build for C language) */
#if defined(_LANGUAGE_C)

/*
**
** List of ADC/DAC Sample Rates (in Hz) supported by SSM2603
**
** Note: While operating SSM2603 in Slave mode, make sure that
**       Blackfin SCLK is set to Multiples of ADC/DAC sampling rate
**       before activating the Audio Codec. Blackfin SPORT derives the
**       Bit Clock and Frame Sync from SCLK.
**/

enum
{

    /* Sampling rate = 96kHz */
    ADI_SSM2603_SR_96000    = 96000U,
    /* Sampling rate = 88.2kHz */
    ADI_SSM2603_SR_88200    = 88200U,
    /* Sampling rate = 48kHz */
    ADI_SSM2603_SR_48000    = 48000U,
    /* Sampling rate = 44.1kHz */
    ADI_SSM2603_SR_44100    = 44100U,
    /* Sampling rate = 32kHz */
    ADI_SSM2603_SR_32000    = 32000U,
    /* Sampling rate = 24kHz */
    ADI_SSM2603_SR_24000    = 24000U,
    /* Sampling rate = 22.05kHz */
    ADI_SSM2603_SR_22050    = 22050U,
    /* Sampling rate = 16kHz */
    ADI_SSM2603_SR_16000    = 16000U,
    /* Sampling rate = 12kHz */
    ADI_SSM2603_SR_12000    = 12000U,
    /* Sampling rate = 11.025kHz */
    ADI_SSM2603_SR_11025    = 11025U,
    /* Sampling rate = 8.02kHz */
    ADI_SSM2603_SR_8020     =  8020U,
    /* Sampling rate = 8kHz */
    ADI_SSM2603_SR_8000     =  8000U

};

/*
**
** List of Master Clock (MCLK) Frequencies supported by SSM2603
**
*/

typedef enum __AdiSSM2603MclkFreq
{

    /* MCLK = 11.2896 MHz */
    ADI_SSM2603_MCLK_11_2896 = 0,
    /* MCLK = 12 MHz */
    ADI_SSM2603_MCLK_12,
    /* MCLK = 12.288 MHz */
    ADI_SSM2603_MCLK_12_288,
    /* MCLK = 16.9344 MHz */
    ADI_SSM2603_MCLK_16_9344,
    /* MCLK = 18.432 MHz */
    ADI_SSM2603_MCLK_18_432,
    /* MCLK = 22.5792 MHz */
    ADI_SSM2603_MCLK_22_5792,
    /* MCLK = 24 MHz */
    ADI_SSM2603_MCLK_24,
    /* MCLK = 24.576 MHz */
    ADI_SSM2603_MCLK_24_576,
    /* MCLK = 33.8688 MHz */
    ADI_SSM2603_MCLK_33_8688,
    /* MCLK = 36.864 MHz */
    ADI_SSM2603_MCLK_36_864

} ADI_SSM2603_MCLK_FREQ;

/*
** Data Structure to pass ADC/DAC sampling rate
*/

typedef struct __AdiSsm2603SampleRate
{

    /* ADC Sample rate  */
    u32     nAdcSampleRate;

    /* DAC Sample rate  */
    u32     nDacSampleRate;

} ADI_SSM2603_SAMPLE_RATE;

/*
**
** Extensible Enumerations for SSM2603 Driver Command IDs
**
*/

enum
{
    /* 0x40310000 - SSM2603 Driver command enumeration start */
    ADI_SSM2603_CMD_START = ADI_SSM2603_ENUMERATION_START,


    /*
    ** SPI related commands
    */

    /* 0x40310001 - Sets SSM2603 driver to use SPI to
                    access SSM2603 hardware registers
                    Value = u8 (SPI Device Number to use)
                    Default = 0 (SPI Device 0) */
    ADI_SSM2603_CMD_SET_SPI_DEVICE_NUMBER,

    /* 0x40310002 - Sets SPI Chipselect number connected to SSM2603 CSB pin
                    Value = u8 (SPI Chipselect)
                    Default = 0 (chipselect not valid) */
    ADI_SSM2603_CMD_SET_SPI_CS,

    /*
    ** TWI related commands
    */

    /* 0x40310003 - Sets SSM2603 driver to use TWI to
                    access SSM2603 hardware registers
                    Value = u8 (TWI Device Number to use)
                    Default - Uses SPI device 0 */
    ADI_SSM2603_CMD_SET_TWI_DEVICE_NUMBER,

    /* 0x40310004 - Sets SSM2603 TWI Global Address to use
                    Value = u8 (TWI Global Address for SSM2603)
                    Default = 0x1A (possible values = 0x1A or 0x1B) */
    ADI_SSM2603_CMD_SET_TWI_GLOBAL_ADDR,

    /*
    ** Command common to SPI and TWI
    */

    /* 0x40310005 - Sets TWI or SPI configuration table to be used to
                    access SSM2603 device registers
                    Value = ADI_DEV_CMD_VALUE_PAIR *
                           (address of a command/value pair table)
                    Default = NULL
                    Note: Client MUST submit a configuration table when
                          the driver is set to use TWI to access
                          SSM2603 registers. Configuration table is
                          optional for SPI based register access  */
    ADI_SSM2603_CMD_SET_TWI_SPI_CONFIG_TABLE,

    /*
    ** SPORT related commands
    */

    /* 0x40310006 - Sets SPORT device number connected to
                    SSM2603 Digital Audio Interface port
                    Value = u8 (SPORT Device Number to use)
                    Default = 0 (SPORT Device 0) */
    ADI_SSM2603_CMD_SET_SPORT_DEVICE_NUMBER,

    /* 0x40310007 - Opens/Closes SPORT device connected to SSM2603
                    Value = TRUE/FALSE (TRUE to open, FALSE to close)
                    Default = Opens SPORT device when application
                              issues ADI_DEV_CMD_SET_DATAFLOW_METHOD command
                    Note: Command can be used to share one SPORT channel
                          between multiple devices */
    ADI_SSM2603_CMD_OPEN_SPORT_DEVICE,

    /* 0x40310008 - Enables/Disables Auto-SPORT configuration mode
                    Value = TRUE/FALSE (TRUE to enable, FALSE to disable)
                    Default = TRUE
                              (Auto-SPORT configuration is enabled by default)
                    Note: Auto-SPORT configuration is not supported for
                          Right-Justified (RJ) and DSP modes */
    ADI_SSM2603_CMD_ENABLE_AUTO_SPORT_CONFIG,

    /*
    ** SSM2603 register configuration commands
    */

    /* 0x40310009 - Configures SSM2603 sampling control register with
                    given ADC/DAC sample rate. Application MUST disable
                    codec dataflow before issuing this command
                    Value = ADI_SSM2603_SAMPLE_RATE *
                            (pointer to ADI_SSM2603_SAMPLE_RATE structure) */
    ADI_SSM2603_CMD_SET_SAMPLE_RATE,

    /* 0x4031000A - Passes MCLK (operating) frequency of SSM2603 device
                    The driver updates USB, BOSR and CLKDIV2 fields in
                    Sampling rate register based on the supplied MCLK value
                    Value = Enumerated value of type ADI_SSM2603_MCLK_FREQ
                    Default = ADI_SSM2603_MCLK_12_288 */
    ADI_SSM2603_CMD_PASS_MCLK_FREQ

    /*  Use Device Access Commands (defined in adi_dev.h) to access SSM2603 hardware registers

        List of Device Access Commands supported by SSM2603 driver
        +-----------------------------------------------------------------------------------------------------------------------------------+
        |           Command ID                      |       Command Argument            |               Comments                            |
        +-----------------------------------------------------------------------------------------------------------------------------------+
        | ADI_DEV_CMD_REGISTER_READ                 | ADI_DEV_ACCESS_REGISTER *         | Reads a single SSM2603 register                   |
        | ADI_DEV_CMD_REGISTER_FIELD_READ           | ADI_DEV_ACCESS_REGISTER_FIELD *   | Reads a specific SSM2603 register field           |
        | ADI_DEV_CMD_REGISTER_TABLE_READ           | ADI_DEV_ACCESS_REGISTER *         | Reads a table of SSM2603 registers                |
        | ADI_DEV_CMD_REGISTER_FIELD_TABLE_READ     | ADI_DEV_ACCESS_REGISTER_FIELD *   | Reads a table of SSM2603 register(s) field(s)     |
        | ADI_DEV_CMD_REGISTER_BLOCK_READ           | ADI_DEV_ACCESS_REGISTER_BLOCK *   | Reads a block of consecutive SSM2603 registers    |
        |                                           |                                   |                                                   |
        | ADI_DEV_CMD_REGISTER_WRITE                | ADI_DEV_ACCESS_REGISTER *         | Writes to a single SSM2603 register               |
        | ADI_DEV_CMD_REGISTER_FIELD_WRITE          | ADI_DEV_ACCESS_REGISTER_FIELD *   | Writes to a SSM2603 register field                |
        | ADI_DEV_CMD_REGISTER_TABLE_WRITE          | ADI_DEV_ACCESS_REGISTER *         | Writes to a table of SSM2603 registers            |
        | ADI_DEV_CMD_REGISTER_FIELD_TABLE_WRITE    | ADI_DEV_ACCESS_REGISTER_FIELD *   | Writes to a table of SSM2603 register(s) field(s) |
        | ADI_DEV_CMD_REGISTER_BLOCK_WRITE          | ADI_DEV_ACCESS_REGISTER_BLOCK *   | Writes to a block of consecutive SSM2603 registers|
        +-----------------------------------------------------------------------------------------------------------------------------------+
    */

};

/*
**
** Extensible Enumerations for SSM2603 Driver Event IDs
**
*/

enum
{
    /* 0x40310000 - SSM2603 Enumeration start */
    ADI_SSM2603_EVENT_START = ADI_SSM2603_ENUMERATION_START

};

/*
**
** Extensible Enumerations for SSM2603 Driver Result IDs
**
*/

enum
{
    /* 0x40310000 - SSM2603 Enumeration start */
    ADI_SSM2603_RESULT_START = ADI_SSM2603_ENUMERATION_START,
    /* 0x40310001 - SSM2603 driver doesnot support this command */
    ADI_SSM2603_RESULT_CMD_NOT_SUPPORTED,
    /* 0x40310002 - The given TWI Global address is not valid */
    ADI_SSM2603_RESULT_TWI_GLOBAL_ADDRESS_INVALID,
    /* 0x40310003 - SSM2603 driver does not support the given Sample rate */
    ADI_SSM2603_RESULT_SAMPLE_RATE_NOT_SUPPORTED,
    /* 0x40310004 - Supplied MCLK value is invalid */
    ADI_SSM2603_RESULT_MCLK_INVALID
};

#endif /* _LANGUAGE_C */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_SSM2603_H__ */
