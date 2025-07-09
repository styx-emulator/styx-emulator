/******************************************************************************
Copyright (c), 2010 - Analog Devices Inc. All Rights Reserved.
This software is proprietary & confidential to Analog Devices, Inc.
and its licensors.

$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Title: ADI Device Driver for BF52xC1 Audio CODEC

Description:
    This is the primary include file for BF52xC1 Audio CODEC driver
    The file defines enumerations, data structures and commands
    supported by BF52xC1 Audio CODEC driver

Note:
    Access to the BF52xC1 control registers is over TWI or SPI port.
    A 16 bit frame is sent over TWI/SPI and the data is broken down as follows:

    +---------------------------------------------+
    | Reserved | Register Address | Register Data |
    |---------------------------------------------|
    |   15:13  |       12:9       |      8:0      |
    +---------------------------------------------+

*****************************************************************************/

#ifndef __ADI_BF52xC1_H__
#define __ADI_BF52xC1_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*=============  E X T E R N A L S  ============*/

/*
**
** Entry point to the BF52xC1 device driver
**
*/

extern ADI_DEV_PDD_ENTRY_POINT ADIBF52xC1EntryPoint;

/*==============  D E F I N E S  ===============*/

/*
**
** BF52xC1 Codec Register definitions
**
*/

/* Left ADC Volume Control */
#define     BF52xC1_REG_LEFT_ADC_VOL            0x00U
/* Right ADC Volume Control */
#define     BF52xC1_REG_RIGHT_ADC_VOL           0x01U
/* Left DAC Volume Control */
#define     BF52xC1_REG_LEFT_DAC_VOL            0x02U
/* Right DAC Volume Control */
#define     BF52xC1_REG_RIGHT_DAC_VOL           0x03U
/* Analogue Audio Path Control */
#define     BF52xC1_REG_ANALOGUE_PATH           0x04U
/* Digital Audio Path Control */
#define     BF52xC1_REG_DIGITAL_PATH            0x05U
/* Power Management */
#define     BF52xC1_REG_POWER                   0x06U
/* Digital Audio Interface Format */
#define     BF52xC1_REG_DIGITAL_IFACE           0x07U
/* Sampling Control */
#define     BF52xC1_REG_SAMPLING_CTRL           0x08U
/* Active Control */
#define     BF52xC1_REG_ACTIVE_CTRL             0x09U
/* Reset Register (write only) */
#define     BF52xC1_REG_RESET                   0x0FU

/*
**
** BF52xC1 Codec Register Field definitions
**  - Mask value to extract the corresponding Register field
**
*/

/*
** Left ADC Volume Control (BF52xC1_REG_LEFT_ADC_VOL)
*/

/* Left Channel PGA Volume control */
#define     BF52xC1_RFLD_LIN_VOL                0x01FU
/* Left Channel Input Mute */
#define     BF52xC1_RFLD_LIN_ENABLE_MUTE        0x080U
/* Left Channel Line Input Volume update */
#define     BF52xC1_RFLD_LRIN_BOTH              0x100U

/*
** Right ADC Volume Control (BF52xC1_REG_RIGHT_ADC_VOL)
*/

/* Right Channel PGA Volume control */
#define     BF52xC1_RFLD_RIN_VOL                0x01FU
/* Right Channel Input Mute  */
#define     BF52xC1_RFLD_RIN_ENABLE_MUTE        0x080U
/* Right Channel Line Input Volume update */
#define     BF52xC1_RFLD_RLIN_BOTH              0x100U

/*
** Left DAC Volume Control (BF52xC1_REG_LEFT_DAC_VOL)
*/

/* Left Channel Headphone volume control */
#define     BF52xC1_RFLD_LHP_VOL                0x07FU
/* Left Channel Zero cross detect enable */
#define     BF52xC1_RFLD_ENABLE_LZC             0x080U
/* Left Channel Headphone volume update */
#define     BF52xC1_RFLD_LRHP_BOTH              0x100U

/*
** Right DAC Volume Control (BF52xC1_REG_RIGHT_DAC_VOL)
*/

/* Right Channel Headphone volume control */
#define     BF52xC1_RFLD_RHP_VOL                0x07FU
/* Right Channel Zero cross detect enable */
#define     BF52xC1_RFLD_ENABLE_RZC             0x080U
/* Right Channel Headphone volume update */
#define     BF52xC1_RFLD_RLHP_BOTH              0x100U

/*
** Analogue Audio Path Control (BF52xC1_REG_ANALOGUE_PATH)
*/

/* Primary Microphone Amplifier gain booster control */
#define     BF52xC1_RFLD_ENABLE_MIC_BOOST       0x001U
/* Microphone Mute Control */
#define     BF52xC1_RFLD_ENABLE_MIC_MUTE        0x002U
/* Microphone/Line IN select to ADC (1=MIC, 0=Line In) */
#define     BF52xC1_RFLD_ADC_IN_SELECT          0x004U
/* Line input bypass to line output */
#define     BF52xC1_RFLD_ENABLE_BYPASS          0x008U
/* Select DAC (1=Select DAC, 0=Don't Select DAC) */
#define     BF52xC1_RFLD_SELECT_DAC             0x010U
/* Enable/Disable Side Tone */
#define     BF52xC1_RFLD_ENABLE_SIDETONE        0x020U
/* Side Tone Attenuation */
#define     BF52xC1_RFLD_SIDETONE_ATTN          0x0C0U

/*
** Digital Audio Path Control (BF52xC1_REG_DIGITAL_PATH)
*/
/* Enable/Disable ADC Highpass Filter */
#define     BF52xC1_RFLD_ENABLE_ADC_HPF         0x001U
/* De-Emphasis Control */
#define     BF52xC1_RFLD_DE_EMPHASIS            0x006U
/* DAC Mute Control */
#define     BF52xC1_RFLD_ENABLE_DAC_MUTE        0x008U
/* Store/Clear DC offset when HPF is disabled */
#define     BF52xC1_RFLD_STORE_OFFSET           0x010U

/*
** Power Down Control (BF52xC1_REG_POWER)
**  (1=Enable PowerDown, 0=Disable PowerDown)
*/

/* Line Input Power Down */
#define     BF52xC1_RFLD_LINE_IN_PDN            0x001U
/* Microphone Input & Bias Power Down */
#define     BF52xC1_RFLD_MIC_PDN                0x002U
/* ADC Power Down */
#define     BF52xC1_RFLD_ADC_PDN                0x004U
/* DAC Power Down */
#define     BF52xC1_RFLD_DAC_PDN                0x008U
/* Outputs Power Down */
#define     BF52xC1_RFLD_OUT_PDN                0x010U
/* Oscillator Power Down */
#define     BF52xC1_RFLD_OSC_PDN                0x020U
/* CLKOUT Power Down */
#define     BF52xC1_RFLD_CLK_OUT_PDN            0x040U
/* POWEROFF Mode */
#define     BF52xC1_RFLD_POWER_OFF              0x080U

/*
** Digital Audio Interface Format (BF52xC1_REG_DIGITAL_IFACE)
*/

/* Digital Audio input format control */
#define     BF52xC1_RFLD_IFACE_FORMAT           0x003U
/* Audio Data word length control */
#define     BF52xC1_RFLD_AUDIO_DATA_LEN         0x00CU
/* Polarity Control for clocks in RJ,LJ and I2S modes */
#define     BF52xC1_RFLD_DAC_LR_POLARITY        0x010U
/* Swap DAC data control */
#define     BF52xC1_RFLD_DAC_LR_SWAP            0x020U
/* Enable/Disable Master Mode */
#define     BF52xC1_RFLD_ENABLE_MASTER          0x040U
/* Bit Clock Inversion control */
#define     BF52xC1_RFLD_BCLK_INVERT            0x080U

/*
** Sampling Control (BF52xC1_REG_SAMPLING_CTRL)
*/

/* Enable/Disable USB Mode */
#define     BF52xC1_RFLD_ENABLE_USB_MODE        0x001U
/* Base Over-Sampling Rate */
#define     BF52xC1_RFLD_BOS_RATE               0x002U
/* Clock setting condition (Sampling rate control) */
#define     BF52xC1_RFLD_SAMPLE_RATE            0x03CU
/* Core Clock divider select */
#define     BF52xC1_RFLD_CORECLK_DIV2           0x040U
/* Clock Out divider select */
#define     BF52xC1_RFLD_CLKOUT_DIV2            0x080U

/*
** Active Control (BF52xC1_REG_ACTIVE_CTRL)
*/

/* Activate Codec Digital Audio Interface */
#define     BF52xC1_RFLD_ACTIVATE_CODEC         0x001U

/*=============  D A T A    T Y P E S   =============*/

/* IF (Build for C language) */
#if defined(_LANGUAGE_C)

/*
**
** Enumeration of Industry Standard sampling rates
**
*/
enum
{
    /* Sampling rate = 96kHz */
    ADI_BF52xC1_SR_96K      = 96000,
    /* Sampling rate = 88.2kHz */
    ADI_BF52xC1_SR_88_2K    = 88200,
    /* Sampling rate = 48kHz */
    ADI_BF52xC1_SR_48K      = 48000,
    /* Sampling rate = 44.1kHz */
    ADI_BF52xC1_SR_44_1K    = 44100,
    /* Sampling rate = 32kHz */
    ADI_BF52xC1_SR_32K      = 32000,
    /* Sampling rate = 24kHz */
    ADI_BF52xC1_SR_24K      = 24000,
    /* Sampling rate = 22.05kHz */
    ADI_BF52xC1_SR_22K      = 22050,
    /* Sampling rate = 16kHz */
    ADI_BF52xC1_SR_16K      = 16000,
    /* #### NOT SUPPORTED by BF52xC1 ### Left for backward compatibility */
    ADI_BF52xC1_SR_12K      = 12000,
    /* #### NOT SUPPORTED by BF52xC1 ### Left for backward compatibility */
    ADI_BF52xC1_SR_11K      = 11000,
    /* Sampling rate = 8.02kHz */
    ADI_BF52xC1_SR_8_02K    =  8020,
    /* Sampling rate = 8kHz */
    ADI_BF52xC1_SR_8K       =  8000
};

/*
**
** Data Structure to pass ADC/DAC sampling rate
**
*/
typedef struct ADI_BF52xC1_SAMPLE_RATE
{
    /* ADC Sample rate */
    u32     AdcSampleRate;

    /* DAC Sample rate */
    u32     DacSampleRate;

} ADI_BF52xC1_SAMPLE_RATE;

/*
**
** Extensible Enumerations for BF52xC1 Driver Command IDs
**
*/
enum
{
    /* 0x402B0000 - Command start */
    ADI_BF52xC1_CMD_START = ADI_BF52xC1_ENUMERATION_START,

    /*
    ** SPI related commands
    */

    /* 0x402B0001 - Sets BF52xC1 driver to use SPI to access BF52xC1 hardware registers
                    Value = u8 (SPI Device Number to use)
                    Default = 0 (SPI Device 0) */
    ADI_BF52xC1_CMD_SET_SPI_DEVICE_NUMBER,

    /* 0x402B0002 - Sets SPI Chipselect number connected to BF52xC1 CSB pin
                    Value = u8 (SPI Chipselect)
                    Default = 0 (chipselect not valid) */
    ADI_BF52xC1_CMD_SET_SPI_CS,

    /*
    ** TWI related commands
    */

    /* 0x402B0003 - Sets BF52xC1 driver to use TWI to access BF52xC1 hardware registers
                    Value = u8 (TWI Device Number to use)
                    Default = Uses SPI device 0 */
    ADI_BF52xC1_CMD_SET_TWI_DEVICE_NUMBER,

    /* 0x402B0004 - Sets BF52xC1 TWI Global Address
                    Value = u8 (TWI Global Address for BF52xC1)
                    Default = 0x1A (possible values = 0x1A or 0x1B) */
    ADI_BF52xC1_CMD_SET_TWI_GLOBAL_ADDR,

    /*
    ** Commands common to SPI and TWI
    */
    /* 0x402B0005 - Sets TWI or SPI configuration table to be used to access BF52xC1 device registers
                    Value = ADI_DEV_CMD_VALUE_PAIR * (address of a command/value pair table)
                    Default = NULL.
                    Note: Client MUST submit a configuration table when the driver set to use TWI for
                          BF52xC1 register access. Configuration table is optional for SPI based register access */
    ADI_BF52xC1_CMD_SET_TWI_SPI_CONFIG_TABLE,

    /*
    ** SPORT related commands
    */
    /* 0x402B0006 - Sets SPORT device number connected to BF52xC1 Digital Audio Interface port
                    Value = u8 (SPORT Device Number to use)
                    Default = 0 (SPORT Device 0) */
    ADI_BF52xC1_CMD_SET_SPORT_DEVICE_NUMBER,

    /* 0x402B0007 - Opens/Closes SPORT device connected to BF52xC1
                    Value = TRUE/FALSE (TRUE to open, FALSE to close)
                    Default = Opens SPORT device when application issues ADI_DEV_CMD_SET_DATAFLOW_METHOD command
                    Note: Command can be used to share one SPORT channel between multiple Audio Codecs */
    ADI_BF52xC1_CMD_OPEN_SPORT_DEVICE,

    /* 0x402B0008 - Enables/Disables Auto-SPORT configuration mode
                    Value = TRUE/FALSE (TRUE to enable, FALSE to disable)
                    Default = TRUE (Auto-SPORT configuration is enabled by default)
                    Note: Auto-SPORT configuration is not supported for Right-Justified (RJ) and DSP modes */
    ADI_BF52xC1_CMD_ENABLE_AUTO_SPORT_CONFIG,

    /*
    ** BF52xC1 register configuration commands
    */
    /* 0x402B0009 - Configures BF52xC1 sampling control register with given ADC/DAC sample rate.
                    Application MUST disable codec dataflow before issuing this command
                    Value = ADI_BF52xC1_SAMPLE_RATE * (pointer to ADI_BF52xC1_SAMPLE_RATE structure) */
    ADI_BF52xC1_CMD_SET_SAMPLE_RATE

    /*  Use Device Access Commands (defined in adi_dev.h) to access BF52xC1 hardware registers

        List of Device Access Commands supported by BF52xC1 driver
        +-----------------------------------------------------------------------------------------------------------------------------------+
        |           Command ID                      |       Command Argument            |               Comments                            |
        +-----------------------------------------------------------------------------------------------------------------------------------+
        | ADI_DEV_CMD_REGISTER_READ                 | ADI_DEV_ACCESS_REGISTER *         | Reads a single BF52xC1 register                   |
        | ADI_DEV_CMD_REGISTER_FIELD_READ           | ADI_DEV_ACCESS_REGISTER_FIELD *   | Reads a specific BF52xC1 register field           |
        | ADI_DEV_CMD_REGISTER_TABLE_READ           | ADI_DEV_ACCESS_REGISTER *         | Reads a table of BF52xC1 registers                |
        | ADI_DEV_CMD_REGISTER_FIELD_TABLE_READ     | ADI_DEV_ACCESS_REGISTER_FIELD *   | Reads a table of BF52xC1 register(s) field(s)     |
        | ADI_DEV_CMD_REGISTER_BLOCK_READ           | ADI_DEV_ACCESS_REGISTER_BLOCK *   | Reads a block of consecutive BF52xC1 registers    |
        |                                           |                                   |                                                   |
        | ADI_DEV_CMD_REGISTER_WRITE                | ADI_DEV_ACCESS_REGISTER *         | Writes to a single BF52xC1 register               |
        | ADI_DEV_CMD_REGISTER_FIELD_WRITE          | ADI_DEV_ACCESS_REGISTER_FIELD *   | Writes to a BF52xC1 register field                |
        | ADI_DEV_CMD_REGISTER_TABLE_WRITE          | ADI_DEV_ACCESS_REGISTER *         | Writes to a table of BF52xC1 registers            |
        | ADI_DEV_CMD_REGISTER_FIELD_TABLE_WRITE    | ADI_DEV_ACCESS_REGISTER_FIELD *   | Writes to a table of BF52xC1 register(s) field(s) |
        | ADI_DEV_CMD_REGISTER_BLOCK_WRITE          | ADI_DEV_ACCESS_REGISTER_BLOCK *   | Writes to a block of consecutive BF52xC1 registers|
        +-----------------------------------------------------------------------------------------------------------------------------------+
    */

};

/*
**
** Extensible Enumerations for BF52xC1 Driver Event IDs
**
*/
enum
{
    /* 0x402B0000 - Enumeration start */
    ADI_BF52xC1_EVENT_START = ADI_BF52xC1_ENUMERATION_START
};

/*
**
** Extensible Enumerations for BF52xC1 Driver Result IDs
**
*/
enum
{
    /* 0x402B0000 - Enumeration start */
    ADI_BF52xC1_RESULT_START = ADI_BF52xC1_ENUMERATION_START,
    /* 0x402B0001 - BF52xC1 driver doesnot support this command */
    ADI_BF52xC1_RESULT_CMD_NOT_SUPPORTED,
    /* 0x402B0002 - The given TWI Global address is not valid */
    ADI_BF52xC1_RESULT_TWI_GLOBAL_ADDRESS_INVALID,
    /* 0x402B0003 - BF52xC1 driver does not support the given ADC/DAC Sample rate */
    ADI_BF52xC1_RESULT_SAMPLE_RATE_NOT_SUPPORTED
};

#endif /* _LANGUAGE_C */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_BF52xC1_H__ */
