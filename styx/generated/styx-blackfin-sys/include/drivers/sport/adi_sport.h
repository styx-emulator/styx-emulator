/*********************************************************************************

Copyright(c) 2005 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_sport.h,v $
$Revision: 3578 $
$Date: 2010-10-19 09:36:04 -0400 (Tue, 19 Oct 2010) $

Description:
            This is the include file for the SPORT driver.

*********************************************************************************/

#ifndef __ADI_SPORT_H__
#define __ADI_SPORT_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* integer typedefs - for all modules */
#include <services_types.h>

/*********************************************************************

Extensible enumerations and defines

*********************************************************************/


enum {                              // Command IDs
    ADI_SPORT_CMD_START=ADI_SPORT_ENUMERATION_START,    // 0x40100000

    // direct register transactions
    // maintain this order including the padding of not used commands
    // ****** order start
    ADI_SPORT_CMD_SET_TCR1,                     // 0x0001 - set the transmit configuration 1 register       (value = register value)
    ADI_SPORT_CMD_SET_TCR2,                     // 0x0002 - set the transmit configuration 2 register       (value = register value)
    ADI_SPORT_CMD_SET_TCLKDIV,                  // 0x0003 - set the transmit clock divide register          (value = register value)
    ADI_SPORT_CMD_SET_TFSDIV,                   // 0x0004 - set the transmit frame sync divide register (value = register value)
    ADI_SPORT_CMD_SET_TX16,                     // 0x0005 - set the transmit data register (16 bit)     (value = register value)
    ADI_SPORT_CMD_NOT_USED1,                    // 0x0006 -
    ADI_SPORT_CMD_GET_RX16,                     // 0x0007 - get the receive data register (16 bit)          (value = pointer to a u16)
    ADI_SPORT_CMD_NOT_USED2,                    // 0x0008 -
    ADI_SPORT_CMD_SET_RCR1,                     // 0x0009 - set the receive configuration 1 register        (value = register value)
    ADI_SPORT_CMD_SET_RCR2,                     // 0x000a - set the receive configuration 2 register        (value = register value)
    ADI_SPORT_CMD_SET_RCLKDIV,                  // 0x000b - set the receive clock divide register           (value = register value)
    ADI_SPORT_CMD_SET_RFSDIV,                   // 0x000c - set the receive frame sync divide register      (value = register value)
    ADI_SPORT_CMD_GET_STAT,                     // 0x000d - get the status register                         (value = pointer to ADI_SPORT_STATUS_REG structure)
    ADI_SPORT_CMD_GET_CHNL,                     // 0x000e - get the multichannel current channel register   (value = pointer to a u16)
    ADI_SPORT_CMD_SET_MCMC1,                    // 0x000f - set the multichannel config 1 register          (value = register value)
    ADI_SPORT_CMD_SET_MCMC2,                    // 0x0010 - set the multichannel config 2 register          (value = register value)
    ADI_SPORT_CMD_SET_MTCS0,                    // 0x0011 - set the multichannel transmit select 0 reg      (value = register value)
    ADI_SPORT_CMD_SET_MTCS1,                    // 0x0012 - set the multichannel transmit select 1 reg      (value = register value)
    ADI_SPORT_CMD_SET_MTCS2,                    // 0x0013 - set the multichannel transmit select 2 reg      (value = register value)
    ADI_SPORT_CMD_SET_MTCS3,                    // 0x0014 - set the multichannel transmit select 3 reg      (value = register value)
    ADI_SPORT_CMD_SET_MRCS0,                    // 0x0015 - set the multichannel receive select 0 reg       (value = register value)
    ADI_SPORT_CMD_SET_MRCS1,                    // 0x0016 - set the multichannel receive select 1 reg       (value = register value)
    ADI_SPORT_CMD_SET_MRCS2,                    // 0x0017 - set the multichannel receive select 2 reg       (value = register value)
    ADI_SPORT_CMD_SET_MRCS3,                    // 0x0018 - set the multichannel receive select 3 reg       (value = register value)
    ADI_SPORT_CMD_SET_TX32,                     // 0x0019 - set the transmit data register (32 bit)     (value = register value)
    ADI_SPORT_CMD_GET_RX32,                     // 0x001a - get the receive data register (32 bit)          (value = pointer to a u32)
    // ****** order end

    // clear errors
    ADI_SPORT_CMD_CLEAR_TX_ERRORS,              // 0x001b - clears all transmit error conditions            (value = na)
    ADI_SPORT_CMD_CLEAR_RX_ERRORS,              // 0x001c - clears all receive error conditions         (value = na)

    // transmit commands (based on the SCLK)
    ADI_SPORT_CMD_SET_TX_CLOCK_FREQ,            // 0x001d - set the transmit data clock                 (value = clock frequency (in Hz))
    ADI_SPORT_CMD_SET_TX_FRAME_SYNC_FREQ,       // 0x001e - set the transmit frame sync clock               (value = clock frequency (in Hz))

    // receive commands (based on the SCLK)
    ADI_SPORT_CMD_SET_RX_CLOCK_FREQ,            // 0x001f - set the receive data clock                      (value = clock frequency (in Hz))
    ADI_SPORT_CMD_SET_RX_FRAME_SYNC_FREQ,       // 0x0020 - set the receive frame sync clock                (value = clock frequency (in Hz))

    // imperative that the following commands remain in this exact order
    // ****** order start
    // transmit commands
    ADI_SPORT_CMD_SET_TX_CLOCK_SOURCE,          // 0x0021 - sets the transmit clock source                  (value = u16, 0 - external, 1 - internal)
    ADI_SPORT_CMD_SET_TX_DATA_FORMAT,           // 0x0022 - sets the transmit data format                   (value = u16, 0 - normal, 1 - reserved, 2 - u-law, 3 - A-law)
    ADI_SPORT_CMD_SET_TX_BIT_ORDER,             // 0x0023 - sets the transmit bit order                 (value = u16, 0 - MSB first, 1 - LSB first)
    ADI_SPORT_CMD_SET_TX_FS_SOURCE,             // 0x0024 - sets the transmit frame sync source         (value = u16, 0 - external, 1 - internal)
    ADI_SPORT_CMD_SET_TX_FS_REQUIREMENT,        // 0x0025 - sets the transmit frame sync required           (value = u16, 0 - no TFS for each word, 1 - TFS for each word)
    ADI_SPORT_CMD_SET_TX_FS_DATA_GEN,           // 0x0026 - sets the transmit data based fs generation      (value = u16, 0 - data dependent TFS gen, 1 - data independent TFS gen)
    ADI_SPORT_CMD_SET_TX_FS_POLARITY,           // 0x0027 - sets the transmit frame sync polarity           (value = u16, 0 - active high TFS, 1 - active low TFS)
    ADI_SPORT_CMD_SET_TX_FS_TIMING,             // 0x0028 - sets the transmit frame sync timing         (value = u16, 0 - early frame sync, 1 - late frame sync)
    ADI_SPORT_CMD_SET_TX_EDGE_SELECT,           // 0x0029 - sets the transmit edge selection                (value = u16, 0 - data and internal fs on rising edge of TSCLK, external fs on falling edge)
                                                //                                                           1 - data and internal fs on falling edge of TSCLK, external fs on rising edge)
    ADI_SPORT_CMD_SET_TX_WORD_LENGTH,           // 0x002a - sets the transmit word length                   (value = u16, 1 less than the serial word length (in bits) required, values of 0, 1 and > 31 are illegal)
    ADI_SPORT_CMD_SET_TX_SECONDARY_ENABLE,      // 0x002b - enables/disables the secondary TX channel       (value = TRUE - enabled, FALSE - disabled)
    ADI_SPORT_CMD_SET_TX_STEREO_FS_ENABLE,      // 0x002c - enables/disables the stereo frame sync          (value = TRUE - FS is L/R clock, FALSE - normal mode)
    ADI_SPORT_CMD_SET_TX_LEFT_RIGHT_ORDER,      // 0x002d - sets the channel order                          (value = u16, 0 - left channel first, 1 - right channel first)

    // receive commands
    ADI_SPORT_CMD_SET_RX_CLOCK_SOURCE,          // 0x002e - sets the receive clock source                   (value = u16, 0 - external, 1 - internal)
    ADI_SPORT_CMD_SET_RX_DATA_FORMAT,           // 0x002f - sets the receive data format                    (value = u16, 0 - zero fill, 1 - sign extend, 2 - u-law, 3 - A-law)
    ADI_SPORT_CMD_SET_RX_BIT_ORDER,             // 0x0030 - sets the receive bit order                      (value = u16, 0 - MSB first, 1 - LSB first)
    ADI_SPORT_CMD_SET_RX_FS_SOURCE,             // 0x0031 - sets the receive frame sync source              (value = u16, 0 - external, 1 - internal)
    ADI_SPORT_CMD_SET_RX_FS_REQUIREMENT,        // 0x0032 - sets the receive frame sync required            (value = u16, 0 - no RFS for each word, 1 - RFS for each word)
    ADI_SPORT_CMD_SET_RX_FS_POLARITY,           // 0x0033 - sets the receive frame sync polarity            (value = u16, 0 - active high RFS, 1 - active low RFS)
    ADI_SPORT_CMD_SET_RX_FS_TIMING,             // 0x0034 - sets the receive frame sync timing              (value = u16, 0 - early frame sync, 1 - late frame sync)
    ADI_SPORT_CMD_SET_RX_EDGE_SELECT,           // 0x0035 - sets the receive edge selection             (value = u16, 0 - data and internal fs on rising edge of RSCLK, external fs on falling edge)
                                                //                                                           1 - data and internal fs on falling edge of RSCLK, external fs on rising edge)
    ADI_SPORT_CMD_SET_RX_WORD_LENGTH,           // 0x0036 - sets the receive word length                    (value = u16, 1 less than the serial word length (in bits) required, values of 0, 1 and > 31 are illegal)
    ADI_SPORT_CMD_SET_RX_SECONDARY_ENABLE,      // 0x0037 - enables/disables the secondary RX channel       (value = TRUE - enabled, FALSE - disabled)
    ADI_SPORT_CMD_SET_RX_STEREO_FS_ENABLE,      // 0x0038 - enables/disables the stereo frame sync          (value = TRUE - FS is L/R clock, FALSE - normal mode)
    ADI_SPORT_CMD_SET_RX_LEFT_RIGHT_ORDER,      // 0x0039 - sets the channel order                          (value = u16, 0 - left channel first, 1 - right channel first)

    // multichannel commands
    ADI_SPORT_CMD_SET_MC_WINDOW_OFFSET,         // 0x003a - sets the window offset                      (value = u16, 0 - 1023)
    ADI_SPORT_CMD_SET_MC_WINDOW_SIZE,           // 0x003b - sets the window size                            (value = u16, (windows size/8) - 1)
    ADI_SPORT_CMD_SET_MC_CLOCK_RECOVERY_MODE,   // 0x003c - sets the 2X clock recovery mode                 (value = u16, 0,1 - bypass, 2 - recover 2MHz from 4MHz, 3 - recover 8MHz from 16MHz)
    ADI_SPORT_CMD_SET_MC_TX_PACKING,            // 0x003d - sets the transmit packing                       (value = FALSE - disabled, TRUE - Enabled)
    ADI_SPORT_CMD_SET_MC_RX_PACKING,            // 0x003e - sets the receive packing                        (value = FALSE - disabled, TRUE - Enabled)
    ADI_SPORT_CMD_SET_MC_MODE,                  // 0x003f - sets the multichannel mode                      (value = FALSE - disabled, TRUE - Enabled)
    ADI_SPORT_CMD_SET_MC_FS_TO_DATA,            // 0x0040 - sets the frame sync to data relationship        (value = u16, 0 - normal, 1 - reversed (H.100 mode))
    ADI_SPORT_CMD_SET_MC_FRAME_DELAY,           // 0x0041 - sets the delay between fs and first data bit    (value = u16, 0 - 15 cycles)
    // ****** order end

    ADI_SPORT_CMD_MC_TX_CHANNEL_ENABLE,         // 0x0042 - enables a transmit channel                      (value = u16, 0 - 127 channel number)
    ADI_SPORT_CMD_MC_TX_CHANNEL_DISABLE,        // 0x0043 - disables a transmit channel                 (value = u16, 0 - 127 channel number)
    ADI_SPORT_CMD_MC_RX_CHANNEL_ENABLE,         // 0x0044 - enables a receive channel                       (value = u16, 0 - 127 channel number)
    ADI_SPORT_CMD_MC_RX_CHANNEL_DISABLE,        // 0x0045 - disables a receive channel                      (value = u16, 0 - 127 channel number)

    ADI_SPORT_CMD_SET_PIN_MUX_MODE,             /* 0x40100046 - Sets processor specific pin mux mode     (Value - Enumeration of type ADI_SPORT_PIN_MUX_MODE)
                                                                from the pin mux enumeration table */

    ADI_SPORT_CMD_SET_HYSTERESIS_ENABLE,        // 0x0047 - enables/disables input pin hysteresis           (value = TRUE - enabled, FALSE - disabled)

    // obsolete commands (retained for backward compatibility)
    ADI_SPORT_CMD_SET_MC_TRANSMIT_PACKING = ADI_SPORT_CMD_SET_MC_TX_PACKING,
    ADI_SPORT_CMD_SET_MC_RECEIVE_PACKING = ADI_SPORT_CMD_SET_MC_RX_PACKING

};


enum {                              // Events
    ADI_SPORT_EVENT_START=ADI_SPORT_ENUMERATION_START,  // 0x40100000
    ADI_SPORT_EVENT_ERROR_INTERRUPT                    // 0x0001 - error generated
};


enum {                              // Return codes
    ADI_SPORT_RESULT_START=ADI_SPORT_ENUMERATION_START, // 0x40100000
    ADI_SPORT_RESULT_BAD_ACCESS_WIDTH                   // 0x0001 - register is not configured for the given access width (16/32)
};


/*********************************************************************

Data Structures

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADISPORTEntryPoint;      // entry point to the device driver

#pragma pack(2)         // needed to allow these to be 16 bit entries
typedef struct {            // SPORT transmit configuration 1 register
    volatile u16 tspen      :1; // transmit enable
    volatile u16 itclk      :1; // internal transmit clock select
    volatile u16 tdtype     :2; // data formatting type select
    volatile u16 tlsbit     :1; // transmit bit order
    volatile u16            :4; // bits 5-8 reserved
    volatile u16 itfs       :1; // internal transmit frame sync select
    volatile u16 tfsr       :1; // transmit frame sync required select
    volatile u16 ditfs      :1; // data-independent transmit frame sync select
    volatile u16 ltfs       :1; // low transmit frame sync select
    volatile u16 latfs      :1; // late transmit frame sync
    volatile u16 tckfe      :1; // clock falling edge select
    volatile u16            :1; // bit 15 undefined
} ADI_SPORT_TX_CONFIG1_REG;

typedef struct {            // SPORT transmit configuration 2 register
    volatile u16 slen       :5; // SPORT word length
    volatile u16            :3; // bits 5-7 reserved
    volatile u16 txse       :1; // secondary Tx channel enable
    volatile u16 tsfse      :1; // transmit stereo frame sync enable
    volatile u16 trfst      :1; // left/right order
    volatile u16            :5; // bits 11-15 reserved
} ADI_SPORT_TX_CONFIG2_REG;

typedef struct {            // SPORT receive configuration 1 register
    volatile u16 rspen      :1; // receive enable
    volatile u16 irclk      :1; // internal receive clock select
    volatile u16 rdtype     :2; // data formatting type select
    volatile u16 rlsbit     :1; // receive bit order
    volatile u16            :4; // bits 5-8 reserved
    volatile u16 irfs       :1; // internal receive frame sync select
    volatile u16 rfsr       :1; // receive frame sync required select
    volatile u16            :1; // bit 11 reserved
    volatile u16 lrfs       :1; // low receive frame sync select
    volatile u16 larfs      :1; // late receive frame sync
    volatile u16 rckfe      :1; // clock falling edge select
    volatile u16            :1; // bit 15 undefined
} ADI_SPORT_RX_CONFIG1_REG;

typedef struct {            // SPORT receive configuration 2 register
    volatile u16 slen       :5; // SPORT word length
    volatile u16            :3; // bits 5-7 reserved
    volatile u16 rxse       :1; // secondary Rx channel enable
    volatile u16 rsfse      :1; // receive stereo frame sync enable
    volatile u16 rrfst      :1; // left/right order
    volatile u16            :5; // bits 11-15 reserved
} ADI_SPORT_RX_CONFIG2_REG;

typedef struct {            // SPORT status register
    volatile u16 rxne       :1; // receive FIFO not empty status
    volatile u16 ruvf       :1; // sticky receive underflow status
    volatile u16 rovf       :1; // sticky receive overflow status
    volatile u16 txf        :1; // transmit FIFO full status
    volatile u16 tuvf       :1; // sticky transmit underflow status
    volatile u16 tovf       :1; // sticky transmit overflow status
    volatile u16 txhre      :1; // transmit hold register empty
    volatile u16            :9; // bits 7-15 reserved
} ADI_SPORT_STATUS_REG;

#pragma pack()

/*********************************************************************

Processor specific enumerations and defines

*********************************************************************/

/*
** Enumerations of SPORT pin muxing combinations
**  Use SPORT driver command (ADI_SPORT_CMD_SET_PIN_MUX_MODE) with one of the
**  enumeration id listed below to select a pin mux combination
*/

/********************
   Moy (ADSP-BF50x)
********************/

#if defined(__ADSP_MOY__)

/* Set Pin mux command has no effect on SPORT 0 */

typedef enum
{
    /* SPORT Pin Mux configuration mode 0 (default)
       For SPORT 1 - PG4  as Secondary Rx channel (DR1SEC) */
    ADI_SPORT_PIN_MUX_MODE_0 = 0,

    /* SPORT Pin Mux configuration mode 1
       For SPORT 1 - PG8  as Secondary Rx channel (DR1SEC) */
    ADI_SPORT_PIN_MUX_MODE_1

} ADI_SPORT_PIN_MUX_MODE;

#endif /* Moy */

/********************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_SPORT_H */
