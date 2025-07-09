/*********************************************************************************

Copyright(c) 2004 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_spi.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            This is the include file for the SPI driver.

*********************************************************************************/

#ifndef __ADI_SPI_H__
#define __ADI_SPI_H__

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


enum {                                  // Command IDs
    ADI_SPI_CMD_START=ADI_SPI_ENUMERATION_START,// 0x400f0000 - starting point
    ADI_SPI_CMD_SET_BAUD_RATE,              // 0x400f0001 - set the baud rate                       (value = frequency in Hz)

    ADI_SPI_CMD_SET_SLAVE_FLAG,             // 0x400f0002 - set the SPI slave flag register         (value = register value)
    ADI_SPI_CMD_SET_CONTROL_REG,            // 0x400f0003 - set the SPI control register directly   (value = register value)
    ADI_SPI_CMD_SET_BAUD_REG,               // 0x400f0004 - set the baud register directly          (value = register value)

    ADI_SPI_CMD_ENABLE_SLAVE_SELECT,        // 0x400f0005 - enables a slave select line             (value = slave number)
    ADI_SPI_CMD_DISABLE_SLAVE_SELECT,       // 0x400f0006 - disables a slave select line            (value = slave number)
    ADI_SPI_CMD_SELECT_SLAVE,               // 0x400f0007 - selects a slave                         (value = slave number)
    ADI_SPI_CMD_DESELECT_SLAVE,             // 0x400f0008 - deselects a slave                       (value = slave number)

    ADI_SPI_CMD_SET_EXCLUSIVE_ACCESS,       // 0x400f0009 - prevent others from using SPI           (TRUE - want access, FALSE - done with access)

    // ****** Imperative that the following commands remain in order ******
    ADI_SPI_CMD_SET_TRANSFER_INIT_MODE,     // 0x400f000a - sets TIMOD value                        (0 - start with core read of SPI_RDBR   (interrupt driven inbound data)
                                            //                                                  (1 - start with core write of SPI_TDBR  (interrupt driven outbound data)
                                            //                                                  (2 - start with DMA read of SPI_RDBR    (DMA driven inbound data)
                                            //                                                  (3 - start with DMA write of SPI_TDBR   (DMA driven outbound data)
    ADI_SPI_CMD_NOT_USED_0,                 // 0x400f000b - spacer (not used but must stay)
    ADI_SPI_CMD_SEND_ZEROS,                 // 0x400f000c - sends zeros when TDBR is empty          (TRUE - sends zeros, FALSE - send last data)
    ADI_SPI_CMD_SET_GET_MORE_DATA,          // 0x400f000d - sets the get more data mode         (TRUE - gets more date (overwrite), FALSE - discard incoming data)
    ADI_SPI_CMD_SET_PSSE,                   // 0x400f000e - sets the PSSE bit in control            (TRUE - SPISS enabled, FALSE - SPISS disabled)
    ADI_SPI_CMD_SET_MISO,                   // 0x400f000f - enables/disables MISO                   (TRUE - MISO enabled, FALSE - MISO disabled)
    ADI_SPI_CMD_NOT_USED_1,                 // 0x400f0010 - spacer (not used but must stay)
    ADI_SPI_CMD_NOT_USED_2,                 // 0x400f0011 - spacer (not used but must stay)
    ADI_SPI_CMD_SET_WORD_SIZE,              // 0x400f0012 - sets the number of bits per word        (value = 8 or 16)
    ADI_SPI_CMD_SET_LSB_FIRST,              // 0x400f0013 - sets the MSB/LSB order                  (TRUE - LSB sent first, FALSE - MSB sent first)
    ADI_SPI_CMD_SET_CLOCK_PHASE,            // 0x400f0014 - sets the transfer format                (TRUE - beginning toggle, FALSE - middle toggle)
    ADI_SPI_CMD_SET_CLOCK_POLARITY,         // 0x400f0015 - sets clock polarity                 (TRUE - active low, FALSE - active high)
    ADI_SPI_CMD_SET_MASTER,                 // 0x400f0016 - sets master/slave control               (TRUE - master, FALSE - slave)
    ADI_SPI_CMD_SET_OPEN_DRAIN_MASTER,      // 0x400f0017 - controls the WOM bit in SPI_CTL     (TRUE - open drain, FALSE - normal)
    // ****** Imperative that the above commands remain in order ******

    ADI_SPI_CMD_EXECUTE_DUMMY_READ,         // 0x400f0018 - causes a dummy SPI read to occur        (8 - 8 bit read, 16 - 16 bit read)
    ADI_SPI_CMD_PAUSE_DATAFLOW,             // 0x400f0019 - pauses/resumes dataflow             (TRUE - pause, FALSE - resume)
    ADI_SPI_CMD_SET_TRANSFER_TYPE_BIG_ENDIAN,   // 0x400f001a - switches data transfer type btwn big & little endian (True-Big Endian, FALSE-Little Endian)
    ADI_SPI_CMD_SET_PIN_MUX_MODE            /* 0x400f001b - Sets processor specific pin mux mode (Value - Enumeration of type ADI_SPI_PIN_MUX_MODE)
                                                            from the pin mux enumeration table */
};


enum {                                  // Events
    ADI_SPI_EVENT_START=ADI_SPI_ENUMERATION_START,  // 0x400f0000 - insure this order remains
    ADI_SPI_EVENT_ERROR_INTERRUPT,                  // 0x400f0001 - SPI error generated (superceded with events for each individual error condition)
    ADI_SPI_EVENT_WRITE_BUFFER_PROCESSED,           // 0x400f0002 - Tx-buffer completed processing
    ADI_SPI_EVENT_READ_BUFFER_PROCESSED,            // 0x400f0003 - Rx-buffer completed processing
    ADI_SPI_EVENT_TRANSMISSION_ERROR,               // 0x400f0004 - Status-Register TXE bit set - Transmission error
    ADI_SPI_EVENT_RECEIVE_ERROR,                    // 0x400f0005 - Status-register RBSY bit set - Receive error
    ADI_SPI_EVENT_SEQ_BUFFER_PROCESSED,             // 0x400f0006 - Sequential buffer completed processing
    ADI_SPI_EVENT_TRANSMIT_COLLISION_ERROR,         // 0x400f0007 - Transmit collision error
    ADI_SPI_EVENT_MODE_FAULT_ERROR                  // 0x400f0008 - Mode fault error detected
};


enum {                                  // Return codes
    ADI_SPI_RESULT_START=ADI_SPI_ENUMERATION_START, // 0x400f0000 - insure this order remains
    ADI_SPI_RESULT_ALREADY_EXCLUSIVE,               // 0x400f0001 - exclusive access not granted
    ADI_SPI_RESULT_BAD_SLAVE_NUMBER,                // 0x400f0002 - bad slave number
    ADI_SPI_RESULT_BAD_TRANSFER_INIT_MODE,          // 0x400f0003 - bad transfer init mode value
    ADI_SPI_RESULT_BAD_WORD_SIZE,                   // 0x400f0004 - bad word size (expecting 8 or 16)
    ADI_SPI_RESULT_BAD_VALUE,                       // 0x400f0005 - bad value passed in (expecting TRUE or FALSE)
    ADI_SPI_RESULT_DATAFLOW_ENABLED,                // 0x400f0006 - illegal because dataflow is active
    ADI_SPI_RESULT_NO_VALID_BUFFER,                 // 0x400f0007 - no buffer for data transfer
    ADI_SPI_RESULT_BAD_BAUD_NUMBER,                 // 0x400f0008 - bad baud rate value
    ADI_SPI_RESULT_RW_SEQIO_MISMATCH               // 0x400f0009 - illegal use of Read/Write() and SeqIO()
};

/*********************************************************************

Data Structures

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADISPIIntEntryPoint;     // entry point to the device driver
extern ADI_DEV_PDD_ENTRY_POINT ADISPIDMAEntryPoint;     // entry point to the device driver




#pragma pack(2)         // needed to allow these to be 16 bit entries
typedef struct {            // SPI control register
    volatile u16 timod      :2; // transfer initiation mode
    volatile u16 sz         :1; // send zero
    volatile u16 gm         :1; // get mode data
    volatile u16 psse       :1; // slave select enable
    volatile u16 emiso      :1; // enable MISO
    volatile u16            :2; // bits 6-7 reserved
    volatile u16 size       :1; // size of words
    volatile u16 lsbf       :1; // LSB first
    volatile u16 cpha       :1; // clock phase
    volatile u16 cpol       :1; // clock polarity
    volatile u16 mstr       :1; // master
    volatile u16 wom        :1; // write open drain master
    volatile u16 spe        :1; // SPI enable
    volatile u16            :1; // bit 15 undefined
} ADI_SPI_CONTROL_REG;

typedef struct {            // SPI status register
    volatile u16 spif       :1; // SPI finished
    volatile u16 modf       :1; // mode fault error
    volatile u16 txe        :1; // transmission error
    volatile u16 tsx        :1; // SPI_TDBR data buffer status
    volatile u16 rbsy       :1; // receive error
    volatile u16 rxs        :1; // RX data buffer status
    volatile u16 txcol      :1; // transmit collision error
    volatile u16            :9; // bits 7-15 reserved
} ADI_SPI_STATUS_REG;

#pragma pack()

/*********************************************************************

Processor specific enumerations and defines

*********************************************************************/

/*
** Enumerations of SPI pin muxing combinations
**  Use SPI driver command (ADI_SPI_CMD_SET_PIN_MUX_MODE) with one of the
**  enumeration id listed below to select a pin mux combination
*/

/********************
   Moy (ADSP-BF50x)
********************/

#if defined(__ADSP_MOY__)

typedef enum
{
    /* SPI Pin Mux configuration mode 0 (default)
       For SPI 0 - PF15 as Slave Select 3 (SPI0 SSEL3)
       For SPI 1 - PG1  as Slave Select 2 (SPI1 SSEL2)
                   PG0  as Slave Select 3 (SPI1 SSEL3) */
    ADI_SPI_PIN_MUX_MODE_0 = 0,

    /* SPI Pin Mux configuration mode 1
       For SPI 0 - PH0 as Slave Select 3 (SPI0 SSEL3)
       For SPI 1 - PG1 as Slave Select 2 (SPI1 SSEL2)
                   PH1 as Slave Select 3 (SPI1 SSEL3) */
    ADI_SPI_PIN_MUX_MODE_1 ,

    /* SPI Pin Mux configuration mode 2
       For SPI 0 - PF15 as Slave Select 3 (SPI0 SSEL3)
       For SPI 1 - PH2  as Slave Select 2 (SPI1 SSEL2)
                   PG0  as Slave Select 3 (SPI1 SSEL3) */
    ADI_SPI_PIN_MUX_MODE_2,

    /* SPI Pin Mux configuration mode 3
       For SPI 0 - PH0 as Slave Select 3 (SPI0 SSEL3)
       For SPI 1 - PH2 as Slave Select 2 (SPI1 SSEL2)
                   PH1 as Slave Select 3 (SPI1 SSEL3) */
    ADI_SPI_PIN_MUX_MODE_3

} ADI_SPI_PIN_MUX_MODE;

#endif /* Moy */

/********************
   Delta (ADSP-BF59x)
********************/

#if defined(__ADSP_DELTA__)

typedef enum
{
    /* SPI Pin Mux configuration mode 0 (default)
       For SPI 1 - PF14 as Slave Select 4 (SPI1 SSEL4)
       For SPI 1 - PF15 as Slave Select 5 (SPI1 SSEL5)
       For SPI 1 - PG5  as Slave Select 6 (SPI1 SSEL6) */
    ADI_SPI_PIN_MUX_MODE_0 = 0,

    /* SPI Pin Mux configuration mode 1
       For SPI 1 - PF14 as Slave Select 4 (SPI1 SSEL4)
       For SPI 1 - PG11 as Slave Select 5 (SPI1 SSEL5)
       For SPI 1 - PG15 as Slave Select 6 (SPI1 SSEL6) */
    ADI_SPI_PIN_MUX_MODE_1 ,

    /* SPI Pin Mux configuration mode 2
       For SPI 1 - PF14 as Slave Select 4 (SPI1 SSEL4)
       For SPI 1 - PG11 as Slave Select 5 (SPI1 SSEL5)
       For SPI 1 - PG5  as Slave Select 6 (SPI1 SSEL6) */
    ADI_SPI_PIN_MUX_MODE_2,

    /* SPI Pin Mux configuration mode 3
       For SPI 1 - PF14 as Slave Select 4 (SPI1 SSEL4)
       For SPI 1 - PG11 as Slave Select 5 (SPI1 SSEL5)
       For SPI 1 - PG15  as Slave Select 6 (SPI1 SSEL6) */
    ADI_SPI_PIN_MUX_MODE_3,

    /* SPI Pin Mux configuration mode 4
       For SPI 1 - PG14 as Slave Select 4 (SPI1 SSEL4)
       For SPI 1 - PF15 as Slave Select 5 (SPI1 SSEL5)
       For SPI 1 - PG5  as Slave Select 6 (SPI1 SSEL6) */
    ADI_SPI_PIN_MUX_MODE_4 ,

    /* SPI Pin Mux configuration mode 5
       For SPI 1 - PG14 as Slave Select 4 (SPI1 SSEL4)
       For SPI 1 - PF15 as Slave Select 5 (SPI1 SSEL5)
       For SPI 1 - PG15 as Slave Select 6 (SPI1 SSEL6) */
    ADI_SPI_PIN_MUX_MODE_5,

    /* SPI Pin Mux configuration mode 6
       For SPI 1 - PG14 as Slave Select 4 (SPI1 SSEL4)
       For SPI 1 - PG11 as Slave Select 5 (SPI1 SSEL5)
       For SPI 1 - PG5   as Slave Select 6 (SPI1 SSEL6) */
    ADI_SPI_PIN_MUX_MODE_6,

    /* SPI Pin Mux configuration mode 7
       For SPI 1 - PG14 as Slave Select 4 (SPI1 SSEL4)
       For SPI 1 - PG11 as Slave Select 5 (SPI1 SSEL5)
       For SPI 1 - PG15 as Slave Select 6 (SPI1 SSEL6) */
    ADI_SPI_PIN_MUX_MODE_7


} ADI_SPI_PIN_MUX_MODE;

#endif /* Delta */

/********************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_SPI_H */
