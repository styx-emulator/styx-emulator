/*********************************************************************************

Copyright(c) 2004 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.



*********************************************************************************/

#ifndef __ADI_ETHER_H__
#define __ADI_ETHER_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*********************************************************************

Include files

*********************************************************************/
#include <drivers/adi_dev.h>

/*********************************************************************

User configurable items

*********************************************************************/



/*********************************************************************

Extensible enumerations and defines

*********************************************************************/


enum {                                          /* Command IDs  */
    ADI_ETHER_CMD_FIRST=ADI_DEV_CMD_PDD_START,  /* insure this order remains    */

    ADI_ETHER_CMD_MEM_SIZES,
    ADI_ETHER_CMD_SUPPLY_MEM,
    ADI_ETHER_CMD_GET_MAC_ADDR,
    ADI_ETHER_CMD_SET_MAC_ADDR,
    ADI_ETHER_CMD_GET_STATISTICS,
    ADI_ETHER_CMD_GET_BUFFER_PREFIX,
    ADI_ETHER_CMD_UNPROCESSED_BUFFER_COUNTS,
    ADI_ETHER_CMD_GET_MIN_RECV_BUFSIZE,
    ADI_ETHER_CMD_GEN_CHKSUMS,
    ADI_ETHER_CMD_SET_SPEED,
    ADI_ETHER_CMD_SET_FULL_DUPLEX,
    ADI_ETHER_CMD_SET_NEGOTIATE,
    ADI_ETHER_CMD_START,
    ADI_ETHER_CMD_GET_PHY_REGS,
    ADI_ETHER_CMD_SET_LOOPBACK,
    ADI_ETHER_CMD_BUFFERS_IN_CACHE,
    ADI_ETHER_CMD_SHUTDOWN_DRIVER,
    ADI_ETHER_ADD_MULTICAST_MAC_FILTER,
    ADI_ETHER_DEL_MULTICAST_MAC_FILTER,
    ADI_ETHER_CMD_SET_PHY_POWER_DOWN

};

#define ADI_ETHER_CMD_SPECIFIC_START  (ADI_DEV_CMD_PDD_START+256)                   /* controller specific  */

enum {                                      /* Events   */
    ADI_ETHER_EVENT_FIRST=ADI_DEV_EVENT_PDD_START,
    ADI_ETHER_EVENT_FRAME_RCVD,             /* one or more frames received  */
    ADI_ETHER_EVENT_FRAME_XMIT,             /* one or more frames received  */
    ADI_ETHER_EVENT_INTERRUPT,              /* ethernet event has occured   */
    ADI_ETHER_EVENT_INTERRUPT_PHY           /* interrupt from the PHY   */
};

#define ADI_ETHER_EVENT_SPECIFIC_START  (ADI_DEV_EVENT_PDD_START+256)               /* controller specific  */

enum {                              /* Return codes */
    ADI_ETHER_RESULT_START=ADI_DEV_RESULT_PDD_START,

    ADI_ETHER_RESULT_SPECIFIC_START = ADI_ETHER_RESULT_START+256,               /* controller specific  */
    ADI_ETHER_RESULT_MEMORY_NOT_ALIGNED = ADI_ETHER_RESULT_START+257,
    ADI_ETHER_RESULT_MEMORY_LENGTH_INVALID = ADI_ETHER_RESULT_START+258

};



/*********************************************************************

Data Structures

*********************************************************************/
#ifdef ADI_ETHER_BF537_DEBUG
typedef enum  usage {
    Free = 1,
    Queued,
    Pending,
    Active,
    Completed,
    Posted
}  USAGE;
#endif

typedef struct adi_ether_buffer {
    char Reserved[ADI_DEV_RESERVED_SIZE];
                            /* reserved for physical device */
                            /* driver use   */
    void    *Data;          /* pointer to data  */
    u32 ElementCount;       /* data element count   */
    u32 ElementWidth;       /* data element width (in bytes)    */
    void*   CallbackParameter;/* callback flag/pArg value   */
    u32 ProcessedFlag;      /* processed flag   */
    u32 ProcessedElementCount;
                            /* # of bytes read in/out   */
    struct adi_ether_buffer *pNext;
                            /* next buffer  */
    void    *PayLoad;       /* pointer to IP Payload    */
    u16 IPHdrChksum;        /* the IP header checksum   */
    u16 IPPayloadChksum;    /* the IP header and payload checksum   */
    u32 StatusWord;         /* the frame status word    */
#ifdef ADI_ETHER_BF537_DEBUG
    USAGE usage;
    int rxusage;
#endif
        void* x;                /* user's per-buffer data   */
} ADI_ETHER_BUFFER;


typedef struct adi_ether_mem_sizes {
    u32     BaseMemSize;    /* no. of bytes for the driver  */
    u32     MemPerRecv;     /* no. of bytes per outstanding read    */
    u32     MemPerXmit;     /* no. of bytes per outstanding send    */
} ADI_ETHER_MEM_SIZES;


typedef struct adi_ether_supply_mem {
    void    *RcveMem;       /* memory area for the receive control data */
    u32     RcveMemLength;  /* the size of the supplied receive */
                            /* memory area in bytes */
    u32     MaxRcveFrames;  /* on return the maximum no. of */
                            /* simultaneous recvs   */
    void    *XmitMem;       /* memory area for the transmit control data    */
    u32     XmitMemLength;  /* the size of the supplied */
                            /* transmit memory area in bytes    */
    u32     MaxXmitFrames;  /* on return the maximum. no. of    */
                            /* simultaneous transmits   */
    void    *BaseMem;       /* memory area for the drivers base memory  */
    u32     BaseMemLength;  /* the size of the supplied */
                            /* base memory in bytes */
} ADI_ETHER_SUPPLY_MEM;


typedef struct adi_ether_statistics_counts {
    u64 cEMAC_RX_CNT_OK;    /* RX Frame Successful Count    */
    u64 cEMAC_RX_CNT_FCS;   /* RX Frame FCS Failure Count   */
    u64 cEMAC_RX_CNT_ALIGN; /* RX Alignment Error Count */
    u64 cEMAC_RX_CNT_OCTET; /* RX Octets Successfully Received Count    */
    u64 cEMAC_RX_CNT_LOST;  /* Internal MAC Sublayer Error RX Frame Count   */
    u64 cEMAC_RX_CNT_UNI;   /* Unicast RX Frame Count   */
    u64 cEMAC_RX_CNT_MULTI; /* Multicast RX Frame Count */
    u64 cEMAC_RX_CNT_BROAD; /* Broadcast RX Frame Count */
    u64 cEMAC_RX_CNT_IRL;   /* RX Frame In Range Error Count    */
    u64 cEMAC_RX_CNT_ORL;   /* RX Frame Out Of Range Error Count    */
    u64 cEMAC_RX_CNT_LONG;  /* RX Frame Too Long Count  */
    u64 cEMAC_RX_CNT_MACCTL;/* MAC Control RX Frame Count   */
    u64 cEMAC_RX_CNT_OPCODE;/* Unsupported Op-Code RX Frame Count   */
    u64 cEMAC_RX_CNT_PAUSE; /* MAC Control Pause RX Frame Count */
    u64 cEMAC_RX_CNT_ALLF;  /* Overall RX Frame Count   */
    u64 cEMAC_RX_CNT_ALLO;  /* Overall RX Octet Count   */
    u64 cEMAC_RX_CNT_TYPED; /* Type/Length Consistent RX Frame Count    */
    u64 cEMAC_RX_CNT_SHORT; /* RX Frame Fragment Count - Byte Count x < 64  */
    u64 cEMAC_RX_CNT_EQ64;  /* Good RX Frame Count -    */
                            /* Byte Count x = 64    */
    u64 cEMAC_RX_CNT_LT128; /* Good RX Frame Count -    */
                            /* Byte Count  64 <= x < 128    */
    u64 cEMAC_RX_CNT_LT256; /* Good RX Frame Count -    */
                            /* Byte Count 128 <= x < 256    */
    u64 cEMAC_RX_CNT_LT512; /* Good RX Frame Count -    */
                            /* Byte Count 256 <= x < 512    */
    u64 cEMAC_RX_CNT_LT1024;/* Good RX Frame Count -    */
                            /* Byte Count 512 <= x < 1024   */
    u64 cEMAC_RX_CNT_EQ1024;/* Good RX Frame Count -    */
                            /* Byte Count x >= 1024 */

    u64 cEMAC_TX_CNT_OK;    /* TX Frame Successful Count    */
    u64 cEMAC_TX_CNT_SCOLL; /* TX Frames Successful */
                            /* After Single Collision Count */
    u64 cEMAC_TX_CNT_MCOLL; /* TX Frames Successful */
                            /* After Multiple Collisions Count  */
    u64 cEMAC_TX_CNT_OCTET; /* TX Octets Successfully Received Count    */
    u64 cEMAC_TX_CNT_DEFER; /* TX Frame Delayed Due To Busy Count   */
    u64 cEMAC_TX_CNT_LATE;  /* Late TX Collisions Count */
    u64 cEMAC_TX_CNT_ABORTC;/* TX Frame Failed  */
                            /* Due To Excessive Collisions Count    */
    u64 cEMAC_TX_CNT_LOST;  /* Internal MAC Sublayer Error TX Frame Count   */
    u64 cEMAC_TX_CNT_CRS;   /* Carrier Sense Deasserted */
                            /* During TX Frame Count    */
    u64 cEMAC_TX_CNT_UNI;   /* Unicast TX Frame Count   */
    u64 cEMAC_TX_CNT_MULTI; /* Multicast TX Frame Count */
    u64 cEMAC_TX_CNT_BROAD; /* Broadcast TX Frame Count */
    u64 cEMAC_TX_CNT_EXDEF; /* TX Frames With Excessive Deferral Count  */
    u64 cEMAC_TX_CNT_MACCTL;/* MAC Control TX Frame Count   */
    u64 cEMAC_TX_CNT_ALLF;  /* Overall TX Frame Count   */
    u64 cEMAC_TX_CNT_ALLO;  /* Overall TX Octet Count   */
    u64 cEMAC_TX_CNT_EQ64;  /* Good TX Frame Count -    */
                            /* Byte Count x = 64    */
    u64 cEMAC_TX_CNT_LT128; /* Good TX Frame Count -    */
                            /* Byte Count  64 <= x < 128    */
    u64 cEMAC_TX_CNT_LT256; /* Good TX Frame Count -    */
                            /* Byte Count 128 <= x < 256    */
    u64 cEMAC_TX_CNT_LT512; /* Good TX Frame Count -    */
                            /* Byte Count 256 <= x < 512    */
    u64 cEMAC_TX_CNT_LT1024;/* Good TX Frame Count -    */
                            /* Byte Count 512 <= x < 1024   */
    u64 cEMAC_TX_CNT_EQ1024;/* Good TX Frame Count -    */
                            /* Byte Count x >= 1024 */
    u64 cEMAC_TX_CNT_ABORT; /* Total TX Frames Aborted Count    */

} ADI_ETHER_STATISTICS_COUNTS;

typedef struct adi_ether_buffer_counts {
    u32 RcvrBufferCnt;      /* returns the number of available  */
                            /* receive buffers  */
    u32 XmitBufferCnt;      /* returns the number of queued */
                            /* transmit buffers */
} ADI_ETHER_BUFFER_COUNTS;


typedef struct adi_ether_ivg_mapping {
    u32 TxIVG;              /* specifies the IVG for the TX interrupt   */
    u32 RxIVG;              /* specifies the IVG for the RX interrupt   */
    u32 ErrIVG;             /* specifies the IVG for any other interupt */
} ADI_ETHER_IVG_MAPPING;

typedef struct adi_ether_dma_mapping {
    u32 TxChannel;          /* specifies the TX DMA channel */
    u32 RxChannel;          /* specifies the RX DMA channel */
} ADI_ETHER_DMA_MAPPING;


/********************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /* __ADI_ETHER_H__  */
