/*********************************************************************************

Copyright(c) 2007 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_hdrc.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            Hi-speed USB OTG dual-role controller driver header file.

*********************************************************************************/

#ifndef _ADI_USB_HDRC_H_
#define _ADI_USB_HDRC_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <drivers/adi_dev.h>
#include <sys/exception.h>

#if defined(__ADSP_MOAB__)

#define USB_DMA_CTRL_BASE           0xFFC04004
#define USB_DMA_ADDR_LOW_BASE       0xFFC04008
#define USB_DMA_ADDR_HIGH_BASE      0xFFC0400C
#define USB_DMA_COUNT_LOW_BASE      0xFFC04010
#define USB_DMA_COUNT_HIGH_BASE     0xFFC04014

#elif defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__)

#define USB_DMA_CTRL_BASE           0xFFC03C04
#define USB_DMA_ADDR_LOW_BASE       0xFFC03C08
#define USB_DMA_ADDR_HIGH_BASE      0xFFC03C0C
#define USB_DMA_COUNT_LOW_BASE      0xFFC03C10
#define USB_DMA_COUNT_HIGH_BASE     0xFFC03C14

#else
#error *** Processor not supported ***
#endif

/*
 * Sets DMA control register with the passed data and for the specified endpoint
 */
inline void set_dma_ctrl(unsigned int ep_num,unsigned short data)
{
  unsigned short volatile *paddr = (unsigned short*)(USB_DMA_CTRL_BASE + (ep_num * 0x20));
  *paddr = data;
  ssync();
}

/*
 * Sets DMA address register with the passed data and for the specified endpoint
 */
inline void set_dma_addr(unsigned int ep_num,unsigned short addr_low, unsigned short addr_high)
{
  unsigned short volatile *paddr = (unsigned short*)(USB_DMA_ADDR_LOW_BASE + (ep_num * 0x20));
  *paddr = addr_low;
  ssync();
  paddr = (unsigned short*)(USB_DMA_ADDR_HIGH_BASE + (ep_num * 0x20));
  ssync();
  *paddr = addr_high;
}

/*
 * Sets DMA count register with the passed data and for the specified endpoint
 */
inline void set_dma_count(unsigned int ep_num,unsigned short count_low, unsigned short count_high)
{
  unsigned short volatile *paddr = (unsigned short*)(USB_DMA_COUNT_LOW_BASE + (ep_num * 0x20));
  *paddr = count_low;
  ssync();
  paddr = (unsigned short*)(USB_DMA_COUNT_HIGH_BASE + (ep_num * 0x20));
  ssync();
  *paddr = count_high;
}

/*
 * Gets DMA address register with the passed data and for the specified endpoint
 */
inline void get_dma_addr(unsigned int ep_num,unsigned int *addr)
{
  unsigned short volatile *paddr = (unsigned short*)(USB_DMA_ADDR_LOW_BASE + (ep_num * 0x20));
  *addr = (unsigned int)*paddr;
  ssync();
  paddr = (unsigned short*)(USB_DMA_ADDR_HIGH_BASE + (ep_num * 0x20));
  ssync();
  *addr |= (unsigned int)((short)*paddr << 16);
}

/* Resets the DMA registers for the supplied endpoint*/
inline void reset_dma(unsigned int ep_num)
{
    set_dma_ctrl(ep_num,0);
    set_dma_count(ep_num,0,0);
    set_dma_addr(ep_num,0,0);
}

/* Configure the USB Interrupt levels */
typedef struct adi_usb_hdrc_ivg_levels
{
 interrupt_kind IvgUSBINT0;
 interrupt_kind IvgUSBINT1;
 interrupt_kind IvgUSBINT2;
 interrupt_kind IvgUSBDMAINT;
}ADI_USB_HDRC_IVG_LEVELS;

/* DMA Channel configuration*/
typedef struct adi_usb_hdrc_dma_config
{
  int DmaMode;
  int DmaChannel;
}ADI_USB_HDRC_DMA_CONFIG;


#if defined(__ADSP_MOAB__)

#define USBDRC_DMA_INTERRUPT          0xFFC04000 /* Indicates the pending interrupts for the DMA channels */
#define USBDRC_DMA_CTRL(ep)          ( (0xFFC04004) + (ep * 0x20) ) /* 4(2n)4 where n= 0-7 */
#define USBDRC_DMA_ADDR_LOW(ep)      ( (0xFFC04008) + (ep * 0x20) ) /* 4(2n)8 where n= 0-7 */
#define USBDRC_DMA_ADDR_HIGH(ep)     ( (0xFFC0400C) + (ep * 0x20) ) /* 4(2n)C where n= 0-7 */
#define USBDRC_DMA_COUNT_LOW(ep)     ( (0xFFC04010) + (ep * 0x20) ) /* 4(2n+1)0 where n= 0-7 */
#define USBDRC_DMA_COUNT_HIGH(ep)    ( (0xFFC04014) + (ep * 0x20) ) /* 4(2n+1)4 where n= 0-7 */

#elif defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__)

#define USBDRC_DMA_INTERRUPT          0xFFC03C00 /* Indicates the pending interrupts for the DMA channels */
#define USBDRC_DMA_CTRL(ep)          ( (0xFFC03C04) + (ep * 0x20) ) /* 4(2n)4 where n= 0-7 */
#define USBDRC_DMA_ADDR_LOW(ep)      ( (0xFFC03C08) + (ep * 0x20) ) /* 4(2n)8 where n= 0-7 */
#define USBDRC_DMA_ADDR_HIGH(ep)     ( (0xFFC03C0C) + (ep * 0x20) ) /* 4(2n)C where n= 0-7 */
#define USBDRC_DMA_COUNT_LOW(ep)     ( (0xFFC03C10) + (ep * 0x20) ) /* 4(2n+1)0 where n= 0-7 */
#define USBDRC_DMA_COUNT_HIGH(ep)    ( (0xFFC03C14) + (ep * 0x20) ) /* 4(2n+1)4 where n= 0-7 */

#else
#error *** Processor not supported ***
#endif


/* Bit specific entities - Global Control Register USB_GLOBAL_CTRL */
#define USB_GLOBAL_ENABLE_B              (1 << 0)
#define USB_GLOBAL_CTRL_TX_EP1_B         (1 << 1)
#define USB_GLOBAL_CTRL_TX_EP2_B         (1 << 2)
#define USB_GLOBAL_CTRL_TX_EP3_B         (1 << 3)
#define USB_GLOBAL_CTRL_TX_EP4_B         (1 << 4)
#define USB_GLOBAL_CTRL_TX_EP5_B         (1 << 5)
#define USB_GLOBAL_CTRL_TX_EP6_B         (1 << 6)
#define USB_GLOBAL_CTRL_TX_EP7_B         (1 << 7)
#define USB_GLOBAL_CTRL_RX_EP1_B         (1 << 8)
#define USB_GLOBAL_CTRL_RX_EP2_B         (1 << 9)
#define USB_GLOBAL_CTRL_RX_EP3_B         (1 << 10)
#define USB_GLOBAL_CTRL_RX_EP4_B         (1 << 11)
#define USB_GLOBAL_CTRL_RX_EP5_B         (1 << 12)
#define USB_GLOBAL_CTRL_RX_EP6_B         (1 << 13)
#define USB_GLOBAL_CTRL_RX_EP7_B         (1 << 14)
#define USB_GLOBAL_CTRL_TM_TIMER_REDUCTION_B  (1 << 15)

#define USB_GLOBAL_CTRL_ALL_TX_RX_B (USB_GLOBAL_CTRL_TX_EP1_B | \
                      USB_GLOBAL_CTRL_TX_EP2_B | \
                      USB_GLOBAL_CTRL_TX_EP3_B | \
                      USB_GLOBAL_CTRL_TX_EP4_B | \
                      USB_GLOBAL_CTRL_TX_EP5_B | \
                      USB_GLOBAL_CTRL_TX_EP6_B | \
                      USB_GLOBAL_CTRL_TX_EP7_B | \
                      USB_GLOBAL_CTRL_RX_EP1_B | \
                      USB_GLOBAL_CTRL_RX_EP2_B | \
                      USB_GLOBAL_CTRL_RX_EP3_B | \
                      USB_GLOBAL_CTRL_RX_EP4_B | \
                      USB_GLOBAL_CTRL_RX_EP5_B | \
                      USB_GLOBAL_CTRL_RX_EP6_B | \
                      USB_GLOBAL_CTRL_RX_EP7_B)



/* Bit entities for the USB_INTRUSB, USB_INTRUSBE registers */
#define USB_INTRUSB_VBUSERROR_B     (1 << 7)   /* VBus below Vbus valid thershold detected - host mode (HM) */
#define USB_INTRUSB_SESSION_REQ_B   (1 << 6)   /* Session Request signaling detected - host mode */
#define USB_INTRUSB_DISCONN_B       (1 << 5)   /* Device disconnect detected -HM, Session End detected PM */
#define USB_INTRUSB_CONN_B          (1 << 4)   /* Device connection detected -HM */
#define USB_INTRUSB_SOF_B           (1 << 3)   /* Start of USB Frame detected */
#define USB_INTRUSB_RESET_OR_BABBLE_B  (1 << 2)   /* Reset detected - PM, Babble detected -HM */
#define USB_INTRUSB_RESUME_B        (1 << 1)   /* Resume signal detected while in suspend mode */
#define USB_INTRUSB_SUSPEND_B       (1 << 0)   /* Suspend signal detected */

/* Bit entities for USB_OTG_DEV_CTL register */
#define USB_OTG_DEV_CTL_B_DEVICE_B   (1 << 7)  /* Readonly bit indicates whether the device is A(0) or B(1) device */
#define USB_OTG_DEV_CTL_FS_DEVICE_B  (1 << 6)  /* Full speed or High speed device */
#define USB_OTG_DEV_CTL_LS_DEVICE_B  (1 << 5)  /* Low speed device */
#define USB_OTG_DEV_CTL_VBUS_LEVEL_B ( (1 << 4) | (1 << 3)) /* used to check Vbus levels */
#define USB_OTG_DEV_CTL_HOST_MODE_B  (1 << 2)  /* Set if device is in host mode */
#define USB_OTG_DEV_CTL_HOST_REQ_B   (1 << 1)  /* Initiate host negotiation protocol */
#define USB_OTG_DEV_CTL_SESSION_B    (1 << 0)  /* Initiate session request protocol */

/* Bit entities for USB_POWER register */
#define USB_POWER_ISO_UPDATE_B           (1 << 7)  /* Isonchronous update enable */
#define USB_POWER_SOFT_CONN_B            (1 << 6)  /* Soft reset */
#define USB_POWER_HS_ENABLE_B            (1 << 5)  /* Negotiate for HIGH speed */
#define USB_POWER_HS_MODE_B              (1 << 4)  /* High speed mode success/failure */
#define USB_POWER_RESET_B                (1 << 3)  /* Reset singaling is present - RW - HM RO - PM */
#define USB_POWER_RESUME_B               (1 << 2)  /* Generates resume signaling from the suspended mode */
#define USB_POWER_ENABLE_SUSPEND_MODE_B  (1 << 1)  /* Suspend mode enable */
#define USB_POWER_ENABLE_SUSPENDM_B      (1 << 0)  /* Suspend mode output enable */

/* Bit entities for DMA control register */
#define USB_DMA_CTRL_DMA_ENA_B           (1 << 0)  /* DMA enable bit */
#define USB_DMA_CTRL_DMA_DIR_B           (1 << 1)  /* DMA direction 0-read 1-write */
#define USB_DMA_CTRL_DMA_MODE_B          (1 << 2)  /* DMA mode bit  Mode-1 Bulk, Mode-0 Packet*/
#define USB_DMA_CTRL_DMA_INT_ENA_B       (1 << 3)  /* DMA mode bit  Mode-1 Bulk, Mode-0 Packet*/
#define USB_DMA_CTRL_DMA_BUSERROR_B      (1 << 8)  /* DMA bus error */

/* Endpoints  */
#define EP0 0
#define EP1 1
#define EP2 2
#define EP3 3
#define EP4 4
#define EP5 5
#define EP6 6
#define EP7 7
#define DMA_MODE_0 0
#define DMA_MODE_1 1

#define ADI_USB_DMA_MODE_0 DMA_MODE_0
#define ADI_USB_DMA_MODE_1 DMA_MODE_1

typedef enum
{
  ADI_USB_HDRC_RX_CHANNEL=0,
  ADI_USB_HDRC_TX_CHANNEL
}ADI_USB_HDRC_CHANNEL;

extern ADI_DEV_PDD_ENTRY_POINT ADI_USBDRC_Entrypoint;
extern ADI_DEV_PDD_ENTRY_POINT ADI_USB_HDRC_Entrypoint;


#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_HDRC_H_ */
