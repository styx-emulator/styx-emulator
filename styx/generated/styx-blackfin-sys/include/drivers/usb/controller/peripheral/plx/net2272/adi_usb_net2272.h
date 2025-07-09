/*******************************************************************************

Copyright(c) 2009 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_net2272.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
             PLX NET2272 device driver header file.

*******************************************************************************/

#ifndef _ADI_USB_NET2272_H_
#define _ADI_USB_NET2272_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <drivers\usb\usb_core\adi_usb_objects.h>

#include <services\services.h>

/* Some assumptions are made as to how the NET2272 is connected to the
 * processor.
 * For example, we assume 16-bit wide data and that all 5 address bits are
 * used.  Commands are provided so that you may change the base address, but
 * other deviations from the USB-LAN EZ-EXTENDER design may require changes and
 * a rebuild.
 */

/* (1) target processor definitions
 * (2) base address for the NET2272 registers in the async bank
 *     (bank 3 assumed if USB_BASE_ADDR is not already defined)
 */
#if   defined(__ADSP_BRODIE__)
    #ifndef USB_BASE_ADDR
    #define USB_BASE_ADDR       0x20300000
    #endif
#elif defined(__ADSP_EDINBURGH__)
    #ifndef USB_BASE_ADDR
    #define USB_BASE_ADDR       0x20300000
    #endif
#elif defined(__ADSP_BRAEMAR__)
    #ifndef USB_BASE_ADDR
    #define USB_BASE_ADDR       0x20300000
    #endif
#elif defined(__ADSP_TETON__)
    #ifndef USB_BASE_ADDR
    #define USB_BASE_ADDR       0x2C000000
    #endif
#else
    #error *** Processor not supported ***
#endif

/* entry point to the device driver */
extern ADI_DEV_PDD_ENTRY_POINT ADI_USB_NET2272_Entrypoint;

/*
 * NET2272 Registers
 *
 * Note that only registers with offsets 0x00 - 0x1F are directly accessible.
 * Registers with larger offsets must be accessed indirectly by placing the
 * offset in REGADDRPTR and reading/writing the value via REGDATA.
 */

/*
 * Main control register group
 * NET2272 USB Periperipheral controller - Revision 1.2 (Oct 15 2003)
 * Ref: pg-53
 *
 */
#define REGADDRPTR      0x00 /* Register address pointer */
#define REGDATA         0x01 /* Register Data */
#define IRQSTAT0        0x02 /* Interrupt status register low byte */
#define IRQSTAT1        0x03 /* Interrupt status register high byte */
#define PAGESEL         0x04 /* Endpoint page select register */
#define DMAREQ          0x1C /* DMA Request control */
#define SCRATCH         0x1D /* General purpose scratch pad */
#define IRQENB0         0x20 /* Interrupt Enable Register low byte */
#define IRQENB1         0x21 /* Interrupt Enable Register high byte*/
#define LOCCTL          0x22 /* Local bus control */
#define CHIPREV_LEGACY  0x23 /* Legacy chip silicon revision  */
#define LOCCTL1         0x24 /* Local bus control */
#define CHIPREV_2272    0x25 /* Net2272 Chip Silicon Revision */

/*
 * Direct addresses for Main Control register group.
 */
#define REGADDRPTR_ADDR     (USB_BASE_ADDR + (REGADDRPTR << 2))
#define REGDATA_ADDR        (USB_BASE_ADDR + (REGDATA    << 2))
#define IRQSTAT0_ADDR       (USB_BASE_ADDR + (IRQSTAT0   << 2))
#define IRQSTAT1_ADDR       (USB_BASE_ADDR + (IRQSTAT1   << 2))
#define PAGESEL_ADDR        (USB_BASE_ADDR + (PAGESEL    << 2))
#define DMAREQ_ADDR         (USB_BASE_ADDR + (DMAREQ     << 2))
#define SCRATCH_ADDR        (USB_BASE_ADDR + (SCRATCH    << 2))

/**
 *
 * USB Control register group
 * NET2272 USB Periperipheral controller - Revision 1.2 (Oct 15 2003)
 * Ref: pg-54
 *
 **/
#define USBCTL0         0x18 /* USB control register (low byte) */
#define USBCTL1         0x19 /* USB control register (high byte) */
#define USBFRAME0       0x1A /* USB frame number (low byte) */
#define USBFRAME1       0x1B /* USB frame number (high byte) */
#define OURADDRESS      0x30 /* Our USB address  */
#define USBDIAG         0x31 /* USB diagnostic register  */
#define USBTEST         0x32 /* USB diagnostic register  */
#define XCVRDIAG        0x33 /* USB Transceiver diagnostic register  */
#define VIRTOUT0        0x34 /* VirtualOut interrupt 0 */
#define VIRTOUT1        0x35 /* VirtualOut interrupt 1 */
#define VIRTIN0         0x36 /* VirtualIN interrupt 0 */
#define VIRTIN1         0x37 /* VirtualIN interrupt 1 */
#define SETUP0          0x40 /* Setup byte 0 */
#define SETUP1          0x41 /* Setup byte 1 */
#define SETUP2          0x42 /* Setup byte 2 */
#define SETUP3          0x43 /* Setup byte 3 */
#define SETUP4          0x44 /* Setup byte 4 */
#define SETUP5          0x45 /* Setup byte 5 */
#define SETUP6          0x46 /* Setup byte 6 */
#define SETUP7          0x47 /* Setup byte 7 */

/*
 * Direct addresses for USB Control register group.
 */

#define USBCTL0_ADDR        (USB_BASE_ADDR + (USBCTL0   << 2))
#define USBCTL1_ADDR        (USB_BASE_ADDR + (USBCTL1   << 2))
#define USBFRAME0_ADDR      (USB_BASE_ADDR + (USBFRAME0 << 2))
#define USBFRAME1_ADDR      (USB_BASE_ADDR + (USBFRAME1 << 2))

/**
 *
 * Endpoint register group
 * NET2272 USB Periperipheral controller - Revision 1.2 (Oct 15 2003)
 * Ref: pg-54
 *
 * Note: These set of EP register are for each endpoint. PAGESEL register
 * is used to select the endpoint.
 **/
#define EP_DATA         0x05 /* Endpoint DATA register */
#define EP_STAT0        0x06 /* Endpoint Status register (low byte) */
#define EP_STAT1        0x07 /* Endpoint Status register (high byte) */
#define EP_TRANSFER0    0x08 /* IN endpoint byte count0 */
#define EP_TRANSFER1    0x09 /* IN endpoint byte count1 */
#define EP_TRANSFER2    0x0A /* IN endpoint byte count2 */
#define EP_IRQENB       0x0B /* Endpoint interrupt enable */
#define EP_AVAIL0       0x0C /* Bufferspace/byte count (byte 0) */
#define EP_AVAIL1       0x0D /* Bufferspace/byte count (byte 1) */
#define EP_RSPCLR       0x0E /* Ep response control clear */
#define EP_RSPSET       0x0F /* Ep response set */
#define EP_MAXPKT0      0x28 /* Ep Maximum packet low byte */
#define EP_MAXPKT1      0x29 /* Ep Maximum packet high byte */
#define EP_CFG          0x2A /* Ep configuration */
#define EP_HBW          0x2B /* Ep high bandwidth */
#define EP_BUFF_STATES  0x2C /* Ep buffer states */

/*
 * Direct addresses for Endpoint register group.
 */
#define EP_DATA_ADDR        (USB_BASE_ADDR + (EP_DATA      << 2))
#define EP_STAT0_ADDR       (USB_BASE_ADDR + (EP_STAT0     << 2))
#define EP_STAT1_ADDR       (USB_BASE_ADDR + (EP_STAT1     << 2))
#define EP_TRANSFER0_ADDR   (USB_BASE_ADDR + (EP_TRANSFER0 << 2))
#define EP_TRANSFER1_ADDR   (USB_BASE_ADDR + (EP_TRANSFER1 << 2))
#define EP_TRANSFER2_ADDR   (USB_BASE_ADDR + (EP_TRANSFER2 << 2))
#define EP_IRQENB_ADDR      (USB_BASE_ADDR + (EP_IRQENB    << 2))
#define EP_AVAIL0_ADDR      (USB_BASE_ADDR + (EP_AVAIL0    << 2))
#define EP_AVAIL1_ADDR      (USB_BASE_ADDR + (EP_AVAIL1    << 2))
#define EP_RSPCLR_ADDR      (USB_BASE_ADDR + (EP_RSPCLR    << 2))
#define EP_RSPSET_ADDR      (USB_BASE_ADDR + (EP_RSPSET    << 2))

/*************************************************************************/

/* IRQSTAT0/IRQENB0 interrupt bits pg:56 */
/* NET2272 USB Periperipheral controller - Revision 1.2 (Oct 15 2003) */
#define EP_0_INTERRUPT          (1 << 0)
#define EP_A_INTERRUPT          (1 << 1)
#define EP_B_INTERRUPT          (1 << 2)
#define EP_C_INTERRUPT          (1 << 3)
#define VIRTUAL_EP_INTERRUPT    (1 << 4)
#define SETUP_PKT_INT           (1 << 5)
#define DMA_DONE_INT            (1 << 6)
#define SOF_INT                 (1 << 7)
#define IRQSTAT0_ALL_INT        ((SOF_INT) | (DMA_DONE_INT) | (SETUP_PKT_INT))

/* IRQSTAT1/IRQENB1 interrupt bits pg:57/59 */
/* NET2272 USB Periperipheral controller - Revision 1.2 (Oct 15 2003) */
#define ROOT_PORT_RESET_INT     (1 << 6)
#define RESUME_INT              (1 << 5)
#define SUSPEND_RQT_CHANGE_INT  (1 << 4)
#define SUSPEND_RQT_INT         (1 << 3)
#define VBS_INT                 (1 << 2)
#define CONTROL_STATUS_INT      (1 << 1)

#define IRQSTAT1_ALL_INT        ((ROOT_PORT_RESET_INT)    | \
                                 (RESUME_INT)             | \
                                 (SUSPEND_RQT_CHANGE_INT) | \
                                 (SUSPEND_RQT_INT)        | \
                                 (VBS_INT)                | \
                                 (CONTROL_STATUS_INT))

/* Endpoints pg:57 */
#define EP0 0x00
#define EPA 0x01
#define EPB 0x02
#define EPC 0x03

/* EPSTAT0 pg:68 */
#define EP_BUFFER_FULL          (1 << 7)
#define EP_BUFFER_EMPTY         (1 << 6)
#define EP_NAC_OUT_INT          (1 << 5)
#define EP_SHORT_PKT_TFRD_INT   (1 << 4)
#define EP_DATA_RCVD_INT        (1 << 3)
#define EP_DATA_XMTD_INT        (1 << 2)
#define EP_DATA_OUT_TOKEN_INT   (1 << 1)
#define EP_DATA_IN_TOKEN_INT    (1 << 0)

#define EP_STAT0_INT_ALL        ((EP_NAC_OUT_INT)        | \
                                 (EP_SHORT_PKT_TFRD_INT) | \
                                 (EP_DATA_RCVD_INT)      | \
                                 (EP_DATA_XMTD_INT)      | \
                                 (EP_DATA_OUT_TOKEN_INT) | \
                                 (EP_DATA_IN_TOKEN_INT))

/* EPSTAT1 pg:69 */
#define EP_BUFFER_FLUSH         (1 << 7)
#define EP_USB_STALL_SENT       (1 << 5)
#define EP_USB_IN_NACK_SENT     (1 << 4)
#define EP_USB_IN_NACK_RCV      (1 << 3)
#define EP_USB_OUT_NACK_SENT    (1 << 2)
#define EP_USB_OUT_ACK_SENT     (1 << 1)
#define EP_USB_TIMEOUT          (1 << 0)

#define EP_STAT1_INT_ALL        ((EP_BUFFER_FLUSH)      | \
                                 (EP_USB_STALL_SENT)    | \
                                 (EP_USB_IN_NACK_SENT)  | \
                                 (EP_USB_IN_NACK_RCV)   | \
                                 (EP_USB_OUT_NACK_SENT) | \
                                 (EP_USB_OUT_ACK_SENT)  | \
                                 (EP_USB_TIMEOUT))

/* EP_RSPCLR/EP_RSPSET register bits pg:71&72*/
#define EP_ALT_NAK_OUT_PACKETS      (1 << 7)
#define EP_HIDE_STATUS_PHASE        (1 << 6)
#define EP_AUTO_VALIDATE            (1 << 5)
#define EP_INTERRUPT_MODE           (1 << 4)
#define EP_CONTROL_STATUS_PHASE_HS  (1 << 3)
#define EP_NAK_OUT_PACKETS_MODE     (1 << 2)
#define EP_TOGGLE                   (1 << 1)
#define EP_HALT                     (1 << 0)

/* USBCTL0 register bits */
#define ROOT_PORT_WAKEUP_ENABLE     (1 << 5)
#define USB_DETECT_ENABLE           (1 << 3)
#define IO_WAKEUP_ENABLE            (1 << 1)
#define USBCTL0_ENABLE_ALL          ((ROOT_PORT_WAKEUP_ENABLE) | \
                                     (USB_DETECT_ENABLE)       | \
                                     (IO_WAKEUP_ENABLE))

/* USBCTL1 register bits */
#define VIRTUAL_EP_ENABLE           (1 << 4)
#define GENERATE_RESUME             (1 << 3)
#define USB_HIGH_SPEED              (1 << 2)
#define USB_FULL_SPEED              (1 << 1)
#define VBUS_STATE                  (1 << 0)

/*
 * Use direct addressing for NET2272 registers sitting at 0x00 - 0x1F.  The
 * rest (0x20 - 0x40) have to use indirect addressing with REGADDRPTR.
 *
 * The functions ensure that data load and store instructions cannot
 * be interrupted (fatal for FIFO, and possibly others).
 */

/* OUT BYTE DIRECT */
inline void _outpb_d(unsigned int addr,unsigned char value)
{
    unsigned char volatile *paddr = (unsigned char volatile*)(addr);
    unsigned int imask = cli();
    *paddr = value;
    sti(imask);
    csync();
}

/* OUT WORD DIRECT */
inline void _outpw_d(unsigned int addr,unsigned short value)
{
    unsigned short volatile *paddr = (unsigned short volatile*)(addr);
    unsigned int imask = cli();
    *paddr = value;
    sti(imask);
    csync();
}

/* OUT BYTE INDIRECT */
inline void _outpb_ind(int reg_addr,unsigned char value)
{
    unsigned char volatile *paddr = (unsigned char volatile*)REGADDRPTR_ADDR;
    unsigned int imask;

    /* put the register address in the REGADDRPTR register */
    *paddr = reg_addr;
    csync();
    paddr = (unsigned char volatile*)(REGDATA_ADDR);
    imask = cli();
    *paddr = value;
    sti(imask);
    csync();
}

/* OUT WORD INDIRECT */
inline void _outpw_ind(int reg_addr,unsigned short value)
{
    unsigned short volatile *paddr = (unsigned short volatile*)REGADDRPTR_ADDR;
    unsigned int imask;

    /* put the register address in the REGADDRPTR register */
    *paddr = reg_addr;
    csync();
    paddr = (unsigned short volatile*)(REGDATA_ADDR);
    imask = cli();
    *paddr = value;
    sti(imask);
    csync();
}

/* IN BYTE DIRECT */
inline char _inpb_d(unsigned int addr)
{
    unsigned char r_val;
    unsigned char volatile *paddr = (unsigned char volatile*)(addr);
    unsigned int imask;
    csync();
    imask = cli();
    r_val = *paddr;
    sti(imask);
    return r_val;
}

/* IN WORD DIRECT */
inline short _inpw_d(unsigned int addr)
{
    unsigned short r_val;
    unsigned short volatile *paddr = (unsigned short volatile*)(addr);
    unsigned int imask;
    csync();
    imask = cli();
    r_val = *paddr;
    sti(imask);
    return r_val;
}

/* IN BYTE INDIRECT */
inline char _inpb_ind(int reg_addr)
{
    unsigned char r_val;
    unsigned char volatile *paddr = (unsigned char volatile*)REGADDRPTR_ADDR;
    unsigned int imask;

    /* put the register address in the REGADDRPTR register */
    *paddr = reg_addr;
    csync();
    paddr = (unsigned char volatile*)REGDATA_ADDR;
    imask = cli();
    r_val = *paddr;
    sti(imask);
    return r_val;
}

/* IN WORD INDIRECT */
inline short _inpw_ind(int reg_addr)
{
    unsigned short r_val;
    unsigned short volatile *paddr = (unsigned short volatile*)REGADDRPTR_ADDR;
    unsigned int imask;

    /* put the register address in the REGADDRPTR register */
    *paddr = reg_addr;
    csync();
    paddr = (unsigned short volatile*)REGDATA_ADDR;
    imask = cli();
    r_val = *paddr;
    sti(imask);
    return r_val;
}

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_NET2272_H_ */
