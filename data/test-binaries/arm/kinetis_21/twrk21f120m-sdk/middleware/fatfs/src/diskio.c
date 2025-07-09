/*
 * The Clear BSD License
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted (subject to the limitations in the disclaimer below) provided
 * that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this list
 *   of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * o Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY THIS LICENSE.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*-----------------------------------------------------------------------*/
/* Low level disk I/O module skeleton for FatFs  (C)ChaN, 2016  */
/*-----------------------------------------------------------------------*/
#include "ffconf.h"     /* FatFs configuration options */
#include "diskio.h"     /* FatFs lower layer API */
#ifdef RAM_DISK_ENABLE
#include "fsl_ram_disk.h"
#endif

#ifdef USB_DISK_ENABLE
#include "fsl_usb_disk.h"
#endif

#ifdef SD_DISK_ENABLE
#include "fsl_sd_disk.h"
#endif

#ifdef MMC_DISK_ENABLE
#include "fsl_mmc_disk.h"
#endif

#ifdef SDSPI_DISK_ENABLE
#include "fsl_sdspi_disk.h"
#endif

/*-----------------------------------------------------------------------*/
/* Get Drive Status                                                      */
/*-----------------------------------------------------------------------*/

DSTATUS disk_status (
	BYTE pdrv		/* Physical drive nmuber to identify the drive */
)
{
	DSTATUS stat;
    switch (pdrv)
    {
#ifdef RAM_DISK_ENABLE
        case RAMDISK:
            stat = ram_disk_status(pdrv);
            return stat;
#endif
#ifdef USB_DISK_ENABLE
        case USBDISK:
            stat = USB_HostMsdGetDiskStatus(pdrv);
            return stat;
#endif
#ifdef SD_DISK_ENABLE
        case SDDISK:
            stat = sd_disk_status(pdrv);
            return stat;
#endif
#ifdef MMC_DISK_ENABLE
        case MMCDISK:
            stat = mmc_disk_status(pdrv);
            return stat;
#endif
#ifdef SDSPI_DISK_ENABLE
        case SDSPIDISK:
            stat = sdspi_disk_status(pdrv);
            return stat;
#endif
        default:
            break;
    }
    return STA_NOINIT;
}



/*-----------------------------------------------------------------------*/
/* Inidialize a Drive                                                    */
/*-----------------------------------------------------------------------*/

DSTATUS disk_initialize (
	BYTE pdrv				/* Physical drive nmuber to identify the drive */
)
{
	DSTATUS stat;
    switch (pdrv)
    {
#ifdef RAM_DISK_ENABLE
        case RAMDISK:
            stat = ram_disk_initialize(pdrv);
            return stat;
#endif
#ifdef USB_DISK_ENABLE
        case USBDISK:
            stat = USB_HostMsdInitializeDisk(pdrv);
            return stat;
#endif
#ifdef SD_DISK_ENABLE
        case SDDISK:
            stat = sd_disk_initialize(pdrv);
            return stat;
#endif
#ifdef MMC_DISK_ENABLE
        case MMCDISK:
            stat = mmc_disk_initialize(pdrv);
            return stat;
#endif
#ifdef SDSPI_DISK_ENABLE
        case SDSPIDISK:
            stat = sdspi_disk_initialize(pdrv);
            return stat;
#endif
        default:
            break;
    }
    return STA_NOINIT;
}



/*-----------------------------------------------------------------------*/
/* Read Sector(s)                                                        */
/*-----------------------------------------------------------------------*/

DRESULT disk_read (
	BYTE pdrv,		/* Physical drive nmuber to identify the drive */
	BYTE *buff,		/* Data buffer to store read data */
	DWORD sector,	/* Start sector in LBA */
	UINT count		/* Number of sectors to read */
)
{
	DRESULT res;
    switch (pdrv)
    {
#ifdef RAM_DISK_ENABLE
        case RAMDISK:
            res = ram_disk_read(pdrv, buff, sector, count);
            return res;
#endif
#ifdef USB_DISK_ENABLE
        case USBDISK:
            res = USB_HostMsdReadDisk(pdrv, buff, sector, count);
            return res;
#endif
#ifdef SD_DISK_ENABLE
        case SDDISK:
            res = sd_disk_read(pdrv, buff, sector, count);
            return res;
#endif
#ifdef MMC_DISK_ENABLE
        case MMCDISK:
            res = mmc_disk_read(pdrv, buff, sector, count);
            return res;
#endif
#ifdef SDSPI_DISK_ENABLE
        case SDSPIDISK:
            res = sdspi_disk_read(pdrv, buff, sector, count);
            return res;
#endif
        default:
            break;
    }

	return RES_PARERR;
}



/*-----------------------------------------------------------------------*/
/* Write Sector(s)                                                       */
/*-----------------------------------------------------------------------*/

DRESULT disk_write (
	BYTE pdrv,			/* Physical drive nmuber to identify the drive */
	const BYTE *buff,	/* Data to be written */
	DWORD sector,		/* Start sector in LBA */
	UINT count			/* Number of sectors to write */
)
{
	DRESULT res;
    switch (pdrv)
    {
#ifdef RAM_DISK_ENABLE
        case RAMDISK:
            res = ram_disk_write(pdrv, buff, sector, count);
            return res;
#endif
#ifdef USB_DISK_ENABLE
        case USBDISK:
            res = USB_HostMsdWriteDisk(pdrv, buff, sector, count);
            return res;
#endif
#ifdef SD_DISK_ENABLE
        case SDDISK:
            res = sd_disk_write(pdrv, buff, sector, count);
            return res;
#endif
#ifdef MMC_DISK_ENABLE
        case MMCDISK:
            res = mmc_disk_write(pdrv, buff, sector, count);
            return res;
#endif
#ifdef SDSPI_DISK_ENABLE
        case SDSPIDISK:
            res = sdspi_disk_write(pdrv, buff, sector, count);
            return res;
#endif
        default:
            break;
    }
    return RES_PARERR;
}


/*-----------------------------------------------------------------------*/
/* Miscellaneous Functions                                               */
/*-----------------------------------------------------------------------*/

DRESULT disk_ioctl (
	BYTE pdrv,		/* Physical drive nmuber (0..) */
	BYTE cmd,		/* Control code */
	void *buff		/* Buffer to send/receive control data */
)
{
	DRESULT res;
    switch (pdrv)
    {
#ifdef RAM_DISK_ENABLE
        case RAMDISK:
            res = ram_disk_ioctl(pdrv, cmd, buff);
            return res;
#endif
#ifdef USB_DISK_ENABLE
        case USBDISK:
            res = USB_HostMsdIoctlDisk(pdrv, cmd, buff);
            return res;
#endif
#ifdef SD_DISK_ENABLE
        case SDDISK:
            res = sd_disk_ioctl(pdrv, cmd, buff);
            return res;
#endif
#ifdef MMC_DISK_ENABLE
        case MMCDISK:
            res = mmc_disk_ioctl(pdrv, cmd, buff);
            return res;
#endif
#ifdef SDSPI_DISK_ENABLE
        case SDSPIDISK:
            res = sdspi_disk_ioctl(pdrv, cmd, buff);
            return res;
#endif
        default:
            break;
    }
    return RES_PARERR;
}
