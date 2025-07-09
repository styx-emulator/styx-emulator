#ifndef _ADI_RAWPID_H_
#define _ADI_RAWPID_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <services/services.h>
#include <services/fss/adi_fss.h>

/*****************************************************************************
 * Raw PID module for accessing a PID at its most basic level
 *****************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Structure to communicate pertinent information about the Media
 *****************************************************************************/
typedef struct {
    u32 SizeInSectors;
    u32 FirstUsableSector;
    u32 SectorSize;
} ADI_RAWPID_MEDIA_INFO;


#if !defined(__ADI_RAWPID_C__)
extern ADI_DCB_CALLBACK_FN adi_rawpid_ClientCallbackFn;
#endif

/*
 * ****************************************************************************
 * ****************************************************************************
 * IMPORTANT
 * Please note that in order to use Raw PID you will need to ensure that
 * adi_sem_Init has been called to assign resources for 3 Semaphores,
 * 2 for the PID and one for Raw PID. You will also need to ensure sufficient
 * semaphores in your RTOS implementation
 * ****************************************************************************
 * ****************************************************************************
*/

u32 adi_rawpid_Init(
                    ADI_FSS_DEVICE_DEF      *pDeviceDef,        /* PID definitition structure           */
                    ADI_DEV_MANAGER_HANDLE  DevManHandle,       /* Device Manager Handle                */
                    ADI_DMA_MANAGER_HANDLE  DmaManHandle,       /* DMA Manager Handle                   */
                    ADI_DCB_HANDLE          DCBQueueHandle,     /* DCB Queue Handle                     */
                    ADI_DEV_DEVICE_HANDLE   *pDeviceHandle,     /* Location to store PID Device Handle  */
                    ADI_SEM_HANDLE          *pSemaphoreHandle   /* Location to store Semaphore Handle   */

);

u32 adi_rawpid_Terminate(
                    ADI_DEV_DEVICE_HANDLE   DeviceHandle,       /* PID Device Handle                    */
                    ADI_SEM_HANDLE          SemaphoreHandle     /* Semaphore Handle                     */
);

u32 adi_rawpid_RegisterPID(
                    ADI_DEV_DEVICE_HANDLE  DeviceHandle,
                    void                   *ClientHandle
);

u32 adi_rawpid_DeregisterPID(
                    ADI_DEV_DEVICE_HANDLE  DeviceHandle
);

u32 adi_rawpid_PollForMedia(
                    ADI_DEV_DEVICE_HANDLE  DeviceHandle
);

u32 adi_rawpid_GetMediaInfo(
                    ADI_DEV_DEVICE_HANDLE   DeviceHandle,       /* PID Device Handle                    */
                    ADI_RAWPID_MEDIA_INFO   *pDriveInfo         /* location to store Drive Information  */
);

/* Transfer Sectors: buffer size, in 16 bit words, must be >= SectorCount*size-of-sectors/2
 *                   where size-of-sectors is given in bytes.
 *                   For HDD this is 512 bytes
*/
u32 adi_rawpid_TransferSectors(
                    ADI_DEV_DEVICE_HANDLE   DeviceHandle,       /* PID Device Handle                    */
                    u32                     Drive,              /* Device Number of Device on chain     */
                    u32                     SectorNumber,       /* Starting Sector number (LBA)         */
                    u32                     SectorCount,        /* Number of sectors to transfer        */
                    u32                     SectorSize,         /* Size of sector in bytes              */
                    u16                     *buf,               /* Buffer to place date in              */
                    u32                     ReadFlag,           /* Flag: 1=Read, 0=Write                */
                    ADI_SEM_HANDLE          SemaphoreHandle     /* Semaphore Handle                     */

);

/* Non blocking variant - does not use PID lock and returns immediately */
u32 adi_rawpid_TransferSectorsNonBlock(
                                ADI_DEV_DEVICE_HANDLE DeviceHandle,
                                u32 Drive,
                                u32 SectorNumber,
                                u32 SectorCount,
                                u32 SectorSize,
                                u16 *buf,
                                u32 ReadFlag
);

#ifdef __cplusplus
}
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_RAWPID_H_ */
