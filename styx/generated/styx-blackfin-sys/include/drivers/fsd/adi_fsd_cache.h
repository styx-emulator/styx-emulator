/* *****************************************************
 * FSD Driver File Allocation Table Cache
 * *****************************************************
 */
#ifndef  __ADI_FSD_CACHE_H__
#define  __ADI_FSD_CACHE_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <services/services.h>
#include <services/fss/adi_fss.h>

typedef void* ADI_FSD_CACHE_HANDLE;


/* Flag to indicate flush on write */
#define ADI_FSD_CACHE_FLUSH_ON_WRITE        1


u32 adi_fsd_cache_Open (
    ADI_DEV_DEVICE_HANDLE   PIDHandle,
    u32                     DeviceNumber,
    ADI_FSD_CACHE_HANDLE    *CacheHandle,
    u32                     Flags,              /* Bit mapped flags */
    u32                     CacheSize,          /* Number of cache blocks */
    u32                     BlockSize,          /* Number of sectors per block */
    u32                     SectorSize,         /* Number of bytes per sectos */
    u32                     DataElementWidth,   /* Data transfer element width */
    u32                     GeneralHeapIndex,
    u32                     CacheHeapIndex,
    u32                     PreCharge,
    u32                     PreChargeSector,
    ADI_SEM_HANDLE          SemaphoreHandle);


/* Close the FSD Cache, any modified blocks are flushed */
u32 adi_fsd_cache_Close(
    ADI_FSD_CACHE_HANDLE    CacheHandle,
    u32                     FlushFlag);


/* Use hash for cache lookup, this will speed up large caches */
u32 adi_fsd_cache_CreateHash(
    ADI_FSD_CACHE_HANDLE    CacheHandle,
    u32                     BlockCount);        /* Number of cache blocks for each hash entry */


/* Flush all modified blocks */
u32 adi_fsd_cache_Flush(
    ADI_FSD_CACHE_HANDLE    CacheHandle);


/* Read a block, the block will be read from physical media if it is not
    psesent in the cache, the block will become locked and needs to be
    written or released. If there are no free blocks in the cache the least
    use block will be flushed and re-allocated to the new block.
*/
u32 adi_fsd_cache_Read(
    ADI_FSD_CACHE_HANDLE    CacheHandle,
    u32                     SectorNumber,
    u32                     SectorCount,
    u8                      **pData);


/* Allocate a block, The same as adi_fsd_cache_Read but the block will not
    actually be read off the PID. This is used when the contents of the
    block is not important
*/
u32 adi_fsd_cache_Allocate(
    ADI_FSD_CACHE_HANDLE    CacheHandle,
    u32                     SectorNumber,
    u32                     SectorCount,
    u8                      **pData);


/* Clear the lock and set the block to modified, when flush is called the
    block will be written back to the hardware
*/
u32 adi_fsd_cache_Write(
    ADI_FSD_CACHE_HANDLE    CacheHandle,
    u8                      *pData);


/* Clear the lock only */
u32 adi_fsd_cache_Release(
    ADI_FSD_CACHE_HANDLE    CacheHandle,
    u8                      *pData);


/* Flush just the block */
u32 adi_fsd_cache_FlushBlock(
    ADI_FSD_CACHE_HANDLE    CacheHandle,
    u32                     SectorNumber,
    u32                     SectorCount);


/* Remove the block from the cache, if the block is modified then flush
    first
*/
u32 adi_fsd_cache_RemoveBlock(
    ADI_FSD_CACHE_HANDLE    CacheHandle,
    u32                     SectorNumber,
    u32                     SectorCount);



#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /* __ADI_FSD_CACHE_H__ */
