/*********************************************************************************

Copyright(c) 2010 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_fss.h,v $
$Revision: 3578 $
$Date: 2010-10-19 09:36:04 -0400 (Tue, 19 Oct 2010) $

Description:
            This is the header file for the File System Service (FSS).

*********************************************************************************/

#ifndef __ADI_FSS_H__
#define __ADI_FSS_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if !defined(_LANGUAGE_ASM)


#include <device.h>
#include <time.h>
#include <drivers/adi_dev.h>
#include <services/services.h>
#include <services/sem/adi_sem.h>

/*********************************************************************
This flag allows the user to perform the "format" function on the
storage devices whose PID's accept the format command. It does increase
code size should it be enabled. If the User needs to reduce code size
they can undefine the ADI_USE_FAT_FORMAT flag and either re-compile
the proper library or include the adi_fss.c file in their project
and recompile their project with that file included. Doing so will
remove the support for the "format" function, thus redicing code size.
This define is located in two places, the file adi_fss.c and adi_fss.h.
BOTH locations need to be changed for the change to take effect.
*********************************************************************/
#if !defined(ADI_USE_FAT_FORMAT)
#define ADI_USE_FAT_FORMAT 1
#endif



/*********************************************************************
* Datatypes & Macros
*********************************************************************/

typedef void *ADI_FSS_FILE_HANDLE;      /* Handle type for Open Files */
typedef void *ADI_FSS_DIR_HANDLE;       /* Handle type for Open Directory */
typedef char ADI_FSS_VOLUME_IDENT;      /* Data type for Volume Identifiers */

typedef char ADI_FSS_CHAR;      /* Strong type for characters. This may change
                                   if general strings should ever require to
                                   be defined as Unicode 'Wide' chars */

/* Strong type for Unicode 'Wide' characters. The _UNICODE_SUPPORT_ macro
   enables the FSS to switch between using 16 bit arrays for UTF-8 Unicode
   and standard ascii 8 bit format.
 */
#if defined(_UNICODE_SUPPORT_)
typedef u16  ADI_FSS_WCHAR;
#else
typedef char ADI_FSS_WCHAR;
#endif

/* Extern declaration of libio DevEntry structure defining the
 * the 'CRT I/O Device Driver' representation of the FSS
 */
#ifndef ADI_FSS_MODULE
extern DevEntry adi_fss_entry;
#endif

/* Device ID for DevEntry structure. Is an 'int' hence leading 0. */
#define ADI_FSS_DEVID 0x00AD1F55

/************************************************************************************
*************************************************************************************

           DEFINITIONS AND PROTOTYPES FOR ADDITIONAL POSIX FUNCTIONS

************************************************************************************
*************************************************************************************/

#ifndef _UNISTD_H

#include <services/services.h>
#include <time.h>

typedef u32 ino_t;
typedef u32 off_t;

#define S_IFDIR       0x0040000 /* Directory.  */
#define S_IFCHR       0x0020000 /* Character device.  */
#define S_IFBLK       0x0060000 /* Block device.  */
#define S_IFREG       0x0100000 /* Regular file.  */
#define S_IFIFO       0x0010000 /* FIFO.  */
#define S_IFLNK       0x0120000 /* Symbolic link.  */
#define S_IFSOCK      0x0140000 /* Socket.  */

struct stat {
    int             st_mode;                   /* File mode.  */
    int             st_size;                   /* Size of file, in bytes.  */
    time_t          st_mtime;                  /* Modified time */
};

#pragma linkage_name __adi_fss_stat
int stat(const char *restrict path, struct stat *restrict buf);
#pragma linkage_name __adi_fss_chdir
int chdir(const char *path);
#pragma linkage_name __adi_fss_getcwd
char *getcwd(char *buf, size_t size);

#endif /* _UNISTD_H */

#ifndef _DIRENT_H

#define _DIRENT_HAVE_D_TYPE
#define _DIRENT_HAVE_D_NAMLEN

struct dirent {
    ino_t d_ino;                /* File Serial Number */
    off_t d_off;                /* Offset to next directory entry */
    unsigned char d_namlen;     /* length minus trailing \0 of entry name */
    unsigned char d_type;       /* type (see valid values below) */
    char d_name[256];           /* Entry name */

    u32 d_size;                 /* File Size */
    struct tm DateCreated;      /* Date & Time whem entry was created */
    struct tm DateModified;     /* Date & Time whem entry was last modified*/
    struct tm DateLastAccess;   /* Date & Time whem entry was last accessed */
                                /* availability depends on File System */
};

/* this new structure is compatible with struct dirent but adds a new member
*/
typedef struct ADI_FSS_DIR_ENTRY {
    ino_t d_ino;                /* File Serial Number */
    off_t d_off;                /* Offset to next directory entry */
    unsigned char d_namlen;     /* length minus trailing \0 of entry name */
    unsigned char d_type;       /* type (see valid values below) */
    char d_name[256];           /* Entry name */

    u32 d_size;                 /* File Size */
    struct tm DateCreated;      /* Date & Time whem entry was created */
    struct tm DateModified;     /* Date & Time whem entry was last modified*/
    struct tm DateLastAccess;   /* Date & Time whem entry was last accessed */
                                /* availability depends on File System */
    u32 Attributes;             /* FAT File attributes */

} ADI_FSS_DIR_ENTRY;


/* d_type values (applicable to embedded DSP)  */
enum {
    DT_UNKNOWN,
    DT_REG,         // regular file
    DT_DIR          // Directory entry
};

/* DIR is an opaque handle to directory stream */
typedef struct __DIR DIR;
typedef u32 mode_t;

#pragma linkage_name __adi_fss_closedir
int            closedir(DIR *);
#pragma linkage_name __adi_fss_opendir
DIR           *opendir(const char *);
#pragma linkage_name __adi_fss_readdir
struct dirent *readdir(DIR *);
#pragma linkage_name __adi_fss_readdir_r
int            readdir_r(DIR *restrict, struct dirent *restrict,
                   struct dirent **restrict);
#pragma linkage_name __adi_fss_rewinddir
void           rewinddir(DIR *);
#pragma linkage_name __adi_fss_seekdir
void           seekdir(DIR *, long);
#pragma linkage_name __adi_fss_telldir
long           telldir(DIR *);
#pragma linkage_name __adi_fss_mkdir
int            mkdir(const char *path, mode_t mode);
#pragma linkage_name __adi_fss_rmdir
int            rmdir(const char *path);

#endif /* _DIRENT_H */


/************************************************************************************
*************************************************************************************/



/*********************************************************
* Result Codes
*********************************************************/

enum {
    ADI_FSS_RESULT_SUCCESS,             /* (0x00000000) Successful completion of request                */
    ADI_FSS_RESULT_FAILED,              /* (0x00000000) Generic failure code                            */

    ADI_FSS_RESULT_START = ADI_FSS_ENUMERATION_START,       /* (0x000B0000) */

    ADI_FSS_RESULT_OPEN_FAILED,             /* (0x000B0001) File/Directory open failure (media fault)       */
    ADI_FSS_RESULT_NOT_FOUND,               /* (0x000B0002) File/Directory not found                        */
    ADI_FSS_RESULT_CLOSE_FAILED,            /* (0x000B0003) File/Directory close failure (media fault)      */
    ADI_FSS_RESULT_NO_MEDIA,                /* (0x000B0004) No media detected                               */
    ADI_FSS_RESULT_MEDIA_CHANGED,           /* (0x000B0005) Media has changed since last check              */
    ADI_FSS_RESULT_MEDIA_FULL,              /* (0x000B0006) No room left on media                           */
    ADI_FSS_RESULT_NO_MEMORY,               /* (0x000B0007) Insufficient memory to perform request          */
    ADI_FSS_RESULT_INVALID_DEVICE,          /* (0x000B0008) The device driver cannot be initialized         */
    ADI_FSS_RESULT_BAD_FILE_HANDLE,         /* (0x000B0009) No valid File descriptor at address supplied    */
    ADI_FSS_RESULT_BAD_NAME,                /* (0x000B000A) Invalid path specified for file/directory       */
    ADI_FSS_RESULT_EOF,                     /* (0x000B000B) End of file is reached                          */
    ADI_FSS_RESULT_EOD,                     /* (0x000B000C) End of directory reached                        */
    ADI_FSS_RESULT_BAD_VOLUME,              /* (0x000B000D) Invalid partition specified                     */
    ADI_FSS_RESULT_NOT_SUPPORTED,           /* (0x000B000E) Command code is not supported                   */
    ADI_FSS_RESULT_TIMEOUT,                 /* (0x000B0010) A timeout has occurred                          */
    ADI_FSS_RESULT_BAD_CACHE_HANDLE,        /* (0x000B0011) Bad cache handle                                */
    ADI_FSS_RESULT_CANT_CREATE_SEMAPHORE    /* (0x000B0012) Can't create semaphore in file cache            */
};

/*********************************************************
* Command ID's
*********************************************************/
enum {
    ADI_FSS_CMD_START = ADI_FSS_ENUMERATION_START,      /* (0x000B0000) */

    /* FSS only commands
    */
    ADI_FSS_CMD_SET_SEPARATOR,              /* (0x000B0001) Defines the directory separator             */
    ADI_FSS_CMD_END,                        /* (0x000B0002) End of table of Control Command pairs       */
    ADI_FSS_CMD_PAIR,                       /* (0x000B0003) Value is pointer to Control Command pair    */
    ADI_FSS_CMD_TABLE,                      /* (0x000B0004) Value is pointer to table of Command pairs  */
    ADI_FSS_CMD_ADD_DRIVER,                 /* (0x000B0005) Set location of File System Table           */
    ADI_FSS_CMD_SET_MALLOC_FUNC,            /* (0x000B0006) Set client malloc function                  */
    ADI_FSS_CMD_SET_REALLOC_FUNC,           /* (0x000B0007) Set client realloc fucntion                 */
    ADI_FSS_CMD_SET_FREE_FUNC,              /* (0x000B0008) Set client free function                    */
    ADI_FSS_CMD_SET_VOLUME_SEPARATOR,       /* (0x000B0009) Set volume separator character              */
    ADI_FSS_CMD_SET_DIRECTORY_SEPARATOR,    /* (0x000B000A) Set directory separator character           */
    ADI_FSS_CMD_GET_NUMBER_VOLUMES,         /* (0x000B000B) Get the number of available partitions      */
    ADI_FSS_CMD_GET_VOLUME_INFO,            /* (0x000B000C) Get information re available partitions     */
    ADI_FSS_CMD_SET_DMA_MGR_HANDLE,         /* (0x000B000D) Set DMA manager handle                      */
    ADI_FSS_CMD_SET_DEV_MGR_HANDLE,         /* (0x000B000E) Set Device manager handle                   */
    ADI_FSS_CMD_SET_DCB_MGR_HANDLE,         /* (0x000B000F) Set DCB queue manager handle                */
    ADI_FSS_CMD_SET_MEDIA_CHANGE_TIMER,     /* (0x000B0010) Set Media Change Timer interval             */
    ADI_FSS_CMD_SET_CACHE_HEAP_ID,          /* (0x000B0011) Heap ID for cache blocks       .            */
    ADI_FSS_CMD_SET_NUMBER_CACHE_BLOCKS,    /* (0x000B0012) Number of cache blocks to use (min 2)       */
    ADI_FSS_CMD_SET_NUMBER_CACHE_SUB_BLOCKS,/* (0x000B0013) Number of cache sub blocks to use (min 1)   */
    ADI_FSS_CMD_SET_GENERAL_HEAP_ID,        /* (0x000B0014) Heap ID for file descriptors etc.           */
    ADI_FSS_CMD_ACQUIRE_LOCK_SEMAPHORE,     /* (0x000B0015) Requests a Lock Semaphore from an FSD/PID   */
    ADI_FSS_CMD_RELEASE_LOCK_SEMAPHORE,     /* (0x000B0016) Releases a Lock Semaphore to an FSD/PID     */
    ADI_FSS_CMD_GET_BACKGRND_XFER_SUPPORT,  /* (0x000B0017) determines whether FSD/PID supports background transfers */
    ADI_FSS_CMD_GET_DATA_ELEMENT_WIDTH,     /* (0x000B0018) Requests FSD/PID to provide the Element width required */
    ADI_FSS_CMD_REGISTER_DEVICE,            /* (0x000B0018) Register a device driver PID/FSD with FSS  */
    ADI_FSS_CMD_DEREGISTER_DEVICE,          /* (0x000B0018) Deregister a device driver PID/FSD with FSS */
    ADI_FSS_CMD_SET_MEDIA_CHANGE_CALLBACK,  /* (0x000B0019) Set the client callback function for media change */
    ADI_FSS_CMD_SET_MEDIA_CHANGE_HANDLE,    /* (0x000B001A) Set the client handle for media change callback  */
    ADI_FSS_CMD_SET_DATA_SEMAPHORE_TIMEOUT, /* (0x000B001B) Set the adi_sem_pend() timeout argument */
    ADI_FSS_CMD_SET_TRANSFER_RETRY_COUNT,   /* (0x000B001C) Set the number of retries after semaphore time-outs */
    ADI_FSS_CMD_SET_MEM_ALIGNMENT,          /* (0x000B001D) Set the alignment option for Memory allocation */


    /* FSD only commands
    */
    ADI_FSD_GENERAL_CMD_START = ADI_FSS_ENUMERATION_START + 0x00004000, /* (0x000B4000) */

    ADI_FSD_CMD_SET_PID_HANDLE,             /* (0x000B4001) Set the device handle for the required PID  */
    ADI_FSD_CMD_MOUNT_VOLUME,               /* (0x000B4002) Mount the volume                            */
    ADI_FSD_CMD_UNMOUNT_VOLUME,             /* (0x000B4003) Unmount the volume                          */
    ADI_FSD_CMD_GET_LABEL,                  /* (0x000B4004) Get pointer to label string                 */
    ADI_FSD_CMD_GET_BLOCK_SIZE,             /* (0x000B4005) Get Smallest meaningful block size          */
    ADI_FSD_CMD_CHANGE_DIR,                 /* (0x000B4006) Change the current working directory        */
    ADI_FSD_CMD_MAKE_DIR,                   /* (0x000B4007) Create a new directory                      */
    ADI_FSD_CMD_REMOVE_DIR,                 /* (0x000B4008) Remove an empty directory                   */
    ADI_FSD_CMD_REMOVE,                     /* (0x000B400A) Remove a file                               */
    ADI_FSD_CMD_RENAME,                     /* (0x000B400B) Rename a file/directory                     */
    ADI_FSD_CMD_OPEN_FILE,                  /* (0x000B400C) Open an existing file                       */
    ADI_FSD_CMD_CLOSE_FILE,                 /* (0x000B400D) Close an open file                          */
    ADI_FSD_CMD_SEEK_FILE,                  /* (0x000B400E) Seek to the given location in a file        */
    ADI_FSD_CMD_OPEN_DIR,                   /* (0x000B400F) Open a directory for reading                */
    ADI_FSD_CMD_CLOSE_DIR,                  /* (0x000B4010) Close a directory                           */
    ADI_FSD_CMD_READ_DIR,                   /* (0x000B4011) Read the next directory entry               */
    ADI_FSD_CMD_SEEK_DIR,                   /* (0x000B4012) Seek to the given location in a directory   */
    ADI_FSD_CMD_REWIND_DIR,                 /* (0x000B4013) Rewind to start of a directory              */
    ADI_FSD_CMD_STAT,                       /* (0x000B4014) Get status information for file/directory   */
    ADI_FSD_CMD_GET_FILE_SYSTEM_SUPPORT,    /* (0x000B4015) Query FSD for support of give file system   */
    ADI_FSD_CMD_GET_TYPE_STRING,            /* (0x000B4016) Query FSD for File system string            */
    ADI_FSD_CMD_FORMAT_VOLUME,              /* (0x000B4017) Format a volume                             */
    ADI_FSD_CMD_GET_VOLUME_USAGE,           /* (0x000B4018) Get Volume usage Statistics                 */
    ADI_FSD_CMD_ADD_FILE_ATTR,              /* (0x000B4019) Write back directory entry (Attributes only)*/
    ADI_FSD_CMD_REMOVE_FILE_ATTR,           /* (0x000B401A) Write back directory entry (Attributes only)*/
    ADI_FSD_CMD_REPLACE_FILE_ATTR,          /* (0x000B401B) Write back directory entry (Attributes only)*/
    ADI_FSD_CMD_GET_MAX_CONTIG_BLOCKS,      /* (0x000B401C) Get max contiguous blocks in chain          */

    ADI_FSD_CUSTOM_CMD_START = ADI_FSS_ENUMERATION_START + 0x00006000,/* (0x000B6000) */
    /* PID only commands
    */
    ADI_PID_GENERAL_CMD_START = ADI_FSS_ENUMERATION_START + 0x00008000,/* (0x000B8000) */

    ADI_PID_CMD_SET_DIRECT_CALLBACK,        /* (0x000B8001) Pass the FSS callback funciton address      */
    ADI_PID_CMD_MEDIA_ACTIVATE,             /* (0x000B8002) Activate the media                          */
    ADI_PID_CMD_GET_GLOBAL_MEDIA_DEF,       /* (0x000B8003) Get Global media sizes                      */
    ADI_PID_CMD_SEND_LBA_REQUEST,           /* (0x000B8004) Send read request to media                  */
    ADI_PID_CMD_GET_FIXED,                  /* (0x000B8006) Determine whether fixed or removable        */
    ADI_PID_CMD_SET_NUMBER_DEVICES,         /* (0x000B8007) Sets the number of devices attached         */
    ADI_PID_CMD_SET_VOLUME_PRIORITY,        /* (0x000B8008) Set priority of volumes found on media      */
    ADI_PID_CMD_POLL_MEDIA_CHANGE,          /* (0x000B8009) Poll PID for presence/absence of media      */
    ADI_PID_CMD_DETECT_VOLUMES,             /* (0x000B800A) Get the driver to detect any volumes        */
    ADI_PID_CMD_ENABLE_DATAFLOW,            /* (0x000B800B) Enables Dataflow on Device only             */
    ADI_PID_CMD_GET_MAX_READ_SPEED,         /* (0x000B800C) Get maximum read speed (optical drive)      */
    ADI_PID_CMD_SET_READ_SPEED,             /* (0x000B800D) Set read speed (optical drive)              */
    ADI_PID_CMD_GET_MAX_WRITE_SPEED,        /* (0x000B800E) Get maximum write speed (optical drive)     */
    ADI_PID_CMD_SET_WRITE_SPEED,            /* (0x000B800F) Set write speed (optical drive)             */
    ADI_PID_CDAUDIO_CMD_GET_DISK_INFO,      /* (0x000B8010) Get the Disk Information (CD Audio)         */
    ADI_PID_CDAUDIO_CMD_GET_TRACK_INFO,     /* (0x000B8011) Get Track information (CD Audio)            */
    ADI_PID_CDAUDIO_CMD_GET_CD_TEXT,        /* (0x000B8012) Get raw CD Text data  (CDAudio)             */
    ADI_PID_CMD_DISABLE_INTERRUPT,          /* (0x000B8013) Disable Device Interrupt                    */
    ADI_PID_CMD_ENABLE_INTERRUPT,           /* (0x000B8014) Enable Device Interrupt                     */
    ADI_PID_CMD_GET_MAX_TFRCOUNT,           /* (0x000B8015) Get max number sectors for single transfer  */

    ADI_PID_CUSTOM_CMD_START = ADI_FSS_ENUMERATION_START + 0x0000A000,/* (0x000BA000) */

    ADI_FSS_CMD_LAST  = ADI_FSS_ENUMERATION_START + 0x0000C000   /* (0x000BC000) */
};

#define ADI_FSS_FILE_ATTR_ADD       ADI_FSD_CMD_ADD_FILE_ATTR
#define ADI_FSS_FILE_ATTR_REMOVE    ADI_FSD_CMD_REMOVE_FILE_ATTR
#define ADI_FSS_FILE_ATTR_REPLACE   ADI_FSD_CMD_REPLACE_FILE_ATTR

/*********************************************************
 FSS command value pair
*********************************************************/
typedef struct {
    u32     CommandID;                      /* command ID                                               */
    void    *Value;                         /* Associated argument                                      */
} ADI_FSS_CMD_VALUE_PAIR;


/*********************************************************
* Event ID's
*********************************************************/
enum {
    ADI_FSS_EVENT_START = ADI_FSS_ENUMERATION_START,            /* (0x000B0000) */

    ADI_FSS_EVENT_MEDIA_INSERTED,           /* (0x000B0001) Media has been inserted (hotplug)           */
    ADI_FSS_EVENT_MEDIA_REMOVED,            /* (0x000B0002) Media has been removed (hotplug)            */
    ADI_FSS_EVENT_VOLUME_DETECTED,          /* (0x000B0003) Media has detected a new volume             */
    ADI_FSS_EVENT_VOLUME_MOUNT,             /* (0x000B0004) New volume has been mounted                 */
    ADI_FSS_EVENT_VOLUME_UNMOUNT,           /* (0x000B0005) Volume is about to be un-mounted            */
    ADI_FSS_EVENT_ERROR_INTERRUPT,          /* (0x000B0006) An error has occurred in transmission       */
    ADI_PID_EVENT_DEVICE_INTERRUPT,         /* (0x000B0007) An error has occurred in transmission       */
    ADI_FSS_EVENT_MEDIA_DETECTED,           /* (0x000B0008) Media has been removed (hotplug)            */
    ADI_FSS_EVENT_MEDIA_ERROR               /* (0x000B0009) Error in accessing media                    */
};


/*********************************************************
* Open File Mode masks
*********************************************************/
enum {
    ADI_FSS_MODE_READ           = 0x00000000,  /* Read only access                                      */
    ADI_FSS_MODE_WRITE          = 0x00000001,  /* Write access only                                     */
    ADI_FSS_MODE_READ_WRITE     = 0x00000002,  /* Read and Write access                                 */
    ADI_FSS_MODE_INVALID        = 0x00000003,  /* invalid mode                                          */
    ADI_FSS_MODE_APPEND         = 0x00000008,  /* Append mode                                           */
    ADI_FSS_MODE_CREATE         = 0x00000100,  /* Create file if not found                              */
    ADI_FSS_MODE_TRUNCATE       = 0x00000200,  /* Truncate file if existing file opened for write       */
    ADI_FSS_MODE_TEXT_STREAM    = 0x00004000,  /* File is to be regarded as a text stream               */
    ADI_FSS_MODE_BINARY_STREAM  = 0x00008000   /* File is to be regarded as a binary stream (raw)       */
};

/*********************************************************
* Memory allocation alignment options
*********************************************************/
enum {
    ADI_FSS_MEM_NOALIGN,
    ADI_FSS_MEM_ALIGN
};

/*******************************************************************
* Structure to contain Timer Definition for Configuration of Media
* Change Polling.
*******************************************************************/
typedef struct {
    u32                 TimerID;            /* ID of Timer as per the Timer Service                   */
    u32                 IVG;                /* IVG level of Timer interrupt                           */
    u32                 Interval;           /* Interval in millisecs between polliung                 */
    ADI_DCB_CALLBACK_FN ClientCallback;     /* Callback function to call on detection of media change */
    void                *ClientHandle;      /* application data handle passed to callback             */
} ADI_FSS_TIMER_DEF;

/*******************************************************************
* Doubly Linked List Structure for a full name
* pNext = NULL for last item (file), others are directories
* name = NULL for root directory.
*******************************************************************/

typedef struct ADI_FSS_FULL_FNAME {
    struct ADI_FSS_FULL_FNAME   *pNext;         /* Next item in line             */
    struct ADI_FSS_FULL_FNAME   *pPrevious;     /* Previous item in line         */
    ADI_FSS_WCHAR               *name;          /* Name in UTF-8 Unicode         */
    u32                         namelen;        /* length of name string (chars) */
} ADI_FSS_FULL_FNAME;


/*******************************************************************
* Structure to define a Device Driver, both FSD & PID
*******************************************************************/

typedef struct {
    u32                     DeviceNumber;               /* Peripheral Device Number */
    ADI_DEV_PDD_ENTRY_POINT *pEntryPoint;               /* Entry point table                         */
    ADI_DEV_CMD_VALUE_PAIR  *pConfigTable;              /* Configuration table                       */
    void                    *pCriticalRegionData;       /* Critical region data                      */
    ADI_DEV_DIRECTION       Direction;                  /* Direction (CD-ROM's etc would be RO)      */
    ADI_DEV_DEVICE_HANDLE   DeviceHandle;               /* Device Handle as returned by adi_dev_Open */
    ADI_FSS_VOLUME_IDENT    DefaultMountPoint;      /* Default Mounting Point to use, if NULL then
                                                        defaults to the FSS Mount Point. FSD Mount
                                                        point has priority over PID ident. */
} ADI_FSS_DEVICE_DEF;

/*******************************************************************
* Enumerator for known File System types.
*******************************************************************/

enum {
    ADI_FSS_FSD_TYPE_UNKNOWN      = 0,
    ADI_FSS_FSD_TYPE_FAT          = 1,
    ADI_FSS_FSD_TYPE_CDDATA_MODE1 = 2,
    ADI_FSS_FSD_TYPE_CDDATA_MODE2 = 3,
    ADI_FSS_FSD_TYPE_CDAUDIO      = 4,
    ADI_FSS_FSD_TYPE_YAFFS        = 5,
    ADI_FSS_FSD_TYPE_UNASSIGNED   = 0x6FFFFFFF,
    ADI_FSS_FSD_TYPE_FREE         = 0x7FFFFFFF
};

/*******************************************************************
* Volume enumerations used for volume type prioritisation
*******************************************************************/

enum {
    ADI_FSS_PID_VOLUME_ROCKRIDGE,   /* not supported, unix style FS */
    ADI_FSS_PID_VOLUME_JOLIET3,     /* Microsoft extension V3 */
    ADI_FSS_PID_VOLUME_JOLIET2,     /* Microsoft extension V2 */
    ADI_FSS_PID_VOLUME_JOLIET1,     /* Microsoft extension V1 */
    ADI_FSS_PID_VOLUME_HFS,         /* not supported, Apple FS */
    ADI_FSS_PID_VOLUME_HIGHSIERRA,  /* Standard ISO9660 volume */

    ADI_FSS_PID_VOLUME_END          /* Count of the number of volumes */
};

/*******************************************************************
* Structure for Volume Information
*******************************************************************/

typedef struct {
    u32 FileSystemType;     /* File System Type                     */
    u32 StartAddress;       /* Start address of volume on media     */
    u32 VolumeSize;         /* Number of Sectors in volume          */
    u32 SectorSize;         /* Number of bytes per sector in volume */
    u32 DeviceNumber;       /* The number of the device on the bus  */
} ADI_FSS_VOLUME_DEF;

/*******************************************************************
* Structure to convey pertinent volume information
*******************************************************************/

typedef struct {
    u32                     Index;      /* Index used to get volume info          */
    ADI_FSS_VOLUME_IDENT    Ident;      /* Unique Volume Identifier               */
    ADI_FSS_WCHAR           *label;     /* Volume label (NULL terminated)         */
    ADI_FSS_WCHAR           *type;      /* Volume type                            */
    u32                     size;       /* Volume size in MB                      */
    u8                      status;     /* Mount Status: 0=not mounted, 1=mounted */
} ADI_FSS_VOLUME_INFO;

/*******************************************************************
* Structure to return CD Disc information
*******************************************************************/
typedef struct {
    u32             DeviceNumber;       /* Device Number in chain                 */
    u32             Tracks;             /* number of audio tracks                 */
} ADI_FSS_CDAUDIO_DISK_INFO;

/*******************************************************************
* Structure to return CD Track information
*******************************************************************/
typedef struct {
    u32             DeviceNumber;       /* Device Number in chain                 */
    u32             Index;              /* index of track                         */
    u32             Address;            /* LBA address of track                   */
    u32             Size;               /* Size of track in sectors               */
} ADI_FSS_CDAUDIO_TRACK_INFO;

/*******************************************************************
* Structure to return CD-Text
*******************************************************************/
typedef struct {
    u32             DeviceNumber;       /* Device Number in chain                 */
    u32             Size;               /* Size of buffer supplied                */
    u32             Read;               /* Total size of CD-Text                  */
    u8              *pData;             /* Data buffer supplied by fsd, the size
                                           of this buffer is given in Size */
} ADI_FSS_CDAUDIO_CD_TEXT;



/*******************************************************************
* Macros to formulate/interpret options Mask
*******************************************************************/
#define ADI_FSS_FMT_OPTION_VALUE(FILESYS,TYPE) \
            (   (FILESYS) << ADI_FSS_FMT_OPTION_SHIFT_FILESYS \
              | (TYPE) << ADI_FSS_FMT_OPTION_SHIFT_TYPE \
            )

#define ADI_FSS_FMT_OPTION_GET_FILESYS(VALUE)  \
            ( ((VALUE)&ADI_FSS_FMT_OPTION_MASK_FILESYS)>>ADI_FSS_FMT_OPTION_SHIFT_FILESYS )
#define ADI_FSS_FMT_OPTION_GET_TYPE(VALUE)  \
            ( ((VALUE)&ADI_FSS_FMT_OPTION_MASK_TYPE)>>ADI_FSS_FMT_OPTION_SHIFT_TYPE )

/*******************************************************************
* Structure to convey pertinent format information to FSD
*******************************************************************/
typedef struct {
    ADI_FSS_VOLUME_IDENT ident;         /* Volume Identifier                 */
    ADI_FSS_WCHAR        *label;        /* label                             */
    u32                  label_len;     /* Length of label string            */
    u32                  OptionMask;    /* Options to pass to FSD            */
    ADI_FSS_VOLUME_DEF   VolumeDef;     /* Volume Definition                 */
} ADI_FSS_FORMAT_DEF;

#define ADI_FSS_FMT_OPTION_MASK_FILESYS     0xFFFF0000
#define ADI_FSS_FMT_OPTION_SHIFT_FILESYS    16
#define ADI_FSS_FMT_OPTION_MASK_TYPE        0x0000000F
#define ADI_FSS_FMT_OPTION_SHIFT_TYPE       0

/* Smallest size of unassigned media space is 512 byte sectors */
#define ADI_FSS_SMALLEST_PARTITIONABLE_SIZE (16*1024) /* 8MB */

/*******************************************************************
* Structure to request a new partition
*******************************************************************/
typedef struct {
    ADI_FSS_VOLUME_DEF *pExistingVolumeDef;             /* This is the original 'free' volume */
    ADI_FSS_VOLUME_DEF *pNewVolumeDef;                  /* a new 'free' volume if partition does not fill entire space */
} ADI_FSS_PARTITION_REQUEST;


/*******************************************************************
* Opaque Handle data types to hide internal detail from Cache module
* and FSD drivers.
*******************************************************************/

typedef void *ADI_FSS_FSD_DATA_HANDLE;      /* Handle type for FSD File Data */
typedef void *ADI_FSS_CACHE_DATA_HANDLE;    /* Handle type for Cache Data    */


/*******************************************************************
* File Descriptor Structure - pointer to which returned by 'open'
*******************************************************************/

typedef struct {
    ADI_FSS_FULL_FNAME        *pFullFileName;           /* linked list of path name                         */
    u32                       curpos;                   /* Current position in file/directory               */
    u32                       fsize;                    /* total file size                                  */
    int                       mode;                     /* access mode                                      */
    ADI_FSS_FSD_DATA_HANDLE   FSD_data_handle;          /* handle to FSD internal data structure            */
    ADI_DEV_DEVICE_HANDLE     FSD_device_handle;        /* handle to FSD device driver                      */
    void                      *pCriticalRegionData;     /* Critical region data                             */
    ADI_FSS_CACHE_DATA_HANDLE Cache_data_handle;        /* handle to Cache module internal data structure   */
} ADI_FSS_FILE_DESCRIPTOR;

/*******************************************************************
* Seek definition Structure
*******************************************************************/

typedef struct {
    ADI_FSS_FILE_DESCRIPTOR *pFileDesc;     /* File Descriptor of required file */
    int whence;                             /* From 'whence' to seek            */
    long offset;                            /* signed offset to seek position   */
} ADI_FSS_SEEK_REQUEST;


/*******************************************************************
* Directory Entry definition Structure
*******************************************************************/

typedef struct {
    ADI_FSS_FILE_DESCRIPTOR *pFileDesc;     /* File Descriptor of required directory */
    ADI_FSS_DIR_ENTRY entry;                /* Current directory entry               */
    u32 tellpos;                            /* Location of current directory entry   */
} ADI_FSS_DIR_DEF;


/*******************************************************************
* File/Directory rename Structure
*******************************************************************/

typedef struct {
    ADI_FSS_FULL_FNAME      *pSource;       /* linked list of path name of file to be renamed           */
    ADI_FSS_FULL_FNAME      *pTarget;       /* linked list of path name of new file name or directory   */
} ADI_FSS_RENAME_DEF;


/*******************************************************************
* LBA Request Structure
*******************************************************************/
struct ADI_FSS_SUPER_BUFFER;

typedef struct ADI_FSS_LBA_REQUEST {
    u32                         SectorCount;        /* Number of Sectors to retrieve           */
    u32                         StartSector;        /* First Sector                            */
    u32                         DeviceNumber;       /* ID of device to which to submit request */
    u32                         ReadFlag;           /* =1 Read; 0=Write                        */
    struct ADI_FSS_SUPER_BUFFER *pBuffer;           /* Pointer to associated Super buffer      */
} ADI_FSS_LBA_REQUEST;


/*******************************************************************
* Super Buffer Structure to wrap around device driver 1D buffer to
* convey extra information
*******************************************************************/
typedef struct ADI_FSS_SUPER_BUFFER{
    ADI_DEV_1D_BUFFER       Buffer;                 /* Device Driver 1D buffer itself */
    struct adi_cache_block  *pBlock;                /* pointer to the cache block to which this buffer belongs */
    u8                      LastInProcessFlag;      /* flag indicating if this is the last buffer in the fill/flush for the block */
    ADI_FSS_LBA_REQUEST     LBARequest;             /* LBA Request required for sub buffer */
    ADI_SEM_HANDLE          SemaphoreHandle;        /* Handle of Semaphore to Post on transfer completion */
    ADI_FSS_FILE_DESCRIPTOR *pFileDesc;             /* FSS File Descriptor */
    ADI_DCB_CALLBACK_FN     FSDCallbackFunction;    /* FSD Callback function */
    void                    *FSDCallbackHandle;     /* FSD Callback Handle   */
    ADI_DCB_CALLBACK_FN     PIDCallbackFunction;   /* PID Callback function */
    void                    *PIDCallbackHandle;     /* FSD Callback Handle   */
    volatile u32           CompletionBitMask;
} ADI_FSS_SUPER_BUFFER;

/*******************************************************************
*Structure to hold Volume usage information
*******************************************************************/
typedef struct {
    u32 nSectorSize;                        /* Sector Size in Bytes                   */
    u32 nClusterSize;                       /* Number of sectors per cluster          */
    u32 nFreeClusters;                      /* Number of Free clusters                */
    u32 nTotalClusters;                     /* Total number of clusters               */
    u32 nVolumeSize;                        /* Total number of sectors                */
} ADI_FSS_VOLUME_USAGE_DEF;

/************************************************************************************
*************************************************************************************

                            API FUNCTION PROTOTYPES

************************************************************************************
*************************************************************************************/
#ifdef __cplusplus
extern "C"
{
#endif

/* Service Management Functions
   ****************************
*/

u32 adi_fss_Init (          /* Initialize File System Service */
    ADI_FSS_CMD_VALUE_PAIR *pTable         /* Address of Command Table                      */
);

u32 adi_fss_Terminate(      /* Terminate File System Service */
    void
);

u32 adi_fss_Control(        /* Control function */
    u32     CommandID,                  /* command ID                                       */
    void    *Value                      /* command specific value                           */
);

/* File Operations
   ***************
*/

u32 adi_fss_FileOpen (      /* Open a file stream */
    ADI_FSS_WCHAR *name,                /* Unicode UTF-8 array identifying file to open     */
    u32 namelen,                        /* Length of Unicode array                          */
    u32 mode,                           /* Mode in which file is to be opened               */
    ADI_FSS_FILE_HANDLE *FileHandle     /* location to store Handle identifying file stream */
);

u32 adi_fss_FileClose(      /* Close a file stream */
    ADI_FSS_FILE_HANDLE FileHandle      /* Handle identifying file stream                   */
);

u32 adi_fss_FileWrite(      /* Write to file stream */
    ADI_FSS_FILE_HANDLE FileHandle,     /* Handle identifying file stream                   */
    u8 *buf,                            /* Start address of buffer to write                 */
    u32 size,                           /* Number of bytes to write                         */
    u32 *BytesWritten                   /* Location to store actual size written            */
);

u32 adi_fss_FileRead (      /* Read from file stream */
    ADI_FSS_FILE_HANDLE FileHandle,     /* Handle identifying file stream                   */
    u8 *buf,                            /* Start address of buffer to fill                  */
    u32 size,                           /* Number of bytes to read                          */
    u32 *BytesRead                      /* Location to store actual size read               */
);

u32 adi_fss_FileSeek (      /* Seek to location in file stream */
    ADI_FSS_FILE_HANDLE FileHandle,     /* Handle identifying file stream                   */
    s32 offset,                         /* Offset from 'whence' location                    */
    u32 whence,                         /* Location to begin seek from                      */
    u32 *tellpos                        /* Location to store current position after seek    */
);

u32 adi_fss_FileTell (      /* Report current location in file stream */
    ADI_FSS_FILE_HANDLE FileHandle,     /* Handle identifying file stream                   */
    u32 *tellpos                        /* Location to store current position in stream     */
);

u32 adi_fss_IsEOF(          /* Determine if end of file is reached */
    ADI_FSS_FILE_HANDLE FileHandle      /* Handle identifying file stream                   */
);

u32 adi_fss_FileRemove(     /* Remove a file */
    ADI_FSS_WCHAR *name,                /* Unicode UTF-8 array identifying file to open     */
    u32 namelen                         /* Length of name array                             */
);

u32 adi_fss_FileRename(     /* rename a file */
    ADI_FSS_WCHAR *old_path,            /* Unicode UTF-8 array identifying file to open     */
    u32 oldlen,                         /* Length of name array                             */
    ADI_FSS_WCHAR *new_path,            /* Unicode UTF-8 array identifying file to open     */
    u32 newlen                          /* Length of name array                             */
);

u32
adi_fss_FileSetAttr(        /* change attributes of a file */
    ADI_FSS_WCHAR *name,               /* Unicode UTF-8 array identifying file to open     */
    u32 namelen,                       /* Length of name array                              */
    u32 Attributes,                    /* Attributes to change */
    u32 ActionCommand                  /* Add/remove/replace option */
);

/* Directory Operations
   ********************
*/

u32 adi_fss_DirOpen  (      /* Open a directory stream */
    ADI_FSS_WCHAR *name,                /* Unicode UTF-8 array identifying directory to open */
    u32 namelen,                        /* Length of name array                              */
    ADI_FSS_DIR_HANDLE *DirHandle       /* location to store Handle identifying dir stream   */
);

u32 adi_fss_DirClose (      /* Close directory stream */
    ADI_FSS_DIR_HANDLE DirHandle       /* Handle identifying directory stream                */
);

u32 adi_fss_DirRead (       /* Read next entry from directory stream */
    ADI_FSS_DIR_HANDLE DirHandle,      /* Handle identifying directory stream               */
    ADI_FSS_DIR_ENTRY **pDirEntry      /* Location to store pointer to dir entry structure  */
);

u32 adi_fss_DirSeek (       /* Seek to location in directory stream */
    ADI_FSS_DIR_HANDLE DirHandle,      /* Handle identifying directory stream               */
    u32 tellpos                        /* Position in dir stream to seek to                 */
);

u32 adi_fss_DirTell (       /* Report current location in directory stream */
    ADI_FSS_DIR_HANDLE DirHandle,      /* Handle identifying directory stream               */
    u32 *tellpos                       /* Location to store current position                */
);

u32 adi_fss_DirRewind (     /* Rewind directory stream */
    ADI_FSS_DIR_HANDLE DirHandle       /* Handle identifying directory stream               */
);

u32 adi_fss_DirChange(      /* Change current working directory */
    ADI_FSS_WCHAR *name,                /* Unicode UTF-8 array identifying new CWD          */
    u32 namelen                         /* Length of name array                             */
);

u32 adi_fss_GetCurrentDir(  /* Open a directory stream */
    ADI_FSS_WCHAR *name,                /* Array to store Unicode UTF-8 name of CWD         */
    u32 *namelen                        /* location to store length of name array           */
);

u32 adi_fss_DirCreate  (    /* Create directory */
    ADI_FSS_WCHAR *name,                /* Unicode UTF-8 array identifying directory to open */
    u32 namelen,                        /* Length of name array                              */
    u32 mode                            /* mode of newly created file (ignored)              */
);

u32 adi_fss_DirRemove  (    /* Remove directory */
    ADI_FSS_WCHAR *name,                /* Unicode UTF-8 array identifying directory to open */
    u32 namelen                         /* Length of name array                              */
);

/* Other Operations
   ********************
*/

u32
adi_fss_Stat (  /* Get file/directory status */
    ADI_FSS_WCHAR *name,                /* Array to store Unicode UTF-8 name of file/dir    */
    u32 namelen,                        /* Length of name array                             */
    struct stat *pStat                  /* Address of structure to hold information         */
);

u32 adi_fss_GetVolumeUsage( /* Get Volume Usage Statistics */
    ADI_FSS_VOLUME_IDENT        Ident,          /* IDENT of volume                    */
    ADI_FSS_VOLUME_USAGE_DEF    *poVolumeUsage  /* Address of structure to hold stats */
);

u32 adi_fss_TransferSectors(  /* Transfer Sectors on raw PID Interface */
                            ADI_DEV_DEVICE_HANDLE   hDevice,                /* Device Handle */
                            void                    *pData,                 /* Data buffer */
                            u32                     Drive,                  /* Drive number in chain */
                            u32                     SectorNumber,           /* Sector Number */
                            u32                     SectorCount,            /* Sector Count */
                            u32                     SectorSize,             /* Sector Size in bytes*/
                            u32                     DataElementWidth,       /* Datalement width in bytes */
                            u32                     bReadFlag,              /* true = read, false = write */
                            ADI_SEM_HANDLE          hSemaphore             /* semaphore handle to pend on */
);


/* Poll Media Functions
   ********************
*/

u32 adi_fss_PollMedia (  /* Call ADI_PID_CMD_POLL_MEDIA_CHANGE control for all PID's */
    void
);

#ifndef _DEVICE_REGISTRATION_MODS_
#define _DEVICE_REGISTRATION_MODS_
#endif
#ifdef _DEVICE_REGISTRATION_MODS_
u32 adi_fss_RegisterDevice( ADI_FSS_DEVICE_DEF *pDeviceDef, u32 PollForMedia );
u32 adi_fss_DeRegisterDevice( ADI_DEV_DEVICE_HANDLE DeviceHandle );
u32 adi_fss_PollMediaOnDevice( ADI_DEV_DEVICE_HANDLE DeviceHandle );
#endif

/************************************************************************************
*************************************************************************************

           FUNCTION PROTOTYPES FOR STDIO RENAME/REMOVE REPLACEMENTS

************************************************************************************
*************************************************************************************/

#pragma linkage_name __adi_fss_remove
int remove(const char *_filename);
#pragma linkage_name __adi_fss_rename
int rename(const char *_oldnm, const char *_newnm);

#ifdef __cplusplus
}
#endif



/************************************************************************************
*************************************************************************************/

#endif /* !defined(_LANGUAGE_ASM) */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_FSS_H__ */
