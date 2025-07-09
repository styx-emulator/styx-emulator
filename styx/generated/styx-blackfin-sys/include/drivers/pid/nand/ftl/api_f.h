#ifndef _API_F_H_
#define _API_F_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/****************************************************************************
 *
 *            Copyright (c) 2003-2007 by HCC Embedded
 *
 * This software is copyrighted by and is the sole property of
 * HCC.  All rights, title, ownership, or other interests
 * in the software remain the property of HCC.  This
 * software may only be used in accordance with the corresponding
 * license agreement.  Any unauthorized use, duplication, transmission,
 * distribution, or disclosure of this software is expressly forbidden.
 *
 * This Copyright notice may not be removed or modified without prior
 * written consent of HCC.
 *
 * HCC reserves the right to modify this software without notice.
 *
 * HCC Embedded
 * Budapest 1133
 * Vaci ut 110
 * Hungary
 *
 * Tel:  +36 (1) 450 1302
 * Fax:  +36 (1) 450 1303
 * http: www.hcc-embedded.com
 * email: info@hcc-embedded.com
 *
 ***************************************************************************/

/****************************************************************************
 *
 * open bracket for C++ compatibility
 *
 ***************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 *
 * if there is no udefs_f.h is included before
 * then this followed #define must be revised to be compatible
 * with UNICODE or LFN or 8+3 system
 * also FN_MAXPATH and FN_MUTEX_TYPE must be set to original
 *
 ***************************************************************************/

#ifndef _UDEFS_F_H_

/****************************************************************************
 *
 *  if Unicode is used then comment in HCC_UNICODE define
 *
 ***************************************************************************/

/* #define HCC_UNICODE  */

#ifndef HCC_UNICODE
    #define F_LONGFILENAME 0 /*  0 - 8+3 names   1 - long file names   */
    #define W_CHAR char
#else
    #define F_LONGFILENAME 1 /* don't change it, because unicode version alvays uses long file name */
    #define W_CHAR wchar
#endif

#define FN_MAXPATH  256     /* maximum allowed filename or pathname */
#define FN_MUTEX_TYPE unsigned long

#ifdef HCC_UNICODE
typedef unsigned short wchar;
#endif

/****************************************************************************
 *
 * End of udefs.h definition checking
 *
 ***************************************************************************/

#endif /* #ifndef _UDEFS_F_H_ */

/* definition of short filename */
#define F_MAXNAME   8       /*  8 byte name  */
#define F_MAXEXT    3       /*  3 byte extension  */

#ifndef NULL
#define NULL (void *)0
#endif

/* public structure for FN_FILE */
typedef struct
{
    void *reference;    /* reference which fileint used */
} FN_FILE;

/* F_NAME structure definition */
#if (!F_LONGFILENAME)
    typedef struct
    {
        int drivenum;               /*  drive number 0-A 1-B 2-C  */
        char path [FN_MAXPATH];     /*  pathnam  /directory1/dir2/   */
        char filename[F_MAXNAME];   /*  filename  */
        char fileext [F_MAXEXT];    /*  extension  */
    } F_NAME;
#else
    #define F_MAXLNAME  256         /* maximum length of long filename */
    typedef struct
    {
        int drivenum;               /*  drive number 0-A 1-B 2-C  */
        W_CHAR path  [FN_MAXPATH];  /*  pathname /directory1/dir2/   */
        W_CHAR lname [F_MAXLNAME];  /*  long file name   */
    } F_NAME;
#endif /*  F_LONGFILENAME   */

typedef struct
{
    unsigned long cluster;      /* which cluster is used */
    unsigned long prevcluster;  /* previous cluster for bad block handling */
    unsigned long sectorbegin;  /* calculated sector start */
    unsigned long sector;       /* current sector */
    unsigned long sectorend;    /* last saector position of the cluster */
    unsigned long pos;          /* current position */
} F_POS;

typedef struct
{
    char filename[FN_MAXPATH];  /* file name+ext */
    char name[F_MAXNAME];       /* file name */
    char ext[F_MAXEXT];         /* file extension */
    unsigned char attr;         /* attribute of the file */

    unsigned short ctime;       /* creation time */
    unsigned short cdate;       /* creation date */
    unsigned long filesize;     /* length of file */

    unsigned long cluster;      /* current file starting position */
    F_NAME findfsname;          /* find properties */
    F_POS pos;                  /* position of the current list */
} FN_FIND;

#ifdef HCC_UNICODE
typedef struct
{
    W_CHAR filename[FN_MAXPATH];/* file name+ext */
    char name[F_MAXNAME];       /* file name */
    char ext[F_MAXEXT];         /* file extension */
    unsigned char attr;         /* attribute of the file */

    unsigned short ctime;       /* creation time */
    unsigned short cdate;       /* creation date */
    unsigned long filesize;     /* length of file */

    unsigned long cluster;      /* current file starting position */
    F_NAME findfsname;          /* find properties */
    F_POS pos;                  /* position of the current list */
} FN_WFIND;
#endif

/* attribute file/directory bitpattern definitions */
#define F_ATTR_ARC      0x20
#define F_ATTR_DIR      0x10
#define F_ATTR_VOLUME   0x08
#define F_ATTR_SYSTEM   0x04
#define F_ATTR_HIDDEN   0x02
#define F_ATTR_READONLY 0x01

/*  definitions for ctime  */
#define F_CTIME_SEC_SHIFT       0
#define F_CTIME_SEC_MASK    0x001f  /* 0-30 in 2seconds */
#define F_CTIME_MIN_SHIFT       5
#define F_CTIME_MIN_MASK    0x07e0  /* 0-59  */
#define F_CTIME_HOUR_SHIFT      11
#define F_CTIME_HOUR_MASK   0xf800  /* 0-23 */

/*  definitions for cdate  */
#define F_CDATE_DAY_SHIFT       0
#define F_CDATE_DAY_MASK    0x001f  /* 0-31 */
#define F_CDATE_MONTH_SHIFT     5
#define F_CDATE_MONTH_MASK  0x01e0  /* 1-12 */
#define F_CDATE_YEAR_SHIFT      9
#define F_CDATE_YEAR_MASK   0xfe00  /* 0-119 (1980+value) */

typedef struct
{
    unsigned short number_of_cylinders;
    unsigned short sector_per_track;
    unsigned short number_of_heads;
    unsigned long number_of_sectors;
    unsigned char media_descriptor;

    unsigned short bytes_per_sector;
} F_PHY;

/* media descriptor to be set in getphy function */
#define F_MEDIADESC_REMOVABLE   0xf0
#define F_MEDIADESC_FIX         0xf8

/* return bitpattern for driver getphy function */
#define F_ST_MISSING   0x00000001
#define F_ST_CHANGED   0x00000002
#define F_ST_WRPROTECT 0x00000004

/* Driver definitions */
typedef struct F_DRIVER F_DRIVER;

typedef int (*F_WRITESECTOR)(F_DRIVER *driver,void *data, unsigned long sector);
typedef int (*F_WRITEMULTIPLESECTOR)(F_DRIVER *driver,void *data, unsigned long sector, int cnt);
typedef int (*F_READSECTOR)(F_DRIVER *driver,void *data, unsigned long sector);
typedef int (*F_READMULTIPLESECTOR)(F_DRIVER *driver,void *data, unsigned long sector, int cnt);
typedef int (*F_GETPHY)(F_DRIVER *driver,F_PHY *phy);
typedef long (*F_GETSTATUS)(F_DRIVER *driver);
typedef void (*F_RELEASE)(F_DRIVER *driver);

typedef struct F_DRIVER
{
    FN_MUTEX_TYPE mutex;    /* mutex for the driver */
    int separated;          /* signal if the driver is separated */

    unsigned long user_data;    /* user defined data */
    void *user_ptr;             /* user define pointer */

    /* driver functions */
    F_WRITESECTOR writesector;
    F_WRITEMULTIPLESECTOR writemultiplesector;
    F_READSECTOR readsector;
    F_READMULTIPLESECTOR readmultiplesector;
    F_GETPHY getphy;
    F_GETSTATUS getstatus;
    F_RELEASE release;
} _F_DRIVER;


typedef F_DRIVER *(*F_DRIVERINIT)(unsigned long driver_param);

/* When initvolume the driver will assign automatically a free driver */
#define F_AUTO_ASSIGN (unsigned long)(-1)

/* definition for a media and f_format */
enum
{
/* 0 */ F_UNKNOWN_MEDIA,
/* 1 */ F_FAT12_MEDIA,
/* 2 */ F_FAT16_MEDIA,
/* 3 */ F_FAT32_MEDIA
};

/* definition for partitions */
typedef struct
{
    unsigned long secnum;               /* number of sectors in this partition */
    unsigned char system_indicator;     /* use F_SYSIND_XX values*/
} F_PARTITION;

/* select system indication for creating partition */
#define F_SYSIND_DOSFAT12         0x01
#define F_SYSIND_DOSFAT16UPTO32MB 0x04
#define F_SYSIND_DOSFAT16OVER32MB 0x06
#define F_SYSIND_DOSFAT32         0x0b

/* these values for extended partition */
#define F_SYSIND_EXTWIN 0x0f
#define F_SYSIND_EXTDOS 0x05

/* definition for f_getfreespace */
typedef struct
{
    unsigned long total;
    unsigned long free;
    unsigned long used;
    unsigned long bad;

    unsigned long total_high;
    unsigned long free_high;
    unsigned long used_high;
    unsigned long bad_high;
} FN_SPACE;

/* definition for f_stat*/
typedef struct
{
    unsigned long filesize;
    unsigned short createdate;
    unsigned short createtime;
    unsigned short modifieddate;
    unsigned short modifiedtime;
    unsigned short lastaccessdate;
    unsigned char attr;                 /* 00ADVSHR */
    int drivenum;
} FN_STAT;

/****************************************************************************
 *
 * defines for f_findfirst
 *
 ***************************************************************************/

/* Beginning of file */
#ifdef SEEK_SET
#define FN_SEEK_SET SEEK_SET
#else
#define FN_SEEK_SET 0
#endif

/* Current position of file pointer */
#ifdef SEEK_CUR
#define FN_SEEK_CUR SEEK_CUR
#else
#define FN_SEEK_CUR 1
#endif

/* End of file */
#ifdef SEEK_END
#define FN_SEEK_END SEEK_END
#else
#define FN_SEEK_END 2
#endif

/****************************************************************************
 *
 * structure defines
 *
 ***************************************************************************/

#if (!FN_CAPI_USED)
#define F_FILE FN_FILE
#define F_FIND FN_FIND
#define F_SPACE FN_SPACE
#define F_MAXPATH FN_MAXPATH
#define F_SEEK_SET FN_SEEK_SET
#define F_SEEK_END FN_SEEK_END
#define F_SEEK_CUR FN_SEEK_CUR
#define F_STAT FN_STAT
#endif

/****************************************************************************
 *
 * function defines
 *
 ***************************************************************************/

#if (!FN_CAPI_USED)
#define f_init fn_init
#define f_getversion fm_getversion
#define f_createdriver(driver,driver_init,driver_param) fm_createdriver(driver,driver_init,driver_param)
#define f_releasedriver(driver) fm_releasedriver(driver)
#define f_createpartition(driver,parnum,par) fm_createpartition(driver,parnum,par)
#define f_getpartition(driver,parnum,par) fm_getpartition(driver,parnum,par)
#define f_initvolume(drvnumber,driver_init,driver_param) fm_initvolume(drvnumber,driver_init,driver_param)
#define f_initvolumepartition(drvnumber,driver,partition) fm_initvolumepartition(drvnumber,driver,partition)
#define f_getlasterror fm_getlasterror

#define f_delvolume(drvnumber) fm_delvolume(drvnumber)
#define f_get_volume_count() fm_get_volume_count()
#define f_get_volume_list(buf) fm_get_volume_list(buf)
#define f_checkvolume(drvnumber) fm_checkvolume(drvnumber)
#define f_format(drivenum,fattype) fm_format(drivenum,fattype)
#define f_getcwd(buffer,maxlen) fm_getcwd(buffer,maxlen)
#define f_getdcwd(drivenum,buffer,maxlen) fm_getdcwd(drivenum,buffer,maxlen)
#define f_chdrive(drivenum) fm_chdrive(drivenum)
#define f_getdrive fm_getdrive
#define f_getfreespace(drivenum,pspace) fm_getfreespace(drivenum,pspace)

#define f_chdir(dirname) fm_chdir(dirname)
#define f_mkdir(dirname) fm_mkdir(dirname)
#define f_rmdir(dirname) fm_rmdir(dirname)

#define f_findfirst(filename,find) fm_findfirst(filename,find)
#define f_findnext(find) fm_findnext(find)
#define f_rename(filename,newname) fm_rename(filename,newname)
#define f_move(filename,newname) fm_move(filename,newname)
#define f_filelength(filename) fm_filelength(filename)

#define f_close(filehandle) fm_close(filehandle)
#define f_flush(filehandle) fm_flush(filehandle)
#define f_open(filename,mode) fm_open(filename,mode)
#define f_truncate(filename,length) fm_truncate(filename,length)
#define f_ftruncate(filehandle,length) fm_ftruncate(filehandle,length)

#define f_read(buf,size,size_st,filehandle) fm_read(buf,size,size_st,filehandle)
#define f_write(buf,size,size_st,filehandle) fm_write(buf,size,size_st,filehandle)

#define f_seek(filehandle,offset,whence) fm_seek(filehandle,offset,whence)
#define f_seteof(filehandle) fm_seteof(filehandle)

#define f_tell(filehandle) fm_tell(filehandle)
#define f_getc(filehandle) fm_getc(filehandle)
#define f_putc(ch,filehandle) fm_putc(ch,filehandle)
#define f_rewind(filehandle) fm_rewind(filehandle)
#define f_eof(filehandle) fm_eof(filehandle)

#define f_stat(filename,stat) fm_stat(filename,stat)
#define f_gettimedate(filename,pctime,pcdate) fm_gettimedate(filename,pctime,pcdate)
#define f_settimedate(filename,ctime,cdate) fm_settimedate(filename,ctime,cdate)
#define f_delete(filename) fm_delete(filename)

#define f_getattr(filename,attr) fm_getattr(filename,attr)
#define f_setattr(filename,attr) fm_setattr(filename,attr)

#define f_getlabel(drivenum,label,len) fm_getlabel(drivenum,label,len)
#define f_setlabel(drivenum,label) fm_setlabel(drivenum,label)

#define f_get_oem(drivenum,str,maxlen) fm_get_oem(drivenum,str,maxlen)
#endif

#ifdef HCC_UNICODE
#if (!FN_CAPI_USED)
#define F_WFIND FN_WFIND
#define f_wgetcwd(buffer,maxlen) fm_wgetcwd(buffer,maxlen)
#define f_wgetdcwd(drivenum,buffer,maxlen) fm_wgetdcwd(drivenum,buffer,maxlen)
#define f_wchdir(dirname) fm_wchdir(dirname)
#define f_wmkdir(dirname) fm_wmkdir(dirname)
#define f_wrmdir(dirname) fm_wrmdir(dirname)
#define f_wfindfirst(filename,find) fm_wfindfirst(filename,find)
#define f_wfindnext(find) fm_wfindnext(find)
#define f_wrename(filename,newname) fm_wrename(filename,newname)
#define f_wmove(filename,newname) fm_wmove(filename,newname)
#define f_wfilelength(filename) fm_wfilelength(filename)
#define f_wopen(filename,mode) fm_wopen(filename,mode)
#define f_wtruncate(filename,length) fm_wtruncate(filename,length)
#define f_wstat(filename,stat) fm_wstat(filename,stat)
#define f_wgettimedate(filename,pctime,pcdate) fm_wgettimedate(filename,pctime,pcdate)
#define f_wsettimedate(filename,ctime,cdate) fm_wsettimedate(filename,ctime,cdate)
#define f_wdelete(filename) fm_wdelete(filename)
#define f_wgetattr(filename,attr) fm_wgetattr(filename,attr)
#define f_wsetattr(filename,attr) fm_wsetattr(filename,attr)
#endif
#endif

/****************************************************************************
 *
 * function externs
 *
 ***************************************************************************/

extern int fn_init(void);
extern char *fn_getversion(void);

extern char *fm_getversion(void);
extern int fm_initvolume(int drvnumber,F_DRIVERINIT driver_init,unsigned long driver_param);
extern int fm_initvolumepartition(int drvnumber,F_DRIVER *driver,int partition);
extern int fm_createpartition(F_DRIVER *driver,int parnum, F_PARTITION *par);
extern int fm_createdriver(F_DRIVER **driver,F_DRIVERINIT driver_init,unsigned long driver_param);
extern int fm_releasedriver(F_DRIVER *driver);
extern int fm_getpartition(F_DRIVER *driver,int parnum, F_PARTITION *par);
extern int fm_delvolume (int drvnumber);
extern int fm_checkvolume (int drvnumber);
extern int fm_get_volume_count (void);
extern int fm_get_volume_list (int *buf);
extern int fm_format(int drivenum,long fattype);
extern int fm_getcwd(char *buffer, int maxlen );
extern int fm_getdcwd(int drivenum, char *buffer, int maxlen );
extern int fm_chdrive(int drivenum);
extern int fm_getdrive(void);
extern int fm_getfreespace(int drivenum,FN_SPACE *pspace);
extern int fm_getlasterror(void);

extern int fm_chdir(const char *dirname);
extern int fm_mkdir(const char *dirname);
extern int fm_rmdir(const char *dirname);

extern int fm_findfirst(const char *filename,FN_FIND *find);
extern int fm_findnext(FN_FIND *find);
extern int fm_rename(const char *filename, const char *newname);
extern int fm_move(const char *filename, const char *newname);
extern long fm_filelength(const char *filename);

extern int fm_close(FN_FILE *filehandle);
extern int fm_flush(FN_FILE *filehandle);
extern FN_FILE *fm_open(const char *filename,const char *mode);
extern FN_FILE *fm_truncate(const char *filename,unsigned long length);
extern int  fm_ftruncate(FN_FILE *filehandle,unsigned long length);

extern long fm_read(void *buf,long size,long size_st,FN_FILE *filehandle);
extern long fm_write(const void *buf,long size,long size_st,FN_FILE *filehandle);

extern int fm_seek(FN_FILE *filehandle,long offset,long whence);

extern long fm_tell(FN_FILE *filehandle);
extern int fm_getc(FN_FILE *filehandle);
extern int fm_putc(int ch,FN_FILE *filehandle);
extern int fm_rewind(FN_FILE *filehandle);
extern int fm_eof(FN_FILE *filehandle);
extern int fm_seteof(FN_FILE *filehandle);

extern int fm_stat(const char *filename,F_STAT *stat);
extern int fm_gettimedate(const char *filename,unsigned short *pctime,unsigned short *pcdate);
extern int fm_settimedate(const char *filename,unsigned short ctime,unsigned short cdate);
extern int fm_delete(const char *filename);

extern int fm_getattr(const char *filename,unsigned char *attr);
extern int fm_setattr(const char *filename,unsigned char attr);

extern int fm_getlabel(int drivenum, char *label, long len);
extern int fm_setlabel(int drivenum, const char *label);

extern int fm_get_oem (int drivenum, char *str, long maxlen);

#if (!FN_CAPI_USED)
extern int f_enterFS(void);
extern void f_releaseFS(long ID);
#endif

#ifdef HCC_UNICODE
extern int fm_wgetcwd(wchar *buffer, int maxlen );
extern int fm_wgetdcwd(int drivenum, wchar *buffer, int maxlen );
extern int fm_wchdir(const wchar *dirname);
extern int fm_wmkdir(const wchar *dirname);
extern int fm_wrmdir(const wchar *dirname);
extern int fm_wfindfirst(const wchar *filename,FN_WFIND *find);
extern int fm_wfindnext(FN_WFIND *find);
extern int fm_wrename(const wchar *filename, const wchar *newname);
extern int fm_wmove(const wchar *filename, const wchar *newname);
extern long fm_wfilelength(const wchar *filename);
extern FN_FILE *fm_wopen(const wchar *filename,const wchar *mode);
extern FN_FILE *fm_wtruncate(const wchar *filename,unsigned long length);
extern int fm_wstat(const wchar *filename,F_STAT *stat);
extern int fm_wgettimedate(const wchar *filename,unsigned short *pctime,unsigned short *pcdate);
extern int fm_wsettimedate(const wchar *filename,unsigned short ctime,unsigned short cdate);
extern int fm_wdelete(const wchar *filename);
extern int fm_wgetattr(const wchar *filename,unsigned char *attr);
extern int fm_wsetattr(const wchar *filename,unsigned char attr);
#endif

/****************************************************************************
 *
 * errorcodes
 *
 ***************************************************************************/
#ifndef __ECC__
#include "fwerr.h"
#endif
/****************************************************************************
 *
 * closing bracket for C++ compatibility
 *
 ***************************************************************************/

#ifdef __cplusplus
}
#endif

/****************************************************************************
 *
 * end of api_f.h
 *
 ***************************************************************************/

 #ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _API_F_H_ */
