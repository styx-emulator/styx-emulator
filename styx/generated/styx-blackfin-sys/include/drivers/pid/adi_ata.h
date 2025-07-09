/*********************************************************************************

Copyright(c) 2005 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_ata.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            This is the header file defining ATA commands and structures

*********************************************************************************/

#ifndef __ADI_ATA_H__
#define __ADI_ATA_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

typedef struct {
    u16 :1;
    u16 hard_sectored:1;
    u16 not_soft_sectored:1;
    u16 not_mfm_encoded:1;
    u16 head_switch_time_gt15us:1;
    u16 spindle_motor_control_option_not_implemented:1;
    u16 fixed_drive:1;
    u16 rem_cart_drive:1;
    u16 tfr_rate_gt5mbs:1;
    u16 tfr_rate_gt5mbs_lt10mbs:1;
    u16 tfr_rate_le10mbs:1;
    u16 rot_spd_tol_lt_0p5:1;
    u16 data_strobe_offset_option_not_available:1;
    u16 track_offset_option_not_available:1;
    u16 fmt_speed_tol:1;
} ADI_ATA_IDENT_GENCON;

typedef struct {
    u16 bytes:8;
    u16 after_index_before_splice:8;
} ADI_ATA_IDENT_SECTOR_GAP;

// CF card itendify data block as given in CF+ & CF Specification Rev. 3.0
typedef struct {
    ADI_ATA_IDENT_GENCON gencon;        /* 0 */
    u16 default_num_cylinders;
    u16 resvd1;
    u16 default_num_heads;
    u16 obsolete1[2];
    u16 default_num_sectors;
    u16 num_sectors_per_card[2];
    u16 obsolete2;
    char serial_number[20];
    u16 obsolete3[2];
    u16 num_ECC_bytes;
    char firmware_rev[8];
    char model_number[40];
    u16 max_rw_multiples;
    u16 resvd2;
    u16 capabilities;
    u16 resvd3;
    u16 pio_timing_mode;
    u16 obsolete4;
    u16 field_validity;
    u16 cur_num_cylinders;
    u16 cur_num_heads;
    u16 cur_num_sectors;
    u16 cur_capacity[2];
    u16 multiple_sectors_setting;
    u16 total_lba_sects_addressable[2];
    u16 resvd4;
    u16 multi_dma_xfr;
    u16 advanced_pio_modes;
    u16 min_multiword_dma_xfer_time;
    u16 recommended_multiword_dma_xfer_time;
    u16 min_pio_xfr_time_without_flow_control;
    u16 min_pio_xfr_time_with_flow_control;
    u16 resvd5[12];
    u16 features_supported[3];
    u16 features_enabled[3];
    u16 ultra_dma_supported;
    u16 security_erase_time;
    u16 enhanced_security_erase_time;
    u16 current_advanced_power_mngmnt_value;
    u16 resvd6[36];
    u16 security_status;
    u16 vendor_unique_bytes[32];
    u16 power_req_desc;
    u16 resvd7;
    u16 key_mngmnt_schemes_supported;
    u16 cf_adv_trueIDE_timing_mode;
    u16 cf_adv_PCMCIA_timing_mode;
    u16 resvd8[11];

} ADI_ATA_IDENTITY;



#pragma pack(1)
typedef struct {
    u8 error;               // not used
    union {
        u8 data;
        struct {
            u8 cd:1;
            u8 io:1;
            u8 rel:1;
            u8 tag:5;
        };
    } interrupt_reason;
    u8 lba_low;             // not used
    u16 byte_count;         // number of bytes to send
    u8 device;              // device id
    union {
        u8 data;
        struct {
            u8 chk:1;
            u8 resvd1:2;
            u8 drq:1;
            u8 serv:1;
            u8 dmrd:1;
            u8 resvd2:1;
            u8 busy:1;
        };
    } status;               //status
} ADI_ATAPI_REQUEST;
#pragma pack()

typedef struct {
    u16 cmd_packet_size:2;
    u16 incomplete_response:1;
    u16 resvd1:2;
    u16 drq_timing:2;
    u16 removeable_media_device:1;
    u16 cmd_packet_set:5;
    u16 resvd2:1;
    u16 device_type:2;
} ADI_ATAPI_IDENT_GENCON;

typedef struct {
    u32 vendor:8;
    u32 incomplete_response:1;
    u32 resvd1:2;
    u32 drq_timing:2;
    u32 removeable_media_device:1;
    u32 cmd_packet_set:5;
    u32 resvd2:1;
    u32 device_type:2;
} ADI_ATAPI_IDENT_CAPABILITIES;

typedef struct {
    ADI_ATAPI_IDENT_GENCON gencon;                  /* 0 */
    u16 resvd1;
    u16 vendor_config;
    u16 resvd2[7];
    char serial_number[20];
    u16 resvd3[3];
    char firmare_revision[8];
    char model_number[40];
    u16 resvd4[2];
    ADI_ATAPI_IDENT_CAPABILITIES capabilities;
    u16 obsolete1[2];
    u16 field_validity;
    u16 resvd5[8];
    u32 dma_support;
    u16 pio_support;
    u16 dma_min_cycle;
    u16 dma_manufact_cycle;
    u16 pio_min_cycle_wo_flow;
    u16 pio_min_cycle;
    u16 resvd6[2];
    u16 packet_timing;
    u16 service_timing;
    u16 resvd7[2];
    u16 queue_depth;
    u16 resvd8[4];

    u16 version_major;
    u16 version_minor;

    u32 command_set_support;
    u16 command_feature_support;
    u32 command_set_enable;
    u16 command_featuer_default;

    u16 ultra_dma_config;
    u16 resvd9[4];
    u16 hardware_reset_result;
    u16 acoustic_value;
    u16 resvd10[30];
    u16 atapi_byte_count;
    u16 obsolete2;
    u16 removeable_media_notify_support;
    u16 security_status;
    u16 vendor[31];
    u16 resvd_compacflash[16];
    u16 resvd11[79];
    u16 integrity;
} ADI_ATAPI_IDENTITY;
#if 0 /* moved to adi_scsi.h */
enum {
    ADI_SCSI_CMD_INQUERY=0x12,
    ADI_SCSI_CMD_LOAD=0xA6,
    ADI_SCSI_CMD_MECHSTATUS=0xBD,
    ADI_SCSI_CMD_READ=0xBE,
};

#pragma pack(1)
typedef struct {
    u8 opcode;
    struct {
        u8 evpd:1;
        u8 cmddt:1;
    };
    u8 page;
    u8 resvd1;
    u8 length;
    u8 control;
} ADI_SCSI_CDB_INQUERY;
#pragma pack()

#pragma pack(1)
typedef struct {
    u8 opcode;
    struct {
        u8 resvd1:1;
        u8 dap:1;
        u8 sector_type:3;
        u8 resvd2:3;
    };
    u8 lba3;
    u8 lba2;
    u8 lba1;
    u8 lba0;
    u8 length2;
    u8 length1;
    u8 length0;
    struct {
        u8 resvd3:1;
        u8 c2error:2;
        u8 edcecc:1;
        u8 userdata:1;
        u8 header:2;
        u8 sync:1;
    };
    struct {
        u8 subchannel:3;
        u8 resvd4:5;
    };
    u8 control;
} ADI_SCSI_CDB_READ;
#pragma pack()

#pragma pack(1)
typedef struct {
    u8 opcode;
    struct {
        u8 immediate:1;
    };
    u8 resvd1[2];
    struct {
        u8 start:1;         // start and lounlo are used in combination
        u8 lounlo:1;        // to load/unload the device
    };
    u8 resvd2[3];
    u8 slot;
    u8 resvd3[2];
    u8 control;
} ADI_SCSI_CDB_LOAD;
#pragma pack()

#pragma pack(1)
typedef struct {
    u8 opcode;
    u8 resvd1[7];
    u8 length1;
    u8 length0;
    u8 resvd2;
    u8 control;
} ADI_SCSI_CDB_MECHSTATUS;
#pragma pack()

typedef union {
    struct {
        u8 opcode;
        u8 data[11];
    };
    ADI_SCSI_CDB_INQUERY inquery;
    ADI_SCSI_CDB_LOAD load;
    ADI_SCSI_CDB_MECHSTATUS mechstatus;
    ADI_SCSI_CDB_READ read;
} ADI_SCSI_CDB;

#endif

/*******************************************************************
* Enumerator for known volume types. Values for FAT devices
* are those that would be reported in the 'type' field of a
* partitition table on the media.
*******************************************************************/

enum {
    ADI_ATA_VOLUME_TYPE_PRI_FAT12       = 0x01,
    ADI_ATA_VOLUME_TYPE_PRI_FAT16_A     = 0x04,    /* Under 32MB  */
    ADI_ATA_VOLUME_TYPE_EXT_FAT16       = 0x05,    /* extended partition (in extended)*/
    ADI_ATA_VOLUME_TYPE_PRI_FAT16_B     = 0x06,    /* Over 32MB   */
    ADI_ATA_VOLUME_TYPE_PRI_FAT32       = 0x0B,    /* */
    ADI_ATA_VOLUME_TYPE_PRI_FAT32_LBA   = 0x0C,    /* LBA mapped  */
    ADI_ATA_VOLUME_TYPE_PRI_FAT16_LBA   = 0x0E,    /* LBA mapped  */
    ADI_ATA_VOLUME_TYPE_PRI_EXTENDED    = 0x0F,    /* LBA mapped  */
    ADI_ATA_VOLUME_TYPE_PRI_UNASSIGNED  = 0x52     /* Used to indicate a new partition
                                                      which has yet to be formatted.
                                                      This ID is actually a CP/M partition,
                                                      which is moribund if not obsolete, for
                                                      the intended customer base!
                                                   */
};

/*******************************************************************
* Partition Table Entry Structure as seen on the media
*******************************************************************/

typedef struct {
    u8 dl;              /* Not used                     */
    u8 dh_start;        /* Not used                     */
    u8 cl_start;        /* Not used                     */
    u8 ch_start;        /* Not used                     */
    u8 type;            /* Type of partition            */
    u8 dh_end;          /* Not used                     */
    u8 cl_end;          /* Not used                     */
    u8 ch_end;          /* Not used                     */
    u32 lba_start;      /* Starting sector of partition */
    u32 size;           /* Size in 512 byte sectors     */
} ADI_ATA_PARTITION_ENTRY;



// Word 49: Capabilities
#define ADI_ATA_LBA_SUPPORTED_MASK  0x0200
#define ADI_ATA_DMA_SUPPORTED_MASK  0x0100
#define ADI_ATA_LBA_SUPPORTED(P)( (((P)->capabilities)&ADI_ATA_LBA_SUPPORTED_MASK)==ADI_ATA_LBA_SUPPORTED_MASK )
#define ADI_ATA_DMA_SUPPORTED(P)( (((P)->capabilities)&ADI_ATA_DMA_SUPPORTED_MASK)==ADI_ATA_DMA_SUPPORTED_MASK )

// Word 51: PIO modes
#define ADI_ATA_PIO_MODE_MASK   0xFF00
#define ADI_ATA_PIO_MODE_0      0x0000
#define ADI_ATA_PIO_MODE_1      0x0100
#define ADI_ATA_PIO_MODE_2      0x0200
#define ADI_ATA_PIO_MODE_SUPPORTED(P)  ( (((P)->pio_timing_mode)&ADI_ATA_PIO_MODE_MASK)>>8 )
#define ADI_ATA_PIO_MODE_0_SUPPORTED(P)( (((P)->pio_timing_mode)&ADI_ATA_PIO_MODE_MASK)==ADI_ATA_PIO_MODE_0 )
#define ADI_ATA_PIO_MODE_1_SUPPORTED(P)( (((P)->pio_timing_mode)&ADI_ATA_PIO_MODE_MASK)==ADI_ATA_PIO_MODE_1 )
#define ADI_ATA_PIO_MODE_2_SUPPORTED(P)( (((P)->pio_timing_mode)&ADI_ATA_PIO_MODE_MASK)==ADI_ATA_PIO_MODE_2 )

// Word 53: Translation Parameters Valid
#define ADI_ATA_FLDS64TO70_VALID_MASK   0x0002
#define ADI_ATA_FLDS54TO58_VALID_MASK   0x0001
#define ADI_ATA_FLDS64TO70_VALID(P) ( (((P)->field_validity)&ADI_ATA_FLDS64TO70_VALID_MASK)==ADI_ATA_FLDS64TO70_VALID_MASK )
#define ADI_ATA_FLDS54TO58_VALID(P) ( (((P)->field_validity)&ADI_ATA_FLDS54TO58_VALID_MASK)==ADI_ATA_FLDS54TO58_VALID_MASK )

// Word 59: multiple_sectors_setting
#define ADI_ATA_MULTI_SECTORS_VALID_MASK 0x0100
#define ADI_ATA_MULTI_SECTORS_COUNT_MASK 0x00FF
#define ADI_ATA_MULTI_SECTORS_ALLOWED(P) ( (((P)->multiple_sectors_setting)&ADI_ATA_MULTI_SECTORS_VALID_MASK)==ADI_ATA_MULTI_SECTORS_VALID_MASK )
#define ADI_ATA_MULTI_SECTORS_COUNT(P)   ( ((P)->multiple_sectors_setting)&ADI_ATA_MULTI_SECTORS_COUNT_MASK )

// Word 64: advanced PIO modes
#define ADI_ATA_PIO_MODE_3_MASK     0x0001
#define ADI_ATA_PIO_MODE_4_MASK     0x0002
#define ADI_ATA_PIO_MODE_3_SUPPORTED(P)( (((P)->advanced_pio_modes)&ADI_ATA_PIO_MODE_3_MASK)==ADI_ATA_PIO_MODE_3_MASK )
#define ADI_ATA_PIO_MODE_4_SUPPORTED(P)( (((P)->advanced_pio_modes)&ADI_ATA_PIO_MODE_4_MASK)==ADI_ATA_PIO_MODE_4_MASK )

#define BIT(b,w)    ( (w)>>(b) &0x0001)
#define FIELD(m,s,w) ( ((w)&(m))>>(s) )

/* 48 bit LBA Support */
#define ADI_ATAPI_MAX_SECTOR_28BIT 0x0FFFFFFF
#define IS_48BIT_ADDRESSABLE(N) ( pDevice->Device[(N)].LastSectorOnMedia > ADI_ATAPI_MAX_SECTOR_28BIT)
#define IS_48BIT_COMMAND(C) ( ((C)==ADI_ATA_CMD_READ_MULTIPLE_EXT) || ((C)==ADI_ATA_CMD_WRITE_MULTIPLE_EXT)|| ((C)==ADI_ATA_CMD_READ_DMA_EXT) || ((C)==ADI_ATA_CMD_WRITE_DMA_EXT) )


////////////////////////////////////////
// ATA Commands

enum {
    ADI_ATA_CMD_FORMAT_TRACK                = 0x50,
    ADI_ATA_CMD_IDENTIFY                    = 0xEC,
    ADI_ATA_CMD_INIT_DRIVE_PARAMS           = 0x91,
    ADI_ATA_CMD_RECALIBRATE                 = 0x10,
    ADI_ATA_CMD_READ_BUFFER                 = 0xE4,
    ADI_ATA_CMD_READ_SECTORS_RETRY          = 0x20,
    ADI_ATA_CMD_READ_SECTORS                = 0x21,
    ADI_ATA_CMD_READ_LONG_RETRY             = 0x22,
    ADI_ATA_CMD_READ_LONG                   = 0x23,
    ADI_ATA_CMD_READ_SECTORS_EXT            = 0x24,
    ADI_ATA_CMD_READ_DMA_EXT                = 0x25,
    ADI_ATA_CMD_READ_MULTIPLE_EXT           = 0x29,
    ADI_ATA_CMD_READ_VERIFY_SECTOR_RETRY    = 0x40,
    ADI_ATA_CMD_READ_VERIFY_SECTOR          = 0x41,
    ADI_ATA_CMD_SEEK                        = 0x70,
    ADI_ATA_CMD_SET_FEATURES                = 0xEF,
    ADI_ATA_CMD_WRITE_BUFFER                = 0xE8,
    ADI_ATA_CMD_WRITE_SECTORS_RETRY         = 0x30,
    ADI_ATA_CMD_WRITE_SECTORS               = 0x31,
    ADI_ATA_CMD_WRITE_LONG_RETRY            = 0x32,
    ADI_ATA_CMD_WRITE_LONG                  = 0x33,
    ADI_ATA_CMD_WRITE_SECTORS_EXT           = 0x34,
    ADI_ATA_CMD_WRITE_DMA_EXT               = 0x35,
    ADI_ATA_CMD_WRITE_MULTIPLE_EXT          = 0x39,
    ADI_ATA_CMD_SET_MULTIPLE_MODE           = 0xC6,
    ADI_ATA_CMD_READ_MULTIPLE               = 0xC4,
    ADI_ATA_CMD_WRITE_MULTIPLE              = 0xC5,
    ADI_ATA_CMD_READ_DMA                    = 0xC8,
    ADI_ATA_CMD_WRITE_DMA                   = 0xCA,

    ADI_ATA_CMD_PACKET                      = 0xA0,
    ADI_ATA_CMD_IDENTIFY_PACKET             = 0xA1

};

////////////////////////////////////////
// ATA Feature register definitions

enum {
    ADI_ATA_FEAT_ENABLE_8BIT_PIO                = 0x01,
    ADI_ATA_FEAT_ENABLE_WRITE_CACHE             = 0x02,
    ADI_ATA_FEAT_TRANFER_MODE                   = 0x03,
    ADI_ATA_FEAT_ENABLE_ADV_POWER_MANAGEMENT    = 0x05,
    ADI_ATA_FEAT_DISABLE_MEDIA_STATUS_NOTIFN    = 0x31,
    ADI_ATA_FEAT_DISABLE_READ_LOOKAHEAD         = 0x55,
    ADI_ATA_FEAT_DISABLE_WRITE_CACHE            = 0x82,
    ADI_ATA_FEAT_DISABLE_ADV_POWER_MANAGEMENT   = 0x85,
    ADI_ATA_FEAT_ENABLE_READ_LOOKAHEAD          = 0xAA,
    ADI_ATA_FEAT_ENABLE_MEDIA_STATUS_NOTIFN     = 0x95
#if 0
    ADI_ATA_FEAT_ENABLE_          = 0x,
    ADI_ATA_FEAT_DISABLE_          = 0x,
#endif
};




////////////////////////////////////////
// Address offsets for ATA registers
#define ADI_ATA_RDD_OFFSET     0x0
#define ADI_ATA_WRD_OFFSET     0x0
#define ADI_ATA_FEAT_OFFSET    0x1
#define ADI_ATA_ERR_OFFSET     0x1

#define ADI_ATA_SCNT_OFFSET    0x2
#define ADI_ATA_SNUM_OFFSET    0x3
#define ADI_ATA_CYLL_OFFSET    0x4
#define ADI_ATA_CYLH_OFFSET    0x5
#define ADI_ATA_CDH_OFFSET     0x6
#define ADI_ATA_CMD_OFFSET     0x7

#define ADI_ATA_STAT_OFFSET    0x7
#define ADI_ATA_ASTAT_OFFSET   0xE
#define ADI_ATA_CTRL_OFFSET    0xE

#define ADI_ATA_DADDR_OFFSET   0x1e
////////////////////////////////////////

/************************************************************************************************************
 *  ATA Device Status Register bitfield manipulation
 ************************************************************************************************************
 */

#define ADI_ATA_DEV_STATUS_ERR_MASK                 0x01
#define ADI_ATA_DEV_STATUS_ERR_SHIFT                0
#define ADI_ATA_DEV_STATUS_ERR_GET(R)               ( ( (R) & ADI_ATA_DEV_STATUS_ERR_MASK ) >> ADI_ATA_DEV_STATUS_ERR_SHIFT )


#define ADI_ATA_DEV_STATUS_DRQ_MASK                 0x08
#define ADI_ATA_DEV_STATUS_DRQ_SHIFT                3
#define ADI_ATA_DEV_STATUS_DRQ_GET(R)               ( ( (R) & ADI_ATA_DEV_STATUS_DRQ_MASK ) >> ADI_ATA_DEV_STATUS_DRQ_SHIFT )


#define ADI_ATA_DEV_STATUS_DRDY_MASK                0x40
#define ADI_ATA_DEV_STATUS_DRDY_SHIFT               6
#define ADI_ATA_DEV_STATUS_DRDY_GET(R)              ( ( (R) & ADI_ATA_DEV_STATUS_DRDY_MASK ) >> ADI_ATA_DEV_STATUS_DRDY_SHIFT )

#define ADI_ATA_DEV_STATUS_BSY_MASK                 0x80
#define ADI_ATA_DEV_STATUS_BSY_SHIFT                7
#define ADI_ATA_DEV_STATUS_BSY_GET(R)               ( ( (R) & ADI_ATA_DEV_STATUS_BSY_MASK ) >> ADI_ATA_DEV_STATUS_BSY_SHIFT )


#define ADI_ATA_DEV_CONTROL_NIEN_MASK               0x02
#define ADI_ATA_DEV_CONTROL_NIEN_SHIFT              1
#define ADI_ATA_DEV_CONTROL_NIEN_SET(R,V)           ( (R) = ( (V) << ADI_ATA_DEV_CONTROL_NIEN_SHIFT ) | ( (R) & ~ADI_ATA_DEV_CONTROL_NIEN_MASK ) )

#define ADI_ATA_DEV_CDH_LBA_ADDR_MASK               0x0F
#define ADI_ATA_DEV_CDH_LBA_ADDR_SHIFT              0
#define ADI_ATA_DEV_CDH_LBA_ADDR_SET(R,V)           ( (R) = ( (V) << ADI_ATA_DEV_CDH_LBA_ADDR_SHIFT ) | ( (R) & ~ADI_ATA_DEV_CDH_LBA_ADDR_MASK ) )

#define ADI_ATA_DEV_CDH_DRIVE_MASK                  0x10
#define ADI_ATA_DEV_CDH_DRIVE_SHIFT                 4
#define ADI_ATA_DEV_CDH_DRIVE_SET(R,V)              ( (R) = ( (V) << ADI_ATA_DEV_CDH_DRIVE_SHIFT ) | ( (R) & ~ADI_ATA_DEV_CDH_DRIVE_MASK ) )

#define ADI_ATA_DEV_CDH_LBA_MASK                    0x40
#define ADI_ATA_DEV_CDH_LBA_SHIFT                   6
#define ADI_ATA_DEV_CDH_LBA_SET(R,V)                ( (R) = ( (V) << ADI_ATA_DEV_CDH_LBA_SHIFT ) | ( (R) & ~ADI_ATA_DEV_CDH_LBA_MASK ) )

#define ADI_ATA_DEV_ERROR_NOMEDIA_MASK              0x02
#define ADI_ATA_DEV_ERROR_NOMEDIA_SHIFT             1
#define ADI_ATA_DEV_ERROR_NOMEDIA_GET(R)            ( ( (R) & ADI_ATA_DEV_ERROR_NOMEDIA_MASK ) >> ADI_ATA_DEV_ERROR_NOMEDIA_SHIFT )


#define ADI_ATA_DEV_ERROR_MC_MASK                   0x20
#define ADI_ATA_DEV_ERROR_MC_SHIFT                  5
#define ADI_ATA_DEV_ERROR_MC_GET(R)                 ( ( (R) & ADI_ATA_DEV_ERROR_MC_MASK ) >> ADI_ATA_DEV_ERROR_MC_SHIFT )

#define ADI_ATA_DEV_ERROR_ABRT_MASK                 0x04
#define ADI_ATA_DEV_ERROR_ABRT_SHIFT                2
#define ADI_ATA_DEV_ERROR_ABRT_GET(R)               ( ( (R) & ADI_ATA_DEV_ERROR_ABRT_MASK ) >> ADI_ATA_DEV_ERROR_ABRT_SHIFT )

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_ATA_H__ */
