/* callbacks.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */




#ifndef WOLFSSL_CALLBACKS_H
#define WOLFSSL_CALLBACKS_H

#include <sys/time.h>

#ifdef __cplusplus
    extern "C" {
#endif


enum { /* CALLBACK CONTSTANTS */
    MAX_PACKETNAME_SZ     =  24,
    MAX_CIPHERNAME_SZ     =  24,
    MAX_TIMEOUT_NAME_SZ   =  24,
    MAX_PACKETS_HANDSHAKE =  14,       /* 12 for client auth plus 2 alerts */
    MAX_VALUE_SZ          = 128,       /* all handshake packets but Cert should
                                          fit here  */
};


typedef struct handShakeInfo_st {
    char   cipherName[MAX_CIPHERNAME_SZ + 1];    /* negotiated cipher */
    char   packetNames[MAX_PACKETS_HANDSHAKE][MAX_PACKETNAME_SZ + 1];
                                                 /* SSL packet names  */
    int    numberPackets;                        /* actual # of packets */
    int    negotiationError;                     /* cipher/parameter err */
} HandShakeInfo;


typedef struct timeval Timeval;


typedef struct packetInfo_st {
    char           packetName[MAX_PACKETNAME_SZ + 1]; /* SSL packet name */
    Timeval        timestamp;                       /* when it occurred    */
    unsigned char  value[MAX_VALUE_SZ];             /* if fits, it's here */
    unsigned char* bufferValue;                     /* otherwise here (non 0) */
    int            valueSz;                         /* sz of value or buffer */
} PacketInfo;


typedef struct timeoutInfo_st {
    char       timeoutName[MAX_TIMEOUT_NAME_SZ + 1]; /* timeout Name */
    int        flags;                              /* for future use */
    int        numberPackets;                      /* actual # of packets */
    PacketInfo packets[MAX_PACKETS_HANDSHAKE];     /* list of all packets  */
    Timeval    timeoutValue;                       /* timer that caused it */
} TimeoutInfo;



#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* WOLFSSL_CALLBACKS_H */
