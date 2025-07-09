/* ocsp.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */




/* wolfSSL OCSP API */

#ifndef WOLFSSL_OCSP_H
#define WOLFSSL_OCSP_H

#ifdef HAVE_OCSP

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>

#ifdef __cplusplus
    extern "C" {
#endif

struct buffer;
typedef struct WOLFSSL_OCSP WOLFSSL_OCSP;

WOLFSSL_LOCAL int  InitOCSP(WOLFSSL_OCSP*, WOLFSSL_CERT_MANAGER*);
WOLFSSL_LOCAL void FreeOCSP(WOLFSSL_OCSP*, int dynamic);

WOLFSSL_LOCAL int  CheckCertOCSP(WOLFSSL_OCSP*, DecodedCert*,
                                            struct buffer* responseBuffer);
WOLFSSL_LOCAL int  CheckOcspRequest(WOLFSSL_OCSP* ocsp,
                   OcspRequest* ocspRequest, struct buffer* responseBuffer);

#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* HAVE_OCSP */
#endif /* WOLFSSL_OCSP_H */
