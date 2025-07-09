/* ed25519.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */



#ifndef WOLF_CRYPT_ED25519_H
#define WOLF_CRYPT_ED25519_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_ED25519

#include <wolfssl/wolfcrypt/fe_operations.h>
#include <wolfssl/wolfcrypt/ge_operations.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha512.h>

#ifdef __cplusplus
    extern "C" {
#endif


/* info about EdDSA curve specifically ed25519, defined as an elliptic curve
   over GF(p) */
/*
    32,                key size
    "ED25519",         curve name
    "2^255-19",        prime number
    "SHA512",          hash function
    "-121665/121666",  value of d
*/

#define ED25519_KEY_SIZE     32 /* private key only */
#define ED25519_SIG_SIZE     64

#define ED25519_PUB_KEY_SIZE 32 /* compressed */
/* both private and public key */
#define ED25519_PRV_KEY_SIZE (ED25519_PUB_KEY_SIZE+ED25519_KEY_SIZE)

/* An ED25519 Key */
typedef struct {
    byte    p[ED25519_PUB_KEY_SIZE]; /* compressed public key */
    byte    k[ED25519_PRV_KEY_SIZE]; /* private key : 32 secret -- 32 public */
#ifdef FREESCALE_LTC_ECC
    /* uncompressed point coordinates */
    byte pointX[ED25519_KEY_SIZE]; /* recovered X coordinate */
    byte pointY[ED25519_KEY_SIZE]; /* Y coordinate is the public key with The most significant bit of the final octet always zero. */
#endif
} ed25519_key;


WOLFSSL_API
int wc_ed25519_make_key(WC_RNG* rng, int keysize, ed25519_key* key);
WOLFSSL_API
int wc_ed25519_sign_msg(const byte* in, word32 inlen, byte* out,
                        word32 *outlen, ed25519_key* key);
WOLFSSL_API
int wc_ed25519_verify_msg(byte* sig, word32 siglen, const byte* msg,
                          word32 msglen, int* stat, ed25519_key* key);
WOLFSSL_API
int wc_ed25519_init(ed25519_key* key);
WOLFSSL_API
void wc_ed25519_free(ed25519_key* key);
WOLFSSL_API
int wc_ed25519_import_public(const byte* in, word32 inLen, ed25519_key* key);
WOLFSSL_API
int wc_ed25519_import_private_key(const byte* priv, word32 privSz,
                               const byte* pub, word32 pubSz, ed25519_key* key);
WOLFSSL_API
int wc_ed25519_export_public(ed25519_key*, byte* out, word32* outLen);
WOLFSSL_API
int wc_ed25519_export_private_only(ed25519_key* key, byte* out, word32* outLen);
WOLFSSL_API
int wc_ed25519_export_private(ed25519_key* key, byte* out, word32* outLen);
WOLFSSL_API
int wc_ed25519_export_key(ed25519_key* key,
                          byte* priv, word32 *privSz,
                          byte* pub, word32 *pubSz);

/* size helper */
WOLFSSL_API
int wc_ed25519_size(ed25519_key* key);
WOLFSSL_API
int wc_ed25519_priv_size(ed25519_key* key);
WOLFSSL_API
int wc_ed25519_pub_size(ed25519_key* key);
WOLFSSL_API
int wc_ed25519_sig_size(ed25519_key* key);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_ED25519 */
#endif /* WOLF_CRYPT_ED25519_H */
