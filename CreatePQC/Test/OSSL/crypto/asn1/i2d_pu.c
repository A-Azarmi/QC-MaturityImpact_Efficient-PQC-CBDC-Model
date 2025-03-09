/* crypto/asn1/i2d_pu.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_EC
# include <openssl/ec.h>
#endif
#ifndef OPENSSL_NO_CMC
# include <openssl/cmc.h>
#endif
#ifndef OPENSSL_NO_DILITHIUM
# include <openssl/dilithium.h>
#endif
#ifndef OPENSSL_NO_FRODODH
# include <openssl/frododh.h>
#endif
#ifndef OPENSSL_NO_FRODOKEM
# include <openssl/frodokem.h>
#endif
#ifndef OPENSSL_NO_HSS
# include <openssl/hss.h>
#endif
#ifndef OPENSSL_NO_KYBER
# include <openssl/kyber.h>
#endif
#ifndef OPENSSL_NO_NHDH
# include <openssl/nhdh.h>
#endif
#ifndef OPENSSL_NO_NTRUP
# include <openssl/ntrup.h>
#endif
#ifndef OPENSSL_NO_RAINBOW
# include <openssl/rainbow.h>
#endif
#ifndef OPENSSL_NO_SAMWISE
# include <openssl/samwise.h>
#endif
#ifndef OPENSSL_NO_SIDH
# include <openssl/sidh.h>
#endif
#ifndef OPENSSL_NO_SIKE
# include <openssl/sike.h>
#endif
#ifndef OPENSSL_NO_SPHINCS
# include <openssl/sphincs.h>
#endif
#ifndef OPENSSL_NO_XMSS
# include <openssl/xmss.h>
#endif
#ifndef OPENSSL_NO_XMSSMT
# include <openssl/xmssmt.h>
#endif

static int octet2raw(ASN1_OCTET_STRING *s, unsigned char **pp)
{
    unsigned char *retbuf = OPENSSL_malloc(s->length);

    if (s == NULL) {
        ASN1err(ASN1_F_OCTET2RAW, ASN1_R_NULL_POINTER);
        return -1;
    }

    if (retbuf == NULL) {
        ASN1err(ASN1_F_OCTET2RAW, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    memcpy(retbuf, s->data, s->length);
    *pp = retbuf;
    return s->length;
}

/* Note that this function gives ownership of the returned buffer pointed to by
 * *pp. The user must still free the memory pointed to by *pp. Note that this
 * will only work for Quantum-Safe key exchanges.
 */
int i2o_PublicKey(EVP_PKEY *a, unsigned char **pp)
{
    if ((a == NULL) || (pp == NULL)) {
        ASN1err(ASN1_F_I2O_PUBLICKEY, ASN1_R_NULL_POINTER);
        return (-1);
    }

    switch (a->type) {
#ifndef OPENSSL_NO_FRODODH
    case EVP_PKEY_FRODODH:
        return octet2raw(a->pkey.frododh->my_public_key, pp);
#endif
#ifndef OPENSSL_NO_KYBER
    case EVP_PKEY_KYBER:
        return octet2raw(a->pkey.kyber->pub_key, pp);
#endif
#ifndef OPENSSL_NO_NHDH
    case EVP_PKEY_NHDH:
        return octet2raw(a->pkey.nhdh->my_public_key, pp);
#endif
#ifndef OPENSSL_NO_SAMWISE
    case EVP_PKEY_SAMWISE:
        return octet2raw(a->pkey.samwise->my_public_key, pp);
#endif
#ifndef OPENSSL_NO_SIDH
    case EVP_PKEY_SIDH:
        return octet2raw(a->pkey.sidh->my_public_key, pp);
#endif
#ifndef OPENSSL_NO_SIKE
    case EVP_PKEY_SIKE:
        return octet2raw(a->pkey.sike->pub_key, pp);
#endif
    default:
        ASN1err(ASN1_F_I2O_PUBLICKEY, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
        return (-1);
    }
    return (-1);
}

int i2o_KemInfo(EVP_PKEY *a, unsigned char **pp)
{
    if ((a == NULL) || (pp == NULL)) {
        ASN1err(ASN1_F_I2O_KEMINFO, ASN1_R_NULL_POINTER);
        return (-1);
    }

    switch (a->type) {
#ifndef OPENSSL_NO_SIKE
    case EVP_PKEY_SIKE:
        return (octet2raw(a->pkey.sike->kem_info, pp));
#endif
#ifndef OPENSSL_NO_KYBER
    case EVP_PKEY_KYBER:
        return (octet2raw(a->pkey.kyber->kem_info, pp));
#endif
    default:
        ASN1err(ASN1_F_I2O_KEMINFO, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
        return (-1);
    }
}

int i2d_PublicKey(EVP_PKEY *a, unsigned char **pp)
{
    switch (a->type) {
#ifndef OPENSSL_NO_RSA
    case EVP_PKEY_RSA:
        return (i2d_RSAPublicKey(a->pkey.rsa, pp));
#endif
#ifndef OPENSSL_NO_DSA
    case EVP_PKEY_DSA:
        return (i2d_DSAPublicKey(a->pkey.dsa, pp));
#endif
#ifndef OPENSSL_NO_EC
    case EVP_PKEY_EC:
        return (i2o_ECPublicKey(a->pkey.ec, pp));
#endif
#ifndef OPENSSL_NO_CMC
    case EVP_PKEY_CMC:
        return (i2d_CMCPublicKey(a->pkey.cmc, pp));
#endif
#ifndef OPENSSL_NO_DILITHIUM
    case EVP_PKEY_DILITHIUM:
        return (i2d_DILITHIUMPublicKey(a->pkey.dilithium, pp));
#endif
#ifndef OPENSSL_NO_FRODODH
    case EVP_PKEY_FRODODH:
        return (i2d_FRODODHPublicKey(a->pkey.frododh, pp));
#endif
#ifndef OPENSSL_NO_FRODOKEM
    case EVP_PKEY_FRODOKEM:
        return (i2d_FRODOKEMPublicKey(a->pkey.frodokem, pp));
#endif
#ifndef OPENSSL_NO_HSS
    case EVP_PKEY_HSS:
        return (i2d_HSSPublicKey(a->pkey.hss, pp));
#endif
#ifndef OPENSSL_NO_KYBER
    case EVP_PKEY_KYBER:
        return (i2d_KYBERPublicKey(a->pkey.kyber, pp));
#endif
#ifndef OPENSSL_NO_NHDH
    case EVP_PKEY_NHDH:
        return (i2d_NHDHPublicKey(a->pkey.nhdh, pp));
#endif
#ifndef OPENSSL_NO_NTRUP
    case EVP_PKEY_NTRUP:
        return (i2d_NTRUPPublicKey(a->pkey.ntrup, pp));
#endif
#ifndef OPENSSL_NO_RAINBOW
    case EVP_PKEY_RAINBOW:
        return (i2d_RAINBOWPublicKey(a->pkey.rainbow, pp));
#endif
#ifndef OPENSSL_NO_SAMWISE
    case EVP_PKEY_SAMWISE:
        return (i2d_SAMWISEPublicKey(a->pkey.samwise, pp));
#endif
#ifndef OPENSSL_NO_SIDH
    case EVP_PKEY_SIDH:
        return (i2d_SIDHPublicKey(a->pkey.sidh, pp));
#endif
#ifndef OPENSSL_NO_SIKE
    case EVP_PKEY_SIKE:
        return (i2d_SIKEPublicKey(a->pkey.sike, pp));
#endif
#ifndef OPENSSL_NO_SPHINCS
    case EVP_PKEY_SPHINCS:
        return (i2d_SPHINCSPublicKey(a->pkey.sphincs, pp));
#endif
#ifndef OPENSSL_NO_XMSS
    case EVP_PKEY_XMSS:
        return (i2d_XMSSPublicKey(a->pkey.xmss, pp));
#endif
#ifndef OPENSSL_NO_XMSSMT
    case EVP_PKEY_XMSSMT:
        return (i2d_XMSSMTPublicKey(a->pkey.xmssmt, pp));
#endif
    default:
        ASN1err(ASN1_F_I2D_PUBLICKEY, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
        return (-1);
    }
}

int i2d_KemInfo(EVP_PKEY *a, unsigned char **pp) {
    switch (a->type) {
#ifndef OPENSSL_NO_CMC
    case EVP_PKEY_CMC:
        return (i2d_CMCKemInfo(a->pkey.cmc, pp));
#endif
#ifndef OPENSSL_NO_FRODOKEM
    case EVP_PKEY_FRODOKEM:
        return (i2d_FRODOKEMKemInfo(a->pkey.frodokem, pp));
#endif
#ifndef OPENSSL_NO_KYBER
    case EVP_PKEY_KYBER:
        return (i2d_KYBERKemInfo(a->pkey.kyber, pp));
#endif
#ifndef OPENSSL_NO_NTRUP
    case EVP_PKEY_NTRUP:
        return (i2d_NTRUPKemInfo(a->pkey.ntrup, pp));
#endif
#ifndef OPENSSL_NO_SIKE
    case EVP_PKEY_SIKE:
        return (i2d_SIKEKemInfo(a->pkey.sike, pp));
#endif
    default:
        ASN1err(ASN1_F_I2D_KEMINFO, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
        return (-1);
    }

    return 1;
}
