/* crypto/cmc/cmc.h loosly based off of crypto/rsa/rsa.h */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, CMC,
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

#ifndef HEADER_CMC_H
# define HEADER_CMC_H

# include <openssl/asn1.h>

# ifndef OPENSSL_NO_BIO
#  include <openssl/bio.h>
# endif
# include <openssl/crypto.h>
# include <openssl/ossl_typ.h>

# ifdef OPENSSL_NO_CMC
#  error CMC is disabled.
# endif

#ifdef  __cplusplus
extern "C" {
#endif

#define EVP_PKEY_CTRL_CMC_PARAMETER_SET  (EVP_PKEY_ALG_CTRL + 2)
#define set_parameter_set_ctrl_string    "parameter_set"

#define CMC_6960119_R2 1
#define CMC_8192128_R2 2

/* Declared already in ossl_typ.h */
/* typedef struct cmc_st CMC; */

struct cmc_st {
    /*
     * The first parameter is used to pickup errors where this is passed
     * instead of an EVP_PKEY, it is set to 0
     */
    int pad;
    long version;
    int write_params;

    ENGINE *engine;

    /* CMC parameter.  Please see the spec. */
    long parameter_set;

    ASN1_OCTET_STRING *pub_key;                 /* public key */
    ASN1_OCTET_STRING *priv_key;                /* private key */
    ASN1_OCTET_STRING *kem_info;                /* KEM public info */
    ASN1_OCTET_STRING *kem_shared_key;          /* KEM shared secret key */


    /* not sure if we need this, keep it for now */
    CRYPTO_EX_DATA ex_data;
    int references;
    int flags;
};

/* memory management methods for the CMC struct */
CMC *CMC_new(void);
CMC *CMC_new_with_engine(ENGINE *engine);
void CMC_free(CMC *r);
int CMC_up_ref(CMC *r);

/* We will will need ASN1 because we will need the keys for encryption and
 * decryption.  
 */

/* ASN.1 for public key
 * Expanded version of DECLARE_ASN1_ENCODE_FUNCTIONS_const(CMC, CMCPublicKey)
 */
CMC *d2i_CMCPublicKey(CMC **a, const unsigned char **pp, long length);
int i2d_CMCPublicKey(const CMC *a, unsigned char **pp);

/* ASN.1 for public kem info
 * Expanded version of DECLARE_ASN1_ENCODE_FUNCTIONS_const(CMC, CMCKemInfo)
 */
CMC *d2i_CMCKemInfo(CMC **a, const unsigned char **pp, long length);
int i2d_CMCKemInfo(const CMC *a, unsigned char **pp);


/* ASN.1 for private key
 * Expanded version of DECLARE_ASN1_ENCODE_FUNCTIONS_const(CMC, CMCPrivateKey)
 */
CMC *d2i_CMCPrivateKey(CMC **a, const unsigned char **pp, long length);
int i2d_CMCPrivateKey(const CMC *a, unsigned char **pp);

/* not sure if we need this, keep for now. */
int CMC_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int CMC_set_ex_data(CMC *r, int idx, void *arg);
void *CMC_get_ex_data(CMC *r, int idx);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_CMC_strings(void);

/* Error codes for the CMC functions. */

/* Function codes. */
# define CMC_F_CMC_NEW_WITH_ENGINE                        100

/* Reason codes. */
# define CMC_R_ENGINE_INIT_FAILURE                        100
# define CMC_R_MALLOC_FAILURE                             101

#ifdef  __cplusplus
}
#endif
#endif
