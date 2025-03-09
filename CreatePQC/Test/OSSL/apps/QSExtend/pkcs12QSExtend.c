/** @file pkcs12QSExtend.c Load a PKCS12 file with a X.509 MPKAC certificate
 *  and convential private key.  Then load a file with an alt private key.
 *  Add the alt private key to the PKCS12 file and append [ALT] to the front
 *  of the friendly name.
 *
 * @copyright Copyright (C) 2018-2019, ISARA Corporation, All Rights Reserved.
 */

/* Modified.  Was genpkey.c. 
 */

/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../apps/apps.h"
#include <openssl/asn1_mac.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>

#undef PROG
#define PROG    pkcs12QSExtend_main

static int set_pbe(BIO *err, int *ppbe, const char *str)
{
    if (!str)
        return 0;
    if (!strcmp(str, "NONE")) {
        *ppbe = -1;
        return 1;
    }
    *ppbe = OBJ_txt2nid(str);
    if (*ppbe == NID_undef) {
        BIO_printf(bio_err, "Unknown PBE algorithm %s\n", str);
        return 0;
    }
    return 1;
}

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    char **args = NULL;
    int badarg = 0;
    int ret = 1;
    char *pass = NULL;
    char *passarg = NULL;
    ENGINE *e = NULL;
    char *pass_qs = NULL;
    char *passarg_qs = NULL;


    EVP_PKEY *pkey_qs_priv = NULL;
    const char *file_qs_priv = NULL;

    BIO *bio_pkcs12in = NULL;
    BIO *bio_pkcs12out = NULL;
    const char *file_pkcs12in = NULL;
    const char *file_pkcs12out = NULL;

    PKCS12 *pkcs12 = NULL;

    PKCS7 *safe = NULL;
    STACK_OF(PKCS7) *safes = NULL;
    int safe_iter = 0;

    PKCS12_SAFEBAG * bag = NULL;
    PKCS12_SAFEBAG * qs_priv_bag = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
    int bag_iter = 0;
    int bag_nid = 0;

    X509 *cert = NULL;
    X509 *found_cert = NULL;
    char *found_priv = NULL;
    int key_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;

    CRYPTO_malloc_debug_init();
    CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    ERR_load_crypto_strings();
    ENGINE_load_dynamic();

    args = argv + 1;
    while (!badarg && *args && *args[0] == '-') {
        if (strcmp(*args, "-engine") == 0) {
            if (!args[1])
                goto bad;
            e = setup_engine(bio_err, *(++args), 0);
        } else if (strcmp(*args, "-pkcs12in") == 0) {
            if (!args[1])
                goto bad;
            file_pkcs12in = *(++args);
        } else if (strcmp(*args, "-pkcs12out") == 0) {
            if (!args[1])
                goto bad;
            file_pkcs12out = *(++args);
        } else if (strcmp(*args, "-privqs") == 0) {
            if (!args[1])
                goto bad;
            file_qs_priv = *(++args);
        } else if (strcmp(*args, "-passqs") == 0) {
            if (--argc < 1)
                goto bad;
            passarg_qs = *(++args);
        } else if (strcmp(*args, "-pass") == 0) {
            if (--argc < 1)
                goto bad;
            passarg = *(++args);
        } else if (!strcmp(*args, "-keypbe")) {
            if (!set_pbe(bio_err, &key_pbe, *++args))
                goto bad; 
        } else {
            badarg = 1;
        }
        args++;
    }

    if (file_pkcs12in == NULL)
        badarg = 1;

    if (file_pkcs12out == NULL)
        badarg = 1;

    if (file_qs_priv == NULL)
        badarg = 1;

    if (badarg) {
bad:
        BIO_printf(bio_err, "Usage: openssl pkcs12QSExtend [options]\n");
        BIO_printf(bio_err, "where options may be\n");
        BIO_printf(bio_err,
                   "-engine e          Use IQR Engine library <e>.\n");
        BIO_printf(bio_err,
                   "-pkcs12in file     The .p12 file\n");
        BIO_printf(bio_err,
                   "-pkcs12out file    The new .p12 file with the alternative private key with new [ALT] prefix in\n");
        BIO_printf(bio_err,
                   "                   friendly name.\n");
        BIO_printf(bio_err,
                   "-privqs file       The private QS key.\n");
        BIO_printf(bio_err,
                   "-passqs            The password source for decrypting the QS private key. Only required if the QS\n");
        BIO_printf(bio_err,
                   "                   private key was encrypted.\n");
        BIO_printf(bio_err,
                   "-pass              The password source for PKCS12 private key encryption. Optional. If not present\n");
        BIO_printf(bio_err,
                   "                   the private keys are not encrypted.\n");
        BIO_printf(bio_err,
                   "-keypbe            The algorithm for QS private key encryption. Without -pass, this is ignored.\n");
        BIO_printf(bio_err,
                   "                   Default is PBE-SHA1-3DES. See PKCS8 manpage.\n");
        goto end;
    }

    if (!app_passwd(bio_err, passarg, NULL, &pass, NULL)) {
        BIO_printf(bio_err, "Error getting password for the private key.\n");
        goto end;
    }

    if (!app_passwd(bio_err, passarg_qs, NULL, &pass_qs, NULL)) {
        BIO_printf(bio_err, "Error getting password to decrypt the QS private key.\n");
        goto end;
    }

    /* This block of code will succeed if the private key file contains a dual
     * key and the ALT key is QS. It will also succeed if the private key file
     * contains a single QS key. Otherwise, fail.
     *
     * Read in the alt private key without a valid err_bio. If an error occurs,
     * this might not be a dual key so erase the error message and try
     * load_key()  with a valid err_bio. If that fails, or succeeds but is not
     * QS, then call load_alt_key() again with valid error bio to output an
     * error message for the alt key as well.
     */
    pkey_qs_priv = load_alt_key(NULL, file_qs_priv, FORMAT_PEM, 0, pass_qs, e, "QS Private Key");
    ERR_clear_error();
    if (pkey_qs_priv == NULL) {
        pkey_qs_priv = load_key(bio_err, file_qs_priv, FORMAT_PEM, 0, pass_qs, e, "Private Key");
        if ((pkey_qs_priv == NULL) || (!EVP_PKEY_is_QS_auth(EVP_PKEY_id(pkey_qs_priv)))) {
            load_alt_key(bio_err, file_qs_priv, FORMAT_PEM, 0, pass_qs, e, "QS Private Key");
            /* load_key() and/or load_alt_key() have already printed an appropriate
             * message.
             */
            goto end;
        }
    }

    /* Ensure the QS private key is actually a key for a QS signature scheme. */
    if (!EVP_PKEY_is_QS_auth(EVP_PKEY_id(pkey_qs_priv))) {
        BIO_puts(bio_err, "The provided private key is not compatible with a quantum-safe algorithm.\n");
        goto end;
    }

    bio_pkcs12in = BIO_new_file(file_pkcs12in, "rb");
    pkcs12 = d2i_PKCS12_bio(bio_pkcs12in, NULL);
    safes = PKCS12_unpack_authsafes(pkcs12);

    /* Going to assume that there was at most one private key in the input
     * pkcs12 file. This is appropriate as this is a limitation of the pkcs12
     * application that created the file.
     */

    for (safe_iter = 0; safe_iter < sk_PKCS7_num(safes); safe_iter++) {
        safe = sk_PKCS7_value(safes, safe_iter);
        bag_nid = OBJ_obj2nid(safe->type);

        if (bag_nid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(safe);
        } else if (bag_nid == NID_pkcs7_encrypted) {
            bags = PKCS12_unpack_p7encdata(safe, pass, strlen(pass));
        }

        if (bags == NULL) {
            continue;
        }

        for (bag_iter = 0; bag_iter <  sk_PKCS12_SAFEBAG_num(bags); bag_iter++) {
            bag = sk_PKCS12_SAFEBAG_value(bags, bag_iter);
            if (bag == NULL) {
                continue;
            }

            /* Look for the certificate. */
            cert = PKCS12_certbag2x509(bag);
            if (cert != NULL) {
                if (X509_check_alt_private_key(cert, pkey_qs_priv) == 1) {
                    found_cert = cert;
                } else {
                    X509_free(cert);
                    cert = NULL;
                }
                continue;
            }

            /* Look for an encrypted or unencrypted private key.
             * Grab the friendlyname and prepend [ALT] to it.
             */
            if ((M_PKCS12_bag_type(bag) == NID_keyBag) || (M_PKCS12_bag_type(bag) == NID_pkcs8ShroudedKeyBag)) {
                if (found_priv != NULL) {
                    fprintf(stderr, "Multiple private keys in the PKCS12 input file.\n");
                }
                found_priv = PKCS12_get_friendlyname(bag);
                if (found_priv == NULL) {
                    found_priv = OPENSSL_malloc(strlen("[ALT]") + 1);
                    if (found_priv == NULL) {
                        fprintf(stderr, "Memory allocation error while creating friendly name\n");
                    }
                    strcpy(found_priv, "[ALT]");
                } else {
                    char *ctmp = OPENSSL_malloc(strlen("[ALT]") + strlen(found_priv) + 1);
                    if (ctmp == NULL) {
                        fprintf(stderr, "Memory allocation error while creating friendly name\n");
                    }
                    strcpy(ctmp, "[ALT]");
                    strcat(ctmp, found_priv);
                    OPENSSL_free(found_priv);
                    found_priv = ctmp;
                }

                continue;
            }
        }

        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        bags = NULL;
    }


    if ((found_cert == NULL) || (found_priv == 0)) {
        fprintf (stderr, "Certificate and/or private key not found.\n");
        goto end;
    }

    for (safe_iter = 0; safe_iter < sk_PKCS7_num(safes); safe_iter++) {
        safe = sk_PKCS7_value(safes, safe_iter);
        bag_nid = OBJ_obj2nid(safe->type);

        if (bag_nid == NID_pkcs7_encrypted) {
            bags = PKCS12_unpack_p7encdata(safe, pass, strlen(pass));
        }

        if (bags != NULL) {
            /* We are only interested in NID_pkcs7_encrypted because
             * that is where we want to put the private key.
             */
            break;
        }
    }

    qs_priv_bag = PKCS12_add_key(&bags, pkey_qs_priv, 0, PKCS12_DEFAULT_ITER,
                                 key_pbe, pass);
    if (qs_priv_bag == NULL) {
        fprintf (stderr, "Error adding the QS private key.\n");
        goto end;
    }

    /* Add the new friendly name to this alt private key. */
    if (PKCS12_add_friendlyname_asc(qs_priv_bag, found_priv, strlen(found_priv)) == 0) {
        fprintf(stderr, "Error adding the QS private key friendly name.\n");
        goto end;
    }

    /* Remove and deallocate the safe and then replace it. */
    PKCS7_free(sk_PKCS7_delete(safes, safe_iter));
    if (sk_PKCS7_push(safes, PKCS12_pack_p7encdata(key_pbe, pass, strlen(pass), NULL, 0,
                      PKCS12_DEFAULT_ITER, bags)) == 0) {
        fprintf(stderr, "Error pushing a PKCS7 into stack.\n");
        goto end;
    }

    if (PKCS12_pack_authsafes(pkcs12, safes) == 0) {
        fprintf(stderr, "Error packing the safes\n");
        goto end;
    }

    if (PKCS12_set_mac(pkcs12, pass, strlen(pass), NULL, 0, PKCS12_DEFAULT_ITER, NULL) == 0) {
        fprintf(stderr, "Error setting the MAC\n");
        goto end;
    }

    bio_pkcs12out = BIO_new_file(file_pkcs12out, "wb");
    if (i2d_PKCS12_bio(bio_pkcs12out, pkcs12) == 0) {
        fprintf(stderr, "Error encoding or outputting the file.\n");
        goto end;
    }

    ret = 0;

 end:
    if (ret != 0)
        ERR_print_errors(bio_err);

    if (bio_pkcs12in)
        BIO_free_all(bio_pkcs12in);
    if (bio_pkcs12out)
        BIO_free_all(bio_pkcs12out);
    if (pkey_qs_priv)
        EVP_PKEY_free(pkey_qs_priv);
    if (passarg && pass)
        OPENSSL_free(pass);
    if (passarg_qs && pass_qs)
        OPENSSL_free(pass_qs);
    if (pkcs12)
        PKCS12_free(pkcs12);
    if (safes)
        sk_PKCS7_pop_free(safes, PKCS7_free);
    if (found_cert)
        X509_free(found_cert);
    if (found_priv)
        OPENSSL_free(found_priv);
    if (bags)
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);

    release_engine(e);
    OBJ_cleanup();
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

