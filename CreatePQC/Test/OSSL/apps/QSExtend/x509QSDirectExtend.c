/** @file x509QSDirectExtend.c Load QS keypair and traditional X509 certificates and use them to create a multiple public key algorithm certificate.
 *
 * @copyright Copyright (C) 2017-2019, ISARA Corporation, All Rights Reserved.
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
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>

#undef PROG
#define PROG    x509QSDirectExtend_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    char **args = NULL;
    int badarg = 0;
    int ret = 1;
    int self_sign = 0;
    char *passin = NULL;
    char *pass_qs = NULL;
    char *passargin = NULL;
    char *passarg_qs = NULL;
    int qs_pub_key_ind = -1;
    int qs_sigalg_ind = -1;
    int qs_sigval_ind = -1;
    int qs_key_format = FORMAT_PEM;

    ENGINE *e = NULL;
    EVP_PKEY_CTX *tmpctx = NULL;
    EVP_PKEY *pkey_qs_priv = NULL;
    EVP_PKEY *pkey_qs_pub = NULL;
    EVP_PKEY *classical_privkey = NULL;

    BIO *bio_x509in = NULL;
    BIO *bio_x509out = NULL;
    BIO *bio_privqsout = NULL;

    const char *file_priv = NULL;
    const char *file_qs_pub = NULL;
    const char *file_qs_priv = NULL;
    const char *file_x509in = NULL;
    const char *file_x509out = NULL;
    char *file_qs_priv_out = NULL;

    X509_ALGOR *algor_for_qssigalg = NULL;
    X509_EXTENSION *ext_qssigalg = NULL;

    X509 *cert = NULL;
    ASN1_BIT_STRING *qs_sigval_as_asn1bitstring = NULL;

    X509_EXTENSION *ext_qssig = NULL;

    X509_PUBKEY *x509_pub_qs = NULL;
    X509_PUBKEY *x509_sig_qs = NULL;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki = NULL;
    X509_EXTENSION *ext_sapki = NULL;

    EVP_MD_CTX mctx;
    EVP_MD_CTX_init(&mctx);

    const EVP_CIPHER *cipher = NULL;

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
        } else if (strcmp(*args, "-x509in") == 0) {
            if (!args[1])
                goto bad;
            file_x509in = *(++args);
        } else if (strcmp(*args, "-x509out") == 0) {
            if (!args[1])
                goto bad;
            file_x509out = *(++args);
        } else if (strcmp(*args, "-privin") == 0) {
            if (!args[1])
                goto bad;
            file_priv = *(++args);
        } else if (strcmp(*args, "-pubqs") == 0) {
            if (!args[1])
                goto bad;
            file_qs_pub = *(++args);
        } else if (strcmp(*args, "-privqs") == 0) {
            if (!args[1])
                goto bad;
            file_qs_priv = *(++args);
        } else if (strcmp(*args, "-privqs_engine") == 0) {
            qs_key_format = FORMAT_ENGINE;
        } else if (strcmp(*args, "-self_sign") == 0) {
            self_sign = 1;
        } else if (strcmp(*args, "-passin") == 0) {
            if (--argc < 1)
                goto bad;
            passargin = *(++args);
        } else if (strcmp(*args, "-passqs") == 0) {
            if (--argc < 1)
                goto bad;
            passarg_qs = *(++args);
        } else {
            cipher = EVP_get_cipherbyname(*args + 1);
            if (cipher == NULL) {
                BIO_printf(bio_err, "Unknown cipher %s\n", *args + 1);
                badarg = 1;
            }
        }
        args++;
    }

    if (file_x509in == NULL)
        badarg = 1;

    if (file_x509out == NULL)
        badarg = 1;

    if ((file_qs_pub == NULL) && (self_sign == 0))
        badarg = 1;

    if ((file_qs_pub != NULL) && (self_sign == 1))
        badarg = 1;

    if ((file_qs_priv == NULL) && (self_sign == 1))
        badarg = 1;

    if ((file_qs_priv == NULL) && (qs_key_format == FORMAT_ENGINE))
        badarg = 1;

    if ((file_qs_priv == NULL) && (passarg_qs != NULL))
        badarg = 1;

    if (badarg) {
bad:
        BIO_printf(bio_err, "Usage: openssl x509QSDirectExtend [options]\n");
        BIO_printf(bio_err, "where options may be\n");
        BIO_printf(bio_err,
                   "-engine e          Use IQR Engine library <e>.\n");
        BIO_printf(bio_err,
                   "-x509in file       The X509 certificate in pem format.\n");
        BIO_printf(bio_err,
                   "-x509out file      The X509 MPKA certificate in pem format with new ALT extensions.\n");
        BIO_printf(bio_err,
                   "-privin file       The private key used to sign the original x509 certificate in pem format.\n");
        BIO_printf(bio_err,
                   "                   Optional. If absent, the QS private key must be present and be an extended\n");
        BIO_printf(bio_err,
                   "                   private key.\n");
        BIO_printf(bio_err,
                   "-pubqs file        The public QS key. Incompatible with -self_sign.\n");
        BIO_printf(bio_err,
                   "-privqs file       The private QS key. Optional; QS signature algorithm and value will be added\n");
        BIO_printf(bio_err,
                   "                   if present.\n");
        BIO_printf(bio_err,
                   "                   Will be rewritten to contain the classical key and QS key.\n");
        BIO_printf(bio_err,
                   "-privqs_engine     The private QS key should be loaded via the engine. Optional. Requires -privqs.\n");
        BIO_printf(bio_err,
                   "-self_sign         The public key should be obtained from the private key. Incompatible with.\n");
        BIO_printf(bio_err,
                   "                   -pubqs. Requires -privqs.\n");
        BIO_printf(bio_err,
                   "-passin            The private key password source. Optional.\n");
        BIO_printf(bio_err,
                   "-passqs            The private QS key password source. Requires -privqs. Optional.\n");
        BIO_printf(bio_err,
                   "-<cipher>          Use cipher <cipher> to encrypt the key. Optional.\n");
        goto end;
    }

    if (!app_passwd(bio_err, passargin, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting password for the private key.\n");
        goto end;
    }

    if (!app_passwd(bio_err, passarg_qs, NULL, &pass_qs, NULL)) {
        BIO_printf(bio_err, "Error getting password for the QS private key.\n");
        goto end;
    }

    bio_x509in = BIO_new_file(file_x509in, "rb");
    cert = PEM_read_bio_X509(bio_x509in, NULL, NULL, NULL);
    if (cert == NULL) {
        BIO_printf(bio_err, "Bad certificate\n");
        goto end;
    }
    BIO_free_all(bio_x509in);
    bio_x509in = NULL;

    /* Ensure this certificate does not already have alternative extensions. */
    qs_pub_key_ind = X509_get_ext_by_NID(cert, NID_subjectAltPublicKeyInfo, -1);
    qs_sigalg_ind = X509_get_ext_by_NID(cert, NID_altSignatureAlgorithm, -1);
    qs_sigval_ind = X509_get_ext_by_NID(cert, NID_altSignatureValue, -1);
    if ((qs_pub_key_ind != -1) || (qs_sigalg_ind != -1) || (qs_sigval_ind != -1)) {
        BIO_puts(bio_err, "The input certificate already has alternative extensions.\n");
        goto end;
    }

    if (file_priv == NULL) {
        if (qs_key_format == FORMAT_ENGINE) {
            char *tmp1 = strstr(file_qs_priv, "::");
            if (tmp1 == NULL) {
                BIO_puts(bio_err, "Engine private key, but no state separator (::).\n");
                goto end;
            }

            char *tmp2 = OPENSSL_malloc((int)(tmp1 - file_qs_priv + 1));
            if (tmp2 == NULL) {
                BIO_puts(bio_err, "Memory allocation failure.\n");
                goto end;
            }

            memcpy(tmp2, file_qs_priv, tmp1 - file_qs_priv);
            tmp2[tmp1 - file_qs_priv] = '\0';
            classical_privkey = load_key(bio_err, tmp2, FORMAT_PEM, 0, pass_qs, e, "Classical Private Key");
            OPENSSL_free(tmp2);
        } else {
            classical_privkey = load_key(bio_err, file_qs_priv, FORMAT_PEM, 0, pass_qs, e, "Classical Private Key");
        }
    } else {
        classical_privkey = load_key(bio_err, file_priv, FORMAT_PEM, 0, passin, e, "Classical Private Key");
    }

    if (classical_privkey == NULL) {
        /* load_key() has already printed an appropriate message. */
        goto end;
    }

    if (file_qs_priv != NULL) {
        if (file_priv == NULL) {
            pkey_qs_priv = load_alt_key(bio_err, file_qs_priv, qs_key_format, 0, pass_qs, e, "QS Private Key");
        } else {
            /* Try to load the alt key.  If its present, then that is an error
             * since that means that the user has given 2 classical private
             * keys.
             */
            pkey_qs_priv = load_alt_key(NULL, file_qs_priv, FORMAT_PEM, 0, pass_qs, e, "QS Private Key");
            if (pkey_qs_priv != NULL) {
                BIO_puts(bio_err, "Both dual private key file and classical private key file have been provided.\n");
                goto end;
            }

            pkey_qs_priv = load_key(bio_err, file_qs_priv, qs_key_format, 0, pass_qs, e, "QS Private Key");
        }
        if (pkey_qs_priv == NULL) {
            /* load_key() has already printed an appropriate message. */
            goto end;
        }
    }

    /* Read the QS Public key to be embedded in the QS certificate if it was specified.
     * If not check the private key.
     */
    if (file_qs_pub == NULL) {
        pkey_qs_pub = pkey_qs_priv;
    } else {
        pkey_qs_pub = load_pubkey(bio_err, file_qs_pub, FORMAT_PEM, 0, NULL, e, "QS Public Key");
        if (pkey_qs_pub == NULL) {
            /* load_pubkey() has already printed an appropriate message. */
            goto end;
        }
    }

    /* Ensure the private key is actually a QS key */
    if ((pkey_qs_priv != NULL) && (!EVP_PKEY_is_QS_auth(EVP_PKEY_id(pkey_qs_priv)))) {
        BIO_puts(bio_err, "The provided private key is not compatible with a quantum-safe algorithm.\n");
        goto end;
    }

    /* Ensure the public key is actually a QS key */
    if (!EVP_PKEY_is_QS_auth(EVP_PKEY_id(pkey_qs_pub))) {
        BIO_puts(bio_err, "The provided public key is not compatible with a quantum-safe algorithm.\n");
        goto end;
    }

    /* Convert the pkey in to an x509 public key.  This is the standard way
     * of doing it for x509 subject public key.
     */
    X509_PUBKEY_set(&x509_pub_qs, pkey_qs_pub);

    sapki = SUBJECT_ALT_PUBLIC_KEY_INFO_new();
    if (sapki == NULL) {
        BIO_puts(bio_err, "Error converting public key to x509 pubkey\n");
        goto end;
    }

    X509_ALGOR_free(sapki->algor);
    ASN1_BIT_STRING_free(sapki->public_key);
    sapki->algor = x509_pub_qs->algor;
    sapki->public_key = x509_pub_qs->public_key;

    if (pkey_qs_priv != NULL) {
        /* Convert the private key into an x509 public key.  This lets us
         * get the algorithm identifier of the private key so we can associate
         * it with the signature.
         */
        X509_PUBKEY_set(&x509_sig_qs, pkey_qs_priv);

        /* Create and insert QS signature algorithm as an extension. */

        /* Duplicate the algorithm for the signature. */
        algor_for_qssigalg = X509_ALGOR_dup(x509_sig_qs->algor);
        if (algor_for_qssigalg == NULL) {
            BIO_puts(bio_err, "Error duplicating signature algor.\n");
            goto end;
        }

        if (X509_ALGOR_set0(algor_for_qssigalg, OBJ_nid2obj(EVP_PKEY_id(pkey_qs_priv)), ASN1_get_sigparam(pkey_qs_priv), NULL) == 0) {
            BIO_puts(bio_err, "Error setting algorithm object ID.\n");
            goto end;
        }

        ext_qssigalg = X509V3_EXT_i2d(NID_altSignatureAlgorithm, 0, algor_for_qssigalg);
        if (ext_qssigalg == NULL) {
            BIO_puts(bio_err, "Error creating signature algorithm extension.\n");
            goto end;
        }

        /* Insert QS signature algorithm as an extension. */
        if (X509_add_ext(cert, ext_qssigalg, -1) == 0) {
            BIO_puts(bio_err, "Error adding signature algorithm extension.\n");
            goto end;
        }
    }


    /* Create and insert QS public key as an extension. */
    ext_sapki = X509V3_EXT_i2d(NID_subjectAltPublicKeyInfo, 0, sapki);
    sapki->algor = NULL;
    sapki->public_key = NULL;
    if (ext_sapki == NULL) {
        BIO_puts(bio_err, "Error converting x509 pubkey to extension.\n");
        goto end;
    }

    if (X509_add_ext(cert, ext_sapki, -1) == 0) {
        BIO_puts(bio_err, "Error adding public key as extension\n");
        goto end;
    }

    /* Sign the cert with the QS private key if required. */
    if (pkey_qs_priv != NULL) {
        if (EVP_DigestSignInit(&mctx, NULL, NULL, NULL, pkey_qs_priv) < 1) {
            BIO_puts(bio_err, "Error doing EVP digest initialization\n");
            goto end;
        }

        /* We could call X509_sign_ctx() here, but the following code in
         * ASN1_item_sign_ctx() made that a bad idea:
         *
         *   if (algor1)
         *       X509_ALGOR_set0(algor1, OBJ_nid2obj(signid), paramtype, NULL);
         *   if (algor2)
         *       X509_ALGOR_set0(algor2, OBJ_nid2obj(signid), paramtype, NULL);
         *
         * Those lines were modifying AlgorithmIdentifier in the X509 cert.
         * That would change the resulting digest result which is a side effect
         * we would like to avoid.
         *
         * X509_sign_ctx() just sets the modified flag and calls
         * ASN1_item_sign_ctx().  We can do that and instead of passing the
         * algors, we just pass NULL and a custom signature BISTRING.
         */

        cert->cert_info->enc.modified = 1;

        qs_sigval_as_asn1bitstring = ASN1_BIT_STRING_new();
        if (qs_sigval_as_asn1bitstring == NULL) {
             BIO_puts(bio_err, "ASN1 bit string memory allocation error.\n");
             goto end;
        }

        if (ASN1_item_sign_ctx(ASN1_ITEM_rptr(X509_PCINF), NULL, NULL, qs_sigval_as_asn1bitstring, cert->cert_info, &mctx) <= 0) {
            BIO_puts(bio_err, "Quantum-safe signing operation failed.\n");
            goto end;
        }


        qs_sigval_as_asn1bitstring->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        qs_sigval_as_asn1bitstring->flags |= ASN1_STRING_FLAG_BITS_LEFT;

        /* Create QS signature as an extension. */
        ext_qssig = X509V3_EXT_i2d(NID_altSignatureValue, 0, qs_sigval_as_asn1bitstring);
        if (ext_qssig == NULL) {
            BIO_puts(bio_err, "Error creating signature extension.\n");
            goto end;
        }

        /* Insert QS signature as an extension. */
        if (X509_add_ext(cert, ext_qssig, -1) == 0) {
            BIO_puts(bio_err, "Error adding signature extension\n");
            goto end;
        }
    }

    /* Re-sign the certificate with the original classical private key. */
    if (X509_sign(cert, classical_privkey, NULL) == 0) {
        BIO_puts(bio_err, "Error generating classical signature.\n");
        goto end;
    }

    /* Write the new signed certificate with extensions in it. */
    bio_x509out = BIO_new_file(file_x509out, "wb");
    if (PEM_write_bio_X509(bio_x509out, cert) == 0) {
        BIO_puts(bio_err, "Error writing new certificate.\n");
        goto end;
    }

    if (file_qs_priv != NULL) {
        if (qs_key_format == FORMAT_ENGINE) {
            char *tmp = strstr(file_qs_priv, "::");
            if (tmp == NULL) {
                BIO_puts(bio_err, "Engine private key, but no state separator (::).\n");
                goto end;
            }

            file_qs_priv_out = OPENSSL_malloc((int)(tmp - file_qs_priv + 1));
            if (file_qs_priv_out == NULL) {
                BIO_puts(bio_err, "Memory allocation failure.\n");
                goto end;
            }

            memcpy(file_qs_priv_out, file_qs_priv, tmp - file_qs_priv);
            file_qs_priv_out[tmp - file_qs_priv] = '\0';
            bio_privqsout = BIO_new_file(file_qs_priv_out, "wb");
        } else {
            bio_privqsout = BIO_new_file(file_qs_priv, "wb");
        }

        /* Write the combined private key.  Encrypt BOTH with the QS password. */
        if (PEM_write_bio_PKCS8PrivateKey(bio_privqsout, classical_privkey, cipher, NULL, 0, NULL, pass_qs) == 0) {
            BIO_puts(bio_err, "Error writing classical private key to the combined file.\n");
            goto end;
        }

        if (PEM_write_bio_ALT_PKCS8PrivateKey(bio_privqsout, pkey_qs_priv, cipher, NULL, 0, NULL, pass_qs) == 0) {
            BIO_puts(bio_err, "Error writing QS private key to the combined file.\n");
            goto end;
        }
    }

    ret = 0;

 end:
    if (ret != 0)
        ERR_print_errors(bio_err);

    EVP_MD_CTX_cleanup(&mctx);
    if (tmpctx)
        EVP_PKEY_CTX_free(tmpctx);
    if (bio_x509in)
        BIO_free_all(bio_x509in);
    if (bio_x509out)
        BIO_free_all(bio_x509out);
    if (bio_privqsout)
        BIO_free_all(bio_privqsout);
    if (cert)
        X509_free(cert);
    if (pkey_qs_pub == pkey_qs_priv)
        pkey_qs_pub = NULL;
    if (pkey_qs_pub)
        EVP_PKEY_free(pkey_qs_pub);
    if (pkey_qs_priv)
        EVP_PKEY_free(pkey_qs_priv);
    if (classical_privkey)
        EVP_PKEY_free(classical_privkey);
    if (x509_pub_qs)
        X509_PUBKEY_free(x509_pub_qs);
    if (x509_sig_qs)
        X509_PUBKEY_free(x509_sig_qs);
    if (sapki)
        SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki);
    if (algor_for_qssigalg)
        X509_ALGOR_free(algor_for_qssigalg);
    if (file_qs_priv_out)
        OPENSSL_free(file_qs_priv_out);

    if (qs_sigval_as_asn1bitstring)
        ASN1_BIT_STRING_free(qs_sigval_as_asn1bitstring);
    if (ext_sapki)
        X509_EXTENSION_free(ext_sapki);
    if (ext_qssig)
        X509_EXTENSION_free(ext_qssig);
    if (ext_qssigalg)
        X509_EXTENSION_free(ext_qssigalg);

    if (passargin && passin)
        OPENSSL_free(passin);
    if (passarg_qs && pass_qs)
        OPENSSL_free(pass_qs);
    release_engine(e);
    OBJ_cleanup();
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

