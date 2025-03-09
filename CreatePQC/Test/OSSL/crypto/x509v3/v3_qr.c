/* v3_qr.c */

#include "cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

/* ====================================================================
 * General output.
 * ====================================================================
 */
static int bitstring_print(BIO *bp, const char *prefix, const ASN1_BIT_STRING *str, int off)
{
    int n = 0;
    int i = 0;

    if (str == NULL || str->length == 0) {
        return 1;
    }

    if (BIO_printf(bp, "%s", prefix) <= 0) {
        return 0;
    }

    n = str->length;
    for (i = 0; i < n; i++) {
        if ((i % 15) == 0) {
            if (BIO_puts(bp, "\n") <= 0 || !BIO_indent(bp, off + 4, 128))
                return 0;
        }

        if (BIO_printf(bp, "%02x%s", str->data[i], ((i + 1) == n) ? "" : ":")
            <= 0) {
            return 0;
        }
    }

    if (BIO_write(bp, "\n", 1) <= 0) {
        return 0;
    }

    return 1;
}

/* ====================================================================
 * ALT Public Key Extension.
 * ====================================================================
 */
static int i2r_SUBJECT_ALT_PUBLIC_KEY_INFO(X509V3_EXT_METHOD *method,
                                 SUBJECT_ALT_PUBLIC_KEY_INFO *altpub, BIO *out,
                                 int indent);

const X509V3_EXT_METHOD v3_subject_alt_public_key_info = {
    NID_subjectAltPublicKeyInfo,
    X509V3_EXT_MULTILINE, ASN1_ITEM_ref(SUBJECT_ALT_PUBLIC_KEY_INFO),
    0, 0, 0, 0,
    0, 0, 0, 0,
    (X509V3_EXT_I2R) i2r_SUBJECT_ALT_PUBLIC_KEY_INFO, NULL,
    NULL
};

/* This is the same as the definition of the X509 subject public key in x_pubkey.c  */
ASN1_SEQUENCE(SUBJECT_ALT_PUBLIC_KEY_INFO) = {
        ASN1_SIMPLE(SUBJECT_ALT_PUBLIC_KEY_INFO, algor, X509_ALGOR),
        ASN1_SIMPLE(SUBJECT_ALT_PUBLIC_KEY_INFO, public_key, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(SUBJECT_ALT_PUBLIC_KEY_INFO)

IMPLEMENT_ASN1_FUNCTIONS(SUBJECT_ALT_PUBLIC_KEY_INFO)

static int i2r_SUBJECT_ALT_PUBLIC_KEY_INFO(X509V3_EXT_METHOD *method,
                                 SUBJECT_ALT_PUBLIC_KEY_INFO *alt_pub, BIO *out,
                                 int indent)
{

    X509_PUBKEY *x509_pub = NULL;
    EVP_PKEY * pkey_pub = NULL;
    int ret = 0;

    x509_pub = X509_PUBKEY_new();
    if (x509_pub == NULL) {
        goto end;
    }

    /* Prevent the leaking of memory */
    X509_ALGOR_free(x509_pub->algor);
    ASN1_BIT_STRING_free(x509_pub->public_key);

    x509_pub->algor = alt_pub->algor;
    x509_pub->public_key = alt_pub->public_key;

    pkey_pub = X509_PUBKEY_get(x509_pub);
    if (pkey_pub == NULL) {
        goto end;
    }
    BIO_indent(out, indent, 128);
    BIO_printf(out, "%s\n", OBJ_nid2ln(OBJ_obj2nid(alt_pub->algor->algorithm)));
    EVP_PKEY_print_public(out, pkey_pub, indent, NULL);
    ret = 1;

end:
    if (pkey_pub)
        EVP_PKEY_free(pkey_pub);
    if(x509_pub) {
        /* Prevent a double free */
        x509_pub->algor = NULL;
        x509_pub->public_key = NULL;
        X509_PUBKEY_free(x509_pub);
    }

    return ret;
}

/* ====================================================================
 * ALT Signature Value Extension.
 * ====================================================================
 */
static int i2r_ALT_SIGNATURE_VALUE(X509V3_EXT_METHOD *method,
                                 ASN1_BIT_STRING *signature, BIO *out,
                                 int indent);

const X509V3_EXT_METHOD v3_altSignatureValue = {
    NID_altSignatureValue, 0, ASN1_ITEM_ref(ASN1_BIT_STRING),
    0, 0, 0, 0,
    0, 0, 0, 0,
    (X509V3_EXT_I2R)i2r_ALT_SIGNATURE_VALUE, NULL,
    NULL
};

static int i2r_ALT_SIGNATURE_VALUE(X509V3_EXT_METHOD *method,
                                 ASN1_BIT_STRING *signature, BIO *out,
                                 int indent)
{
    BIO_printf(out, "%*s", indent, "");
    if (signature) {
        bitstring_print(out, "Signature: ", signature, indent);
    }
    return 1;
}

/* ====================================================================
 * ALT Signature Algorithm Extension.
 * ====================================================================
 */
static int i2r_ALT_SIGALG(X509V3_EXT_METHOD *method,
                                 X509_ALGOR *sigalg, BIO *out,
                                 int indent);

const X509V3_EXT_METHOD v3_altSignatureAlgorithm = {
    NID_altSignatureAlgorithm, 0, ASN1_ITEM_ref(X509_ALGOR),
    0, 0, 0, 0,
    0, 0, 0, 0,
    (X509V3_EXT_I2R)i2r_ALT_SIGALG, NULL,
    NULL
};

static int i2r_ALT_SIGALG(X509V3_EXT_METHOD *method,
                                 X509_ALGOR *sigalg, BIO *out,
                                 int indent)
{
    BIO_indent(out, indent, 128);
    BIO_printf(out, "%s\n", OBJ_nid2ln(OBJ_obj2nid(sigalg->algorithm)));
    return 1;
}

