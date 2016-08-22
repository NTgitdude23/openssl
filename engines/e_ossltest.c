/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is the OSSLTEST engine. It provides deliberately crippled digest
 * implementations for test purposes. It is highly insecure and must NOT be
 * used for any purpose except testing
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>


#include <openssl/engine.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>

#define OSSLTEST_LIB_NAME "OSSLTEST"
#include "e_ossltest_err.c"

/* Engine Id and Name */
static const char *engine_ossltest_id = "ossltest";
static const char *engine_ossltest_name = "OpenSSL Test engine support";


/* Engine Lifetime functions */
static int ossltest_destroy(ENGINE *e);
static int ossltest_init(ENGINE *e);
static int ossltest_finish(ENGINE *e);
void ENGINE_load_ossltest(void);


/* Set up digests */
static int ossltest_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid);

/* MD5 */
static int digest_md5_init(EVP_MD_CTX *ctx);
static int digest_md5_update(EVP_MD_CTX *ctx, const void *data,
                             size_t count);
static int digest_md5_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_md5_md = NULL;
static const EVP_MD *digest_md5(void)
{
    if (_hidden_md5_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_md5, NID_md5WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, MD5_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, MD5_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(MD5_CTX))
            || !EVP_MD_meth_set_flags(md, 0)
            || !EVP_MD_meth_set_init(md, digest_md5_init)
            || !EVP_MD_meth_set_update(md, digest_md5_update)
            || !EVP_MD_meth_set_final(md, digest_md5_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_md5_md = md;
    }
    return _hidden_md5_md;
}

/* SHA1 */
static int digest_sha1_init(EVP_MD_CTX *ctx);
static int digest_sha1_update(EVP_MD_CTX *ctx, const void *data,
                              size_t count);
static int digest_sha1_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_sha1_md = NULL;
static const EVP_MD *digest_sha1(void)
{
    if (_hidden_sha1_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SHA_CTX))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, digest_sha1_init)
            || !EVP_MD_meth_set_update(md, digest_sha1_update)
            || !EVP_MD_meth_set_final(md, digest_sha1_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha1_md = md;
    }
    return _hidden_sha1_md;
}

/* SHA256 */
static int digest_sha256_init(EVP_MD_CTX *ctx);
static int digest_sha256_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count);
static int digest_sha256_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_sha256_md = NULL;
static const EVP_MD *digest_sha256(void)
{
    if (_hidden_sha256_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha256, NID_sha256WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA256_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA256_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SHA256_CTX))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, digest_sha256_init)
            || !EVP_MD_meth_set_update(md, digest_sha256_update)
            || !EVP_MD_meth_set_final(md, digest_sha256_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha256_md = md;
    }
    return _hidden_sha256_md;
}

/* SHA384/SHA512 */
static int digest_sha384_init(EVP_MD_CTX *ctx);
static int digest_sha512_init(EVP_MD_CTX *ctx);
static int digest_sha512_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count);
static int digest_sha384_final(EVP_MD_CTX *ctx, unsigned char *md);
static int digest_sha512_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_sha384_md = NULL;
static const EVP_MD *digest_sha384(void)
{
    if (_hidden_sha384_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha384, NID_sha384WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA384_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA512_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SHA512_CTX))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, digest_sha384_init)
            || !EVP_MD_meth_set_update(md, digest_sha512_update)
            || !EVP_MD_meth_set_final(md, digest_sha384_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha384_md = md;
    }
    return _hidden_sha384_md;
}
static EVP_MD *_hidden_sha512_md = NULL;
static const EVP_MD *digest_sha512(void)
{
    if (_hidden_sha512_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha512, NID_sha512WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA512_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA512_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SHA512_CTX))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, digest_sha512_init)
            || !EVP_MD_meth_set_update(md, digest_sha512_update)
            || !EVP_MD_meth_set_final(md, digest_sha512_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha512_md = md;
    }
    return _hidden_sha512_md;
}
static void destroy_digests(void)
{
    EVP_MD_meth_free(_hidden_md5_md);
    _hidden_md5_md = NULL;
    EVP_MD_meth_free(_hidden_sha1_md);
    _hidden_sha1_md = NULL;
    EVP_MD_meth_free(_hidden_sha256_md);
    _hidden_sha256_md = NULL;
    EVP_MD_meth_free(_hidden_sha384_md);
    _hidden_sha384_md = NULL;
    EVP_MD_meth_free(_hidden_sha512_md);
    _hidden_sha512_md = NULL;
}
static int ossltest_digest_nids(const int **nids)
{
    static int digest_nids[6] = { 0, 0, 0, 0, 0, 0 };
    static int pos = 0;
    static int init = 0;

    if (!init) {
        const EVP_MD *md;
        if ((md = digest_md5()) != NULL)
            digest_nids[pos++] = EVP_MD_type(md);
        if ((md = digest_sha1()) != NULL)
            digest_nids[pos++] = EVP_MD_type(md);
        if ((md = digest_sha256()) != NULL)
            digest_nids[pos++] = EVP_MD_type(md);
        if ((md = digest_sha384()) != NULL)
            digest_nids[pos++] = EVP_MD_type(md);
        if ((md = digest_sha512()) != NULL)
            digest_nids[pos++] = EVP_MD_type(md);
        digest_nids[pos] = 0;
        init = 1;
    }
    *nids = digest_nids;
    return pos;
}

/* Setup RSA */

int ossltest_rsa_verify (int dtype, const unsigned char *m,
                       unsigned int m_length, const unsigned char *sigbuf,
                       unsigned int siglen, const RSA *rsa);

int ossltest_rsa_sign (int type,
                     const unsigned char *m, unsigned int m_length,
                     unsigned char *sigret, unsigned int *siglen,
                     const RSA *rsa);

struct rsa_meth_st {
    char *name;
    int (*rsa_pub_enc) (int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
    int (*rsa_pub_dec) (int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_enc) (int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_dec) (int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding);
    /* Can be null */
    int (*rsa_mod_exp) (BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);
    /* Can be null */
    int (*bn_mod_exp) (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
    /* called at new */
    int (*init) (RSA *rsa);
    /* called at free */
    int (*finish) (RSA *rsa);
    /* RSA_METHOD_FLAG_* things */
    int flags;
    /* may be needed! */
    char *app_data;
    /*
     * New sign and verify functions: some libraries don't allow arbitrary
     * data to be signed/verified: this allows them to be used. Note: for
     * this to work the RSA_public_decrypt() and RSA_private_encrypt() should
     * *NOT* be used RSA_sign(), RSA_verify() should be used instead.
     */
    int (*rsa_sign) (int type,
                     const unsigned char *m, unsigned int m_length,
                     unsigned char *sigret, unsigned int *siglen,
                     const RSA *rsa);
    int (*rsa_verify) (int dtype, const unsigned char *m,
                       unsigned int m_length, const unsigned char *sigbuf,
                       unsigned int siglen, const RSA *rsa);
    /*
     * If this callback is NULL, the builtin software RSA key-gen will be
     * used. This is for behavioural compatibility whilst the code gets
     * rewired, but one day it would be nice to assume there are no such
     * things as "builtin software" implementations.
     */
    int (*rsa_keygen) (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
};

static RSA_METHOD ossl_rsa = {
    "OpenSSL Test RSA method", //name
    NULL,   //rsa_pub_enc
    NULL,   //rsa_pub_dec
    NULL,   //rsa_priv_enc
    NULL,   //rsa_priv_dec
    NULL,   //rsa_mod_exp
    NULL,   //bn_mod_exp
    NULL,   //init
    NULL,   //finish
    0,      //flags
    NULL,   //app_data
    NULL,
    ossltest_rsa_verify,
    NULL    //rsa_keygen
};

/* RSA */

int ossltest_rsa_verify (int dtype, const unsigned char *m,
                       unsigned int m_length, const unsigned char *sigbuf,
                       unsigned int siglen, const RSA *rsa)
{
    return 1;
}

/* Setup ciphers */
static int ossltest_ciphers(ENGINE *, const EVP_CIPHER **,
                            const int **, int);

#define OSSLT_CIPHER_INIT_FUNCTION_NAME(ciphername) \
    ossltest_ ## ciphername ## _init_key
#define OSSLT_CIPHER_INIT_FUNCTION_DEC(ciphername) \
    int ossltest_ ## ciphername ## _init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, \
                             const unsigned char *iv, int enc);
#define OSSLT_CIPHER_INIT_FUNCTION_DEF(ciphername, cipherevp) \
    int ossltest_ ## ciphername ## _init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, \
                             const unsigned char *iv, int enc) \
    { \
        return EVP_CIPHER_meth_get_init( cipherevp () ) (ctx, key, iv, enc); \
    }
#define OSSLT_CIPHER_CIPHER_FUNCTION_NAME(ciphername) \
    ossltest_ ## ciphername ## _cipher
#define OSSLT_CIPHER_CIPHER_FUNCTION_DEC(ciphername) \
    int ossltest_ ## ciphername ## _cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, \
                                   const unsigned char *in, size_t inl);
#define OSSLT_CIPHER_CIPHER_FUNCTION_DEF(ciphername, cipherevp) \
    int ossltest_ ## ciphername ## _cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, \
                                   const unsigned char *in, size_t inl) \
    { \
        /* printf("Ciphering in " #ciphername "\n"); */	\
        unsigned char *tmpbuf;\
        int ret; \
        \
        tmpbuf = OPENSSL_malloc(inl);\
        if (tmpbuf == NULL)\
            return -1;\
        \
        /* Remember what we were asked to encrypt */\
        memcpy(tmpbuf, in, inl);\
        \
        /* Go through the motions of encrypting it */\
        ret = EVP_CIPHER_meth_get_do_cipher( cipherevp ())(ctx, out, in, inl);\
        \
        /* Throw it all away and just use the plaintext as the output */\
        memcpy(out, tmpbuf, inl);\
        OPENSSL_free(tmpbuf);\
        \
        if(ret == -1) \
            return 1; /* Everything is fine! */ \
        return ret;\
    }

#define OSSLT_CIPHER_SETUP_NAME(ciphername) ossltest_ ## ciphername

#define OSSLT_CIPHER_SETUP(ciphername, ciphernid, blocksize, ivlen, keylen, cipherflags, cipherevp) \
    static EVP_CIPHER * _hidden_ ## ciphername = NULL; \
    static const EVP_CIPHER * OSSLT_CIPHER_SETUP_NAME(ciphername) (void) \
    { \
        if (_hidden_ ## ciphername == NULL \
            && ((_hidden_ ## ciphername = EVP_CIPHER_meth_new(ciphernid, \
                                                           blocksize /* block size */, \
                                                           keylen /* key len */)) == NULL \
                || !EVP_CIPHER_meth_set_iv_length(_hidden_ ## ciphername , ivlen) \
                || !EVP_CIPHER_meth_set_flags(_hidden_ ## ciphername , \
                                              cipherflags) \
                || !EVP_CIPHER_meth_set_init(_hidden_ ## ciphername , \
                                              OSSLT_CIPHER_INIT_FUNCTION_NAME(ciphername)) \
                || !EVP_CIPHER_meth_set_do_cipher(_hidden_ ## ciphername , \
                                              OSSLT_CIPHER_CIPHER_FUNCTION_NAME(ciphername)) \
                || !EVP_CIPHER_meth_set_ctrl(_hidden_ ## ciphername, \
                                              EVP_CIPHER_meth_get_ctrl(cipherevp ())) \
                || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_ ## ciphername , \
                                              EVP_CIPHER_impl_ctx_size(cipherevp ())))) { \
            EVP_CIPHER_meth_free(_hidden_ ## ciphername ); \
            _hidden_ ## ciphername  = NULL; \
        } \
        return _hidden_ ## ciphername ; \
    } 


OSSLT_CIPHER_INIT_FUNCTION_DEC(aes128_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEC(aes128_cbc);
OSSLT_CIPHER_SETUP(aes128_cbc, NID_aes_128_cbc, 16, 16, 16, (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CBC_MODE), EVP_aes_128_cbc);

OSSLT_CIPHER_INIT_FUNCTION_DEC(aes256_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEC(aes256_cbc);
OSSLT_CIPHER_SETUP(aes256_cbc, NID_aes_256_cbc, 16, 16, 32, (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CBC_MODE), EVP_aes_256_cbc);

#define AEAD_FLAGS (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_FLAG_AEAD_CIPHER)

OSSLT_CIPHER_INIT_FUNCTION_DEC(aes128_gcm);
OSSLT_CIPHER_CIPHER_FUNCTION_DEC(aes128_gcm);
OSSLT_CIPHER_SETUP(aes128_gcm, NID_aes_128_gcm, 1, 16, 16, (AEAD_FLAGS | EVP_CIPH_GCM_MODE), EVP_aes_128_gcm);

OSSLT_CIPHER_INIT_FUNCTION_DEC(aes256_gcm);
OSSLT_CIPHER_CIPHER_FUNCTION_DEC(aes256_gcm);
OSSLT_CIPHER_SETUP(aes256_gcm, NID_aes_256_gcm, 1, 16, 32, (AEAD_FLAGS | EVP_CIPH_GCM_MODE), EVP_aes_256_gcm);

OSSLT_CIPHER_INIT_FUNCTION_DEC(aes128_ccm);
OSSLT_CIPHER_CIPHER_FUNCTION_DEC(aes128_ccm);
OSSLT_CIPHER_SETUP(aes128_ccm, NID_aes_128_ccm, 1, 16, 16, (AEAD_FLAGS | EVP_CIPH_CCM_MODE), EVP_aes_128_ccm);

OSSLT_CIPHER_INIT_FUNCTION_DEC(aes256_ccm);
OSSLT_CIPHER_CIPHER_FUNCTION_DEC(aes256_ccm);
OSSLT_CIPHER_SETUP(aes256_ccm, NID_aes_256_ccm, 1, 16, 32, (AEAD_FLAGS | EVP_CIPH_CCM_MODE), EVP_aes_256_ccm);

OSSLT_CIPHER_INIT_FUNCTION_DEC(camellia128_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEC(camellia128_cbc);
OSSLT_CIPHER_SETUP(camellia128_cbc, NID_camellia_128_cbc, 16, 16, 16, (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CBC_MODE), EVP_camellia_128_cbc);

OSSLT_CIPHER_INIT_FUNCTION_DEC(camellia256_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEC(camellia256_cbc);
OSSLT_CIPHER_SETUP(camellia256_cbc, NID_camellia_256_cbc, 16, 16, 32, (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CBC_MODE), EVP_camellia_256_cbc);

OSSLT_CIPHER_INIT_FUNCTION_DEC(seed128_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEC(seed128_cbc);
OSSLT_CIPHER_SETUP(seed128_cbc, NID_seed_cbc, 16, 16, 16, (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CBC_MODE), EVP_seed_cbc);

OSSLT_CIPHER_INIT_FUNCTION_DEC(idea_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEC(idea_cbc);
OSSLT_CIPHER_SETUP(idea_cbc, NID_idea_cbc, 8, 8, 16, (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CBC_MODE), EVP_idea_cbc);

OSSLT_CIPHER_INIT_FUNCTION_DEC(des_ede_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEC(des_ede_cbc);
OSSLT_CIPHER_SETUP(des_ede_cbc, NID_des_ede3_cbc, 8, 8, 24, (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CBC_MODE), EVP_des_ede3_cbc);


#define OSSLT_CIPHER_DESTROY(ciphername) \
    EVP_CIPHER_meth_free(_hidden_ ## ciphername); \
    _hidden_ ## ciphername = NULL;


static void destroy_ciphers(void)
{
    OSSLT_CIPHER_DESTROY(aes128_cbc);
    OSSLT_CIPHER_DESTROY(aes256_cbc);
    OSSLT_CIPHER_DESTROY(aes128_gcm);
    OSSLT_CIPHER_DESTROY(aes256_gcm);
    OSSLT_CIPHER_DESTROY(aes128_ccm);
    OSSLT_CIPHER_DESTROY(aes256_ccm);
    OSSLT_CIPHER_DESTROY(camellia128_cbc);
    OSSLT_CIPHER_DESTROY(camellia256_cbc);
    OSSLT_CIPHER_DESTROY(seed128_cbc);
    OSSLT_CIPHER_DESTROY(idea_cbc);
    OSSLT_CIPHER_DESTROY(des_ede_cbc);
}

static int bind_ossltest(ENGINE *e)
{
    /* Ensure the ossltest error handling is set up */
  //    ERR_load_OSSLTEST_strings();

    if (!ENGINE_set_id(e, engine_ossltest_id)
        || !ENGINE_set_name(e, engine_ossltest_name)
        || !ENGINE_set_digests(e, ossltest_digests)
        || !ENGINE_set_ciphers(e, ossltest_ciphers)
        || !ENGINE_set_RSA(e, &ossl_rsa)
        || !ENGINE_set_destroy_function(e, ossltest_destroy)
        || !ENGINE_set_init_function(e, ossltest_init)
        || !ENGINE_set_finish_function(e, ossltest_finish)) {
        OSSLTESTerr(OSSLTEST_F_BIND_OSSLTEST, OSSLTEST_R_INIT_FAILED);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_ossltest_id) != 0))
        return 0;
    if (!bind_ossltest(e))
        return 0;

    const RSA_METHOD *meth1;
    meth1 = RSA_PKCS1_OpenSSL();
    ossl_rsa.rsa_pub_enc = meth1->rsa_pub_enc;
    ossl_rsa.rsa_pub_dec = meth1->rsa_pub_dec;
    ossl_rsa.rsa_priv_enc = meth1->rsa_priv_enc;
    ossl_rsa.rsa_priv_dec = meth1->rsa_priv_dec;
    ossl_rsa.rsa_mod_exp = meth1->rsa_mod_exp;
    ossl_rsa.bn_mod_exp = meth1->bn_mod_exp;
    ossl_rsa.init = meth1->init;
    ossl_rsa.finish = meth1->finish;

    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif

static ENGINE *engine_ossltest(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_ossltest(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_ossltest(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_ossltest();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}


static int ossltest_init(ENGINE *e)
{
    return 1;
}


static int ossltest_finish(ENGINE *e)
{
    return 1;
}


static int ossltest_destroy(ENGINE *e)
{
    destroy_digests();
    destroy_ciphers();
    ERR_unload_OSSLTEST_strings();
    return 1;
}

static int ossltest_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!digest) {
        /* We are returning a list of supported nids */
        return ossltest_digest_nids(nids);
    }
    /* We are being asked for a specific digest */
    switch (nid) {
    case NID_md5:
        *digest = digest_md5();
        break;
    case NID_sha1:
        *digest = digest_sha1();
        break;
    case NID_sha256:
        *digest = digest_sha256();
        break;
    case NID_sha384:
        *digest = digest_sha384();
        break;
    case NID_sha512:
        *digest = digest_sha512();
        break;
    default:
        ok = 0;
        *digest = NULL;
        break;
    }
    return ok;
}

static int ossltest_cipher_nids[] = {
    NID_aes_128_cbc, NID_aes_256_cbc, 
    NID_aes_128_ccm, NID_aes_256_ccm,
    NID_aes_128_gcm, NID_aes_256_gcm,
    NID_camellia_128_cbc, NID_camellia_256_cbc,
    NID_seed_cbc,
    NID_idea_cbc,
    NID_des_ede3_cbc,    
    0
};

static int ossltest_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = ossltest_cipher_nids;
        return (sizeof(ossltest_cipher_nids) - 1)
               / sizeof(ossltest_cipher_nids[0]);
    }
    /* We are being asked for a specific cipher */
    switch (nid) {
    case NID_aes_128_cbc:
        *cipher = OSSLT_CIPHER_SETUP_NAME(aes128_cbc) ();
        break;
    case NID_aes_256_cbc:
        *cipher = OSSLT_CIPHER_SETUP_NAME(aes256_cbc) ();
        break;
    case NID_aes_128_ccm:
        *cipher = OSSLT_CIPHER_SETUP_NAME(aes128_ccm) ();
        break;
    case NID_aes_256_ccm:
        *cipher = OSSLT_CIPHER_SETUP_NAME(aes256_ccm) ();
        break;
    case NID_aes_128_gcm:
        *cipher = OSSLT_CIPHER_SETUP_NAME(aes128_gcm) ();
        break;
    case NID_aes_256_gcm:
        *cipher = OSSLT_CIPHER_SETUP_NAME(aes256_gcm) ();
        break;
    case NID_camellia_128_cbc:
        *cipher = OSSLT_CIPHER_SETUP_NAME(camellia128_cbc) ();
        break;
    case NID_camellia_256_cbc:
        *cipher = OSSLT_CIPHER_SETUP_NAME(camellia256_cbc) ();
        break;
    case NID_seed_cbc:
        *cipher = OSSLT_CIPHER_SETUP_NAME(seed128_cbc) ();
        break;
    case NID_idea_cbc:
        *cipher = OSSLT_CIPHER_SETUP_NAME(idea_cbc) ();
        break;
    case NID_des_ede3_cbc:
        *cipher = OSSLT_CIPHER_SETUP_NAME(des_ede_cbc) ();
        break;
    default:
        ok = 0;
        *cipher = NULL;
        break;
    }
    return ok;
}

static void fill_known_data(unsigned char *md, unsigned int len)
{
    unsigned int i;

    for (i=0; i<len; i++) {
        md[i] = (unsigned char)(i & 0xff);
    }
}

/*
 * MD5 implementation. We go through the motions of doing MD5 by deferring to
 * the standard implementation. Then we overwrite the result with a will defined
 * value, so that all "MD5" digests using the test engine always end up with
 * the same value.
 */
#undef data
#define data(ctx) ((MD5_CTX *)EVP_MD_CTX_md_data(ctx))
static int digest_md5_init(EVP_MD_CTX *ctx)
{
    return MD5_Init(data(ctx));
}

static int digest_md5_update(EVP_MD_CTX *ctx, const void *data,
                             size_t count)
{
    return MD5_Update(data(ctx), data, (size_t)count);
}

static int digest_md5_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = MD5_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, MD5_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * SHA1 implementation.
 */
#undef data
#define data(ctx) ((SHA_CTX *)EVP_MD_CTX_md_data(ctx))
static int digest_sha1_init(EVP_MD_CTX *ctx)
{
    return SHA1_Init(data(ctx));
}

static int digest_sha1_update(EVP_MD_CTX *ctx, const void *data,
                              size_t count)
{
    return SHA1_Update(data(ctx), data, (size_t)count);
}

static int digest_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = SHA1_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, SHA_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * SHA256 implementation.
 */
#undef data
#define data(ctx) ((SHA256_CTX *)EVP_MD_CTX_md_data(ctx))
static int digest_sha256_init(EVP_MD_CTX *ctx)
{
    return SHA256_Init(data(ctx));
}

static int digest_sha256_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count)
{
    return SHA256_Update(data(ctx), data, (size_t)count);
}

static int digest_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = SHA256_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, SHA256_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * SHA384/512 implementation.
 */
#undef data
#define data(ctx) ((SHA512_CTX *)EVP_MD_CTX_md_data(ctx))
static int digest_sha384_init(EVP_MD_CTX *ctx)
{
    return SHA384_Init(data(ctx));
}

static int digest_sha512_init(EVP_MD_CTX *ctx)
{
    return SHA512_Init(data(ctx));
}

static int digest_sha512_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count)
{
    return SHA512_Update(data(ctx), data, (size_t)count);
}

static int digest_sha384_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    /* Actually uses SHA512_Final! */
    ret = SHA512_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, SHA384_DIGEST_LENGTH);
    }
    return ret;
}

static int digest_sha512_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = SHA512_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, SHA512_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * Cipher Implementations
 */

OSSLT_CIPHER_INIT_FUNCTION_DEF(aes128_cbc, EVP_aes_128_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEF(aes128_cbc, EVP_aes_128_cbc);
OSSLT_CIPHER_INIT_FUNCTION_DEF(aes256_cbc, EVP_aes_256_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEF(aes256_cbc, EVP_aes_256_cbc);

OSSLT_CIPHER_INIT_FUNCTION_DEF(aes128_gcm, EVP_aes_128_gcm);
OSSLT_CIPHER_CIPHER_FUNCTION_DEF(aes128_gcm, EVP_aes_128_gcm);
OSSLT_CIPHER_INIT_FUNCTION_DEF(aes256_gcm, EVP_aes_256_gcm);
OSSLT_CIPHER_CIPHER_FUNCTION_DEF(aes256_gcm, EVP_aes_256_gcm);

OSSLT_CIPHER_INIT_FUNCTION_DEF(aes128_ccm, EVP_aes_128_ccm);
OSSLT_CIPHER_CIPHER_FUNCTION_DEF(aes128_ccm, EVP_aes_128_ccm);
OSSLT_CIPHER_INIT_FUNCTION_DEF(aes256_ccm, EVP_aes_256_ccm);
OSSLT_CIPHER_CIPHER_FUNCTION_DEF(aes256_ccm, EVP_aes_256_ccm);

OSSLT_CIPHER_INIT_FUNCTION_DEF(camellia128_cbc, EVP_camellia_128_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEF(camellia128_cbc, EVP_camellia_128_cbc);
OSSLT_CIPHER_INIT_FUNCTION_DEF(camellia256_cbc, EVP_camellia_256_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEF(camellia256_cbc, EVP_camellia_256_cbc);

OSSLT_CIPHER_INIT_FUNCTION_DEF(seed128_cbc, EVP_seed_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEF(seed128_cbc, EVP_seed_cbc);

OSSLT_CIPHER_INIT_FUNCTION_DEF(idea_cbc, EVP_idea_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEF(idea_cbc, EVP_idea_cbc);

OSSLT_CIPHER_INIT_FUNCTION_DEF(des_ede_cbc, EVP_des_ede3_cbc);
OSSLT_CIPHER_CIPHER_FUNCTION_DEF(des_ede_cbc, EVP_des_ede3_cbc);
