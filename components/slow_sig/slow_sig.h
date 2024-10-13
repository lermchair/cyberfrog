#pragma once
#include "mbedtls/ctr_drbg.h"
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>

int rsa_init(mbedtls_pk_context *key, mbedtls_ctr_drbg_context *ctr_drbg,
             mbedtls_entropy_context *entropy);
unsigned char *generate_rsa_pem_key(mbedtls_pk_context *key,
                                    mbedtls_ctr_drbg_context *ctr_drbg);
int load_rsa_key(mbedtls_pk_context *key, unsigned char *pem_key,
                 size_t pem_key_size);
char *rsa_sign_to_base64(mbedtls_pk_context *key,
                         mbedtls_ctr_drbg_context *ctr_drbg,
                         unsigned char *message, size_t message_len);
int rsa_verify_signature(mbedtls_pk_context *key, const unsigned char *message,
                         size_t message_len, const unsigned char *signature,
                         size_t signature_len);
// *); void rsa_cleanup(struct rsa_config *);
