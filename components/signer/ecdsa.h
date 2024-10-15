#pragma once
#include "utils.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

#define ECPARAMS MBEDTLS_ECP_DP_SECP256K1

int ecdsa_init(mbedtls_ecdsa_context *ctx, mbedtls_ctr_drbg_context *ctr_drbg,
               mbedtls_entropy_context *entropy);

char *generate_ecdsa_key(mbedtls_ecdsa_context *ctx,
                         mbedtls_ctr_drbg_context *ctr_drbg);

char *ecdsa_sign_raw(mbedtls_ecdsa_context *ctx,
                     mbedtls_ctr_drbg_context *ctr_drbg,
                     const unsigned char *message, size_t message_len,
                     int recovery_id);

int ecdsa_verify_signature(mbedtls_ecdsa_context *ctx,
                           const unsigned char *message, size_t message_len,
                           const unsigned char *sig, size_t sig_len);

int load_ecdsa_key(mbedtls_ecdsa_context *ctx,
                   mbedtls_ctr_drbg_context *ctr_drbg, unsigned char *pkey);

char *get_ecdsa_public_key(mbedtls_ecdsa_context *ctx);
