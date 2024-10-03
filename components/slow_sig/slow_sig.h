#pragma once
#include "mbedtls/ctr_drbg.h"
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>

struct rsa_config {
  mbedtls_rsa_context *rsa;
  mbedtls_ctr_drbg_context *ctr_drbg;
  mbedtls_entropy_context *entropy;
};

struct rsa_config *generate_keypair(void);
unsigned char *rsa_sign(struct rsa_config *, unsigned char *, unsigned char *);
void rsa_cleanup(struct rsa_config *);