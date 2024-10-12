#include "slow_sig.h"
#include "utils.h"
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <stdio.h>
#include <string.h>

int rsa_init(mbedtls_pk_context *key, mbedtls_ctr_drbg_context *ctr_drbg,
             mbedtls_entropy_context *entropy) {
  mbedtls_pk_init(key);
  mbedtls_ctr_drbg_init(ctr_drbg);
  mbedtls_entropy_init(entropy);

  const char *pers = "rsa_genkey";
  int mbedtls_ret =
      mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                            (const unsigned char *)pers, strlen(pers));
  if (mbedtls_ret != 0) {
    printf("mbedtls_ctr_drbg_seed returned -0x%04x\n", -mbedtls_ret);
    return -1;
  }
  return 0;
}

unsigned char *generate_rsa_pem_key(mbedtls_pk_context *key,
                                    mbedtls_ctr_drbg_context *ctr_drbg) {
  int mbedtls_ret;
  unsigned char *pem_key = NULL;
  size_t pem_key_size = 1680;

  pem_key = malloc(pem_key_size);

  if (pem_key == NULL) {
    printf("Failed to allocate memory for pem_key\n");
    return NULL;
  }
  mbedtls_ret =
      mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (mbedtls_ret != 0) {
    printf("mbedtls_pk_setup returned -0x%04xn=\n", -mbedtls_ret);
    free(pem_key);
    return NULL;
  };

  printf("Generating RSA key pair...\n");
  mbedtls_ret = mbedtls_rsa_gen_key(
      mbedtls_pk_rsa(*key), mbedtls_ctr_drbg_random, ctr_drbg, 2048, 65537);
  if (mbedtls_ret != 0) {
    printf("mbedtls_rsa_gen_key returned -0x%04x", -mbedtls_ret);
    free(pem_key);
    return NULL;
  }

  printf("RSA key pair generated successfully.\n");

  memset(pem_key, 0, pem_key_size);
  mbedtls_ret = mbedtls_pk_write_key_pem(key, pem_key, pem_key_size);
  if (mbedtls_ret != 0) {
    printf("mbedtls_pk_write_key_pem returned -0x%04x\n", -mbedtls_ret);
    free(pem_key);
    return NULL;
  }
  printf("Private key exported in PEM format.\n");
  return pem_key;
}

int load_rsa_key(mbedtls_pk_context *key, unsigned char *pem_key,
                 size_t pem_key_size) {
  int mbedtls_ret =
      mbedtls_pk_parse_key(key, pem_key, pem_key_size, NULL, 0, NULL, NULL);
  if (mbedtls_ret != 0) {
    printf("mbedtls_pk_parse_key returned -0x%04x\n", -mbedtls_ret);
    return -1;
  }
  printf("Private key imported back into mbedtls.\n");
  return 0;
}

char *rsa_sign_to_base64(mbedtls_pk_context *key,
                         mbedtls_ctr_drbg_context *ctr_drbg,
                         unsigned char *message) {
  size_t hash_len = 32;
  unsigned char hash[hash_len];
  unsigned char signature[MBEDTLS_MPI_MAX_SIZE];
  size_t signature_len;

  mbedtls_md_context_t md_ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);

  if (md_info == NULL) {
    printf("Failed to get md_info for md_type %d\n", md_type);
    return NULL;
  }

  mbedtls_md_init(&md_ctx);
  int mbedtls_ret = mbedtls_md_setup(&md_ctx, md_info, 0);
  if (mbedtls_ret != 0) {
    printf("mbedtls_md_setup returned -0x%04x\n", -mbedtls_ret);
    return NULL;
  }
  mbedtls_ret = mbedtls_md(md_info, message, hash_len, hash);
  if (mbedtls_ret != 0) {
    printf("mbedtls_md returned -0x%04x\n", -mbedtls_ret);
    return NULL;
  }

  mbedtls_md_free(&md_ctx);

  mbedtls_ret = mbedtls_pk_sign(key, md_type, hash, sizeof(hash), signature,
                                sizeof(signature), &signature_len,
                                mbedtls_ctr_drbg_random, ctr_drbg);
  if (mbedtls_ret != 0) {
    printf("mbedtls_pk_sign returned -0x%04x", -mbedtls_ret);
    return NULL;
  }

  size_t b64_len = ((signature_len + 2) / 3) * 4 + 1; // +1 for null
  char *b64_signature = malloc(b64_len);
  if (b64_signature == NULL) {
    printf("Failed to allocate memory for b64_signature\n");
    return NULL;
  }

  signature_to_base64(signature, signature_len, b64_signature, b64_len);

  return b64_signature;
}

// void rsa_cleanup(struct rsa_config *config) {
//   mbedtls_rsa_free(config->rsa);
//   mbedtls_ctr_drbg_free(config->ctr_drbg);
//   mbedtls_entropy_free(config->entropy);
//   free(config->rsa);
//   free(config->ctr_drbg);
//   free(config->entropy);
//   free(config);
// }
