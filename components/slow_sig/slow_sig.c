#include "slow_sig.h"
#include "esp_log.h"
#include "esp_system.h"
#include <stdio.h>
#include <string.h>

struct rsa_config *generate_keypair(void) {
  struct rsa_config *config = malloc(sizeof(struct rsa_config));
  if (config == NULL) {
    printf("Failed to allocate memory for config\n");
    return NULL;
  }

  config->rsa = malloc(sizeof(mbedtls_rsa_context));
  config->ctr_drbg = malloc(sizeof(mbedtls_ctr_drbg_context));
  config->entropy = malloc(sizeof(mbedtls_entropy_context));

  if (config->rsa == NULL || config->ctr_drbg == NULL ||
      config->entropy == NULL) {
    printf("Failed to allocate memory for mbedtls contexts\n");
    free(config->rsa);
    free(config->ctr_drbg);
    free(config->entropy);
    free(config);
    return NULL;
  }

  mbedtls_rsa_init(config->rsa);
  mbedtls_ctr_drbg_init(config->ctr_drbg);
  mbedtls_entropy_init(config->entropy);

  const char *pers = "rsa_encrypt_decrypt";

  int ret = mbedtls_ctr_drbg_seed(config->ctr_drbg, mbedtls_entropy_func,
                                  config->entropy, (const unsigned char *)pers,
                                  strlen(pers));
  if (ret != 0) {
    printf("Failed to seed the random number generator: %d\n", ret);
    rsa_cleanup(config);
    return NULL;
  }

  ret = mbedtls_rsa_gen_key(config->rsa, mbedtls_ctr_drbg_random,
                            config->ctr_drbg, 2048, 65537);
  if (ret != 0) {
    printf("Failed to generate RSA keypair: %d\n", ret);
    rsa_cleanup(config);
    return NULL;
  }

  printf("RSA keypair generated successfully\n");
  return config;
}

unsigned char *rsa_sign(struct rsa_config *config, unsigned char *hash,
                        unsigned char *sig_buf) {

  ESP_ERROR_CHECK(mbedtls_rsa_pkcs1_sign(config->rsa, mbedtls_ctr_drbg_random,
                                         config->ctr_drbg, MBEDTLS_MD_SHA256,
                                         32, hash, sig_buf));
  return sig_buf;
}

void rsa_cleanup(struct rsa_config *config) {
  mbedtls_rsa_free(config->rsa);
  mbedtls_ctr_drbg_free(config->ctr_drbg);
  mbedtls_entropy_free(config->entropy);
  free(config->rsa);
  free(config->ctr_drbg);
  free(config->entropy);
  free(config);
}
