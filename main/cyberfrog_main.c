#include "esp_ds.h"
#include "esp_log.h"
#include "esp_system.h"
#include "slow_sig.h"
#include <mbedtls/sha256.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Atomic uint_least32_t nonce = 0;

uint32_t get_nonce() { return atomic_fetch_add(&nonce, 1); }

void signature_to_hex(const unsigned char *signature, size_t sig_len,
                      char *hex_output, size_t hex_len) {
  static const char hex_chars[] = "0123456789ABCDEF";

  if (hex_len < (sig_len * 2 + 1)) {
    // Not enough space in output buffer
    hex_output[0] = '\0';
    return;
  }

  for (size_t i = 0; i < sig_len; i++) {
    hex_output[i * 2] = hex_chars[(signature[i] >> 4) & 0x0F];
    hex_output[i * 2 + 1] = hex_chars[signature[i] & 0x0F];
  }
  hex_output[sig_len * 2] = '\0'; // Null-terminate the string
}

void app_main(void) {
  uint32_t nonce = get_nonce();
  printf("Nonce: %ld\n", nonce);

  int ret;
  unsigned char sig_buf[512];
  unsigned char hash[32];

#ifdef CONFIG_EFUSE_RSA_SIG
  printf("Nah, not implemented\n");
  return;
#else
  printf("Generating keypair...\n");
  struct rsa_config *config = generate_keypair();
  printf("Hashing nonce...\n");
  memcpy(hash, &nonce, sizeof(nonce));

  unsigned char input[sizeof(uint32_t)];

  input[0] = (nonce >> 24) & 0xFF;
  input[1] = (nonce >> 16) & 0xFF;
  input[2] = (nonce >> 8) & 0xFF;
  input[3] = nonce & 0xFF;

  mbedtls_sha256(input, sizeof(uint32_t), hash, 0);
  printf("Signing hash...\n");
  ret = rsa_sign(config, hash, sig_buf);

  size_t sig_len = mbedtls_rsa_get_len(config->rsa);

  char hex_signature[1025]; // 512 bytes * 2 + 1 for null terminator
  signature_to_hex(sig_buf, sig_len, hex_signature, sizeof(hex_signature));

  printf("Signature (hex): %s\n", hex_signature);

  printf("Verification link: https://zupass.org/verify?sig=%s&nonce=%lu\n",
         hex_signature, nonce);

#endif
  // rsa_cleanup(config);
}
