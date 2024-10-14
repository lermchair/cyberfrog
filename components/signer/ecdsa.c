#include "ecdsa.h"
#include "mbedtls/ecp.h"
#include <stdio.h>
#include <string.h>

int ecdsa_init(mbedtls_ecdsa_context *ctx, mbedtls_ctr_drbg_context *ctr_drbg,
               mbedtls_entropy_context *entropy) {
  mbedtls_ecdsa_init(ctx);
  mbedtls_ctr_drbg_init(ctr_drbg);
  mbedtls_entropy_init(entropy);

  const char *pers = "ecdsa";
  int ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                                  (const unsigned char *)pers, strlen(pers));
  if (ret != 0) {
    printf("mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
    return -1;
  }
  return 0;
}

int load_ecdsa_key(mbedtls_ecdsa_context *ctx,
                   mbedtls_ctr_drbg_context *ctr_drbg, unsigned char *pkey) {
  int ret;
  if ((ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, ctx, pkey,
                                  sizeof(pkey)))) {
    printf("failed\n  ! mbedtls_ecp_read_key returned -0x%04x\n", -ret);
    return NULL;
  }
  if ((ret = mbedtls_ecp_keypair_calc_public(ctx, mbedtls_ctr_drbg_random,
                                             ctr_drbg))) {
    printf("failed\n  ! mbedtls_ecp_keypair_calc_public returned -0x%04x\n",
           -ret);
    return NULL;
  }
  printf("Load ECDSA key success\n");
  return 0;
}

char *get_ecdsa_public_key(mbedtls_ecdsa_context *ctx) {
    unsigned char buf[300];
    size_t len;
    int ret;

    ret = mbedtls_ecp_point_write_binary(&ctx->MBEDTLS_PRIVATE(grp), &ctx->MBEDTLS_PRIVATE(Q),
                                         MBEDTLS_ECP_PF_COMPRESSED, &len, buf, sizeof(buf));
    if (ret != 0) {
        printf("Failed to write public key: -0x%04x\n", -ret);
        return NULL;
    }

    // Convert the binary public key to a hex string
    char *pubkey_hex = binary_to_hex(buf, len);
    if (pubkey_hex == NULL) {
        printf("Failed to convert public key to hex\n");
        return NULL;
    }

    return pubkey_hex;
}

char *generate_ecdsa_key(mbedtls_ecdsa_context *ctx,
                         mbedtls_ctr_drbg_context *ctr_drbg) {
  int ret;
  if ((ret = mbedtls_ecdsa_genkey(ctx, ECPARAMS, mbedtls_ctr_drbg_random,
                                  ctr_drbg)) != 0) {
    printf(" failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret);
    return NULL;
  }
  mbedtls_ecp_group_id grp_id = mbedtls_ecp_keypair_get_group_id(ctx);
  const mbedtls_ecp_curve_info *curve_info =
      mbedtls_ecp_curve_info_from_grp_id(grp_id);
  printf(" ok (key size: %d bits)\n", (int)curve_info->bit_size);

  unsigned char buf[300];
  size_t len;

  if (mbedtls_ecp_write_public_key(ctx, MBEDTLS_ECP_PF_COMPRESSED, &len, buf,
                                   sizeof(buf)) != 0) {
    printf("internal error\n");
    return NULL;
  }

  char *pubkey = binary_to_hex(buf, len);
  printf("Public key: %s\n", pubkey);
  return pubkey;
}

int ecdsa_verify_signature(mbedtls_ecdsa_context *ctx,
                           const unsigned char *message, size_t message_len,
                           const unsigned char *sig, size_t sig_len) {
  int ret;
  if ((ret = mbedtls_ecdsa_read_signature(ctx, message, message_len, sig,
                                          sig_len)) != 0) {
    printf(" failed\n  ! mbedtls_ecdsa_read_signature returned -0x%04x\n",
           -ret);
    return NULL;
  }
  return ret;
}

char *ecdsa_sign_to_base64(mbedtls_ecdsa_context *ctx,
                        mbedtls_ctr_drbg_context *ctr_drbg,
                        const unsigned char *message, size_t message_len) {
  int ret;
  size_t hash_len = 32;
  unsigned char padded_message[32] = {0}; // Initialize with zeros
  unsigned char hash[hash_len];
  unsigned char signature[MBEDTLS_ECDSA_MAX_SIG_LEN(256)];
  size_t signature_len;

  if (message_len > 32) {
    printf("Error: Message length exceeds 32 bytes\n");
    return NULL;
  }
  memcpy(padded_message, message, message_len);

  printf("Message: %s\n", binary_to_hex(padded_message, message_len));

  if ((ret = mbedtls_sha256(padded_message, hash_len, hash, 0)) != 0) {
    printf(" failed\n  ! mbedtls_sha256 returned %d\n", ret);
    return NULL;
  }

  printf("Message hash: %s\n", binary_to_hex(hash, hash_len));

  if ((ret = mbedtls_ecdsa_write_signature(
           ctx, MBEDTLS_MD_SHA256, hash, sizeof(hash), signature,
           sizeof(signature), &signature_len, mbedtls_ctr_drbg_random,
           ctr_drbg)) != 0) {
    printf(" failed\n  ! mbedtls_ecdsa_write_signature returned -0x%04x\n",
           -ret);
    return NULL;
  }

  char *hex_sig = binary_to_hex(signature, signature_len);
  printf("Signature: %s\n", hex_sig);
  int valid =
      ecdsa_verify_signature(ctx, hash, hash_len, signature, signature_len);
  if (valid != 0) {
    printf("Signature verification failed\n");
    return NULL;
  }
  return hex_sig;
  // TODO: convert to base64
}
