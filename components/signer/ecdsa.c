#include "ecdsa.h"
#include "mbedtls/ecdsa.h"
#include <mbedtls/error.h>
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
  if ((ret = mbedtls_ecp_read_key(ECPARAMS, ctx, pkey, sizeof(pkey)))) {
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

  ret = mbedtls_ecp_point_write_binary(
      &ctx->MBEDTLS_PRIVATE(grp), &ctx->MBEDTLS_PRIVATE(Q),
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

char *ecdsa_sign_raw(mbedtls_ecdsa_context *ctx,
                     mbedtls_ctr_drbg_context *ctr_drbg,
                     const unsigned char *message, size_t message_len,
                     int recovery_id) {
  int ret;
  size_t hash_len = 32;
  unsigned char padded_message[32] = {0}; // Initialize with zeros
  unsigned char hash[hash_len];
  mbedtls_mpi r, s, k, e, k_inv, n2, tmp;
  mbedtls_ecp_point R;
  mbedtls_ecp_point Q;
  unsigned char buf[64]; // 1 byte for recid, 64 bytes for r and s
  char *hex_sig = NULL;  // Initialize to NULL

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

  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&k);
  mbedtls_mpi_init(&e);
  mbedtls_mpi_init(&k_inv);
  mbedtls_mpi_init(&n2);
  mbedtls_mpi_init(&tmp);
  mbedtls_ecp_point_init(&R);
  mbedtls_ecp_point_init(&Q);

  mbedtls_ecp_group *grp = &ctx->MBEDTLS_PRIVATE(grp);

  // Generate ephemeral key k
  if ((ret = mbedtls_ecp_gen_privkey(grp, &k, mbedtls_ctr_drbg_random,
                                     ctr_drbg)) != 0) {
    printf(" failed\n  ! mbedtls_ecp_gen_privkey returned -0x%04x\n", -ret);
    goto cleanup;
  }

  // Compute R = k * G
  if ((ret = mbedtls_ecp_mul(grp, &R, &k, &grp->G, mbedtls_ctr_drbg_random,
                             ctr_drbg)) != 0) {
    printf(" failed\n  ! mbedtls_ecp_mul returned -0x%04x\n", -ret);
    goto cleanup;
  }

  // Compute r = R.x mod n
  if ((ret = mbedtls_mpi_mod_mpi(&r, &R.MBEDTLS_PRIVATE(X), &grp->N)) != 0) {
    printf(" failed\n  ! mbedtls_mpi_mod_mpi returned -0x%04x\n", -ret);
    goto cleanup;
  }

  // Compute e = hash as mpi
  if ((ret = mbedtls_mpi_read_binary(&e, hash, hash_len)) != 0) {
    printf(" failed\n  ! mbedtls_mpi_read_binary returned -0x%04x\n", -ret);
    goto cleanup;
  }

  // Compute k_inv = k^-1 mod n
  if ((ret = mbedtls_mpi_inv_mod(&k_inv, &k, &grp->N)) != 0) {
    printf(" failed\n  ! mbedtls_mpi_inv_mod returned -0x%04x\n", -ret);
    goto cleanup;
  }

  // Compute tmp = (e + r*d) mod n
  if ((ret = mbedtls_mpi_mul_mpi(&tmp, &r, &ctx->MBEDTLS_PRIVATE(d))) != 0) {
    printf(" failed\n  ! mbedtls_mpi_mul_mpi returned -0x%04x\n", -ret);
    goto cleanup;
  }
  if ((ret = mbedtls_mpi_add_mpi(&tmp, &tmp, &e)) != 0) {
    printf(" failed\n  ! mbedtls_mpi_add_mpi returned -0x%04x\n", -ret);
    goto cleanup;
  }
  if ((ret = mbedtls_mpi_mod_mpi(&tmp, &tmp, &grp->N)) != 0) {
    printf(" failed\n  ! mbedtls_mpi_mod_mpi returned -0x%04x\n", -ret);
    goto cleanup;
  }

  // Compute s = k_inv * tmp mod n
  if ((ret = mbedtls_mpi_mul_mpi(&s, &k_inv, &tmp)) != 0) {
    printf(" failed\n  ! mbedtls_mpi_mul_mpi returned -0x%04x\n", -ret);
    goto cleanup;
  }
  if ((ret = mbedtls_mpi_mod_mpi(&s, &s, &grp->N)) != 0) {
    printf(" failed\n  ! mbedtls_mpi_mod_mpi returned -0x%04x\n", -ret);
    goto cleanup;
  }

  // Compute id = y1 & 1
  recovery_id = mbedtls_mpi_get_bit(&R.MBEDTLS_PRIVATE(Y), 0);

  // Compute n2 = n / 2
  if ((ret = mbedtls_mpi_copy(&n2, &grp->N)) != 0) {
    printf(" failed\n  ! mbedtls_mpi_copy returned -0x%04x\n", -ret);
    goto cleanup;
  }
  if ((ret = mbedtls_mpi_shift_r(&n2, 1)) != 0) { // n2 = n >> 1
    printf(" failed\n  ! mbedtls_mpi_shift_r returned -0x%04x\n", -ret);
    goto cleanup;
  }

  // If s > n/2, s = n - s, id ^= 1
  if (mbedtls_mpi_cmp_mpi(&s, &n2) > 0) {
    if ((ret = mbedtls_mpi_sub_mpi(&s, &grp->N, &s)) != 0) {
      printf(" failed\n  ! mbedtls_mpi_sub_mpi returned -0x%04x\n", -ret);
      goto cleanup;
    }
    recovery_id ^= 1;
  }

  // Ensure r and s are 32 bytes each
  memset(buf, 0, sizeof(buf));

  printf("Recovery ID: %d\n", recovery_id);

  // Write r and s to buf
  if ((ret = mbedtls_mpi_write_binary(&r, buf, 32)) != 0) {
    printf(" failed\n  ! mbedtls_mpi_write_binary for r returned -0x%04x\n",
           -ret);
    goto cleanup;
  }

  if ((ret = mbedtls_mpi_write_binary(&s, buf + 32, 32)) != 0) {
    printf(" failed\n  ! mbedtls_mpi_write_binary for s returned -0x%04x\n",
           -ret);
    goto cleanup;
  }

  // Convert the signature to hex string
  hex_sig = binary_to_hex(buf, 64);
  if (hex_sig == NULL) {
    printf(" failed\n  ! binary_to_hex returned NULL\n");
    goto cleanup;
  }

  ret = mbedtls_ecdsa_verify(grp, hash, sizeof(hash), &ctx->MBEDTLS_PRIVATE(Q),
                             &r, &s);
  if (ret != 0) {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    printf("Signature verification failed: %s\n", error_buf);
    return NULL;
  } else {
    printf("Signature verified successfully\n");
  }

  printf("Encoded Signature with Recovery ID: %s\n", hex_sig);

cleanup:
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&k);
  mbedtls_mpi_free(&e);
  mbedtls_mpi_free(&k_inv);
  mbedtls_mpi_free(&n2);
  mbedtls_mpi_free(&tmp);
  mbedtls_ecp_point_free(&R);

  return hex_sig;
}
