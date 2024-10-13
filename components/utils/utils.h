#pragma once
#include <driver/gpio.h>
#include <nvs.h>
#include <st25dv.h>
#include <st25dv_ndef.h>
#include <stdint.h>
#include <mbedtls/pk.h>

typedef esp_err_t (*nvs_item_exists_callback)(nvs_handle_t handle,
                                              const char *key, void *output);
typedef esp_err_t (*nvs_item_not_exists_callback)(nvs_handle_t handle,
                                                  const char *key,
                                                  void *output);

void signature_to_hex(const unsigned char *signature, size_t sig_len,
                      char *hex_output, size_t hex_len);

void signature_to_base64(const unsigned char *signature, size_t sig_len,
                         char *base64_output, size_t out_len);

esp_err_t configure_and_set_gpio_high(int pin);

char *format_url_safely(const char *hex_signature);
esp_err_t nvs_check_and_do(const char *namespace, const char *key, void *output,
                           nvs_item_exists_callback exists_cb,
                           nvs_item_not_exists_callback not_exists_cb);

void uint32_to_char(uint32_t num, unsigned char *output);

int get_public_key(mbedtls_pk_context *pk,  char *output, size_t output_size);
