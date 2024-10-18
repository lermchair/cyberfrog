#include "utils.h"
#include "driver/ledc.h"
#include "mbedtls/base64.h"
#include <mbedtls/pk.h>
#include <string.h>

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

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void signature_to_base64(const unsigned char *signature, size_t sig_len,
                         char *base64_output, size_t out_len) {
  size_t i, j;
  uint32_t octet_a, octet_b, octet_c, triple;
  printf("Debug: signature_to_base64 called with sig_len=%zu, out_len=%zu\n",
         sig_len, out_len);

  if (out_len < (sig_len * 4 / 3 + 4)) {
    // Not enough space in output buffer
    snprintf(base64_output, out_len, "Error: Insufficient buffer size");
    return;
  }

  for (i = 0, j = 0; i < sig_len;) {
    octet_a = i < sig_len ? signature[i++] : 0;
    octet_b = i < sig_len ? signature[i++] : 0;
    octet_c = i < sig_len ? signature[i++] : 0;

    triple = (octet_a << 16) + (octet_b << 8) + octet_c;

    base64_output[j++] = base64_chars[(triple >> 18) & 0x3F];
    base64_output[j++] = base64_chars[(triple >> 12) & 0x3F];
    base64_output[j++] = base64_chars[(triple >> 6) & 0x3F];
    base64_output[j++] = base64_chars[triple & 0x3F];
  }

  // Add padding if necessary
  switch (sig_len % 3) {
  case 1:
    base64_output[j - 2] = '=';
    base64_output[j - 1] = '=';
    break;
  case 2:
    base64_output[j - 1] = '=';
    break;
  }

  base64_output[j] = '\0'; // Null-terminate the string
}

esp_err_t configure_and_set_gpio_high(int pin, gpio_config_t *io_conf) {
  if (io_conf == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  io_conf->intr_type = GPIO_INTR_DISABLE;
  io_conf->mode = GPIO_MODE_OUTPUT;
  io_conf->pin_bit_mask = (1ULL << pin);
  io_conf->pull_down_en = 0;
  io_conf->pull_up_en = 0;

  esp_err_t ret = gpio_config(io_conf);
  if (ret != ESP_OK) {
    printf("Failed to configure GPIO: %s\n", esp_err_to_name(ret));
    return ret;
  }

  ret = gpio_set_level(pin, 1);
  if (ret != ESP_OK) {
    printf("Failed to set GPIO: %s\n", esp_err_to_name(ret));
    return ret;
  }

  printf("GPIO %d set to high\n", pin);
  return ESP_OK;
}

char *format_url_safely(const char *hex_signature, int recovery_bit,
                        uint32_t nonce) {
  char *base_url = "https://zupass.org/fake/";
  char *format_specifier = "%s%s%d?nonce=%lu";
  size_t required_length = snprintf(NULL, 0, format_specifier, base_url,
                                    hex_signature, recovery_bit, nonce);

  char *url = malloc(required_length + 1); // +1 for null terminator
  if (url == NULL) {
    fprintf(stderr, "Memory allocation failed\n");
    return NULL;
  }

  snprintf(url, required_length + 1, format_specifier, base_url, hex_signature,
           recovery_bit, nonce);

  return url;
}

esp_err_t nvs_check_and_do(const char *namespace, const char *key, void *output,
                           nvs_item_exists_callback exists_cb,
                           nvs_item_not_exists_callback not_exists_cb) {
  nvs_handle_t nvs_handle;
  esp_err_t err;

  err = nvs_open(namespace, NVS_READWRITE, &nvs_handle);
  if (err != ESP_OK) {
    printf("Error (%s) opening NVS handle!\n", esp_err_to_name(err));
    return err;
  }

  size_t required_size = 0;
  err = nvs_get_blob(nvs_handle, key, NULL, &required_size);

  if (err == ESP_OK && required_size > 0) {
    if (exists_cb) {
      err = exists_cb(nvs_handle, key, output);
    }
  } else if (err == ESP_ERR_NVS_NOT_FOUND) {
    if (not_exists_cb) {
      err = not_exists_cb(nvs_handle, key, output);
    }
  } else {
    printf("Error (%s) reading from NVS!\n", esp_err_to_name(err));
  }
  nvs_close(nvs_handle);
  return err;
}

void uint32_to_char(uint32_t num, unsigned char *output) {
  output[0] = (num >> 24) & 0xFF;
  output[1] = (num >> 16) & 0xFF;
  output[2] = (num >> 8) & 0xFF;
  output[3] = num & 0xFF;
}

int get_rsa_public_key(mbedtls_pk_context *pk, char *output,
                       size_t output_size) {
  int ret;
  unsigned char der_buf[1024];
  size_t der_len = 0;
  unsigned char base64_buf[1400]; // Increased buffer size for base64 encoding
  size_t base64_len = 0;
  const char *begin_public_key = "-----BEGIN PUBLIC KEY-----\n";
  const char *end_public_key = "-----END PUBLIC KEY-----\n";
  size_t total_len;

  // Write the public key to DER format
  ret = mbedtls_pk_write_pubkey_der(pk, der_buf, sizeof(der_buf));
  if (ret < 0) {
    return ret;
  }
  der_len = ret;

  // Base64 encode the DER data
  ret = mbedtls_base64_encode(base64_buf, sizeof(base64_buf), &base64_len,
                              der_buf + sizeof(der_buf) - der_len, der_len);
  if (ret != 0) {
    return ret;
  }

  // Calculate total length needed for PEM format
  total_len =
      strlen(begin_public_key) + base64_len + strlen(end_public_key) + 1;

  // Check if output buffer is large enough
  if (output_size < total_len) {
    return -1; // Output buffer too small
  }

  // Construct PEM string
  strcpy(output, begin_public_key);
  strncat(output, (char *)base64_buf, base64_len);
  strcat(output, "\n"); // Add a newline after base64 data
  strcat(output, end_public_key);

  return strlen(output);
}

unsigned char *hex_to_binary(const char *hex_string, size_t *out_len) {
  size_t len = strlen(hex_string) / 2;
  unsigned char *binary = malloc(len);
  *out_len = len;
  for (size_t i = 0; i < len; i++) {
    sscanf(hex_string + 2 * i, "%2hhx", &binary[i]);
  }
  return binary;
}

char *binary_to_hex(const unsigned char *data, size_t len) {
  char *hex = malloc(len * 2 + 1);
  for (size_t i = 0; i < len; i++) {
    sprintf(hex + i * 2, "%02x", data[i]);
  }
  hex[len * 2] = '\0';
  return hex;
}

void zero_memory(void *v, size_t n) {
  volatile unsigned char *p = v;
  while (n--)
    *p++ = 0;
}

void play_tones(uint8_t buz_pin) {
  ledc_timer_config_t ledc_timer = {
      .duty_resolution = LEDC_TIMER_12_BIT,
      .freq_hz = 5000,
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .timer_num = LEDC_TIMER_0,
      .clk_cfg = LEDC_AUTO_CLK,
  };
  ledc_timer_config(&ledc_timer);

  ledc_channel_config_t ledc_channel = {.channel = LEDC_CHANNEL_0,
                                        .duty = 4096, // 50% of 2^13
                                        .gpio_num = buz_pin,
                                        .speed_mode = LEDC_LOW_SPEED_MODE,
                                        .hpoint = 0,
                                        .timer_sel = LEDC_TIMER_0};
  ledc_channel_config(&ledc_channel);

  vTaskDelay(pdMS_TO_TICKS(10));

  for (int i = 0; i < 6; i++) {
    // Calculate frequency for each note
    uint32_t freq =
        262 * (1 << i); // Starting from C4 (262 Hz) and doubling for each step
    ledc_set_freq(LEDC_LOW_SPEED_MODE, LEDC_TIMER_0, freq);
    ledc_set_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, 128); // 50% duty cycle
    ledc_update_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0);
    vTaskDelay(pdMS_TO_TICKS(200));
  }

  // Stop the tone
  ledc_stop(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, 0);
}
