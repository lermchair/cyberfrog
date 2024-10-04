#include "utils.h"

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

  if (out_len < (sig_len * 4 / 3 + 4)) {
    // Not enough space in output buffer
    base64_output[0] = '\0';
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

esp_err_t configure_and_set_gpio_high(int pin) {
  gpio_config_t io_conf = {};
  io_conf.intr_type = GPIO_INTR_DISABLE;
  io_conf.mode = GPIO_MODE_OUTPUT;
  io_conf.pin_bit_mask = (1ULL << pin);
  io_conf.pull_down_en = 0;
  io_conf.pull_up_en = 0;

  esp_err_t ret = gpio_config(&io_conf);
  if (ret != ESP_OK) {
    printf("Failed to configure GPIO: %s", esp_err_to_name(ret));
    return ret;
  }
  ret = gpio_set_level(pin, 1);
  if (ret != ESP_OK) {
    printf("Failed to set GPIO: %s", esp_err_to_name(ret));
    return ret;
  }

  printf("GPIO set to high\n");
  return ESP_OK;
}

char *format_url_safely(const char *hex_signature) {
  // Calculate the required length
  size_t required_length = snprintf(
      NULL, 0, "%s%s", "https://zupass.org/verify?sig=", hex_signature);

  // Allocate memory
  char *url = malloc(required_length + 1); // +1 for null terminator
  if (url == NULL) {
    fprintf(stderr, "Memory allocation failed\n");
    return NULL;
  }

  // Format the string
  snprintf(url, required_length + 1, "%s%s",
           "https://zupass.org/verify?sig=", hex_signature);

  return url;
}

// unsigned char *hash_message(const unsigned char *message, size_t message_len)
// {
//   unsigned char hash[32];
// }