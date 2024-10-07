#include "utils.h"
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
  size_t required_length =
      snprintf(NULL, 0, "%s%s", "https://zupass.org/fake/", hex_signature);

  // Allocate memory
  char *url = malloc(required_length + 1); // +1 for null terminator
  if (url == NULL) {
    fprintf(stderr, "Memory allocation failed\n");
    return NULL;
  }

  // Format the string
  snprintf(url, required_length + 1, "%s%s", "https://zupass.org/fake/",
           hex_signature);

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

esp_err_t st25dv_ndef_write_content_patched(st25dv_config st25dv,
                                            uint16_t *address, bool mb, bool me,
                                            const std25dv_ndef_record record) {
  uint8_t type_size = strlen(record.type);
  uint16_t payload_size = strlen(record.payload);

  uint8_t *record_data = malloc(NDEF_RECORD_SIZE(mb, type_size, payload_size));

  uint8_t *data = record_data;

  // Total length : Record header + Type length + Payload length + ID + Type +
  // Payload
  uint16_t record_length =
      1 + 1 + (payload_size > 0xFF ? 4 : 1) + 1 + type_size + payload_size;

  // If this ndef is the first one
  if (mb) {
    // Type5 Tag TLV-Format: T
    *data++ = ST25DV_TYPE5_NDEF_MESSAGE;

    // Type5 Tag TLV-Format: L
    if (record_length > 0xFE) {
      *data++ = 0xFF;
      *data++ = record_length >> 8;
      *data++ = record_length & 0xFF;
    } else {
      *data++ = record_length;
    }
  }

  // Type5 Tag TLV-Format: V
  uint8_t tnf = 0;
  tnf |= mb ? NDEF_ST25DV_MB : 0;
  tnf |= me ? NDEF_ST25DV_ME : 0;
  tnf |= payload_size > 0xFF ? 0 : NDEF_ST25DV_SR;
  tnf |= NDEF_ST25DV_IL;
  tnf |= record.tnf;
  *data++ = tnf;

  // Type length
  *data++ = type_size;

  // Payload length
  if (payload_size > 0xFF) {
    *data++ = payload_size >> 24;
    *data++ = (payload_size >> 16) & 0xFF;
    *data++ = (payload_size >> 8) & 0xFF;
    *data++ = payload_size & 0xFF;
  } else {
    *data++ = payload_size;
  }

  // ID
  *data++ = 0x00;

  // Add record type
  memcpy(data, record.type, type_size);
  data += type_size;

  // Add record payload
  memcpy(data, record.payload, payload_size);
  data += payload_size;

  uint8_t record_address = CCFILE_LENGTH;

  if (*address > CCFILE_LENGTH) {
    record_address = *address;
  }

  // If this ndef record is not the first one, we need to update the TLV-Format
  // L value
  if (!mb) {

    // Read the possible 3 byte l value
    uint8_t *l_value = malloc(0x03);
    st25dv_read(st25dv.user_address, CCFILE_LENGTH + 1, l_value, 0x03);
    uint16_t old_length = 0;
    uint16_t total_length;

    if (*l_value == 0xFF) {
      // The l value is already 3 byte long
      old_length |= *(l_value + 1) << 8;
      old_length |= *(l_value + 2) & 0xFF;

      total_length = old_length + record_length;

      *(l_value + 1) = total_length >> 8;
      *(l_value + 2) = total_length & 0xFF;

      // Update the value
      st25dv_write(st25dv.user_address, CCFILE_LENGTH + 1, l_value, 0x03);
    } else {
      // The l value is 1 byte long
      old_length = *l_value;

      total_length = old_length + record_length;

      if (total_length > 0xFE) {
        // The l value is 1 byte but needs to be 3
        *l_value = 0xFF;
        *(l_value + 1) = total_length >> 8;
        *(l_value + 2) = total_length & 0xFF;

        // Copy and move the existing records
        uint8_t *st25dv_content = malloc(old_length);
        st25dv_read(st25dv.user_address, CCFILE_LENGTH + 2, st25dv_content,
                    old_length);
        st25dv_write(st25dv.user_address, CCFILE_LENGTH + 1, l_value, 0x03);
        vTaskDelay(100 / portTICK_PERIOD_MS);
        st25dv_write(st25dv.user_address, CCFILE_LENGTH + 4, st25dv_content,
                     old_length);
        record_address += 2;
        free(st25dv_content);
      } else {
        // The l value is already 1 byte
        *l_value = total_length;

        // Update the value
        st25dv_write_byte(st25dv.user_address, CCFILE_LENGTH + 1, *l_value);
      }
    }
    free(l_value);
  }

  uint16_t total_size = data - record_data;
  uint16_t bytes_written = 0;
  uint8_t *write_ptr = record_data;

  while (bytes_written < total_size) {
    uint16_t chunk_size = (total_size - bytes_written) > 0xFF
                              ? 0xFF
                              : (total_size - bytes_written);

    esp_err_t write_result =
        st25dv_write(st25dv.user_address, record_address + bytes_written,
                     write_ptr, chunk_size);
    if (write_result != ESP_OK) {
      free(record_data);
      return write_result;
    }

    bytes_written += chunk_size;
    write_ptr += chunk_size;

    vTaskDelay(100 / portTICK_PERIOD_MS);
  }
  // Add terminator
  if (me) {
    st25dv_write_byte(st25dv.user_address,
                      record_address + (data - record_data),
                      ST25DV_TYPE5_TERMINATOR_TLV);
  }

  *address = record_address + (data - record_data);

  free(record_data);
  return ESP_OK;
}
