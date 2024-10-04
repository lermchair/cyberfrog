#include "esp_ds.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pem.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "slow_sig.h"
#include "utils.h"
#include <driver/gpio.h>
#include <driver/i2c.h>
#include <mbedtls/sha256.h>
#include <st25dv.h>
#include <st25dv_ndef.h>
#include <st25dv_registers.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DEBOUNCE_TIME_US 600000 // 600ms debounce time
#define STORAGE_NAMESPACE "storage"

static _Atomic uint_least32_t nonce = 0;
static mbedtls_pk_context key_read;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;
SemaphoreHandle_t xSemaphore = NULL;

void IRAM_ATTR gpio_isr_handler(void *arg);
static volatile bool gpio_interrupt_flag = false;
static volatile int64_t last_interrupt_time = 0;

void IRAM_ATTR gpio_isr_handler(void *arg) {
  int64_t current_time = esp_timer_get_time();
  if (current_time - last_interrupt_time > DEBOUNCE_TIME_US) {
    last_interrupt_time = current_time;
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xSemaphoreGiveFromISR(xSemaphore, &xHigherPriorityTaskWoken);
    if (xHigherPriorityTaskWoken == pdTRUE) {
      portYIELD_FROM_ISR();
    }
  }
}

uint32_t get_nonce() {
  uint32_t nonce_value = atomic_fetch_add(&nonce, 1);

  // Save the updated nonce to NVS
  nvs_handle_t nvs_handle;
  esp_err_t ret;

  ret = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvs_handle);
  if (ret != ESP_OK) {
    printf("Error (%s) opening NVS handle!\n", esp_err_to_name(ret));
    return nonce_value;
  }

  ret = nvs_set_u32(nvs_handle, "nonce", nonce_value + 1);
  if (ret != ESP_OK) {
    printf("Error (%s) setting nonce in NVS!\n", esp_err_to_name(ret));
    nvs_close(nvs_handle);
    return nonce_value;
  }
  ret = nvs_commit(nvs_handle);
  if (ret != ESP_OK) {
    printf("Error (%s) committing NVS!\n", esp_err_to_name(ret));
  }
  nvs_close(nvs_handle);

  return nonce_value;
}

esp_err_t load_nonce_from_nvs(_Atomic uint_least32_t *nonce) {
  nvs_handle_t nvs_handle;
  esp_err_t ret;

  ret = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvs_handle);
  if (ret != ESP_OK) {
    printf("Error (%s) opening NVS handle!\n", esp_err_to_name(ret));
    return ret;
  }
  uint32_t nonce_value = 0;
  ret = nvs_get_u32(nvs_handle, "nonce", &nonce_value);
  if (ret == ESP_ERR_NVS_NOT_FOUND) {
    printf("Nonce not found in NVS, initializing to 0\n");
    nonce_value = 0;
    ret = nvs_set_u32(nvs_handle, "nonce", nonce_value);
    if (ret != ESP_OK) {
      printf("Error (%s) setting nonce in NVS!", esp_err_to_name(ret));
      nvs_close(nvs_handle);
      return ret;
    }
    ret = nvs_commit(nvs_handle);
    if (ret != ESP_OK) {
      printf("Error (%s) committing NVS!\n", esp_err_to_name(ret));
      nvs_close(nvs_handle);
      return ret;
    }
  } else if (ret != ESP_OK) {
    printf("Error (%s) reading nonce from NVS!\n", esp_err_to_name(ret));
    nvs_close(nvs_handle);
    return ret;
  }

  *nonce = nonce_value;
  nvs_close(nvs_handle);
  return ESP_OK;
}

void nfc_scan_task(void *pvParameter) {
  st25dv_config *config = (st25dv_config *)pvParameter;
  while (1) {
    if (xSemaphoreTake(xSemaphore, portMAX_DELAY) == pdTRUE) {
      printf("\nNFC scan detected\n");
      uint32_t nonce = get_nonce();
      printf("Got nonce: %ld\n", nonce);

      unsigned char hash[32]; // SHA-256 hash size
      unsigned char signature[MBEDTLS_MPI_MAX_SIZE];
      size_t signature_len;

      // memcpy(hash, &nonce, sizeof(nonce));
      unsigned char input[sizeof(uint32_t)];

      input[0] = (nonce >> 24) & 0xFF;
      input[1] = (nonce >> 16) & 0xFF;
      input[2] = (nonce >> 8) & 0xFF;
      input[3] = nonce & 0xFF;

      // Hash the message
      mbedtls_md_context_t md_ctx;
      mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
      const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);

      if (md_info == NULL) {
        printf("Failed to get md_info for md_type %d\n", md_type);
        return;
      }

      mbedtls_md_init(&md_ctx);
      int mbedtls_ret = mbedtls_md_setup(&md_ctx, md_info, 0);
      if (mbedtls_ret != 0) {
        printf("mbedtls_md_setup returned -0x%04x\n", -mbedtls_ret);
        return;
      }

      mbedtls_ret = mbedtls_md(md_info, input, sizeof(input), hash);
      if (mbedtls_ret != 0) {
        printf("mbedtls_md returned -0x%04x\n", -mbedtls_ret);
        return;
      }

      mbedtls_md_free(&md_ctx);

      // print the hash
      printf("Hash: ");
      for (int i = 0; i < sizeof(hash); i++) {
        printf("%02x", hash[i]);
      }
      printf("\n");

      // Sign the hash
      mbedtls_ret = mbedtls_pk_sign(
          &key_read, md_type, hash, sizeof(hash), signature, sizeof(signature),
          &signature_len, mbedtls_ctr_drbg_random, &ctr_drbg);
      if (mbedtls_ret != 0) {
        printf("mbedtls_pk_sign returned -0x%04x", -mbedtls_ret);
        return;
      }

      printf("Message signed successfully.");

      char b64_signature[((signature_len + 2) / 3) * 4 + 1]; // +1 for null
      signature_to_base64(signature, signature_len, b64_signature,
                          sizeof(b64_signature));

      printf("Signature: %s\n", b64_signature);
      st25dv_ndef_write_ccfile(0x00040000010040E2);
      printf("Writing CC File\n");

      vTaskDelay(100 / portTICK_PERIOD_MS);

      char *url = "https://zupass.org";

      uint16_t address = CCFILE_LENGTH; // Start writing after the CC file

      char record_type[] = "U";             // URI record type
      char record_payload[strlen(url) + 1]; // +1 for URI identifier

      printf("Length of URL: %u\n", strlen(url));
      record_payload[0] = 0x04;            // URI identifier for "https://"
      strcpy(record_payload + 1, url + 8); // Copy URL without "https://"

      std25dv_ndef_record url_record = {.tnf = NDEF_ST25DV_TNF_WELL_KNOWN,
                                        .type = record_type,
                                        .payload = record_payload};

      ESP_ERROR_CHECK(
          st25dv_ndef_write_content(*config, &address, true, true, url_record));
      printf("Wrote URL to NFC tag: %s", url);
    }
  }
}

int load_or_generate_rsa_key(mbedtls_pk_context *key) {
  esp_err_t err;
  int mbedtls_ret;
  nvs_handle_t nvs_handle;
  unsigned char *pem_key = NULL;
  unsigned char *pem_key_read = NULL;
  size_t pem_key_size = 1680;

  printf("Checking for private key in NVS\n");
  err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvs_handle);
  if (err != ESP_OK)
    return -1;

  size_t saved_size = 0;

  err = nvs_get_blob(nvs_handle, "rsa_key", NULL, &saved_size);
  if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
    printf("Error (%s) getting private key size from NVS!",
           esp_err_to_name(err));
    return -1;
  }

  pem_key = malloc(pem_key_size);
  if (pem_key == NULL) {
    printf("Failed to allocate memory for pem_key");
    return -1;
  }

  if (saved_size == 0) {
    printf("No saved key found, generating new key\n");

    // Setup the key context
    mbedtls_ret =
        mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (mbedtls_ret != 0) {
      printf("mbedtls_pk_setup returned -0x%04x", -mbedtls_ret);
      return -1;
    }

    // Generate the RSA key pair
    printf("Generating RSA key pair...\n");
    mbedtls_ret =
        mbedtls_rsa_gen_key(mbedtls_pk_rsa(key_read), mbedtls_ctr_drbg_random,
                            &ctr_drbg, 2048, 65537);
    if (mbedtls_ret != 0) {
      printf("mbedtls_rsa_gen_key returned -0x%04x", -mbedtls_ret);
      return -1;
    }
    printf("RSA key pair generated successfully.\n");

    // Export the private key in PEM format
    memset(pem_key, 0, pem_key_size);
    mbedtls_ret = mbedtls_pk_write_key_pem(&key_read, pem_key, pem_key_size);
    if (mbedtls_ret != 0) {
      printf("mbedtls_pk_write_key_pem returned -0x%04x\n", -mbedtls_ret);
      return -1;
    }
    printf("Private key exported in PEM format.\n");

    // Save the private key to NVS
    size_t pem_key_len = strlen((char *)pem_key) + 1; // Include null terminator
    err = nvs_set_blob(nvs_handle, "rsa_key", pem_key, pem_key_len);
    if (err != ESP_OK) {
      printf("Error (%s) saving private key to NVS!\n", esp_err_to_name(err));
      nvs_close(nvs_handle);
      return -1;
    }

    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
      printf("Error (%s) committing NVS!\n", esp_err_to_name(err));
      nvs_close(nvs_handle);
      return -1;
    }
    printf("RSA Private key saved to NVS.\n");
    nvs_close(nvs_handle);
    free(pem_key);
    pem_key = NULL;
  } else {
    // Allocate memory to read the private key
    printf("Loading saved key from NVS\n");
    printf("Saved size: %d\n", saved_size);
    pem_key_read = malloc(saved_size);
    if (pem_key_read == NULL) {
      printf("Failed to allocate memory for reading private key\n");
      nvs_close(nvs_handle);
      return -1;
    }

    // Read the private key from NVS
    err = nvs_get_blob(nvs_handle, "private_key", pem_key_read, &saved_size);
    if (err != ESP_OK) {
      printf("Error (%s) reading private key from NVS!\n",
             esp_err_to_name(err));
      free(pem_key_read);
      nvs_close(nvs_handle);
      return -1;
    }
    nvs_close(nvs_handle);
    printf("Private key read from NVS.\n");
    mbedtls_ret = mbedtls_pk_parse_key(&key_read, pem_key_read, saved_size,
                                       NULL, 0, NULL, NULL);

    if (mbedtls_ret != 0) {
      printf("mbedtls_pk_parse_key returned -0x%04x\n", -mbedtls_ret);
      free(pem_key_read);
      return -1;
    }
    printf("Private key imported back into mbedtls.\n");
  }
  return 0;
}

void app_main(void) {
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
      err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  ESP_ERROR_CHECK(err);

  esp_timer_init(); // Initialize the esp_timer

#ifdef CONFIG_EFUSE_RSA_SIG
  printf("Oopsie, not implemented\n");
  return;
#else
  // turn on ST25DV
  configure_and_set_gpio_high(10);
  vTaskDelay(100 / portTICK_PERIOD_MS);

  i2c_config_t i2c_config = {
      .mode = I2C_MODE_MASTER,
      .sda_io_num = 9,
      .scl_io_num = 8,
      .sda_pullup_en = GPIO_PULLUP_ENABLE,
      .scl_pullup_en = GPIO_PULLUP_ENABLE,
      .master.clk_speed = ST25DV_MAX_CLK_SPEED,
  };

  st25dv_config st25dv_config = {ST25DV_USER_ADDRESS, ST25DV_SYSTEM_ADDRESS};

  st25dv_init_i2c(I2C_NUM_0, i2c_config);

  mbedtls_pk_init(&key_read);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  const char *pers = "rsa_genkey";
  int mbedtls_ret =
      mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                            (const unsigned char *)pers, strlen(pers));
  if (mbedtls_ret != 0) {
    printf("mbedtls_ctr_drbg_seed returned -0x%04x\n", -mbedtls_ret);
    return;
  }

  if (load_or_generate_rsa_key(&key_read) != 0) {
    printf("Failed to load or generate RSA key\n");
    return;
  }

  if (load_nonce_from_nvs(&nonce) != ESP_OK) {
    printf("Failed to load nonce from NVS\n");
    return;
  }

  xSemaphore = xSemaphoreCreateBinary();
  xTaskCreate(nfc_scan_task, "nfc_scan_task", 8192, &st25dv_config, 10, NULL);

  gpio_config_t io_conf = {};
  io_conf.intr_type = GPIO_INTR_POSEDGE;
  io_conf.pin_bit_mask = (1ULL << GPIO_NUM_4);
  io_conf.mode = GPIO_MODE_INPUT;
  io_conf.pull_up_en = GPIO_PULLUP_ENABLE;
  io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
  gpio_config(&io_conf);

  gpio_install_isr_service(0);
  gpio_isr_handler_add(GPIO_NUM_4, gpio_isr_handler, NULL);
  printf("Installed GPIO ISR for GPIO4\n");

  // exit:
  //   // Free resources
  //   mbedtls_pk_free(&key);
  //   mbedtls_pk_free(&key_read);
  //   mbedtls_ctr_drbg_free(&ctr_drbg);
  //   mbedtls_entropy_free(&entropy);
  //   if (pem_key_read != NULL) {
  //     free(pem_key_read);
  //   }
  //   ESP_LOGI(TAG, "Done.");

#endif
}
