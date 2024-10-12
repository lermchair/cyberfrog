#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "slow_sig.h"
#include "utils.h"
#include <driver/gpio.h>
#include <driver/i2c.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <st25dv.h>
#include <st25dv_ndef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define VNFC_PIN 10
#define SDA_PIN 9
#define SCL_PIN 8
#define NFC_INT_PIN 4
#define DEBOUNCE_TIME_US 700000 // 700ms debounce time

static mbedtls_pk_context key;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;

static char public_key[1024];
size_t public_key_len;

static _Atomic uint_least32_t nonce = 0;

static SemaphoreHandle_t xSemaphore = NULL;

uint32_t get_nonce() {
  uint32_t nonce_value = atomic_fetch_add(&nonce, 1);
  nvs_handle_t nvs_handle;
  esp_err_t ret;

  ret = nvs_open("storage", NVS_READWRITE, &nvs_handle);
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

esp_err_t init_nonce_from_nvs(_Atomic uint_least32_t *nonce) {
  nvs_handle_t nvs_handle;
  esp_err_t ret;

  ret = nvs_open("storage", NVS_READWRITE, &nvs_handle);
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

#define CC_FILE_ADDR 0x0000

void app_main(void) {
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
      err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  ESP_ERROR_CHECK(err);

#ifdef CONFIG_EFUSE_RSA_SIG
  printf("Oopsie, not implemented\n");
  return;
#else
  ESP_ERROR_CHECK(configure_and_set_gpio_high(10));
  vTaskDelay(100 / portTICK_PERIOD_MS);

  i2c_config_t i2c_config = {
      .mode = I2C_MODE_MASTER,
      .sda_io_num = SDA_PIN,
      .scl_io_num = SCL_PIN,
      .sda_pullup_en = GPIO_PULLUP_ENABLE,
      .scl_pullup_en = GPIO_PULLUP_ENABLE,
      .master.clk_speed = ST25DV_MAX_CLK_SPEED,
  };

  st25dv_config st25dv_config = {ST25DV_USER_ADDRESS, ST25DV_SYSTEM_ADDRESS};
  st25dv_init_i2c(I2C_NUM_0, i2c_config);

  int ret = rsa_init(&key, &ctr_drbg, &entropy);
  if (ret != 0) {
    printf("Failed to set up RSA\n");
    return;
  }

  nvs_handle_t nvs_handle;
  err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
  if (err != ESP_OK)
    return;

  size_t saved_size = 0;

  err = nvs_get_blob(nvs_handle, "rsa_key", NULL, &saved_size);
  if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
    printf("Error (%s) getting private key size from NVS!",
           esp_err_to_name(err));
    return;
  }

  if (saved_size == 0) {
    printf("No saved key found, generating new key\n");
    unsigned char *pem_key = generate_rsa_pem_key(&key);
    if (pem_key == NULL) {
      printf("Failed to generate RSA key\n");
      return;
    }
    size_t pem_key_len = strlen((char *)pem_key) + 1; // Include null terminator
    err = nvs_set_blob(nvs_handle, "rsa_key", pem_key, pem_key_len);
    if (err != ESP_OK) {
      printf("Error (%s) saving private key to NVS!\n", esp_err_to_name(err));
      nvs_close(nvs_handle);
      return;
    }
    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
      printf("Error (%s) committing NVS!\n", esp_err_to_name(err));
      nvs_close(nvs_handle);
      return;
    }
    printf("RSA Private key saved to NVS.\n");
    nvs_close(nvs_handle);
    free(pem_key); // IMPORTANT
    pem_key = NULL;
  } else {
    printf("Loading saved key from NVS\n");
    unsigned char *pem_key = malloc(saved_size);
    if (pem_key == NULL) {
      printf("Failed to allocate memory for reading private key\n");
      nvs_close(nvs_handle);
      return;
    }
    err = nvs_get_blob(nvs_handle, "rsa_key", pem_key, &saved_size);
    if (err != ESP_OK) {
      printf("Error (%s) reading private key from NVS!\n",
             esp_err_to_name(err));
      free(pem_key);
      nvs_close(nvs_handle);
      return;
    }
    printf("Read private key from NVS.\n");
    int mbedtls_ret = load_rsa_key(&key, pem_key, saved_size);
    if (mbedtls_ret != 0) {
      printf("Failed to load RSA key\n");
      free(pem_key);
      nvs_close(nvs_handle);
      return;
    }
    nvs_close(nvs_handle);
  }

  ESP_ERROR_CHECK(init_nonce_from_nvs(&nonce));

  xSemaphore = xSemaphoreCreateBinary();

  gpio_config_t nfc_int_config = {
      .intr_type = GPIO_INTR_POSEDGE,
      .mode = GPIO_MODE_INPUT,
      .pin_bit_mask = (1ULL << NFC_INT_PIN),
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .pull_up_en = GPIO_PULLUP_ENABLE,
  };
  gpio_config(&nfc_int_config);
  gpio_install_isr_service(0);
  printf("Installed GPIO ISR for GPIO %d\n", NFC_INT_PIN);

  public_key_len = get_public_key(&key, public_key, sizeof(public_key));
  if (public_key_len < 0) {
      printf("Unable to get public key\n");
      return;
  } else {
      printf("Using public key: %s\n", public_key);
  }

  // get the nonce
  uint32_t nonce = get_nonce();
  printf("Got nonce: %lu\n", nonce);
  unsigned char message[sizeof(uint32_t)];
  uint32_to_char(nonce, message);
  char *b64_signature = rsa_sign_to_base64(&key, &ctr_drbg, message);
  if (b64_signature == NULL) {
    printf("Failed to sign message\n");
    return;
  }
  printf("Signature: %s\n", b64_signature);

  uint8_t *blank = malloc(256);
  memset(blank, 0x00, 256);
  st25dv_write(ST25DV_USER_ADDRESS, 0x00, blank, 256);
  free(blank);

  printf("Clearing from 0x00 to 0x200\n");
  vTaskDelay(100 / portTICK_RATE_MS);

  st25dv_ndef_write_ccfile(0x00040000010040E2);
  printf("Writing CC File\n");
  vTaskDelay(100 / portTICK_RATE_MS);
  uint16_t address = CC_FILE_ADDR + CCFILE_LENGTH;

  char *url = format_url_safely(b64_signature);

  char record_type[] = "U";             // URI record type
  char record_payload[strlen(url) + 1]; // +1 for URI identifier

  record_payload[0] = 0x04;            // URI identifier for "https://"
  strcpy(record_payload + 1, url + 8); // Copy URL without "https://"

  std25dv_ndef_record url_record = {.tnf = NDEF_ST25DV_TNF_WELL_KNOWN,
                                    .type = record_type,
                                    .payload = record_payload};

  err = st25dv_ndef_write_content_patched(st25dv_config, &address, true, true,
                                          url_record);

  if (err != ESP_OK) {
    printf("Failed to write chunked NDEF records: %s\n", esp_err_to_name(err));
    free(url);
    free(b64_signature);
    return;
  }

  printf("NDEF URI written in chunks.\n");

  free(url);
  free(b64_signature);
#endif
}
