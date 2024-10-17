#include "driver/ledc.h"
#include "ecdsa.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nonce.h"
#include "portmacro.h"
#include "utils.h"
#include <driver/gpio.h>
#include <driver/i2c.h>
#include <neopixel.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <st25dv.h>
#include <st25dv_ndef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define VEXT_PIN 0
#define VBAT_PIN 1
#define VNFC_PIN 10
#define SDA_PIN 9
#define SCL_PIN 8
#define NFC_INT_PIN 4
#define LED_PIN 6
#define LED_EN 7
#define BUZ_PIN 5
#define SW_PIN 2 // buttons

#define DEBOUNCE_TIME_US 1000000 // 1ms debounce time
#define CC_FILE_ADDR 0x0000

static mbedtls_ecdsa_context key;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;

static _Atomic uint_least32_t nonce = 0;

static volatile bool nfc_operation_pending = false;
static TaskHandle_t nfc_task_handle = NULL;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

void play_tones() {
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
                                        .gpio_num = BUZ_PIN,
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

void enable_sleep() {
  // gpio_config_t io_conf = {};
  // esp_err_t res = configure_and_set_gpio_high(SW_PIN, &io_conf);
  // if (res != ESP_OK) {
  //   printf("Failed to configure GPIO: %s", esp_err_to_name(res));
  //   return;
  // }
  // vTaskDelay(pdMS_TO_TICKS(5));
  // io_conf.mode = GPIO_MODE_INPUT;
  // gpio_config(&io_conf);

  // wake up if nfc is scanned, or connected to power
  gpio_wakeup_enable(VEXT_PIN, GPIO_INTR_HIGH_LEVEL);
  gpio_wakeup_enable(NFC_INT_PIN, GPIO_INTR_HIGH_LEVEL);

  esp_sleep_enable_gpio_wakeup();

  vTaskDelay(pdMS_TO_TICKS(100));
  esp_light_sleep_start();
}

static volatile int64_t last_interrupt_time = 0;

void IRAM_ATTR handle_nfc_scan(void *arg) {
  int64_t current_time = esp_timer_get_time();
  static int64_t last_interrupt_time = 0;
  if (current_time - last_interrupt_time > DEBOUNCE_TIME_US) {
    last_interrupt_time = current_time;
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    vTaskNotifyGiveFromISR(nfc_task_handle, &xHigherPriorityTaskWoken);
    if (xHigherPriorityTaskWoken) {
      portYIELD_FROM_ISR();
    }
  }
}

typedef struct {
  st25dv_config st25dv_conf;
} nfc_task_params_t;

void nfc_task(void *pvParameters) {
  nfc_task_params_t *params = (nfc_task_params_t *)pvParameters;
  st25dv_config st25dv_config = params->st25dv_conf;
  free(params);

  gpio_config_t led_en_gpio_conf = {};
  configure_and_set_gpio_high(LED_EN, &led_en_gpio_conf);

  tNeopixelContext neopixel = neopixel_Init(6, LED_PIN);

  if (neopixel == NULL) {
    printf("Failed to initialize Neopixel\n");
    return;
  }
  while (1) {
    uint32_t notification_value = ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    if (notification_value > 0) {
      for (int i = 0; i < 6; i++) {
        tNeopixel pixels[] = {{i, NP_RGB(0, 50, 0)},
                              {(i + 1) % 6, NP_RGB(0, 0, 0)}};
        neopixel_SetPixel(neopixel, pixels, ARRAY_SIZE(pixels));
        vTaskDelay(pdMS_TO_TICKS(100));
      }

      for (int i = 0; i < 6; i++) {
        pixels[i] = (tNeopixel){i, NP_RGB(0, 0, 0)};
      }
      neopixel_SetPixel(neopixel, pixels, 6);
      gpio_config_t vnfc_io_conf = {};
      esp_err_t err = configure_and_set_gpio_high(VNFC_PIN, &vnfc_io_conf);
      if (err != ESP_OK) {
        printf("Failed to configure GPIO: %s", esp_err_to_name(err));
        return;
      }
      vTaskDelay(100 / portTICK_PERIOD_MS);
      play_tones();

      uint32_t new_nonce = get_and_update_nonce(&nonce);
      printf("Got nonce: %lu\n", new_nonce);

      unsigned char message[sizeof(uint32_t)];
      uint32_to_char(new_nonce, message);
      int recovery_bit = 0;
      char *hex_sig = ecdsa_sign_raw(&key, &ctr_drbg, message, sizeof(message),
                                     recovery_bit);
      if (hex_sig == NULL) {
        printf("Failed to sign message\n");
        continue;
      }

      uint8_t *blank = malloc(256);
      memset(blank, 0x00, 256);
      st25dv_write(ST25DV_USER_ADDRESS, 0x00, blank, 256);
      free(blank);

      vTaskDelay(pdMS_TO_TICKS(100));

      st25dv_ndef_write_ccfile(0x00040000010040E2);

      vTaskDelay(pdMS_TO_TICKS(100));

      uint16_t address = CC_FILE_ADDR + CCFILE_LENGTH;
      char *url = format_url_safely(hex_sig, recovery_bit, new_nonce);
      printf("URL: %s\n", url);
      char record_type[] = "U";

      size_t payload_len = strlen(url) - 7; // Exclude "https://"
      char *record_payload = malloc(payload_len + 1);
      if (record_payload == NULL) {
        printf("Failed to allocate memory for record payload\n");
        free(url);
        gpio_set_level(VNFC_PIN, 0);
        continue;
      }
      record_payload[0] = 0x04; // URL identifier code for "https://"
      memcpy(record_payload + 1, url + 8,
             payload_len - 1); // Exclude "https://"
      record_payload[payload_len] = '\0';

      // char record_payload[strlen(url) + 1];
      // record_payload[0] = 0x04;
      // strcpy(record_payload + 1, url + 8);

      std25dv_ndef_record url_record = {.tnf = NDEF_ST25DV_TNF_WELL_KNOWN,
                                        .type = record_type,
                                        .payload = record_payload};

      err = st25dv_ndef_write_content(st25dv_config, &address, true, true,
                                      url_record);
      if (err != ESP_OK) {
        printf("Failed to write NDEF record: %s\n", esp_err_to_name(err));
      } else {
        printf("NDEF record written successfully\n");
      }

      free(url);
      free(record_payload);
      gpio_set_level(VNFC_PIN, 0);
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

void IRAM_ATTR go_to_sleep(void *arg) { enable_sleep(); }

void app_main(void) {
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
      err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  ESP_ERROR_CHECK(err);

  gpio_config_t vext_io_conf = {};
  vext_io_conf.intr_type = GPIO_INTR_POSEDGE;
  vext_io_conf.mode = GPIO_MODE_OUTPUT;
  vext_io_conf.pin_bit_mask = (1ULL << VEXT_PIN);
  vext_io_conf.pull_up_en = GPIO_PULLUP_DISABLE;
  vext_io_conf.pull_down_en = GPIO_PULLDOWN_ENABLE;
  gpio_config(&vext_io_conf);

  gpio_install_isr_service(0);

  gpio_config_t nfc_int_config = {
      .intr_type = GPIO_INTR_POSEDGE,
      .mode = GPIO_MODE_INPUT,
      .pin_bit_mask = (1ULL << NFC_INT_PIN),
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .pull_up_en = GPIO_PULLUP_ENABLE,
  };
  gpio_config(&nfc_int_config);
  gpio_isr_handler_add(NFC_INT_PIN, handle_nfc_scan, NULL);
  printf("Installed GPIO ISR for GPIO %d\n", NFC_INT_PIN);

  gpio_config_t buz_io_conf = {};
  buz_io_conf.intr_type = GPIO_INTR_POSEDGE;
  buz_io_conf.mode = GPIO_MODE_INPUT;
  buz_io_conf.pin_bit_mask = (1ULL << BUZ_PIN);
  buz_io_conf.pull_up_en = 0;
  buz_io_conf.pull_down_en = 0;
  gpio_config(&buz_io_conf);

  if (gpio_get_level(VEXT_PIN)) {
    printf("External power found\n");
    // go to sleep when external power disconnected
    // gpio_isr_handler_add(VEXT_PIN, go_to_sleep, NULL);
    // gpio_set_intr_type(VEXT_PIN, GPIO_INTR_NEGEDGE);
  }
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

  int ret = ecdsa_init(&key, &ctr_drbg, &entropy);
  if (ret != 0) {
    printf("Failed to set up ECDSA \n");
    return;
  }

  nvs_handle_t nvs_handle;
  err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
  if (err != ESP_OK)
    return;

  size_t saved_size = 0;

  err = nvs_get_blob(nvs_handle, "ecdsa_key", NULL, &saved_size);
  if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
    printf("Error (%s) getting private key size from NVS!",
           esp_err_to_name(err));
    return;
  }

  if (saved_size == 0) {
    printf("No saved key found, generating new key\n");
    char *pubkey_hex = generate_ecdsa_key(&key, &ctr_drbg);
    if (pubkey_hex == NULL) {
      printf("Failed to generate ECDSA key\n");
      return;
    }
    unsigned char priv_buf[MBEDTLS_ECP_MAX_BYTES];
    size_t priv_len;
    ret =
        mbedtls_ecp_write_key_ext(&key, &priv_len, priv_buf, sizeof(priv_buf));
    if (ret != 0) {
      printf("Failed to export private key: -0x%04x\n", -ret);
      return;
    }
    err = nvs_set_blob(nvs_handle, "ecdsa_key", priv_buf, sizeof(priv_buf));
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
    printf("Private key saved to NVS.\n");
    nvs_close(nvs_handle);
    zero_memory(priv_buf, sizeof(priv_buf));
  } else {
    printf("Loading saved key from NVS\n");
    unsigned char *pkey = malloc(saved_size);
    if (pkey == NULL) {
      printf("Failed to allocate memory for reading private key\n");
      nvs_close(nvs_handle);
      return;
    }
    err = nvs_get_blob(nvs_handle, "ecdsa_key", pkey, &saved_size);
    if (err != ESP_OK) {
      printf("Error (%s) reading private key from NVS!\n",
             esp_err_to_name(err));
      free(pkey);
      nvs_close(nvs_handle);
      return;
    }
    printf("Read private key from NVS.\n");
    int mbedtls_ret = load_ecdsa_key(&key, &ctr_drbg, pkey);
    if (mbedtls_ret != 0) {
      printf("Failed to load key\n");
      free(pkey);
      nvs_close(nvs_handle);
      return;
    }
    char *pubkey_hex = get_ecdsa_public_key(&key);
    printf("Public key: %s\n", pubkey_hex);
    nvs_close(nvs_handle);
  }

  ESP_ERROR_CHECK(load_nonce(&nonce));

  nfc_task_params_t *nfc_params = malloc(sizeof(nfc_task_params_t));
  if (nfc_params == NULL) {
    printf("Failed to allocate memory for NFC task parameters\n");
    return;
  }
  nfc_params->st25dv_conf = st25dv_config;

  xTaskCreate(nfc_task, "nfc_task", 8192, nfc_params, 5, &nfc_task_handle);
  // enable_sleep();
}
