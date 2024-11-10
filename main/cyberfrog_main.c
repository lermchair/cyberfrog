#include "constants.h"
#include "ecdsa.h"
#include "esp_err.h"
#include "esp_sleep.h"
#include "hal/gpio_types.h"
#include "nonce.h"
#include "utils.h"
#include <driver/gpio.h>
#include <driver/i2c.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <neopixel.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <portmacro.h>
#include <st25dv.h>
#include <st25dv_ndef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static EventGroupHandle_t event_group;

static mbedtls_ecdsa_context key;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;

static _Atomic uint_least32_t nonce = 0;

static volatile bool nfc_operation_pending = false;
static volatile int64_t last_interrupt_time = 0;

void IRAM_ATTR handle_nfc_scan(void *arg) {
  int64_t current_time = esp_timer_get_time();

  if (current_time - last_interrupt_time > NFC_DEBOUNCE_TIME_US) {
    last_interrupt_time = current_time;
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xEventGroupSetBitsFromISR(event_group, EVENT_NFC_SCANNED,
                              &xHigherPriorityTaskWoken);

    if (xHigherPriorityTaskWoken) {
      portYIELD_FROM_ISR();
    }
  }
}

void IRAM_ATTR vext_isr_handler(void *arg) {
  BaseType_t xHigherPriorityTaskWoken = pdFALSE;
  int level = gpio_get_level(VEXT_PIN);

  if (level == 0) {
    xEventGroupSetBitsFromISR(event_group, EVENT_POWER_DISCONNECTED,
                              &xHigherPriorityTaskWoken);
  } else {
    printf("Woken up from VEXT\n");
    xEventGroupSetBitsFromISR(event_group, EVENT_POWER_CONNECTED,
                              &xHigherPriorityTaskWoken);
  }

  if (xHigherPriorityTaskWoken == pdTRUE) {
    portYIELD_FROM_ISR();
  }
}

esp_err_t configure_all_gios() {
  esp_err_t ret = ESP_OK;
  gpio_config_t vext_io_conf = {
      .pin_bit_mask = (1ULL << VEXT_PIN),
      .mode = GPIO_MODE_INPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_ANYEDGE // Wake on any edge
  };
  ret = configure_gpio(VEXT_PIN, &vext_io_conf);
  if (ret != ESP_OK)
    return ret;
  ret = gpio_isr_handler_add(VEXT_PIN, vext_isr_handler, NULL);
  if (ret != ESP_OK) {
    printf("Failed to add GPIO ISR for GPIO %d\n", VEXT_PIN);
    return ret;
  }
  ret = gpio_hold_en(VEXT_PIN);
  if (ret != ESP_OK) {
    printf("Failed to hold GPIO %d\n", VEXT_PIN);
    return ret;
  }

  gpio_config_t nfc_int_config = {
      .intr_type = GPIO_INTR_ANYEDGE,
      .mode = GPIO_MODE_INPUT,
      .pin_bit_mask = (1ULL << NFC_INT_PIN),
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .pull_up_en = GPIO_PULLUP_ENABLE,
  };
  ret = configure_gpio(NFC_INT_PIN, &nfc_int_config);
  if (ret != ESP_OK)
    return ret;
  ret = gpio_isr_handler_add(NFC_INT_PIN, handle_nfc_scan, NULL);
  if (ret != ESP_OK) {
    printf("Failed to add GPIO ISR for GPIO %d\n", NFC_INT_PIN);
    return ret;
  }
  ret = gpio_hold_en(NFC_INT_PIN);
  if (ret != ESP_OK) {
    printf("Failed to enable pull-up hold on GPIO %d\n", NFC_INT_PIN);
    return ret;
  }

  gpio_config_t led_io_conf = {
      .pin_bit_mask = (1ULL << LED_PIN),
      .mode = GPIO_MODE_OUTPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };
  ret = configure_gpio(LED_PIN, &led_io_conf);
  if (ret != ESP_OK)
    return ret;

  gpio_config_t buz_io_conf = {.pin_bit_mask = (1ULL << BUZ_PIN),
                               .mode = GPIO_MODE_OUTPUT,
                               .pull_up_en = GPIO_PULLUP_DISABLE,
                               .pull_down_en = GPIO_PULLDOWN_DISABLE,
                               .intr_type = GPIO_INTR_DISABLE};
  ret = configure_gpio(BUZ_PIN, &buz_io_conf);
  if (ret != ESP_OK)
    return ret;

  return ESP_OK;
}

static bool setup_led = false;

void handle_sleep() {
  printf("Entering deep sleep...\n");
  configure_all_gios();
  uint64_t wakeup_pins = (1ULL << VEXT_PIN) | (1ULL << NFC_INT_PIN);
  esp_err_t err = esp_deep_sleep_enable_gpio_wakeup((1ULL << VEXT_PIN),
                                                    ESP_GPIO_WAKEUP_GPIO_HIGH);
  err = esp_deep_sleep_enable_gpio_wakeup((1ULL << NFC_INT_PIN),
                                          ESP_GPIO_WAKEUP_GPIO_LOW);
  if (err != ESP_OK) {
    printf("Failed to enable GPIO wakeup: %s\n", esp_err_to_name(err));
    return;
  } else {
    printf("Enabled GPIO wakeup on GPIO %d and GPIO %d\n", VEXT_PIN,
           NFC_INT_PIN);
  }

  if (err != ESP_OK) {
    printf("Failed to reset wakeup status: %s\n", esp_err_to_name(err));
    return;
  }
  vTaskDelay(pdMS_TO_TICKS(100));

  esp_deep_sleep_start();
}

void app_main(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(gpio_install_isr_service(0));
    ESP_ERROR_CHECK(configure_all_gios());

    // Initialize I2C and ECDSA
    st25dv_init_i2c(I2C_NUM_0, I2C_CONFIG);

    int ret = ecdsa_init(&key, &ctr_drbg, &entropy);
    if (ret != 0) {
        printf("Failed to set up ECDSA \n");
        return;
    }

    // Initialize NVS and key management
    nvs_handle_t nvs_handle;
    err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        printf("Error opening NVS handle\n");
        return;
    }

    size_t saved_key_size = 0;
    err = nvs_get_blob(nvs_handle, "ecdsa_key", NULL, &saved_key_size);
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        printf("Error getting private key size from NVS: %s", esp_err_to_name(err));
        return;
    }

    if (saved_key_size == 0) {
        ESP_ERROR_CHECK(generate_and_save_key(&nvs_handle, &key, &ctr_drbg));
    } else {
        ESP_ERROR_CHECK(load_saved_key(&nvs_handle, saved_key_size, &key, &ctr_drbg));
    }

    ESP_ERROR_CHECK(load_nonce(&nonce));

    // Initialize LED strip
    gpio_config_t led_en_gpio_conf = {};
    configure_and_set_gpio_high(LED_EN, &led_en_gpio_conf);
    tNeopixelContext neopixel = neopixel_Init(6, LED_PIN);
    if (neopixel == NULL) {
        printf("Failed to initialize Neopixel\n");
        return;
    }

    // Handle initial power state
    esp_sleep_wakeup_cause_t wakeup_reason = esp_sleep_get_wakeup_cause();
    if (wakeup_reason == ESP_SLEEP_WAKEUP_GPIO) {
        uint64_t wakeup_gpio_mask = esp_sleep_get_gpio_wakeup_status();
        if (wakeup_gpio_mask & (1ULL << VEXT_PIN)) {
            xEventGroupSetBits(event_group, EVENT_POWER_CONNECTED);
        }
        if (wakeup_gpio_mask & (1ULL << NFC_INT_PIN)) {
            xEventGroupSetBits(event_group, EVENT_NFC_SCANNED);
        }
    } else {
        if (gpio_get_level(VEXT_PIN)) {
            xEventGroupSetBits(event_group, EVENT_POWER_CONNECTED);
        } else {
            handle_sleep();
        }
    }

    while (1) {
        EventBits_t bits = xEventGroupWaitBits(
            event_group,
            EVENT_POWER_CONNECTED | EVENT_POWER_DISCONNECTED | EVENT_NFC_SCANNED,
            pdTRUE, pdFALSE, portMAX_DELAY);

        if (bits & EVENT_POWER_CONNECTED) {
            printf("External power detected\n");
        }

        if (bits & EVENT_POWER_DISCONNECTED) {
            printf("External power disconnected\n");
            vTaskDelay(pdMS_TO_TICKS(100));
            if (!nfc_operation_pending) {
                handle_sleep();
            }
        }

        if (bits & EVENT_NFC_SCANNED) {
            printf("NFC scan detected\n");
            nfc_operation_pending = true;

            // Configure VNFC pin
            gpio_config_t vnfc_io_conf = {};
            err = configure_and_set_gpio_high(VNFC_PIN, &vnfc_io_conf);
            if (err != ESP_OK) {
                printf("Failed to configure GPIO: %s", esp_err_to_name(err));
                nfc_operation_pending = false;
                continue;
            }
            vTaskDelay(pdMS_TO_TICKS(100));

            // Handle NFC operation
            ESP_ERROR_CHECK(animate_leds(neopixel));

            uint32_t new_nonce = get_and_update_nonce(&nonce);
            printf("Got nonce: %lu\n", new_nonce);

            uint16_t address = CC_FILE_ADDR + CCFILE_LENGTH;
            st25dv_ndef_record url_record = {0};

            unsigned char message[sizeof(uint32_t)];
            uint32_to_char(nonce, message);

            SignatureResult sig_result = ecdsa_sign_raw(&key, &ctr_drbg, message, sizeof(message));
            if (sig_result.signature == NULL) {
                printf("Failed to sign message\n");
                nfc_operation_pending = false;
                continue;
            }

            char *url = format_url_safely(sig_result.signature, sig_result.recovery_id, nonce);
            if (!url) {
                free(sig_result.signature);
                nfc_operation_pending = false;
                continue;
            }

            // Write NDEF record
            st25dv_ndef_write_ccfile(CC_FILE_DATA);
            vTaskDelay(pdMS_TO_TICKS(100));

            char record_type[] = "U";
            size_t payload_len = strlen(url) - 8;
            char *record_payload = malloc(payload_len + 2);
            if (!record_payload) {
                free(url);
                free(sig_result.signature);
                nfc_operation_pending = false;
                continue;
            }

            record_payload[0] = 0x04;
            memcpy(record_payload + 1, url + 8, payload_len);
            record_payload[payload_len + 1] = '\0';

            url_record.tnf = NDEF_ST25DV_TNF_WELL_KNOWN;
            url_record.type = record_type;
            url_record.payload = record_payload;

            err = st25dv_ndef_write_content(ST25DV_CONF, &address, true, true, url_record);

            free(url);
            free(sig_result.signature);
            free(record_payload);

            gpio_set_level(VNFC_PIN, 0);
            play_tones(BUZ_PIN);
            nfc_operation_pending = false;

            // Handle sleep if needed
            if (!gpio_get_level(VEXT_PIN)) {
                vTaskDelay(pdMS_TO_TICKS(100));
                if (!nfc_operation_pending) {
                    handle_sleep();
                }
            }
        }
    }
}
