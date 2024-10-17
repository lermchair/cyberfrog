#include "nonce.h"
#include <nvs.h>
#include <nvs_flash.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

esp_err_t load_nonce(_Atomic uint_least32_t *nonce) {
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

uint32_t get_and_update_nonce(_Atomic uint_least32_t *nonce) {
  uint32_t new_nonce = atomic_fetch_add(nonce, 1) + 1;

  nvs_handle_t nvs_handle;
  esp_err_t ret;

  ret = nvs_open("storage", NVS_READWRITE, &nvs_handle);
  if (ret != ESP_OK) {
    printf("Error (%s) opening NVS handle!\n", esp_err_to_name(ret));
    // Even if NVS operations fail, we still return the incremented nonce
    return new_nonce;
  }

  ret = nvs_set_u32(nvs_handle, "nonce", new_nonce);
  if (ret != ESP_OK) {
    printf("Error (%s) setting nonce in NVS!\n", esp_err_to_name(ret));
    nvs_close(nvs_handle);
    return new_nonce;
  }

  ret = nvs_commit(nvs_handle);
  if (ret != ESP_OK) {
    printf("Error (%s) committing NVS!\n", esp_err_to_name(ret));
    nvs_close(nvs_handle);
    return new_nonce;
  }

  nvs_close(nvs_handle);
  return new_nonce;
}
