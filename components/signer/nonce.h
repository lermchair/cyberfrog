#pragma once

#include <stdint.h>
#include <esp_err.h>

esp_err_t load_nonce(_Atomic uint_least32_t *nonce);
uint32_t get_and_update_nonce(_Atomic uint_least32_t *nonce);
