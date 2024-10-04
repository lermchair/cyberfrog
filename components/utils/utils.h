#pragma once
#include "esp_log.h"
#include "esp_system.h"
#include <driver/gpio.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void signature_to_hex(const unsigned char *signature, size_t sig_len,
                      char *hex_output, size_t hex_len);

void signature_to_base64(const unsigned char *signature, size_t sig_len,
                         char *base64_output, size_t out_len);

esp_err_t configure_and_set_gpio_high(int pin);

char *format_url_safely(const char *hex_signature);