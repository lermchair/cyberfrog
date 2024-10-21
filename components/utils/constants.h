#pragma once
#include "driver/i2c.h"
#include "st25dv.h"

#define VEXT_PIN 0
#define VBAT_PIN 1
#define VNFC_PIN 10
#define SDA_PIN 9
#define SCL_PIN 8
#define NFC_INT_PIN 4
#define LED_PIN 6
#define LED_EN 7
#define BUZ_PIN 5
#define BUTTON_PIN 2

#define NFC_DEBOUNCE_TIME_US 1500000 // 1.5s debounce time
#define CC_FILE_ADDR 0x0000
#define CC_FILE_DATA 0x00040000010040E2
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#define EVENT_POWER_CONNECTED BIT0
#define EVENT_POWER_DISCONNECTED BIT1
#define EVENT_NFC_SCANNED BIT2

static i2c_config_t I2C_CONFIG = {
    .mode = I2C_MODE_MASTER,
    .sda_io_num = SDA_PIN,
    .scl_io_num = SCL_PIN,
    .sda_pullup_en = GPIO_PULLUP_ENABLE,
    .scl_pullup_en = GPIO_PULLUP_ENABLE,
    .master.clk_speed = ST25DV_MAX_CLK_SPEED,
};

static st25dv_config ST25DV_CONF = {ST25DV_USER_ADDRESS, ST25DV_SYSTEM_ADDRESS};
