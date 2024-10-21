idf_component_register(SRCS "cyberfrog_main.c"
                    INCLUDE_DIRS ""
                    PRIV_REQUIRES nvs_flash mbedtls signer utils esp_timer zorxx__neopixel driver
                    )
