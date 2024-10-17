idf_component_register(SRCS "ecdsa.c" "rsa.c" "nonce.c"
                       INCLUDE_DIRS .
                       REQUIRES mbedtls utils
                       )
