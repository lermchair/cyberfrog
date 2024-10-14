idf_component_register(SRCS "ecdsa.c" "rsa.c"
                       INCLUDE_DIRS .
                       REQUIRES mbedtls utils
                       )
