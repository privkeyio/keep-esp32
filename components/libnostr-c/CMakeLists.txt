set(LIBNOSTR_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../libnostr-c)

idf_component_register(
    SRCS
        "${LIBNOSTR_DIR}/src/bech32.c"
        "${LIBNOSTR_DIR}/src/config.c"
        "${LIBNOSTR_DIR}/src/event.c"
        "${LIBNOSTR_DIR}/src/features.c"
        "${LIBNOSTR_DIR}/src/key.c"
        "${LIBNOSTR_DIR}/src/nip44.c"
        "${LIBNOSTR_DIR}/src/utils.c"
    INCLUDE_DIRS
        "${CMAKE_CURRENT_LIST_DIR}"
        "${CMAKE_CURRENT_LIST_DIR}/include"
        "${LIBNOSTR_DIR}/include"
        "${LIBNOSTR_DIR}/src"
    REQUIRES noscrypt espressif__cjson mbedtls secp256k1-frost
)

target_compile_definitions(${COMPONENT_LIB} PUBLIC
    HAVE_MBEDTLS=1
    HAVE_NOSCRYPT=1
    HAVE_SECP256K1=1
    HAVE_CJSON=1
    NOSTR_FEATURE_EVENTS=1
    NOSTR_FEATURE_KEYS=1
    NOSTR_FEATURE_JSON_ENHANCED=1
    NOSTR_FEATURE_CRYPTO_NOSCRYPT=1
    ESP_PLATFORM=1
)
