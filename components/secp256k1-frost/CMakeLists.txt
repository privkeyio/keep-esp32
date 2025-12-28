set(SECP_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../secp256k1-frost)

idf_component_register(
    SRCS
        "${SECP_DIR}/src/secp256k1.c"
        "${SECP_DIR}/src/precomputed_ecmult.c"
        "${SECP_DIR}/src/precomputed_ecmult_gen.c"
        "${CMAKE_CURRENT_LIST_DIR}/esp_random_adapter.c"
    INCLUDE_DIRS
        "${SECP_DIR}/include"
        "${CMAKE_CURRENT_LIST_DIR}/include"
    PRIV_INCLUDE_DIRS
        "${SECP_DIR}/src"
    PRIV_REQUIRES
        esp_hw_support
)

target_compile_definitions(${COMPONENT_LIB} PUBLIC
    ENABLE_MODULE_FROST=1
    ENABLE_MODULE_SCHNORRSIG=1
    ENABLE_MODULE_EXTRAKEYS=1
    ENABLE_MODULE_ECDH=1
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    ECMULT_GEN_PREC_BITS=2
    ECMULT_WINDOW_SIZE=2
    USE_EXTERNAL_DEFAULT_CALLBACKS=1
)

target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wno-unused-function
    -Wno-nonnull-compare
)
