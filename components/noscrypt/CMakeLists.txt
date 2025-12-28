set(NOSCRYPT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../noscrypt)
set(SECP_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../secp256k1-frost)

idf_component_register(
    SRCS
        "${NOSCRYPT_DIR}/src/hkdf.c"
        "${NOSCRYPT_DIR}/src/nc-crypto.c"
        "${NOSCRYPT_DIR}/src/noscrypt.c"
        "${NOSCRYPT_DIR}/src/noscryptutil.c"
    INCLUDE_DIRS
        "${CMAKE_CURRENT_LIST_DIR}/include"
        "${NOSCRYPT_DIR}/include"
        "${NOSCRYPT_DIR}/src"
    REQUIRES mbedtls secp256k1-frost
)

target_include_directories(${COMPONENT_LIB} PRIVATE
    "${SECP_DIR}"
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    NC_ENABLE_UTILS=1
    MBEDTLS_CRYPTO_LIB=1
    _IMPL_SECURE_ZERO_MEMSET=mbedtls_platform_zeroize
)
