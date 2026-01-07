set(WALLY_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../libwally-core)

set(WALLY_SRCS
    "${WALLY_DIR}/src/base_58.c"
    "${WALLY_DIR}/src/base_64.c"
    "${WALLY_DIR}/src/bech32.c"
    "${WALLY_DIR}/src/bip32.c"
    "${WALLY_DIR}/src/hex_.c"
    "${WALLY_DIR}/src/hmac.c"
    "${WALLY_DIR}/src/internal.c"
    "${WALLY_DIR}/src/map.c"
    "${WALLY_DIR}/src/psbt.c"
    "${WALLY_DIR}/src/pullpush.c"
    "${WALLY_DIR}/src/script.c"
    "${WALLY_DIR}/src/sign.c"
    "${WALLY_DIR}/src/transaction.c"
    "${WALLY_DIR}/src/tx_io.c"
    "${WALLY_DIR}/src/ccan/ccan/base64/base64.c"
    "${WALLY_DIR}/src/ccan/ccan/crypto/ripemd160/ripemd160.c"
    "${WALLY_DIR}/src/ccan/ccan/crypto/sha256/sha256.c"
    "${WALLY_DIR}/src/ccan/ccan/crypto/sha512/sha512.c"
    "${WALLY_DIR}/src/ccan/ccan/str/hex/hex.c"
)

idf_component_register(
    SRCS
        ${WALLY_SRCS}
        "${CMAKE_CURRENT_LIST_DIR}/wally_esp32.c"
    INCLUDE_DIRS
        "${WALLY_DIR}/include"
        "${CMAKE_CURRENT_LIST_DIR}/include"
    PRIV_INCLUDE_DIRS
        "${WALLY_DIR}"
        "${WALLY_DIR}/src"
        "${WALLY_DIR}/src/ccan"
        "${CMAKE_CURRENT_LIST_DIR}/include"
    REQUIRES
        secp256k1-frost
        mbedtls
)

target_compile_definitions(${COMPONENT_LIB} PUBLIC
    WALLY_CORE_BUILD=1
    BUILD_STANDARD_SECP=1
    HAVE_MBEDTLS_SHA256_H=1
    HAVE_MBEDTLS_SHA512_H=1
    HAVE_INLINE_ASM=1
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    SECP256K1_BUILD=1
)

target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wno-unused-function
    -Wno-unused-parameter
    -Wno-sign-compare
    -Wno-implicit-fallthrough
    -Wno-unterminated-string-initialization
    -Wno-missing-field-initializers
)
