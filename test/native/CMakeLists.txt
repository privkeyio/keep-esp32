cmake_minimum_required(VERSION 3.10)
project(keep_native_tests C)

if(NOT UNIX)
    message(FATAL_ERROR "Native tests require Unix (Linux/macOS) for /dev/urandom entropy source")
endif()

set(CMAKE_C_STANDARD 99)

set(SECP_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../secp256k1-frost)
set(CJSON_DIR ${CMAKE_CURRENT_LIST_DIR}/../../managed_components/espressif__cjson/cJSON)
set(MAIN_DIR ${CMAKE_CURRENT_LIST_DIR}/../../main)

add_executable(test_frost test_frost.c)
target_include_directories(test_frost PRIVATE ${SECP_DIR}/include)
target_link_directories(test_frost PRIVATE ${SECP_DIR}/build/src)
target_link_libraries(test_frost secp256k1)
set_target_properties(test_frost PROPERTIES
    BUILD_RPATH ${SECP_DIR}/build/src
    INSTALL_RPATH ${SECP_DIR}/build/src
)

if(EXISTS ${CJSON_DIR}/cJSON.c)
    add_executable(test_protocol test_protocol.c ${CJSON_DIR}/cJSON.c ${MAIN_DIR}/protocol.c ${MAIN_DIR}/error_context.c ${MAIN_DIR}/error_codes.c)
    target_include_directories(test_protocol PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/mocks
        ${CJSON_DIR}
        ${MAIN_DIR}
    )
    target_compile_definitions(test_protocol PRIVATE
        NATIVE_TEST=1
    )
else()
    message(STATUS "Skipping test_protocol (cJSON not found)")
endif()

add_executable(test_storage test_storage.c)
target_include_directories(test_storage PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
    ${MAIN_DIR}
)
target_compile_definitions(test_storage PRIVATE NATIVE_TEST=1)

add_executable(test_session test_session.c)
target_include_directories(test_session PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
    ${MAIN_DIR}
)
target_compile_definitions(test_session PRIVATE NATIVE_TEST=1)

add_executable(test_secure_element test_secure_element.c)
target_include_directories(test_secure_element PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../components/secure_element/include
)
target_compile_definitions(test_secure_element PRIVATE NATIVE_TEST=1 SE_MOCK_SKIP_IMPL=1)

add_executable(test_frost_signer_core test_frost_signer_core.c ${MAIN_DIR}/frost_signer_core.c ${MAIN_DIR}/frost.c ${MAIN_DIR}/random_utils.c ${MAIN_DIR}/hw_entropy.c)
target_include_directories(test_frost_signer_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
    ${MAIN_DIR}
    ${SECP_DIR}/include
)
target_link_directories(test_frost_signer_core PRIVATE ${SECP_DIR}/build/src)
target_link_libraries(test_frost_signer_core secp256k1)
set_target_properties(test_frost_signer_core PROPERTIES
    BUILD_RPATH ${SECP_DIR}/build/src
    INSTALL_RPATH ${SECP_DIR}/build/src
)
target_compile_definitions(test_frost_signer_core PRIVATE NATIVE_TEST=1)

add_executable(test_secresult test_secresult.c)
target_include_directories(test_secresult PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
)
target_compile_definitions(test_secresult PRIVATE NATIVE_TEST=1)

add_executable(test_integration test_integration.c)
target_include_directories(test_integration PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
    ${MAIN_DIR}
)
target_compile_definitions(test_integration PRIVATE NATIVE_TEST=1)

if(EXISTS ${CJSON_DIR}/cJSON.c)
    add_executable(test_integration_full test_integration.c ${CJSON_DIR}/cJSON.c ${MAIN_DIR}/error_codes.c)
    target_include_directories(test_integration_full PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/mocks
        ${MAIN_DIR}
        ${CJSON_DIR}
    )
    target_compile_definitions(test_integration_full PRIVATE NATIVE_TEST=1 HAS_CJSON=1)
endif()

find_package(MbedTLS QUIET)
if(MbedTLS_FOUND)
    add_executable(test_self_test test_self_test.c)
    target_include_directories(test_self_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/mocks
        ${MAIN_DIR}
    )
    target_compile_definitions(test_self_test PRIVATE NATIVE_TEST=1 UNIT_TEST=1)
    target_link_libraries(test_self_test MbedTLS::mbedcrypto)
else()
    find_library(MBEDCRYPTO_LIB mbedcrypto)
    if(MBEDCRYPTO_LIB)
        add_executable(test_self_test test_self_test.c)
        target_include_directories(test_self_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/mocks
            ${MAIN_DIR}
        )
        target_compile_definitions(test_self_test PRIVATE NATIVE_TEST=1 UNIT_TEST=1)
        target_link_libraries(test_self_test ${MBEDCRYPTO_LIB})
    else()
        message(STATUS "Skipping test_self_test (mbedtls not found)")
    endif()
endif()

add_executable(test_hw_entropy test_hw_entropy.c ${MAIN_DIR}/hw_entropy.c ${MAIN_DIR}/random_utils.c)
# main/ first: mocks/random_utils.h otherwise shadows the real header, and its
# static inline rng_init/rng_get_health/secure_random_fill silently bind ahead of
# the random_utils.c compiled into this very target -- so the RNG tests would be
# asserting against the mock, not the code. mocks/ still supplies crypto_asm.h
# and secresult.h, which main/ does not have.
target_include_directories(test_hw_entropy PRIVATE
    ${MAIN_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
)
target_compile_definitions(test_hw_entropy PRIVATE NATIVE_TEST=1)

find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    add_executable(test_hw_entropy_sha256 test_hw_entropy.c ${MAIN_DIR}/hw_entropy.c ${MAIN_DIR}/random_utils.c)
    target_include_directories(test_hw_entropy_sha256 PRIVATE
        ${MAIN_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/mocks
    )
    target_compile_definitions(test_hw_entropy_sha256 PRIVATE NATIVE_TEST=1 HAS_OPENSSL=1)
    target_link_libraries(test_hw_entropy_sha256 OpenSSL::Crypto)
endif()

add_executable(test_psbt_fraud test_psbt_fraud.c)
target_include_directories(test_psbt_fraud PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
)
target_compile_definitions(test_psbt_fraud PRIVATE NATIVE_TEST=1)

set(WALLY_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../libwally-core)
if(EXISTS ${WALLY_DIR}/include/wally_psbt.h)
    add_executable(test_psbt_fraud_integration test_psbt_fraud_integration.c ${MAIN_DIR}/psbt_fraud.c)
    target_include_directories(test_psbt_fraud_integration PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/mocks
        ${MAIN_DIR}
        ${WALLY_DIR}/include
    )
    target_link_directories(test_psbt_fraud_integration PRIVATE ${WALLY_DIR}/src/.libs)
    target_link_libraries(test_psbt_fraud_integration wallycore)
    set_target_properties(test_psbt_fraud_integration PROPERTIES
        BUILD_RPATH ${WALLY_DIR}/src/.libs
        INSTALL_RPATH ${WALLY_DIR}/src/.libs
    )
    target_compile_definitions(test_psbt_fraud_integration PRIVATE NATIVE_TEST=1)
else()
    message(STATUS "Skipping test_psbt_fraud_integration (libwally-core not found)")
endif()

add_executable(test_anti_glitch test_anti_glitch.c ${MAIN_DIR}/anti_glitch.c)
target_include_directories(test_anti_glitch PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
    ${MAIN_DIR}
)
target_compile_definitions(test_anti_glitch PRIVATE NATIVE_TEST=1)

if(EXISTS ${CJSON_DIR}/cJSON.c)
    add_executable(test_coordinator
        test_coordinator.c
        ${MAIN_DIR}/frost_coordinator.c
        ${MAIN_DIR}/random_utils.c
        ${MAIN_DIR}/hw_entropy.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mocks/ws_transport_mock.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mocks/nostr_frost_stubs.c
        ${CJSON_DIR}/cJSON.c
    )
    target_include_directories(test_coordinator PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/mocks
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${MAIN_DIR}
        ${CJSON_DIR}
    )
    target_compile_definitions(test_coordinator PRIVATE NATIVE_TEST=1)
    find_package(Threads REQUIRED)
    target_link_libraries(test_coordinator Threads::Threads)
else()
    message(STATUS "Skipping test_coordinator (cJSON not found)")
endif()

if(EXISTS ${CJSON_DIR}/cJSON.c)
    add_executable(test_coordinator_race
        test_coordinator_race.c
        ${MAIN_DIR}/frost_coordinator.c
        ${MAIN_DIR}/random_utils.c
        ${MAIN_DIR}/hw_entropy.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mocks/ws_transport_mock.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mocks/nostr_frost_stubs.c
        ${CJSON_DIR}/cJSON.c
    )
    target_include_directories(test_coordinator_race PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/mocks
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${MAIN_DIR}
        ${CJSON_DIR}
    )
    target_compile_definitions(test_coordinator_race PRIVATE NATIVE_TEST=1)
    set_target_properties(test_coordinator_race PROPERTIES C_STANDARD 11)
    find_package(Threads REQUIRED)
    target_link_libraries(test_coordinator_race Threads::Threads)

    include(CheckCCompilerFlag)
    check_c_compiler_flag(-fsanitize=thread HAVE_TSAN)
    if(HAVE_TSAN)
        target_compile_options(test_coordinator_race PRIVATE -fsanitize=thread -g)
        target_link_options(test_coordinator_race PRIVATE -fsanitize=thread)
    else()
        message(STATUS "test_coordinator_race: ThreadSanitizer unavailable")
    endif()
endif()

find_library(MBEDCRYPTO_LIB mbedcrypto)
if(MBEDCRYPTO_LIB)
    # Real mbedtls (SHA-256/HMAC/GCM/HKDF/PBKDF2), NOT the mocks/ stubs, so the
    # PBKDF2 and HMAC-tamper tests actually exercise crypto. Deliberately avoids
    # -Imocks (its mbedtls/ stubs would shadow the system headers); crypto_asm
    # and the pbkdf2 _ext shim are supplied by pin_test_compat.c.
    add_executable(test_pin_attempt_limit
        test_pin_attempt_limit.c
        pin_test_compat.c
        ${MAIN_DIR}/random_utils.c
        ${MAIN_DIR}/hw_entropy.c
        ${MAIN_DIR}/error_codes.c
    )
    target_include_directories(test_pin_attempt_limit PRIVATE
        ${MAIN_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/../../components/crypto_asm/include
        ${CMAKE_CURRENT_LIST_DIR}/../../components/secure_element/include
    )
    target_compile_definitions(test_pin_attempt_limit PRIVATE NATIVE_TEST=1 UNIT_TEST=1)
    target_link_libraries(test_pin_attempt_limit ${MBEDCRYPTO_LIB})
else()
    message(STATUS "Skipping test_pin_attempt_limit (mbedtls not found)")
endif()
