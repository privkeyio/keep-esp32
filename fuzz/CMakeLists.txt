cmake_minimum_required(VERSION 3.14)
project(keep_fuzz C)

if(NOT UNIX)
    message(FATAL_ERROR "Fuzzing requires Unix (Linux/macOS)")
endif()

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "LibFuzzer requires Clang. Configure with: CC=clang cmake ..")
endif()

set(CMAKE_C_STANDARD 99)

set(MAIN_DIR ${CMAKE_CURRENT_LIST_DIR}/../main)

include(FetchContent)
FetchContent_Declare(
    cjson
    GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
    GIT_TAG v1.7.18
)
FetchContent_MakeAvailable(cjson)
set(CJSON_DIR ${cjson_SOURCE_DIR})

set(FUZZ_FLAGS "-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g")
set(FUZZ_LINK_FLAGS "-fsanitize=fuzzer,address,undefined")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FUZZ_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${FUZZ_LINK_FLAGS}")

add_compile_definitions(NATIVE_TEST=1)

add_executable(fuzz_protocol fuzz_protocol.c ${CJSON_DIR}/cJSON.c ${MAIN_DIR}/protocol.c ${MAIN_DIR}/error_context.c)
target_include_directories(fuzz_protocol PRIVATE ${CJSON_DIR} ${MAIN_DIR})

add_executable(fuzz_hex fuzz_hex.c)
target_include_directories(fuzz_hex PRIVATE ${MAIN_DIR})

add_executable(fuzz_dkg fuzz_dkg.c)
target_include_directories(fuzz_dkg PRIVATE ${MAIN_DIR})

find_package(PkgConfig)
pkg_check_modules(WALLYCORE wallycore)
pkg_check_modules(MBEDTLS mbedtls)

if(WALLYCORE_FOUND)
    pkg_check_modules(SECP256K1 libsecp256k1)
    add_executable(fuzz_psbt fuzz_psbt.c)
    target_include_directories(fuzz_psbt PRIVATE ${WALLYCORE_INCLUDE_DIRS})
    target_link_libraries(fuzz_psbt ${WALLYCORE_LIBRARIES} ${SECP256K1_LIBRARIES})
    target_link_directories(fuzz_psbt PRIVATE ${WALLYCORE_LIBRARY_DIRS} ${SECP256K1_LIBRARY_DIRS})
else()
    message(WARNING "libwally-core not found, skipping fuzz_psbt")
endif()

add_executable(fuzz_policy fuzz_policy.c ${CJSON_DIR}/cJSON.c)
target_include_directories(fuzz_policy PRIVATE ${CJSON_DIR})

add_executable(fuzz_nostr fuzz_nostr.c ${CJSON_DIR}/cJSON.c)
target_include_directories(fuzz_nostr PRIVATE ${MAIN_DIR} ${CJSON_DIR})

if(MBEDTLS_FOUND)
    pkg_check_modules(MBEDCRYPTO mbedcrypto)
    add_executable(fuzz_storage_crypto fuzz_storage_crypto.c)
    target_include_directories(fuzz_storage_crypto PRIVATE ${MBEDTLS_INCLUDE_DIRS})
    target_link_libraries(fuzz_storage_crypto ${MBEDTLS_LIBRARIES} ${MBEDCRYPTO_LIBRARIES})
    target_link_directories(fuzz_storage_crypto PRIVATE ${MBEDTLS_LIBRARY_DIRS} ${MBEDCRYPTO_LIBRARY_DIRS})
else()
    message(WARNING "mbedtls not found, skipping fuzz_storage_crypto")
endif()
