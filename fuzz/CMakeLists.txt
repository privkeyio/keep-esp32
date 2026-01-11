cmake_minimum_required(VERSION 3.14)
project(keep_fuzz C)

if(NOT UNIX)
    message(FATAL_ERROR "Fuzzing requires Unix (Linux/macOS)")
endif()

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "LibFuzzer requires Clang. Configure with: CC=clang cmake ..")
endif()

set(CMAKE_C_STANDARD 99)

option(USE_LIBFUZZER "Use libFuzzer" ON)

set(MAIN_DIR ${CMAKE_CURRENT_LIST_DIR}/../main)

include(FetchContent)
FetchContent_Declare(
    cjson
    GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
    GIT_TAG v1.7.18
)
FetchContent_MakeAvailable(cjson)
set(CJSON_DIR ${cjson_SOURCE_DIR})

if(USE_LIBFUZZER)
    set(FUZZ_FLAGS "-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g")
    set(FUZZ_LINK_FLAGS "-fsanitize=fuzzer,address,undefined")
else()
    message(FATAL_ERROR "USE_LIBFUZZER must be ON")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FUZZ_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${FUZZ_LINK_FLAGS}")

add_compile_definitions(NATIVE_TEST=1)

add_executable(fuzz_protocol
    fuzz_protocol.c
    ${CJSON_DIR}/cJSON.c
    ${MAIN_DIR}/protocol.c
)
target_include_directories(fuzz_protocol PRIVATE ${CJSON_DIR} ${MAIN_DIR})

add_executable(fuzz_hex
    fuzz_hex.c
    ${MAIN_DIR}/hex_utils.c
)
target_include_directories(fuzz_hex PRIVATE ${MAIN_DIR})

add_executable(fuzz_dkg
    fuzz_dkg.c
    ${MAIN_DIR}/hex_utils.c
)
target_include_directories(fuzz_dkg PRIVATE ${MAIN_DIR})
