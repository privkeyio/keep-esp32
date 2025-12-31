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
    add_executable(test_protocol test_protocol.c ${CJSON_DIR}/cJSON.c ${MAIN_DIR}/protocol.c)
    target_include_directories(test_protocol PRIVATE
        ${CJSON_DIR}
        ${MAIN_DIR}
    )
    target_compile_definitions(test_protocol PRIVATE
        NATIVE_TEST=1
    )
else()
    message(STATUS "Skipping test_protocol (cJSON not found)")
endif()
