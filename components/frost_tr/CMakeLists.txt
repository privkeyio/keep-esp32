set(FROST_TR_LIB "${CMAKE_CURRENT_LIST_DIR}/lib/libfrost_tr.a")

if(NOT EXISTS "${FROST_TR_LIB}")
    message(FATAL_ERROR
        "frost_tr: ${FROST_TR_LIB} is missing. Build it with "
        "scripts/build-frost-tr.sh --docker (or scripts/build-frost-tr.sh inside "
        "the pinned espressif/idf-rust image).")
endif()

idf_component_register(INCLUDE_DIRS "include" PRIV_REQUIRES heap esp_system)

add_prebuilt_library(frost_tr_rust "${FROST_TR_LIB}" PRIV_REQUIRES heap esp_system)
target_link_libraries(${COMPONENT_LIB} INTERFACE frost_tr_rust)
