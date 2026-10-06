set(UI_DIR ${CMAKE_CURRENT_LIST_DIR})
set(LVGL_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../managed_components/lvgl__lvgl)

if(EXISTS ${LVGL_DIR}/lvgl.h)
    file(GLOB_RECURSE LVGL_SOURCES ${LVGL_DIR}/src/*.c)
    add_library(lvgl_host STATIC ${LVGL_SOURCES})
    target_include_directories(lvgl_host PUBLIC ${LVGL_DIR} ${UI_DIR})
    target_compile_definitions(lvgl_host PUBLIC LV_CONF_INCLUDE_SIMPLE)
    target_compile_options(lvgl_host PRIVATE -w)

    find_package(Threads REQUIRED)
    add_executable(test_ui
        ${UI_DIR}/test_ui.c
        ${UI_DIR}/ui_harness.c
        ${MAIN_DIR}/ux_display.c
        ${MAIN_DIR}/ux_manager.c
        ${MAIN_DIR}/ux_serial.c)
    target_include_directories(test_ui PRIVATE ${UI_DIR}/shim ${MAIN_DIR})
    target_compile_definitions(test_ui PRIVATE CONFIG_KEEP_DISPLAY_ENABLED)
    target_link_libraries(test_ui lvgl_host Threads::Threads)
elseif(REQUIRE_ALL_TESTS)
    message(FATAL_ERROR "LVGL not found at ${LVGL_DIR}; test_ui needs the pinned lvgl/lvgl 9.5.0")
else()
    message(STATUS "test_ui skipped: LVGL not found at ${LVGL_DIR}")
endif()
