set(srcs "")

if(CONFIG_SE_MOCK_MODE)
    list(APPEND srcs "se_mock.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
)
