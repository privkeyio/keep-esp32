set(SRCS
    "main.c" "protocol.c" "serial.c" "storage.c" "storage_crypto.c" "storage_checkpoint.c" "storage_metadata.c" "storage_export.c"
    "frost_signer.c" "frost_signer_storage.c" "frost_tr_task.c"
    "psbt.c" "psbt_fraud.c" "policy.c" "policy_pin.c" "bitcoin_rpc.c" "sign_approval.c"
    "error_context.c" "error_codes.c" "random_utils.c" "hw_entropy.c" "ux_manager.c" "ux_serial.c" "self_test.c" "anti_glitch.c"
)

set(REQUIRES
    esp_partition driver esp_driver_usb_serial_jtag esp_driver_uart esp_driver_gpio mbedtls crypto_asm libnostr-c noscrypt secure_element
)

set(PRIV_REQUIRES
    bootloader_support frost_tr secp256k1-frost espressif__cjson espressif__esp_websocket_client libwally-core nvs_flash
)

if(CONFIG_KEEP_DISPLAY_ENABLED)
    list(APPEND SRCS "ux_display.c" "touch_input.c")
    list(APPEND PRIV_REQUIRES espressif__m5stack_core_s3 espressif__esp_lcd_touch espressif__esp_lvgl_port)
endif()

if(CONFIG_KEEP_UI_TEST)
    list(APPEND SRCS "ui_test.c")
endif()

idf_component_register(
    SRCS ${SRCS}
    INCLUDE_DIRS "."
    REQUIRES ${REQUIRES}
    PRIV_REQUIRES ${PRIV_REQUIRES}
)
