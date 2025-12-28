idf_component_register(
    SRCS "main.c" "protocol.c" "serial.c" "storage.c" "frost_signer.c" "frost.c" "session.c" "kfp.c"
    INCLUDE_DIRS "."
    REQUIRES nvs_flash driver esp_driver_usb_serial_jtag esp_driver_uart esp_driver_gpio
    PRIV_REQUIRES secp256k1-frost espressif__cjson
)
