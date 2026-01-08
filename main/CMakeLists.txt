idf_component_register(
    SRCS "main.c" "protocol.c" "serial.c" "storage.c" "frost_signer.c" "frost.c" "session.c"
         "nostr_frost.c" "nostr_frost_sign.c" "nostr_frost_dkg_events.c" "nostr_frost_nip46.c"
         "frost_crypto_ops.c" "frost_coordinator.c" "frost_dkg.c" "psbt.c" "policy.c"
         "hex_utils.c" "random_utils.c"
    INCLUDE_DIRS "."
    REQUIRES esp_partition driver esp_driver_usb_serial_jtag esp_driver_uart esp_driver_gpio mbedtls crypto_asm libnostr-c noscrypt
    PRIV_REQUIRES secp256k1-frost espressif__cjson espressif__esp_websocket_client libwally-core
)
