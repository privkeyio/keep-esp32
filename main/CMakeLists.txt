idf_component_register(
    SRCS "main.c" "protocol.c" "serial.c" "storage.c" "storage_crypto.c"
         "frost_signer.c" "frost_signer_core.c" "frost_signer_storage.c"
         "frost.c" "session.c"
         "nostr_frost.c" "nostr_frost_sign.c" "nostr_frost_dkg_events.c" "nostr_frost_nip46.c"
         "frost_crypto_ops.c" "frost_coordinator.c" "frost_dkg.c" "psbt.c" "psbt_fraud.c" "policy.c"
         "error_context.c" "error_codes.c" "random_utils.c" "hw_entropy.c" "ux_manager.c" "ux_serial.c" "self_test.c"
    INCLUDE_DIRS "."
    REQUIRES esp_partition driver esp_driver_usb_serial_jtag esp_driver_uart esp_driver_gpio esp_adc mbedtls crypto_asm libnostr-c noscrypt
    PRIV_REQUIRES secp256k1-frost espressif__cjson espressif__esp_websocket_client libwally-core
)
