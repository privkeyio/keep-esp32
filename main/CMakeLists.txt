idf_component_register(
    SRCS "main.c" "kfp.c" "session.c" "frost.c" "nostr.c" "provision.c"
    INCLUDE_DIRS "."
    REQUIRES nvs_flash esp_wifi esp_event esp_netif nvs_sec_provider
    PRIV_REQUIRES secp256k1-frost libnostr-c
)
