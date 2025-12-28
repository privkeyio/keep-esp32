#ifndef NOSTR_FEATURES_H
#define NOSTR_FEATURES_H

#define NOSTR_FEATURE_STD 1
#define NOSTR_FEATURE_EVENTS 1
#define NOSTR_FEATURE_KEYS 1
#define NOSTR_FEATURE_ENCODING 1
#define NOSTR_FEATURE_JSON_ENHANCED 1

int nostr_feature_nip_supported(int nip_number);
int nostr_feature_relay_available(void);
int nostr_feature_hd_keys_available(void);
int nostr_feature_json_enhanced_available(void);
int nostr_feature_relay_protocol_available(void);
const char* nostr_feature_list_enabled(void);
const char* nostr_feature_crypto_backend_info(void);

#endif
