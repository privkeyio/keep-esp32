// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef NOSTR_FROST_INTERNAL_H
#define NOSTR_FROST_INTERNAL_H

#include "nostr_frost.h"
#include "cJSON.h"
#include <stdint.h>

int compute_event_id(cJSON *event, uint8_t id_out[32]);
int sign_event_json(cJSON *event, const uint8_t privkey[32]);
char *nip44_encrypt_content(const char *plaintext, const uint8_t sender_priv[32],
                            const uint8_t recipient_pub[32]);
char *nip44_decrypt_content(const char *ciphertext, const uint8_t recipient_priv[32],
                            const uint8_t sender_pub[32]);

#endif
