// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

// Minimal stand-ins for the nostr_frost event codec so frost_coordinator.c can
// be exercised natively. Serialization itself is covered by test_frost.

#include "nostr_frost.h"
#include "nostr_frost_stubs.h"

#include <stdio.h>
#include <string.h>

ns_stub_counts_t ns_stub_counts;

void ns_stub_reset(void) {
    memset(&ns_stub_counts, 0, sizeof(ns_stub_counts));
}

static int emit(char *event_json, size_t max_len, int kind) {
    int n = snprintf(event_json, max_len, "{\"kind\":%d,\"content\":\"stub\"}", kind);
    return (n > 0 && (size_t)n < max_len) ? 0 : -1;
}

int frost_create_sign_request(const frost_group_t *group, const frost_sign_request_t *request,
                              const uint8_t *privkey, char *event_json, size_t max_len) {
    (void)group;
    (void)request;
    (void)privkey;
    return emit(event_json, max_len, FROST_KIND_SIGN_REQUEST);
}

int frost_create_sign_response(const frost_group_t *group, const frost_sign_response_t *response,
                               const uint8_t *privkey, char *event_json, size_t max_len) {
    (void)group;
    (void)response;
    (void)privkey;
    return emit(event_json, max_len, FROST_KIND_SIGN_RESPONSE);
}

int frost_create_dkg_round1_event(const frost_group_t *group, const frost_dkg_round1_t *round1,
                                  const uint8_t *privkey, char *event_json, size_t max_len) {
    (void)group;
    (void)round1;
    (void)privkey;
    return emit(event_json, max_len, FROST_KIND_DKG_ROUND1);
}

int frost_create_dkg_round2_event(const frost_group_t *group, const frost_dkg_round2_t *round2,
                                  const uint8_t *our_privkey, const uint8_t *recipient_pubkey,
                                  char *event_json, size_t max_len) {
    (void)group;
    (void)round2;
    (void)our_privkey;
    (void)recipient_pubkey;
    return emit(event_json, max_len, FROST_KIND_DKG_ROUND2);
}

int frost_parse_sign_request(const char *event_json, const frost_group_t *group,
                             const uint8_t *our_privkey, frost_sign_request_t *request) {
    (void)event_json;
    (void)group;
    (void)our_privkey;
    memset(request, 0, sizeof(*request));
    ns_stub_counts.parse_sign_request++;
    return 0;
}

int frost_parse_sign_response(const char *event_json, const frost_group_t *group,
                              const uint8_t *our_privkey, frost_sign_response_t *response) {
    (void)event_json;
    (void)group;
    (void)our_privkey;
    memset(response, 0, sizeof(*response));
    ns_stub_counts.parse_sign_response++;
    return 0;
}

int frost_parse_dkg_round1_event(const char *event_json, const frost_group_t *group,
                                 const uint8_t *our_privkey, frost_dkg_round1_t *round1) {
    (void)event_json;
    (void)group;
    (void)our_privkey;
    memset(round1, 0, sizeof(*round1));
    ns_stub_counts.parse_dkg_round1++;
    return 0;
}

int frost_parse_dkg_round2_event(const char *event_json, const frost_group_t *group,
                                 const uint8_t *our_privkey, frost_dkg_round2_t *round2) {
    (void)event_json;
    (void)group;
    (void)our_privkey;
    memset(round2, 0, sizeof(*round2));
    ns_stub_counts.parse_dkg_round2++;
    return 0;
}

int frost_parse_nip46_event(const char *event_json, const uint8_t *our_privkey,
                            nip46_request_t *request) {
    (void)event_json;
    (void)our_privkey;
    memset(request, 0, sizeof(*request));
    ns_stub_counts.parse_nip46++;
    return 0;
}

void frost_sign_request_free(frost_sign_request_t *request) {
    (void)request;
}

void frost_nip46_request_free(nip46_request_t *request) {
    (void)request;
}
