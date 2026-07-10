// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef NOSTR_FROST_STUBS_H
#define NOSTR_FROST_STUBS_H

typedef struct {
    int parse_sign_request;
    int parse_sign_response;
    int parse_dkg_round1;
    int parse_dkg_round2;
    int parse_nip46;
} ns_stub_counts_t;

extern ns_stub_counts_t ns_stub_counts;

void ns_stub_reset(void);

#endif
