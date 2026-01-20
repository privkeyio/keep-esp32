#ifndef FROST_H
#define FROST_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct {
    void *ctx;
    void *keypair;
    uint16_t share_index;
    uint16_t threshold;
    uint16_t participants;
    uint8_t group_pubkey[33];
} frost_state_t;

static inline int frost_init(frost_state_t *state, const uint8_t *share_bytes, size_t share_len) {
    (void)share_bytes;
    (void)share_len;
    memset(state, 0, sizeof(frost_state_t));
    state->threshold = 2;
    state->participants = 3;
    state->share_index = 1;
    memset(state->group_pubkey, 0x02, 1);
    memset(state->group_pubkey + 1, 0xAB, 32);
    return 0;
}

static inline void frost_free(frost_state_t *state) {
    memset(state, 0, sizeof(frost_state_t));
}

#endif
