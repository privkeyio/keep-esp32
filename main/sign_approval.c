// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "sign_approval.h"
#include "crypto_asm.h"
#include <string.h>

typedef struct {
    uint8_t message[32];
    uint64_t added_ms;
    bool used;
} approval_t;

static approval_t approvals[SIGN_APPROVAL_SLOTS];

static bool expired(const approval_t *a, uint64_t now_ms) {
    return now_ms < a->added_ms || now_ms - a->added_ms >= SIGN_APPROVAL_TTL_MS;
}

void sign_approval_add(const uint8_t message[32], uint64_t now_ms) {
    approval_t *slot = NULL;
    for (int i = 0; i < SIGN_APPROVAL_SLOTS && !slot; i++) {
        if (approvals[i].used && ct_compare(approvals[i].message, message, 32) == 0) {
            slot = &approvals[i];
        }
    }
    for (int i = 0; i < SIGN_APPROVAL_SLOTS && !slot; i++) {
        if (!approvals[i].used || expired(&approvals[i], now_ms)) {
            slot = &approvals[i];
        }
    }
    if (!slot) {
        slot = &approvals[0];
        for (int i = 1; i < SIGN_APPROVAL_SLOTS; i++) {
            if ((uint32_t)(now_ms - approvals[i].added_ms) > (uint32_t)(now_ms - slot->added_ms)) {
                slot = &approvals[i];
            }
        }
    }
    memcpy(slot->message, message, 32);
    slot->added_ms = now_ms;
    slot->used = true;
}

secresult_t sign_approval_consume_secure(const uint8_t message[32], uint64_t now_ms) {
    for (int i = 0; i < SIGN_APPROVAL_SLOTS; i++) {
        approval_t *a = &approvals[i];
        if (a->used && ct_compare(a->message, message, 32) == 0) {
            bool valid = !expired(a, now_ms);
            secure_memzero(a, sizeof(*a));
            return valid ? SECRESULT_TRUE : SECRESULT_ERR_POLICY_DENIED;
        }
    }
    return SECRESULT_ERR_POLICY_DENIED;
}

void sign_approval_clear(void) {
    secure_memzero(approvals, sizeof(approvals));
}

#ifdef ESP_PLATFORM
#include "esp_timer.h"

uint64_t sign_approval_now_ms(void) {
    return (uint64_t)esp_timer_get_time() / 1000;
}
#else
#include <time.h>

static uint64_t test_offset_ms = 0;

void sign_approval_test_advance_ms(uint32_t ms) {
    test_offset_ms += ms;
}

uint64_t sign_approval_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000 + test_offset_ms;
}
#endif
