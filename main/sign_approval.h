// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef SIGN_APPROVAL_H
#define SIGN_APPROVAL_H

#include <stdbool.h>
#include <stdint.h>

/* Messages bitcoin_sign has approved under the installed policy. With a policy
 * installed, frost_commit signs only a message it can consume from here, so the
 * policy cannot be bypassed by sending a sighash straight to frost_commit. */

#define SIGN_APPROVAL_SLOTS  16
#define SIGN_APPROVAL_TTL_MS 120000

void sign_approval_add(const uint8_t message[32], uint32_t now_ms);
bool sign_approval_consume(const uint8_t message[32], uint32_t now_ms);
void sign_approval_clear(void);
uint32_t sign_approval_now_ms(void);

#ifndef ESP_PLATFORM
void sign_approval_test_advance_ms(uint32_t ms);
#endif

#endif
