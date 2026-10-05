// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef UI_TEST_H
#define UI_TEST_H

#include "protocol.h"
#include <stdbool.h>

/* Test builds only (CONFIG_KEEP_UI_TEST): lets a host tap the touchscreen and read
 * what it shows, so device UI flows run end to end without a person. */
#ifdef CONFIG_KEEP_UI_TEST
void ui_test_init(void);
bool ui_test_handle(const char *line, const rpc_request_t *req, rpc_response_t *resp);
#else
static inline void ui_test_init(void) {
}
static inline bool ui_test_handle(const char *line, const rpc_request_t *req,
                                  rpc_response_t *resp) {
    (void)line;
    (void)req;
    (void)resp;
    return false;
}
#endif

#endif
