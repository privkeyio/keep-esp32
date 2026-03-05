// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef ERROR_CONTEXT_H
#define ERROR_CONTEXT_H

#include <stdint.h>

#define ERROR_FILE_LEN 32
#define ERROR_FUNC_LEN 32

typedef struct {
    int code;
    uint16_t line;
    char file[ERROR_FILE_LEN];
    char func[ERROR_FUNC_LEN];
} error_context_t;

void error_context_set(error_context_t *ctx, int code, const char *file, uint16_t line,
                       const char *func);

#define ERROR_SET(ctx, code) error_context_set((ctx), (code), __FILE__, __LINE__, __func__)

#endif
