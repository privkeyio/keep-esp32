// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "hex_utils.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 2048) {
        return 0;
    }

    char *hex = malloc(size + 1);
    if (!hex) {
        return 0;
    }
    memcpy(hex, data, size);
    hex[size] = '\0';

    uint8_t out[1024];
    hex_to_bytes(hex, out, sizeof(out));

    free(hex);
    return 0;
}
