#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <wally_core.h>
#include <wally_psbt.h>

#define MAX_BASE64_LEN 8192

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    wally_init(0);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > MAX_BASE64_LEN) {
        return 0;
    }

    char *base64 = malloc(size + 1);
    if (!base64) {
        return 0;
    }
    memcpy(base64, data, size);
    base64[size] = '\0';

    struct wally_psbt *psbt = NULL;
    if (wally_psbt_from_base64(base64, 0, &psbt) == WALLY_OK && psbt) {
        wally_psbt_free(psbt);
    }

    free(base64);
    return 0;
}
