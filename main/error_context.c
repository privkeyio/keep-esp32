#include "error_context.h"
#include <string.h>

static const char *path_basename(const char *path) {
    if (!path)
        return "";
    const char *basename = path;
    for (const char *p = path; *p; p++) {
        if (*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }
    return basename;
}

static void safe_string_copy(char *dest, size_t dest_size, const char *src) {
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dest_size - 1) ? src_len : (dest_size - 1);
    memcpy(dest, src, copy_len);
    dest[copy_len] = '\0';
}

void error_context_set(error_context_t *ctx, int code, const char *file, uint16_t line,
                       const char *func) {
    ctx->code = code;
    ctx->line = line;

    const char *base = path_basename(file);
    safe_string_copy(ctx->file, ERROR_FILE_LEN, base);
    safe_string_copy(ctx->func, ERROR_FUNC_LEN, func);
}
