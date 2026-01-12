#include "error_context.h"
#include <string.h>

static const char *path_basename(const char *path) {
    const char *last = path;
    for (; *path; path++) {
        if (*path == '/' || *path == '\\') {
            last = path + 1;
        }
    }
    return last;
}

void error_context_set(error_context_t *ctx, int code, const char *file,
                       uint16_t line, const char *func) {
    ctx->code = code;
    ctx->line = line;

    const char *base = path_basename(file);
    strncpy(ctx->file, base, ERROR_FILE_LEN - 1);
    ctx->file[ERROR_FILE_LEN - 1] = '\0';

    strncpy(ctx->func, func, ERROR_FUNC_LEN - 1);
    ctx->func[ERROR_FUNC_LEN - 1] = '\0';
}
