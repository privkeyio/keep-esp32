#include "protocol.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > PROTOCOL_MAX_MESSAGE_LEN) {
        return 0;
    }

    char *json = malloc(size + 1);
    if (!json) {
        return 0;
    }
    memcpy(json, data, size);
    json[size] = '\0';

    rpc_request_t req;
    int ret = protocol_parse_request(json, &req);

    if (ret == 0) {
        rpc_response_t resp;
        char buf[4096];
        protocol_success(&resp, req.id, "{\"ok\":true}");
        protocol_format_response(&resp, buf, sizeof(buf));
        protocol_free_request(&req);
    }

    free(json);
    return 0;
}
