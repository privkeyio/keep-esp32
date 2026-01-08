#include "random_utils.h"

#ifdef ESP_PLATFORM
#include "esp_random.h"

int secure_random_fill(uint8_t *buf, size_t len) {
    esp_fill_random(buf, len);
    return 0;
}

#else
#include <stdio.h>

int secure_random_fill(uint8_t *buf, size_t len) {
    FILE *fp = fopen("/dev/urandom", "r");
    if (!fp) return -1;
    size_t total = 0;
    while (total < len) {
        size_t n = fread(buf + total, 1, len - total, fp);
        if (n == 0) { fclose(fp); return -1; }
        total += n;
    }
    fclose(fp);
    return 0;
}

#endif
