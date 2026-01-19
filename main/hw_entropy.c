#include "hw_entropy.h"
#include <string.h>

#ifdef ESP_PLATFORM
#include <mbedtls/sha256.h>
#include "crypto_asm.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "hal/adc_types.h"
#include "esp_adc/adc_oneshot.h"

static const char *TAG = "hw_entropy";
static adc_oneshot_unit_handle_t adc_handle = NULL;
static const adc_channel_t NOISE_CHANNEL = ADC_CHANNEL_0;

static int collect_adc_noise(uint8_t *out, size_t len) {
    if (!adc_handle || len == 0)
        return -1;

    for (size_t i = 0; i < len; i++) {
        uint8_t byte = 0;
        for (int bit = 0; bit < 8; bit++) {
            int acc = 0;
            for (int s = 0; s < 4; s++) {
                int raw = 0;
                if (adc_oneshot_read(adc_handle, NOISE_CHANNEL, &raw) != ESP_OK)
                    return -1;
                acc ^= raw;
            }
            byte = (byte << 1) | (acc & 1);
        }
        out[i] = byte;
    }
    return 0;
}

static int get_timing_bit(void) {
    int64_t t1 = esp_timer_get_time();
    volatile uint32_t x = 0;
    for (int j = 0; j < 10; j++)
        x ^= esp_random();
    (void)x;
    int64_t t2 = esp_timer_get_time();
    return (int)((t2 - t1) & 1);
}

static void collect_timing_jitter(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = 0;
        for (int bit = 0; bit < 8; bit++) {
            int result = -1;
            while (result < 0) {
                int b1 = get_timing_bit();
                int b2 = get_timing_bit();
                if (b1 != b2)
                    result = b1;
            }
            byte = (byte << 1) | result;
        }
        out[i] = byte;
    }
}

int hw_entropy_init(void) {
    adc_oneshot_unit_init_cfg_t init_cfg = {
        .unit_id = ADC_UNIT_1,
    };
    if (adc_oneshot_new_unit(&init_cfg, &adc_handle) != ESP_OK) {
        ESP_LOGW(TAG, "ADC init failed, using RNG + timing only");
        return 0;
    }

    adc_oneshot_chan_cfg_t chan_cfg = {
        .atten = ADC_ATTEN_DB_12,
        .bitwidth = ADC_BITWIDTH_12,
    };
    if (adc_oneshot_config_channel(adc_handle, NOISE_CHANNEL, &chan_cfg) != ESP_OK) {
        adc_oneshot_del_unit(adc_handle);
        adc_handle = NULL;
        ESP_LOGW(TAG, "ADC channel config failed, using RNG + timing only");
    }

    ESP_LOGI(TAG, "Hardware entropy mixer initialized (ADC: %s)", adc_handle ? "yes" : "no");
    return 0;
}

int hw_entropy_fill(uint8_t *buf, size_t len) {
    if (!buf || len == 0)
        return -1;

    uint8_t pool[96];
    uint8_t hash[32];
    size_t offset = 0;
    int ret = 0;

    while (offset < len) {
        esp_fill_random(pool, 32);
        collect_timing_jitter(pool + 32, 32);
        if (!adc_handle || collect_adc_noise(pool + 64, 32) != 0) {
            esp_fill_random(pool + 64, 32);
        }

        if (mbedtls_sha256(pool, sizeof(pool), hash, 0) != 0) {
            ret = -1;
            goto cleanup;
        }

        size_t copy_len = len - offset;
        if (copy_len > 32)
            copy_len = 32;
        memcpy(buf + offset, hash, copy_len);
        offset += copy_len;
    }

cleanup:
    secure_memzero(pool, sizeof(pool));
    secure_memzero(hash, sizeof(hash));
    return ret;
}

#else

#include <stdio.h>

int hw_entropy_init(void) {
    return 0;
}

int hw_entropy_fill(uint8_t *buf, size_t len) {
    if (!buf || len == 0)
        return -1;
    FILE *fp = fopen("/dev/urandom", "r");
    if (!fp)
        return -1;
    size_t n = fread(buf, 1, len, fp);
    fclose(fp);
    return n == len ? 0 : -1;
}

#endif
