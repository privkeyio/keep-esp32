// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "hw_entropy.h"
#include <string.h>

static uint32_t g_debiasing_failures = 0;
static bool g_initialized = false;

void hw_entropy_add_debiasing_failure(void) {
    g_debiasing_failures++;
}

uint32_t hw_entropy_get_debiasing_failures(void) {
    return g_debiasing_failures;
}

bool hw_entropy_initialized(void) {
    return g_initialized;
}

#ifdef ESP_PLATFORM
#include <mbedtls/sha256.h>
#include "bootloader_random.h"
#include "crypto_asm.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "soc/sens_reg.h"
#include "soc/syscon_reg.h"

static const char *TAG = "hw_entropy";

/*
 * Read the peripheral state back rather than trusting that the enable call was
 * made. "We called bootloader_random_enable()" and "the SAR ADC is powered and
 * clocked into the HWRNG" are different claims, and reporting the first as
 * though it were the second is the same intent-versus-state confusion that let
 * the COLDCARD defect hide. These are the two bits bootloader_random_enable()
 * sets on the ESP32-S3 (see bootloader_random_esp32s3.c): SAR ADC forced on,
 * and the RNG clock gated in.
 *
 * This is a state check, not a noise measurement. It cannot tell you the ADC is
 * producing entropy, only that the path that carries it is switched on.
 */
bool hw_entropy_source_verified(void) {
    return REG_GET_FIELD(SENS_SAR_POWER_XPD_SAR_REG, SENS_FORCE_XPD_SAR) == 3 &&
           (REG_READ(SYSTEM_WIFI_CLK_EN_REG) & SYSTEM_WIFI_CLK_RNG_EN) != 0;
}

static int get_timing_bit(void) {
    int64_t t1 = esp_timer_get_time();
    volatile uint32_t x = 0;
    for (int j = 0; j < 32; j++) {
        x ^= esp_random();
        x = (x << 5) | (x >> 27);
        x *= 0x9e3779b9;
    }
    (void)x;
    int64_t t2 = esp_timer_get_time();
    return (int)((t2 - t1) & 1);
}

#define TIMING_DEBIAS_MAX_ATTEMPTS 100

static void collect_timing_jitter(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = 0;
        for (int bit = 0; bit < 8; bit++) {
            int result = -1;
            int attempts = 0;
            while (result < 0) {
                int b1 = get_timing_bit();
                int b2 = get_timing_bit();
                if (b1 != b2) {
                    result = b1;
                } else if (++attempts >= TIMING_DEBIAS_MAX_ATTEMPTS) {
                    g_debiasing_failures++;
                    uint32_t r = esp_random();
                    r ^= esp_random();
                    r ^= (uint32_t)esp_timer_get_time();
                    result = (int)(r & 1);
                }
            }
            byte = (byte << 1) | result;
        }
        out[i] = byte;
    }
}

int hw_entropy_init(void) {
    if (g_initialized) {
        ESP_LOGW(TAG, "hw_entropy_init called twice, ignoring");
        return 0;
    }

    /*
     * The ESP32-S3 hardware RNG only produces true random numbers while an
     * entropy source is running: either the RF subsystem, or the SAR ADC noise
     * source enabled by bootloader_random_enable(). This firmware is air-gapped
     * by design and never brings up Wi-Fi or Bluetooth, and the second-stage
     * bootloader disables the ADC source again before handing control to the
     * app. Without this call every esp_random()/esp_fill_random() draw in the
     * image -- FROST nonces, storage keys, PIN salts, AEAD nonces -- is
     * pseudo-random only, and nothing fails or logs to say so.
     *
     * Nothing else in this firmware touches the SAR ADC, so the source is
     * enabled once here and stays enabled for the life of the device.
     * bootloader_random_disable() must never be called: doing so would silently
     * drop every later draw back to the pseudo-random regime. Bringing up RF,
     * the ADC driver, or I2S would require the same care, and so would light or
     * deep sleep, which can drop the SAR/RTC state this leaves configured.
     * scripts/check-rng-hygiene.sh rejects all of those.
     */
    bootloader_random_enable();
    g_initialized = true;

    if (!hw_entropy_source_verified()) {
        ESP_LOGE(TAG, "Entropy source did not come up; RNG output is pseudo-random only");
    } else {
        ESP_LOGI(TAG, "Hardware entropy source enabled (SAR ADC noise into HWRNG)");
    }
    return 0;
}

int hw_entropy_fill(uint8_t *buf, size_t len) {
    if (!buf || len == 0)
        return -1;

    /* Fail closed: before init the entropy source is off and esp_fill_random()
     * is a PRNG. Gated on initialization, not on the register readback: a
     * readback that is wrong about live silicon would turn a boot into a restart
     * loop, and the readback has not been confirmed on hardware. It is reported
     * and logged instead. */
    if (!g_initialized) {
        ESP_LOGE(TAG, "hw_entropy_fill before hw_entropy_init: refusing to emit weak randomness");
        return -1;
    }

    uint8_t pool[96];
    uint8_t hash[32];
    size_t offset = 0;
    int ret = 0;

    while (offset < len) {
        esp_fill_random(pool, 32);
        collect_timing_jitter(pool + 32, 32);
        /* A second draw, not one 64-byte call: it lands after the jitter loop,
         * by which point the SAR ADC has mixed further noise into the HWRNG
         * state. Sampling the same generator twice across a time gap is the
         * point, not an artefact of the removed ADC branch. */
        esp_fill_random(pool + 64, 32);

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

bool hw_entropy_source_verified(void) {
    /* /dev/urandom is a CSPRNG with no source to switch on, so there is no
     * peripheral state to read back and nothing that can be half-configured. */
    return g_initialized;
}

int hw_entropy_init(void) {
    g_initialized = true;
    return 0;
}

int hw_entropy_fill(uint8_t *buf, size_t len) {
    if (!buf || len == 0)
        return -1;
    /*
     * No fail-closed gate here, unlike the ESP path. On a host /dev/urandom is
     * a CSPRNG whether or not hw_entropy_init() ran; there is no entropy source
     * to forget to switch on, so gating would only make host tests diverge from
     * the behaviour they are meant to cover.
     */
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp)
        return -1;
    size_t n = fread(buf, 1, len, fp);
    fclose(fp);
    return n == len ? 0 : -1;
}

#endif
