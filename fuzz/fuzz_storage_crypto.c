#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

#define KEY_SIZE     32
#define NONCE_SIZE   12
#define TAG_SIZE     16
#define MAX_AAD_LEN  128
#define MAX_DATA_LEN 4096

static uint8_t fuzz_key[KEY_SIZE];

static int derive_key(const uint8_t *seed, size_t seed_len) {
    static const uint8_t salt[] = "fuzz-storage-key";
    static const uint8_t info[] = "fuzz-key";
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, sizeof(salt) - 1,
                           seed, seed_len, info, sizeof(info) - 1, fuzz_key, KEY_SIZE);
    if (ret != 0) {
        memset(fuzz_key, 0, KEY_SIZE);
        return -1;
    }
    return 0;
}

static int gcm_init(mbedtls_gcm_context *gcm) {
    mbedtls_gcm_init(gcm);
    return mbedtls_gcm_setkey(gcm, MBEDTLS_CIPHER_ID_AES, fuzz_key, KEY_SIZE * 8);
}

static int encrypt(const uint8_t *plaintext, size_t len, const uint8_t *aad, size_t aad_len,
                   const uint8_t nonce[NONCE_SIZE], uint8_t *ciphertext, uint8_t tag[TAG_SIZE]) {
    mbedtls_gcm_context gcm;
    if (gcm_init(&gcm) != 0)
        return -1;

    int ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, nonce, NONCE_SIZE, aad,
                                        aad_len, plaintext, ciphertext, TAG_SIZE, tag);
    mbedtls_gcm_free(&gcm);
    return ret == 0 ? 0 : -1;
}

static int decrypt(const uint8_t *ciphertext, size_t len, const uint8_t *aad, size_t aad_len,
                   const uint8_t nonce[NONCE_SIZE], const uint8_t tag[TAG_SIZE],
                   uint8_t *plaintext) {
    mbedtls_gcm_context gcm;
    if (gcm_init(&gcm) != 0)
        return -1;

    int ret = mbedtls_gcm_auth_decrypt(&gcm, len, nonce, NONCE_SIZE, aad, aad_len, tag, TAG_SIZE,
                                       ciphertext, plaintext);
    mbedtls_gcm_free(&gcm);
    return ret == 0 ? 0 : -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < NONCE_SIZE + 2 || size > MAX_DATA_LEN + MAX_AAD_LEN + NONCE_SIZE + 4) {
        return 0;
    }

    uint8_t nonce[NONCE_SIZE];
    memcpy(nonce, data, NONCE_SIZE);

    const uint8_t *rest = data + NONCE_SIZE;
    size_t remaining = size - NONCE_SIZE;

    size_t aad_len = rest[0] % (MAX_AAD_LEN + 1);
    if (aad_len + 1 > remaining) {
        aad_len = remaining > 1 ? remaining - 1 : 0;
    }

    const uint8_t *aad = aad_len > 0 ? rest + 1 : NULL;
    const uint8_t *plaintext = rest + 1 + aad_len;
    size_t plaintext_len = remaining - 1 - aad_len;

    if (plaintext_len == 0 || plaintext_len > MAX_DATA_LEN) {
        return 0;
    }

    size_t seed_len = plaintext_len < 16 ? plaintext_len : 16;
    if (derive_key(plaintext, seed_len) != 0) {
        return 0;
    }

    uint8_t *ciphertext = malloc(plaintext_len);
    uint8_t *decrypted = malloc(plaintext_len);
    uint8_t tag[TAG_SIZE];

    if (!ciphertext || !decrypted) {
        free(ciphertext);
        free(decrypted);
        return 0;
    }

    if (encrypt(plaintext, plaintext_len, aad, aad_len, nonce, ciphertext, tag) == 0) {
        if (decrypt(ciphertext, plaintext_len, aad, aad_len, nonce, tag, decrypted) == 0) {
            if (memcmp(plaintext, decrypted, plaintext_len) != 0) {
                __builtin_trap();
            }
        }

        uint8_t bad_tag[TAG_SIZE];
        memcpy(bad_tag, tag, TAG_SIZE);
        bad_tag[0] ^= 0xFF;
        if (decrypt(ciphertext, plaintext_len, aad, aad_len, nonce, bad_tag, decrypted) == 0) {
            __builtin_trap();
        }
    }

    free(ciphertext);
    free(decrypted);
    return 0;
}
