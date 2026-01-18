#ifndef PSBT_H
#define PSBT_H

#include <stdint.h>
#include <stddef.h>

#define PSBT_MAX_BASE64_LEN 8192

typedef struct {
    size_t input_count;
    size_t output_count;
    uint64_t total_in_sats;
    uint64_t total_out_sats;
    uint64_t fee_sats;
} psbt_summary_t;

int psbt_init(void);
int psbt_parse(const char *base64, psbt_summary_t *summary);
int psbt_get_sighash(const char *base64, size_t input_idx, uint8_t sighash[32]);
int psbt_add_taproot_signature(const char *base64_in, size_t input_idx, const uint8_t *sig,
                               size_t sig_len, char *base64_out, size_t out_len);

#endif
