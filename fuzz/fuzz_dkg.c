#include "hex_utils.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#define MAX_THRESHOLD 16

typedef struct {
    uint8_t participant_index;
    uint8_t num_coefficients;
    uint8_t coefficient_commitments[MAX_THRESHOLD][64];
    uint8_t zkp_r[64];
    uint8_t zkp_z[32];
} dkg_round1_data_t;

static int parse_dkg_round1_data(const char *dkg_data, dkg_round1_data_t *out) {
    memset(out, 0, sizeof(*out));

    char *data = strdup(dkg_data);
    if (!data) {
        return -1;
    }

    char *num_coeff_str = strstr(data, "num_coefficients\":");
    char *coeffs_str = strstr(data, "coefficient_commitments\":\"");
    char *zkp_r_str = strstr(data, "zkp_r\":\"");
    char *zkp_z_str = strstr(data, "zkp_z\":\"");

    if (!num_coeff_str || !coeffs_str || !zkp_r_str || !zkp_z_str) {
        free(data);
        return -1;
    }

    char *endptr;
    long num_coeff_tmp = strtol(num_coeff_str + 18, &endptr, 10);
    if (endptr == num_coeff_str + 18 || num_coeff_tmp <= 0 || num_coeff_tmp > MAX_THRESHOLD) {
        free(data);
        return -1;
    }
    out->num_coefficients = (uint8_t)num_coeff_tmp;

    char *coeffs_start = coeffs_str + 26;
    char *coeffs_end = strchr(coeffs_start, '"');
    if (!coeffs_end) {
        free(data);
        return -1;
    }
    *coeffs_end = '\0';

    size_t coeffs_len = strlen(coeffs_start);
    size_t coeff_offset = 0;
    for (uint8_t i = 0; i < out->num_coefficients; i++) {
        if (coeff_offset + 128 > coeffs_len)
            break;
        char coeff_hex[129];
        strncpy(coeff_hex, coeffs_start + coeff_offset, 128);
        coeff_hex[128] = '\0';
        hex_to_bytes(coeff_hex, out->coefficient_commitments[i], 64);
        coeff_offset += 128;
        if (coeff_offset < coeffs_len && coeffs_start[coeff_offset] == ',')
            coeff_offset++;
    }

    char *zkp_r_start = zkp_r_str + 8;
    char zkp_r_hex[129];
    strncpy(zkp_r_hex, zkp_r_start, 128);
    zkp_r_hex[128] = '\0';
    hex_to_bytes(zkp_r_hex, out->zkp_r, 64);

    char *zkp_z_start = zkp_z_str + 8;
    char zkp_z_hex[65];
    strncpy(zkp_z_hex, zkp_z_start, 64);
    zkp_z_hex[64] = '\0';
    hex_to_bytes(zkp_z_hex, out->zkp_z, 32);

    free(data);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 4096) {
        return 0;
    }

    char *dkg_data = malloc(size + 1);
    if (!dkg_data) {
        return 0;
    }
    memcpy(dkg_data, data, size);
    dkg_data[size] = '\0';

    dkg_round1_data_t out;
    parse_dkg_round1_data(dkg_data, &out);

    free(dkg_data);
    return 0;
}
