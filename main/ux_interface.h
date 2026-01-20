// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef UX_INTERFACE_H
#define UX_INTERFACE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct ux_backend ux_backend_t;

typedef struct {
    uint64_t amount_sats;
    uint64_t fee_sats;
    char destination[64];
    char destination_label[32];
    int input_count;
    int output_count;
    bool policy_approved;
    const char *policy_note;
    bool is_external;
    uint8_t threshold;
    uint8_t total_signers;
} ux_tx_info_t;

typedef void (*ux_decision_cb_t)(bool approved, void *user_data);

struct ux_backend {
    const char *name;

    int (*init)(void);
    void (*deinit)(void);

    void (*show_idle)(const char *device_name, bool policy_loaded, uint32_t policy_version);
    void (*show_scanning)(void);
    void (*show_signing)(int current, int total);
    void (*show_success)(const char *message);
    void (*show_error)(const char *title, const char *message);

    void (*confirm_transaction)(const ux_tx_info_t *tx, ux_decision_cb_t cb, void *user_data);

    void (*show_qr)(const char *data, size_t len);
    int (*scan_qr)(char *data, size_t max_len, uint32_t timeout_ms);

    bool (*wait_any_input)(uint32_t timeout_ms);
    bool (*is_available)(void);
};

void ux_register_backend(const ux_backend_t *backend);
const ux_backend_t *ux_get_backend(void);
int ux_set_backend(const char *name);
int ux_init(void);

#endif
