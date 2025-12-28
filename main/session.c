#include "session.h"
#include <string.h>

#ifndef ESP_PLATFORM
#include <time.h>
static uint32_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
#else
#include "esp_timer.h"
static uint32_t now_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}
#endif

void session_init(session_t *s, const kfp_sign_request_t *req, uint16_t threshold) {
    memset(s, 0, sizeof(*s));
    memcpy(s->session_id, req->session_id, 32);
    memcpy(s->message, req->message, req->message_len);
    s->message_len = req->message_len;
    s->threshold = threshold;
    memcpy(s->participants, req->participants, req->participant_count * sizeof(uint16_t));
    s->participant_count = req->participant_count;
    s->state = SESSION_AWAITING_COMMITMENTS;
    s->created_at = now_ms();
}

session_state_t session_state(session_t *s) {
    if (s->state != SESSION_COMPLETE && s->state != SESSION_FAILED) {
        if (now_ms() - s->created_at > SESSION_TIMEOUT_MS) {
            s->state = SESSION_EXPIRED;
        }
    }
    return s->state;
}

bool session_is_participant(session_t *s, uint16_t share_index) {
    for (int i = 0; i < s->participant_count; i++) {
        if (s->participants[i] == share_index) return true;
    }
    return false;
}

int session_add_commitment(session_t *s, uint16_t share_index, const uint8_t *commitment, size_t len) {
    if (s->state != SESSION_AWAITING_COMMITMENTS) return -1;
    if (!session_is_participant(s, share_index)) return -2;
    if (len > 128) return -3;

    for (int i = 0; i < s->commitment_count; i++) {
        if (s->commitment_indices[i] == share_index) return -4;
    }

    int idx = s->commitment_count;
    memcpy(s->commitments[idx], commitment, len);
    s->commitment_lens[idx] = len;
    s->commitment_indices[idx] = share_index;
    s->commitment_count++;

    if (s->commitment_count >= s->threshold) {
        s->state = SESSION_AWAITING_SHARES;
    }
    return 0;
}

int session_add_signature_share(session_t *s, uint16_t share_index, const uint8_t *share, size_t len) {
    if (s->state != SESSION_AWAITING_SHARES) return -1;
    if (!session_is_participant(s, share_index)) return -2;
    if (len > 64) return -3;

    for (int i = 0; i < s->sig_share_count; i++) {
        if (s->sig_share_indices[i] == share_index) return -4;
    }

    int idx = s->sig_share_count;
    memcpy(s->sig_shares[idx], share, len);
    s->sig_share_lens[idx] = len;
    s->sig_share_indices[idx] = share_index;
    s->sig_share_count++;

    return 0;
}

bool session_has_all_commitments(session_t *s) {
    return s->commitment_count >= s->participant_count - 1;
}

bool session_has_all_shares(session_t *s) {
    return s->sig_share_count >= s->participant_count - 1;
}
