#include "session.h"
#include <string.h>

#ifdef ESP_PLATFORM
#include "crypto_asm.h"
#define secure_zero(buf, len) secure_memzero(buf, len)
#else
static void secure_zero(void *buf, size_t len) {
    volatile uint8_t *p = buf;
    while (len--)
        *p++ = 0;
}
#endif

#ifndef ESP_PLATFORM
#include <time.h>
#ifndef now_ms
static uint32_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
#endif
#else
#include "esp_timer.h"
static uint32_t now_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}
#endif

int session_init(session_t *s, const sign_request_t *req, uint16_t threshold) {
    if (!s || !req)
        return -1;
    if (req->message_len > MAX_MESSAGE_LEN)
        return -2;
    if (req->participant_count > MAX_PARTICIPANTS)
        return -3;

    memset(s, 0, sizeof(*s));
    memcpy(s->session_id, req->session_id, SESSION_ID_LEN);
    memcpy(s->message, req->message, req->message_len);
    s->message_len = req->message_len;
    s->threshold = threshold;
    memcpy(s->participants, req->participants, req->participant_count * sizeof(uint16_t));
    s->participant_count = req->participant_count;
    s->state = SESSION_AWAITING_COMMITMENTS;
    s->created_at = now_ms();
    return 0;
}

void session_destroy(session_t *s) {
    secure_zero(s, sizeof(session_t));
}

static bool is_terminal_state(session_state_t state) {
    return state == SESSION_COMPLETE || state == SESSION_FAILED || state == SESSION_EXPIRED;
}

session_state_t session_state(session_t *s) {
    if (!is_terminal_state(s->state)) {
        uint32_t now = now_ms();
        uint32_t created = s->created_at;
        uint32_t elapsed = (now >= created) ? (now - created) : (UINT32_MAX - created + now + 1);
        if (elapsed > SESSION_TIMEOUT_MS) {
            s->state = SESSION_EXPIRED;
        }
    }
    if (is_terminal_state(s->state)) {
        session_state_t final_state = s->state;
        secure_zero(s->message, sizeof(s->message));
        secure_zero(s->commitments, sizeof(s->commitments));
        secure_zero(s->sig_shares, sizeof(s->sig_shares));
        secure_zero(s->our_nonce, sizeof(s->our_nonce));
        return final_state;
    }
    return s->state;
}

bool session_is_participant(session_t *s, uint16_t share_index) {
    for (int i = 0; i < s->participant_count; i++) {
        if (s->participants[i] == share_index)
            return true;
    }
    return false;
}

secresult_t session_is_participant_secure(session_t *s, uint16_t share_index) {
    if (!s) return SECRESULT_ERR_SESSION_INVALID;
    secresult_t found = SECRESULT_FALSE;
    for (int i = 0; i < s->participant_count; i++) {
        if (s->participants[i] == share_index) {
            found = SECRESULT_TRUE;
        }
    }
    return found;
}

int session_add_commitment(session_t *s, uint16_t share_index, const uint8_t *commitment,
                           size_t len) {
    if (!s || !commitment)
        return SESSION_ERR_INVALID_LEN;
    if (s->state != SESSION_AWAITING_COMMITMENTS)
        return SESSION_ERR_INVALID_STATE;
    if (!SECRESULT_IS_TRUE(session_is_participant_secure(s, share_index)))
        return SESSION_ERR_NOT_PARTICIPANT;
    if (len == 0 || len > COMMITMENT_LEN)
        return SESSION_ERR_INVALID_LEN;
    if (s->commitment_count >= MAX_PARTICIPANTS)
        return SESSION_ERR_INVALID_STATE;

    for (int i = 0; i < s->commitment_count; i++) {
        if (s->commitment_indices[i] == share_index)
            return SESSION_ERR_DUPLICATE;
    }

    int idx = s->commitment_count;
    memcpy(s->commitments[idx], commitment, len);
    s->commitment_lens[idx] = len;
    s->commitment_indices[idx] = share_index;
    s->commitment_count++;

    if (session_has_all_commitments(s)) {
        s->state = SESSION_AWAITING_SHARES;
    }
    return 0;
}

int session_add_signature_share(session_t *s, uint16_t share_index, const uint8_t *share,
                                size_t len) {
    if (!s || !share)
        return SESSION_ERR_INVALID_LEN;
    if (s->state != SESSION_AWAITING_SHARES)
        return SESSION_ERR_INVALID_STATE;
    if (!SECRESULT_IS_TRUE(session_is_participant_secure(s, share_index)))
        return SESSION_ERR_NOT_PARTICIPANT;
    if (len == 0 || len > SIGNATURE_LEN)
        return SESSION_ERR_INVALID_LEN;
    if (s->sig_share_count >= MAX_PARTICIPANTS)
        return SESSION_ERR_INVALID_STATE;

    for (int i = 0; i < s->sig_share_count; i++) {
        if (s->sig_share_indices[i] == share_index)
            return SESSION_ERR_DUPLICATE;
    }

    int idx = s->sig_share_count;
    memcpy(s->sig_shares[idx], share, len);
    s->sig_share_lens[idx] = len;
    s->sig_share_indices[idx] = share_index;
    s->sig_share_count++;

    return 0;
}

bool session_has_all_commitments(session_t *s) {
    if (s->participant_count == 0)
        return false;
    return s->commitment_count >= s->participant_count - 1;
}

bool session_has_all_shares(session_t *s) {
    if (s->participant_count == 0)
        return false;
    return s->sig_share_count >= s->participant_count - 1;
}
