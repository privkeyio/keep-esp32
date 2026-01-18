#ifndef SECRESULT_H
#define SECRESULT_H

#include <stdint.h>

typedef uint32_t secresult_t;

#define SECRESULT_TRUE        ((secresult_t)0xAAAAAAAAu)
#define SECRESULT_FALSE       ((secresult_t)0x55555555u)

#define SECRESULT_ERR_INVALID_SIG     ((secresult_t)0x1E1E1E1Eu)
#define SECRESULT_ERR_POLICY_DENIED   ((secresult_t)0x2D2D2D2Du)
#define SECRESULT_ERR_SESSION_INVALID ((secresult_t)0x4B4B4B4Bu)
#define SECRESULT_ERR_POLICY_CHANGED  ((secresult_t)0x69696969u)
#define SECRESULT_ERR_HASH_MISMATCH   ((secresult_t)0x87878787u)
#define SECRESULT_ERR_LOAD_FAILED     ((secresult_t)0xC3C3C3C3u)

#define SECRESULT_IS_TRUE(r)  ((r) == SECRESULT_TRUE)
#define SECRESULT_IS_FALSE(r) ((r) == SECRESULT_FALSE)
#define SECRESULT_IS_ERROR(r) (!SECRESULT_IS_TRUE(r) && !SECRESULT_IS_FALSE(r))

static inline secresult_t secresult_from_bool(int b) {
    return b ? SECRESULT_TRUE : SECRESULT_FALSE;
}

#endif
