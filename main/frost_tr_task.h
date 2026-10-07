// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef FROST_TR_TASK_H
#define FROST_TR_TASK_H

#include <stddef.h>
#include <stdint.h>

typedef int (*ftr_job_fn)(void *arg);

/* Outside the range of frost_tr status codes, so a caller can tell "never ran" apart from
 * a refusal. */
#define FTR_TASK_ERR_NOT_RUNNING -100

/* Starts the task every frost_tr call runs on: its own stack, refilled after each job so
 * no key material or nonce outlives the call. Call once after ftr_init(). */
int ftr_task_start(void);

/* Runs `job(arg)` on the frost task and returns its result; the caller blocks until it
 * finishes. Returns FTR_TASK_ERR_NOT_RUNNING if the task was never started. */
int ftr_task_run(ftr_job_fn job, void *arg);

/* Smallest number of stack bytes that have stayed unused on the frost task. */
size_t ftr_task_stack_free_min(void);

#endif
