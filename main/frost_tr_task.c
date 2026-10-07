// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "frost_tr_task.h"

#ifdef ESP_PLATFORM

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_cpu.h"
#include <stdbool.h>

/* Peak use measured on an ESP32-S3 is about 15.5 KB, by the boot self-test; the rest is
 * margin. get_status reports the smallest amount ever left free. */
#define FTR_TASK_STACK_SIZE 32768
/* FreeRTOS fills new stacks with this byte and measures the high-water mark by it. */
#define FTR_STACK_FILL 0xA5
/* Job frames start at least this far below the task loop's stack pointer, so the refill
 * below can stop short of the loop's own frame and register save area. */
#define FTR_JOB_PAD   512
#define FTR_WIPE_STOP 256

static StaticTask_t task_tcb;
static StackType_t task_stack[FTR_TASK_STACK_SIZE];
static TaskHandle_t task_handle;
static StaticSemaphore_t start_buf, done_buf, lock_buf;
static SemaphoreHandle_t start_sem, done_sem, lock;

static ftr_job_fn job_fn;
static void *job_arg;
static int job_result;
/* The refill below would hide each job's depth from uxTaskGetStackHighWaterMark, so the
 * deepest use is measured here before refilling. */
static size_t stack_free_min = FTR_TASK_STACK_SIZE;

static void __attribute__((noinline)) run_job(void) {
    volatile uint8_t pad[FTR_JOB_PAD];
    pad[0] = 0;
    job_result = job_fn(job_arg);
    pad[FTR_JOB_PAD - 1] = pad[0];
}

static void frost_task(void *unused) {
    (void)unused;
    for (;;) {
        xSemaphoreTake(start_sem, portMAX_DELAY);
        run_job();
        size_t untouched = 0;
        while (untouched < FTR_TASK_STACK_SIZE && task_stack[untouched] == FTR_STACK_FILL) {
            untouched++;
        }
        if (untouched < stack_free_min) {
            stack_free_min = untouched;
        }
        /* Everything below the loop's frame belonged to the job: Rust temporaries, copies
         * of the signing share and nonces. Restore the fill byte, which also lets the next
         * job's depth be measured. Inline volatile stores, no call, so nothing is live below
         * sp. */
        volatile uint8_t *p = (volatile uint8_t *)task_stack;
        volatile uint8_t *stop = (volatile uint8_t *)esp_cpu_get_sp() - FTR_WIPE_STOP;
        while (p < stop) {
            *p++ = FTR_STACK_FILL;
        }
        xSemaphoreGive(done_sem);
    }
}

int ftr_task_start(void) {
    if (task_handle != NULL) {
        return -1;
    }
    start_sem = xSemaphoreCreateBinaryStatic(&start_buf);
    done_sem = xSemaphoreCreateBinaryStatic(&done_buf);
    lock = xSemaphoreCreateMutexStatic(&lock_buf);
    task_handle = xTaskCreateStatic(frost_task, "frost_tr", FTR_TASK_STACK_SIZE, NULL,
                                    uxTaskPriorityGet(NULL), task_stack, &task_tcb);
    return task_handle != NULL ? 0 : -1;
}

int ftr_task_run(ftr_job_fn job, void *arg) {
    if (task_handle == NULL || job == NULL) {
        return FTR_TASK_ERR_NOT_RUNNING;
    }
    xSemaphoreTake(lock, portMAX_DELAY);
    job_fn = job;
    job_arg = arg;
    xSemaphoreGive(start_sem);
    xSemaphoreTake(done_sem, portMAX_DELAY);
    int result = job_result;
    job_fn = NULL;
    job_arg = NULL;
    xSemaphoreGive(lock);
    return result;
}

size_t ftr_task_stack_free_min(void) {
    return task_handle != NULL ? stack_free_min : 0;
}

#else

int ftr_task_start(void) {
    return 0;
}

int ftr_task_run(ftr_job_fn job, void *arg) {
    return job != NULL ? job(arg) : FTR_TASK_ERR_NOT_RUNNING;
}

size_t ftr_task_stack_free_min(void) {
    return 0;
}

#endif
