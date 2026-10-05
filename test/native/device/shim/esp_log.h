#ifndef ESP_LOG_H
#define ESP_LOG_H

#include <stdarg.h>
#include <stdio.h>

/* Firmware log formats target the ESP32, where uint32_t is unsigned long, so host
 * format checking is deliberately not applied. */
static inline void harness_log(char level, const char *tag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%c %s: ", level, tag);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

#define ESP_LOGE(tag, fmt, ...) harness_log('E', tag, fmt, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) harness_log('W', tag, fmt, ##__VA_ARGS__)
#define ESP_LOGI(tag, fmt, ...) harness_log('I', tag, fmt, ##__VA_ARGS__)
#define ESP_LOGD(tag, fmt, ...)

#endif
