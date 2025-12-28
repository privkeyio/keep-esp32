#include "serial.h"
#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>

#define SERIAL_BUF_SIZE 1024

#ifdef CONFIG_USE_UART_CONSOLE
#include "esp_vfs_dev.h"
#include "driver/uart.h"
static char line_buf[SERIAL_BUF_SIZE];
#else
#include "driver/usb_serial_jtag.h"
#endif

static const char *TAG = "serial";

void serial_init(void) {
#ifdef CONFIG_USE_UART_CONSOLE
    ESP_LOGI(TAG, "Using stdio console");
#else
    usb_serial_jtag_driver_config_t config = {
        .rx_buffer_size = SERIAL_BUF_SIZE,
        .tx_buffer_size = SERIAL_BUF_SIZE,
    };
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&config));
    ESP_LOGI(TAG, "USB serial initialized");
#endif
}

int serial_read_line(char *buf, size_t len) {
    if (len == 0) return 0;
    if (len == 1) {
        buf[0] = '\0';
        return 0;
    }

#ifdef CONFIG_USE_UART_CONSOLE
    size_t pos = 0;
    while (pos + 1 < len) {
        int c = getchar();
        if (c == EOF) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        if (c == '\n' || c == '\r') {
            buf[pos] = '\0';
            if (pos > 0) return (int)pos;
            continue;
        }
        buf[pos++] = (char)c;
    }
    buf[pos] = '\0';
    return (int)pos;
#else
    size_t pos = 0;
    while (pos + 1 < len) {
        int n = usb_serial_jtag_read_bytes((uint8_t *)&buf[pos], 1, portMAX_DELAY);
        if (n <= 0) continue;
        if (buf[pos] == '\n' || buf[pos] == '\r') {
            buf[pos] = '\0';
            if (pos > 0) return (int)pos;
            continue;
        }
        pos++;
    }
    buf[pos] = '\0';
    return (int)pos;
#endif
}

int serial_write_line(const char *buf) {
#ifdef CONFIG_USE_UART_CONSOLE
    printf("%s\n", buf);
    fflush(stdout);
    return (int)strlen(buf);
#else
    size_t len = strlen(buf);
    int written = usb_serial_jtag_write_bytes((const uint8_t *)buf, len, portMAX_DELAY);
    usb_serial_jtag_write_bytes((const uint8_t *)"\n", 1, portMAX_DELAY);
    return written;
#endif
}
