#include "serial.h"
#include "driver/usb_serial_jtag.h"
#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include <string.h>

#define SERIAL_BUF_SIZE 1024

static const char *TAG = "serial";

void serial_init(void) {
    usb_serial_jtag_driver_config_t config = {
        .rx_buffer_size = SERIAL_BUF_SIZE,
        .tx_buffer_size = SERIAL_BUF_SIZE,
    };
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&config));
    ESP_LOGI(TAG, "USB serial initialized");
}

int serial_read_line(char *buf, size_t len) {
    if (len == 0) return 0;
    if (len == 1) {
        buf[0] = '\0';
        return 0;
    }

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
}

int serial_write_line(const char *buf) {
    size_t len = strlen(buf);
    int written = usb_serial_jtag_write_bytes((const uint8_t *)buf, len, portMAX_DELAY);
    usb_serial_jtag_write_bytes((const uint8_t *)"\n", 1, portMAX_DELAY);
    return written;
}
