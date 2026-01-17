#include "serial.h"
#include "protocol.h"
#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include <string.h>

#define RX_BUF_SIZE PROTOCOL_MAX_MESSAGE_LEN

static const char *TAG = "serial";
static char rx_buf[RX_BUF_SIZE];
static size_t rx_pos = 0;

int serial_init(void) {
    usb_serial_jtag_driver_config_t cfg = {
        .rx_buffer_size = RX_BUF_SIZE,
        .tx_buffer_size = RX_BUF_SIZE,
    };

    if (usb_serial_jtag_driver_install(&cfg) != ESP_OK) {
        ESP_LOGE(TAG, "USB Serial JTAG init failed");
        return -1;
    }

    /* Redirect VFS (stdout/stderr/ESP_LOG) through the installed driver */
    usb_serial_jtag_vfs_use_driver();

    ESP_LOGI(TAG, "USB Serial JTAG initialized");
    return 0;
}

int serial_read_line(char *buf, size_t len) {
    uint8_t c;

    while (1) {
        int n = usb_serial_jtag_read_bytes(&c, 1, pdMS_TO_TICKS(10));
        if (n <= 0) break;

        if (c == '\n' || c == '\r') {
            if (rx_pos > 0) {
                size_t copy_len = rx_pos < len - 1 ? rx_pos : len - 1;
                memcpy(buf, rx_buf, copy_len);
                buf[copy_len] = '\0';
                rx_pos = 0;
                return (int)copy_len;
            }
        } else if (rx_pos < RX_BUF_SIZE - 1) {
            rx_buf[rx_pos++] = (char)c;
        }
    }
    return 0;
}

int serial_write_line(const char *buf) {
    size_t len = strlen(buf);
    int written = usb_serial_jtag_write_bytes(buf, len, pdMS_TO_TICKS(100));
    if (written < 0 || (size_t)written != len) {
        return -1;
    }
    if (usb_serial_jtag_write_bytes("\n", 1, pdMS_TO_TICKS(100)) != 1) {
        return -1;
    }
    return (int)(len + 1);
}
