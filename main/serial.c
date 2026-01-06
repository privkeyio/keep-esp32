#include "serial.h"
#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "driver/uart.h"
#include "driver/usb_serial_jtag.h"
#include <string.h>
#include <stdio.h>

#define UART_NUM UART_NUM_0
#define RX_BUF_SIZE 2048

static const char *TAG = "serial";
static char rx_buf[RX_BUF_SIZE];
static size_t rx_pos = 0;
static bool use_usb_cdc = false;

int serial_init(void) {
    usb_serial_jtag_driver_config_t usb_cfg = {
        .rx_buffer_size = RX_BUF_SIZE,
        .tx_buffer_size = RX_BUF_SIZE,
    };

    if (usb_serial_jtag_driver_install(&usb_cfg) == ESP_OK) {
        use_usb_cdc = true;
        ESP_LOGI(TAG, "USB CDC initialized");
        return 0;
    }

    ESP_LOGW(TAG, "USB CDC failed, falling back to UART");
    esp_err_t err = uart_driver_install(UART_NUM, RX_BUF_SIZE, 0, 0, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "UART driver install failed: %s (%d)", esp_err_to_name(err), err);
        return -1;
    }
    ESP_LOGI(TAG, "UART driver installed");
    return 0;
}

int serial_read_line(char *buf, size_t len) {
    uint8_t c;
    int bytes_read;

    while (1) {
        if (use_usb_cdc) {
            bytes_read = usb_serial_jtag_read_bytes(&c, 1, pdMS_TO_TICKS(10));
        } else {
            bytes_read = uart_read_bytes(UART_NUM, &c, 1, pdMS_TO_TICKS(10));
        }

        if (bytes_read <= 0) break;

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
    int written, nl_written;

    if (use_usb_cdc) {
        written = usb_serial_jtag_write_bytes(buf, len, pdMS_TO_TICKS(100));
        if (written < 0) {
            return -1;
        }
        if ((size_t)written != len) {
            return -1;
        }
        nl_written = usb_serial_jtag_write_bytes("\n", 1, pdMS_TO_TICKS(100));
        if (nl_written != 1) {
            return -1;
        }
    } else {
        written = uart_write_bytes(UART_NUM, buf, len);
        if (written < 0) {
            return -1;
        }
        if ((size_t)written != len) {
            return -1;
        }
        nl_written = uart_write_bytes(UART_NUM, "\n", 1);
        if (nl_written != 1) {
            return -1;
        }
    }
    return (int)(len + 1);
}
