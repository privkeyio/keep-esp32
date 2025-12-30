#include "serial.h"
#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "driver/uart.h"
#include <string.h>
#include <stdio.h>

#define UART_NUM UART_NUM_0
#define RX_BUF_SIZE 2048

static const char *TAG = "serial";
static char rx_buf[RX_BUF_SIZE];
static size_t rx_pos = 0;

int serial_init(void) {
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
    while (uart_read_bytes(UART_NUM, &c, 1, pdMS_TO_TICKS(10)) > 0) {
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
    uart_write_bytes(UART_NUM, buf, len);
    uart_write_bytes(UART_NUM, "\n", 1);
    return (int)len;
}
