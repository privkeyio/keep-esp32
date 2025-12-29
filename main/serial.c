#include "serial.h"
#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include <string.h>
#include <stdio.h>

#define SERIAL_BUF_SIZE 1024

#ifdef CONFIG_USE_UART_CONSOLE
#include "esp_rom_serial_output.h"
#else
#include "driver/usb_serial_jtag.h"
#endif

static const char *TAG = "serial";

void serial_init(void) {
#ifdef CONFIG_USE_UART_CONSOLE
    ESP_LOGI(TAG, "ROM UART console ready");
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
    if (len < 2) return 0;
    size_t pos = 0;
    while (pos + 1 < len) {
#ifdef CONFIG_USE_UART_CONSOLE
        uint8_t c;
        while (esp_rom_output_rx_one_char(&c) != 0) {
            vTaskDelay(1);
        }
        buf[pos] = (char)c;
#else
        int n = usb_serial_jtag_read_bytes((uint8_t *)&buf[pos], 1, portMAX_DELAY);
        if (n <= 0) continue;
#endif
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
    size_t blen = strlen(buf);
#ifdef CONFIG_USE_UART_CONSOLE
    for (size_t i = 0; i < blen; i++) {
        esp_rom_output_tx_one_char((uint8_t)buf[i]);
    }
    esp_rom_output_tx_one_char('\n');
    return (int)blen;
#else
    int written = usb_serial_jtag_write_bytes((const uint8_t *)buf, blen, portMAX_DELAY);
    usb_serial_jtag_write_bytes((const uint8_t *)"\n", 1, portMAX_DELAY);
    return written;
#endif
}
