# keep-esp32

ESP32-S3 FROST threshold signing participant.

## Prerequisites

```bash
# ESP-IDF v5.2+
cd ~/esp && git clone -b v5.2.2 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf && ./install.sh esp32s3 && source export.sh

# Dependencies (sibling directories)
cd .. && git clone https://github.com/privkeyio/libnostr-c
git clone https://github.com/privkeyio/secp256k1-frost
git clone https://github.com/privkeyio/noscrypt
```

## Build

```bash
source ~/esp/esp-idf/export.sh
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

## Configuration

```bash
idf.py menuconfig
# Set WiFi credentials and relay URL under "FROST Participant Configuration"
```
