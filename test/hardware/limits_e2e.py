#!/usr/bin/env python3
"""Requests at the protocol's size limits must parse on a real device.

Runs against release firmware on an erased or test device; it changes nothing.
Build from a fresh sdkconfig: an existing one keeps settings that sdkconfig.defaults
has since changed.
A request that does not fit in the heap fails as "Parse error" (-32700), which
is how the device answers when cJSON cannot allocate, so each check asks for a
reply that only a parsed request can produce.

  python3 test/hardware/limits_e2e.py [--port /dev/ttyACM0]
"""

import argparse
import base64
import json
import os
import sys
import time

import serial

MAX_MESSAGE_LEN = 16384  # PROTOCOL_MAX_MESSAGE_LEN, including the terminator
MAX_PSBT_LEN = 8192  # PROTOCOL_MAX_PSBT_LEN, including the terminator
PARSE_ERROR = -32700


class Device:
    def __init__(self, port):
        self.ser = serial.Serial(port, 115200, timeout=0.2)
        self.next_id = 1
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.send({"method": "ping"}, wait=1):
                return
        raise SystemExit(f"no device on {port}")

    def send(self, req, wait=10):
        rid = self.next_id
        self.next_id += 1
        line = json.dumps({"id": rid, **req}, separators=(",", ":"))
        self.ser.reset_input_buffer()
        self.ser.write((line + "\r\n").encode())
        self.ser.flush()
        deadline = time.time() + wait
        while time.time() < deadline:
            raw = self.ser.readline().decode("utf-8", errors="replace").strip()
            if raw.startswith("{"):
                try:
                    resp = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if resp.get("id") in (rid, 0):
                    return resp
        return None


def psbt_b64(chars):
    return base64.b64encode(os.urandom(chars * 3 // 4))[:chars].decode()


def padded(params, total):
    """Adds an ignored parameter so the request line is exactly `total` characters."""
    base = len(json.dumps({"id": 999, "method": "bitcoin_parse",
                           "params": {**params, "pad": ""}}, separators=(",", ":")))
    return {**params, "pad": "x" * (total - base)}


failures = []


def check(cond, label, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}: {label}{'' if cond else f' ({detail})'}")
    if not cond:
        failures.append(label)


def parsed(resp):
    return resp is not None and resp.get("error", {}).get("code") != PARSE_ERROR


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/ttyACM0")
    a = ap.parse_args()
    dev = Device(a.port)
    dev.next_id = 100  # three-digit ids, as padded() assumes

    largest_psbt = (MAX_PSBT_LEN - 1) // 4 * 4
    r = dev.send({"method": "bitcoin_parse", "params": {"psbt": psbt_b64(largest_psbt)}})
    check(parsed(r) and "PSBT parse error" in r.get("error", {}).get("message", ""),
          f"a {largest_psbt} character PSBT, the largest allowed, is parsed", r)

    params = padded({"psbt": psbt_b64(largest_psbt)}, MAX_MESSAGE_LEN - 1)
    line_len = len(json.dumps({"id": 999, "method": "bitcoin_parse", "params": params},
                              separators=(",", ":")))
    r = dev.send({"method": "bitcoin_parse", "params": params})
    check(line_len == MAX_MESSAGE_LEN - 1 and parsed(r),
          f"a {line_len} character request, the longest line allowed, is parsed", r)

    for i in range(20):
        r = dev.send({"method": "bitcoin_parse", "params": params})
        if not parsed(r):
            break
    check(parsed(r), "the longest request keeps parsing when repeated 20 times", r)

    print(f"\n{'FAILED: ' + ', '.join(failures) if failures else 'All limit checks passed'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
