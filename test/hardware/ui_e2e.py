#!/usr/bin/env python3
"""Warden key prompt, end to end on a real device, with no one touching it.

Needs firmware built with CONFIG_KEEP_UI_TEST (sdkconfig.ui-test) on an erased
test device: the device taps its own screen when asked over serial.

  python3 test/hardware/ui_e2e.py [--port /dev/ttyACM0] [--with-timeout]
"""

import argparse
import json
import os
import sys
import time

import serial

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "native", "device"))
from e2e import Warden  # noqa: E402

IDLE, CONFIRM_PIN, ERROR, SUCCESS = 0, 3, 6, 7


class Device:
    def __init__(self, port, log=None):
        self.port = port
        self.log = open(log, "a") if log else None
        self.next_id = 1
        self.ser = None
        self.open()

    def open(self, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.ser = serial.Serial(self.port, 115200, timeout=0.2)
                time.sleep(1.5)
                if self.call("ping", wait=3) is not None:
                    return
                self.ser.close()
            except (serial.SerialException, OSError):
                pass
            time.sleep(0.5)
        raise SystemExit(f"no device on {self.port}")

    def call(self, method, params=None, wait=10):
        rid = self.next_id
        self.next_id += 1
        req = {"id": rid, "method": method}
        if params:
            req["params"] = params
        self.ser.reset_input_buffer()
        self.ser.write((json.dumps(req) + "\r\n").encode())
        self.ser.flush()
        deadline = time.time() + wait
        while time.time() < deadline:
            raw = self.ser.readline().decode("utf-8", errors="replace").strip()
            if raw and self.log:
                self.log.write(f"{time.strftime('%H:%M:%S')} {raw}\n")
                self.log.flush()
            if raw.startswith("{"):
                try:
                    resp = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if resp.get("id") == rid:
                    return resp
        return None

    def restart(self):
        self.call("restart", wait=2)
        self.ser.close()
        time.sleep(3)
        self.open()

    def tap(self, text, **opts):
        r = self.call("ui_tap", {"text": text, **opts})
        if not r or "result" not in r:
            raise SystemExit(f"ui_tap failed: {r}")

    def screen(self):
        return self.call("ui_state")["result"]


failures = []


def check(cond, label, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}: {label}{'' if cond else f' ({detail})'}")
    if not cond:
        failures.append(label)


def error_of(resp):
    return (resp or {}).get("error", {}).get("message", "")


def settle_on(dev, state, timeout=5):
    deadline = time.time() + timeout
    s = dev.screen()
    while s["state"] != state and time.time() < deadline:
        time.sleep(0.2)
        s = dev.screen()
    return s


def dismiss(dev, label):
    dev.tap(label)
    s = settle_on(dev, IDLE)
    check(s["state"] == IDLE, f"{label} returns to the home screen", s)
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/ttyACM0")
    ap.add_argument("--with-timeout", action="store_true", help="also wait out the 2 minute prompt")
    ap.add_argument("--log", help="append everything the device prints to this file")
    a = ap.parse_args()
    dev = Device(a.port, a.log)

    s = dev.screen()
    if "No policy" not in s["texts"]:
        raise SystemExit(f"needs an erased device with no policy; screen shows {s['texts']}")
    warden, other = Warden(), Warden()

    print("Reject")
    dev.tap("Reject")
    r = dev.call("policy_update", {"bundle": warden.bundle({"max_amount": 50000}, 100)}, wait=130)
    check("not confirmed" in error_of(r), "Reject refuses the install", r)
    s = dev.screen()
    check(s["state"] == ERROR and "Key rejected" in s["texts"], "Reject shows Key rejected", s)
    time.sleep(3)
    check(dev.screen()["state"] == ERROR, "the result stays until acknowledged")
    dismiss(dev, "OK")

    print("A bounce of the Reject tap")
    dev.tap("Reject", bounce_ms=150)
    r = dev.call("policy_update", {"bundle": warden.bundle({}, 100)}, wait=130)
    check("not confirmed" in error_of(r), "Reject refuses the install", r)
    time.sleep(1)
    s = dev.screen()
    check(s["state"] == ERROR, "the bounce did not dismiss the result", s)
    dismiss(dev, "OK")

    print("A tap as the prompt appears")
    dev.tap("Trust", after_ms=100)
    dev.tap("Reject", after_ms=1500)
    r = dev.call("policy_update", {"bundle": warden.bundle({}, 100)}, wait=130)
    check("not confirmed" in error_of(r), "the early Trust tap was ignored", r)
    dismiss(dev, "OK")

    if a.with_timeout:
        print("No answer")
        r = dev.call("policy_update", {"bundle": warden.bundle({}, 100)}, wait=140)
        check("not confirmed" in error_of(r), "an unanswered prompt refuses the install", r)
        s = dev.screen()
        check(s["state"] == ERROR and "Timed out" in s["texts"], "it says it timed out", s)
        dismiss(dev, "OK")

    print("Trust")
    dev.tap("Trust")
    r = dev.call("policy_update", {"bundle": warden.bundle({"max_amount": 50000}, 100)}, wait=130)
    check(r is not None and "result" in r, "Trust installs the policy", r)
    s = dev.screen()
    check(s["state"] == SUCCESS and "Key trusted" in s["texts"], "Trust shows Key trusted", s)
    s = dismiss(dev, "Done")
    check("Policy v1" in s["texts"] and "No policy" not in s["texts"],
          "the home screen shows the policy", s)

    print("After a reboot")
    dev.restart()
    got = dev.call("policy_get")["result"]
    check(got.get("warden_pubkey") == warden.pubkey.hex() and got.get("created_at") == 100,
          "the pin and policy survive", got)
    check("Policy v1" in dev.screen()["texts"], "the home screen shows the policy at boot")
    r = dev.call("policy_update", {"bundle": other.bundle({}, 500)})
    check("pinned Warden key" in error_of(r), "another key is refused", r)
    r = dev.call("policy_update", {"bundle": warden.bundle({}, 50)})
    check("not newer" in error_of(r), "an older bundle is refused", r)
    r = dev.call("policy_update", {"bundle": warden.bundle({"max_amount": 60000}, 200)})
    check(r is not None and "result" in r, "a newer bundle from the pinned key installs", r)
    check(dev.screen()["state"] == IDLE, "a pinned update needs no prompt")

    missed = dev.screen()["taps_missed"]
    check(missed == 0, "every scheduled tap found its button", missed)
    print(f"\n{'FAILED: ' + ', '.join(failures) if failures else 'All device UI checks passed'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
