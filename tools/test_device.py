#!/usr/bin/env python3
import serial
import json
import time
import sys

DEVICE = "/dev/ttyACM0"
BAUD = 115200

request_id = 0

def send_command(ser, method, params=None, timeout=5):
    global request_id
    request_id += 1

    cmd = {"id": request_id, "method": method}
    if params:
        cmd["params"] = params
    line = json.dumps(cmd) + "\n"

    # Clear any pending data
    ser.reset_input_buffer()
    time.sleep(0.1)

    ser.write(line.encode())
    ser.flush()

    # Read response, skip non-JSON lines, match ID
    old_timeout = ser.timeout
    ser.timeout = timeout
    try:
        for _ in range(20):
            resp_line = ser.readline().decode().strip()
            if not resp_line:
                continue
            if resp_line.startswith("{"):
                try:
                    resp = json.loads(resp_line)
                    if resp.get("id") == request_id:
                        return resp
                except json.JSONDecodeError:
                    continue
    finally:
        ser.timeout = old_timeout
    return None

def main():
    print(f"Connecting to {DEVICE}...")
    ser = serial.Serial(DEVICE, BAUD, timeout=5)
    time.sleep(0.5)

    # Clear any buffered data
    ser.reset_input_buffer()

    # Test ping
    print("\n--- Testing ping ---")
    resp = send_command(ser, "ping")
    if resp:
        print(f"Response: {json.dumps(resp, indent=2)}")
    else:
        print("No response")

    # List shares
    print("\n--- Listing shares ---")
    resp = send_command(ser, "list_shares")
    if resp:
        print(f"Response: {json.dumps(resp, indent=2)}")
    else:
        print("No response")

    # Test UX confirmation screen
    if "--test-ux" in sys.argv or len(sys.argv) == 1:
        print("\n--- Testing transaction confirmation UI ---")
        print("Watch the device screen. You have 30 seconds to approve/reject.")
        print("Tap Approve or Reject on the device...")

        resp = send_command(ser, "ux_test", timeout=40)
        if resp:
            print(f"Response: {json.dumps(resp, indent=2)}")
            if "result" in resp:
                result = resp["result"].get("result", "unknown")
                if result == "approved":
                    print(">>> User APPROVED the transaction")
                elif result == "rejected":
                    print(">>> User REJECTED the transaction")
                elif result == "timeout":
                    print(">>> Confirmation TIMED OUT")
        else:
            print("No response (possible timeout)")

    ser.close()
    print("\nDone!")

if __name__ == "__main__":
    main()
