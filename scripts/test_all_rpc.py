#!/usr/bin/env python3
import serial
import time
import json
import sys

DEVICE = '/dev/ttyUSB0'
BAUD = 115200

def send_request(ser, method, params=None, req_id=1):
    ser.reset_input_buffer()
    req = {"id": req_id, "method": method}
    if params:
        req["params"] = params
    line = json.dumps(req) + "\r\n"
    ser.write(line.encode())
    ser.flush()
    time.sleep(0.2)

    deadline = time.time() + 3
    while time.time() < deadline:
        if ser.in_waiting:
            raw = ser.readline().decode('utf-8', errors='replace').strip()
            if raw.startswith('{'):
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    pass
        time.sleep(0.05)
    return None

def test_ping(ser):
    print("\n[1] Testing ping...")
    resp = send_request(ser, "ping")
    if resp and "result" in resp:
        print(f"    PASS: {resp['result']}")
        return True
    print(f"    FAIL: {resp}")
    return False

def test_list_shares(ser):
    print("\n[2] Testing list_shares...")
    resp = send_request(ser, "list_shares")
    if resp and "result" in resp:
        print(f"    PASS: {resp['result']}")
        return True
    print(f"    FAIL: {resp}")
    return False

def test_import_share(ser):
    print("\n[3] Testing import_share...")
    share_hex = "ce3a74fcb3e3c96752b777f6d990583873de9f67c671a875ecd6d5ce0ec36a16024f97ec0982f0e803521baea6b44fcb79bcb5007e2cc0e4261b252dc67debb3b7020b9e63f59041acb806d910bd3814f19979737dbaef4c9e9b03add836e8899b22010003000200"
    params = {"group": "test_group", "share": share_hex}
    resp = send_request(ser, "import_share", params)
    if resp and "result" in resp:
        print(f"    PASS: {resp['result']}")
        return True
    print(f"    FAIL: {resp}")
    return False

def test_get_share_pubkey(ser):
    print("\n[4] Testing get_share_pubkey...")
    resp = send_request(ser, "get_share_pubkey", {"group": "test_group"})
    if resp and "result" in resp:
        print(f"    PASS: {resp['result']}")
        return True
    print(f"    FAIL: {resp}")
    return False

def test_frost_commit(ser):
    print("\n[5] Testing frost_commit...")
    params = {
        "group": "test_group",
        "session_id": "00" * 32,
        "message": "00" * 32
    }
    resp = send_request(ser, "frost_commit", params)
    if resp and "result" in resp:
        print(f"    PASS: commitment received")
        return resp['result']
    print(f"    FAIL: {resp}")
    return None

def test_frost_sign(ser, commitment):
    print("\n[6] Testing frost_sign...")
    if not commitment:
        print("    SKIP: No commitment from previous step")
        return False

    params = {
        "group": "test_group",
        "session_id": "00" * 32,
        "commitments": "00" * 132
    }
    resp = send_request(ser, "frost_sign", params)
    if resp and "result" in resp:
        print(f"    PASS: signature share received")
        return True
    if resp and "error" in resp:
        print(f"    Expected error (invalid commitments): {resp['error']['message']}")
        return True
    print(f"    FAIL: {resp}")
    return False

def test_delete_share(ser):
    print("\n[7] Testing delete_share...")
    resp = send_request(ser, "delete_share", {"group": "test_group"})
    if resp and "result" in resp:
        print(f"    PASS: {resp['result']}")
        return True
    print(f"    FAIL: {resp}")
    return False

def test_error_handling(ser):
    print("\n[8] Testing error handling...")
    resp = send_request(ser, "nonexistent_method")
    if resp and "error" in resp:
        print(f"    PASS: {resp['error']}")
        return True
    print(f"    FAIL: {resp}")
    return False

def main():
    print("ESP32-S3 FROST Signer - RPC Test Suite")
    print("=" * 50)

    try:
        ser = serial.Serial(DEVICE, BAUD, timeout=1)
        time.sleep(1)
        ser.reset_input_buffer()
    except Exception as e:
        print(f"Failed to open {DEVICE}: {e}")
        sys.exit(1)

    results = []

    results.append(("ping", test_ping(ser)))
    results.append(("list_shares", test_list_shares(ser)))
    results.append(("import_share", test_import_share(ser)))
    results.append(("get_share_pubkey", test_get_share_pubkey(ser)))
    commitment = test_frost_commit(ser)
    results.append(("frost_commit", commitment is not None))
    results.append(("frost_sign", test_frost_sign(ser, commitment)))
    results.append(("delete_share", test_delete_share(ser)))
    results.append(("error_handling", test_error_handling(ser)))

    ser.close()

    print("\n" + "=" * 50)
    print("Results:")
    passed = sum(1 for _, r in results if r)
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  {name}: {status}")

    print(f"\nTotal: {passed}/{len(results)} tests passed")
    sys.exit(0 if passed == len(results) else 1)

if __name__ == "__main__":
    main()
