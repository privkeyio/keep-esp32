#!/usr/bin/env python3
import serial
import json
import time
import sys
import os

DEVICE = os.environ.get("DEVICE", "/dev/ttyUSB0")
BAUD = int(os.environ.get("BAUD", "115200"))
TIMEOUT = int(os.environ.get("TIMEOUT", "5"))

def send_receive(ser, request, timeout=TIMEOUT):
    ser.reset_input_buffer()
    ser.write((json.dumps(request) + "\n").encode())
    ser.flush()
    time.sleep(0.1)

    start = time.time()
    while time.time() - start < timeout:
        line = ser.readline().decode().strip()
        if line:
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None

def generate_test_share():
    return "ae0b3900b19a1f5de719ac0b14311770b5fbe499be512f80144e092e1740ac9d02930950a722fc8b79610e9d5f00ed8a1407fee195b8914d97233c5c8767c81bdd03dd00fe90614f9628d8db944334a6e82867d69896c5995470e17f39273332188e0100030002000000"

def test_ping(ser):
    print("TEST: ping")
    resp = send_receive(ser, {"id": 1, "method": "ping"})
    assert resp is not None, "no response"
    assert "result" in resp, f"unexpected response: {resp}"
    assert resp["result"]["pong"] == True, "pong not true"
    version = resp["result"].get("version", "unknown")
    print(f"  PASS (v{version})")
    return True

def test_import_list_delete(ser):
    print("TEST: import/list/delete")

    test_group = "npub1test"
    test_share = generate_test_share()

    resp = send_receive(ser, {
        "id": 2, "method": "import_share",
        "params": {"group": test_group, "share": test_share}
    })
    assert resp is not None, "no response to import"
    assert "result" in resp, f"import failed: {resp}"
    assert resp["result"]["ok"] == True, "import not ok"

    resp = send_receive(ser, {"id": 3, "method": "list_shares"})
    assert resp is not None, "no response to list"
    assert "result" in resp, f"list failed: {resp}"
    shares = resp["result"].get("shares", [])
    assert test_group in shares, f"{test_group} not in shares: {shares}"

    resp = send_receive(ser, {
        "id": 4, "method": "delete_share",
        "params": {"group": test_group}
    })
    assert resp is not None, "no response to delete"
    assert "result" in resp, f"delete failed: {resp}"
    assert resp["result"]["ok"] == True, "delete not ok"

    print("  PASS")
    return True

def test_get_pubkey(ser):
    print("TEST: get_share_pubkey")

    test_group = "npub1pubkey"
    test_share = generate_test_share()

    send_receive(ser, {
        "id": 10, "method": "import_share",
        "params": {"group": test_group, "share": test_share}
    })

    resp = send_receive(ser, {
        "id": 11, "method": "get_share_pubkey",
        "params": {"group": test_group}
    })
    assert resp is not None, "no response"
    assert "result" in resp, f"get_pubkey failed: {resp}"
    assert "pubkey" in resp["result"], "no pubkey in result"
    assert "index" in resp["result"], "no index in result"

    send_receive(ser, {
        "id": 12, "method": "delete_share",
        "params": {"group": test_group}
    })

    print(f"  PASS (index={resp['result']['index']})")
    return True

def test_frost_commit(ser):
    print("TEST: frost_commit")

    test_group = "npub1commit"
    test_share = generate_test_share()
    message = "b" * 64

    send_receive(ser, {
        "id": 20, "method": "import_share",
        "params": {"group": test_group, "share": test_share}
    })

    resp = send_receive(ser, {
        "id": 21, "method": "frost_commit",
        "params": {"group": test_group, "message": message}
    })
    assert resp is not None, "no response"
    assert "result" in resp, f"commit failed: {resp}"
    assert "commitment" in resp["result"], "no commitment in result"
    assert "session_id" in resp["result"], "no session_id in result"

    send_receive(ser, {
        "id": 22, "method": "delete_share",
        "params": {"group": test_group}
    })

    print(f"  PASS")
    return True

def test_frost_sign(ser):
    print("TEST: frost_sign (partial)")

    test_group = "npub1sign"
    test_share = generate_test_share()
    message = "d" * 64

    send_receive(ser, {
        "id": 30, "method": "import_share",
        "params": {"group": test_group, "share": test_share}
    })

    # frost_commit generates session_id on device
    commit_resp = send_receive(ser, {
        "id": 31, "method": "frost_commit",
        "params": {"group": test_group, "message": message}
    })
    assert commit_resp is not None, "no commit response"
    assert "result" in commit_resp, f"commit failed: {commit_resp}"
    session_id = commit_resp["result"]["session_id"]

    resp = send_receive(ser, {
        "id": 32, "method": "frost_sign",
        "params": {"group": test_group, "session_id": session_id, "commitments": ""}
    })
    assert resp is not None, "no response"
    # With empty commitments, we expect threshold error (need 2-of-3)
    if "error" in resp:
        assert "threshold" in resp["error"]["message"].lower(), f"unexpected error: {resp}"
        print(f"  PASS (expected threshold error)")
    else:
        assert "signature_share" in resp["result"], "no signature_share in result"
        print(f"  PASS")

    send_receive(ser, {
        "id": 33, "method": "delete_share",
        "params": {"group": test_group}
    })

    return True

def main():
    device = sys.argv[1] if len(sys.argv) > 1 else DEVICE

    print(f"\n=== Hardware Tests ({device}) ===\n")

    try:
        ser = serial.Serial(device, BAUD, timeout=TIMEOUT)
        time.sleep(2)
        ser.reset_input_buffer()
    except Exception as e:
        print(f"Failed to open {device}: {e}")
        sys.exit(1)

    tests = [
        test_ping,
        test_import_list_delete,
        test_get_pubkey,
        test_frost_commit,
        test_frost_sign,
    ]

    passed = 0
    failed = 0

    try:
        for test in tests:
            try:
                if test(ser):
                    passed += 1
            except AssertionError as e:
                print(f"  FAIL: {e}")
                failed += 1
            except Exception as e:
                print(f"  FAIL: {e}")
                failed += 1
    finally:
        ser.close()

    print(f"\n=== {passed}/{passed + failed} tests passed ===\n")
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()
