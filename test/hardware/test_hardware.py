#!/usr/bin/env python3
import serial
import json
import time
import sys
import os
import secrets

DEVICE = os.environ.get("DEVICE", "/dev/ttyACM0")
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

# Participant 1 of a public 2-of-3 test group (a frost-secp256k1-tr key package) and a
# commitment from participant 3, enough for the device to complete a signing round.
TEST_KEY_PACKAGE = (
    "00230f8ab30000000000000000000000000000000000000000000000000000000000000001f9806efa"
    "60670799c2f4accc8e28c108ba4655d23568c98f2995583874bd8b3302032ee7b831c0fd1f879e089f"
    "08ed286249afe84edd191284a90b7dcab416b5c002a80c99f8a5ea6af8f238cb68f258125bea2c0d46"
    "b6a3ce1eb75ef95ca899ac3d02"
)
TEST_PARTICIPANTS = 3
PEER_INDEX = 3
PEER_COMMITMENT = (
    "00230f8ab302536c15dc7ffdcf7903717514864a043e130e1da4b56f77897648716d91c8861b03e422"
    "e3fdb39dd5a3267f56229ebef45ebac6e541e03353ec265fc880624ea1f7"
)


def signing_package(message_hex, commitments):
    """frost-core SigningPackage serialization: header, count, identifier and commitment
    pairs in identifier order, then the length-prefixed message."""
    header = bytes.fromhex(next(iter(commitments.values())))[:5]
    out = header + bytes([len(commitments)])
    for index in sorted(commitments):
        out += index.to_bytes(32, "big") + bytes.fromhex(commitments[index])
    message = bytes.fromhex(message_hex)
    return (out + bytes([len(message)]) + message).hex()


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

    resp = send_receive(ser, {
        "id": 2, "method": "import_share",
        "params": {"group": test_group, "key_package": TEST_KEY_PACKAGE,
                   "participants": TEST_PARTICIPANTS}
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

    send_receive(ser, {
        "id": 10, "method": "import_share",
        "params": {"group": test_group, "key_package": TEST_KEY_PACKAGE,
                   "participants": TEST_PARTICIPANTS}
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
    message = "b" * 64
    session_id = secrets.token_hex(32)

    send_receive(ser, {
        "id": 20, "method": "import_share",
        "params": {"group": test_group, "key_package": TEST_KEY_PACKAGE,
                   "participants": TEST_PARTICIPANTS}
    })

    resp = send_receive(ser, {
        "id": 21, "method": "frost_commit",
        "params": {"group": test_group, "session_id": session_id, "message": message}
    })
    assert resp is not None, "no response"
    assert "result" in resp, f"commit failed: {resp}"
    assert "commitment" in resp["result"], "no commitment in result"
    assert "index" in resp["result"], "no index in result"

    send_receive(ser, {
        "id": 22, "method": "delete_share",
        "params": {"group": test_group}
    })

    print("  PASS")
    return True

def test_frost_sign(ser):
    print("TEST: frost_sign")

    test_group = "npub1sign"
    message = "d" * 64
    session_id = secrets.token_hex(32)

    send_receive(ser, {
        "id": 30, "method": "import_share",
        "params": {"group": test_group, "key_package": TEST_KEY_PACKAGE,
                   "participants": TEST_PARTICIPANTS}
    })

    commit_resp = send_receive(ser, {
        "id": 31, "method": "frost_commit",
        "params": {"group": test_group, "session_id": session_id, "message": message}
    })
    assert commit_resp is not None, "no commit response"
    assert "result" in commit_resp, f"commit failed: {commit_resp}"

    mine = commit_resp["result"]["commitment"]
    resp = send_receive(ser, {
        "id": 32, "method": "frost_sign",
        "params": {"group": test_group, "session_id": session_id,
                   "signing_package": signing_package(message, {1: mine})}
    })
    assert resp is not None, "no response"
    assert "error" in resp and "(-9)" in resp["error"]["message"], f"below threshold accepted: {resp}"

    session_id = secrets.token_hex(32)
    commit_resp = send_receive(ser, {
        "id": 34, "method": "frost_commit",
        "params": {"group": test_group, "session_id": session_id, "message": message}
    })
    assert commit_resp is not None and "result" in commit_resp, f"commit failed: {commit_resp}"
    package = signing_package(message, {1: commit_resp["result"]["commitment"],
                                        PEER_INDEX: PEER_COMMITMENT})
    resp = send_receive(ser, {
        "id": 35, "method": "frost_sign",
        "params": {"group": test_group, "session_id": session_id, "signing_package": package}
    }, timeout=30)
    assert resp is not None and "result" in resp, f"sign failed: {resp}"
    assert len(resp["result"]["signature_share"]) == 64, "share must be 32 bytes"
    print("  PASS (below-threshold package refused, full package signed)")

    send_receive(ser, {
        "id": 33, "method": "delete_share",
        "params": {"group": test_group}
    })

    return True

def test_session_replay_protection(ser):
    print("TEST: session_id replay protection")

    test_group = "npub1replay"
    message = "e" * 64
    session_id = secrets.token_hex(32)

    send_receive(ser, {
        "id": 40, "method": "import_share",
        "params": {"group": test_group, "key_package": TEST_KEY_PACKAGE,
                   "participants": TEST_PARTICIPANTS}
    })

    # First commit should succeed
    resp1 = send_receive(ser, {
        "id": 41, "method": "frost_commit",
        "params": {"group": test_group, "session_id": session_id, "message": message}
    })
    assert resp1 is not None, "no response to first commit"
    assert "result" in resp1, f"first commit failed: {resp1}"

    # Second commit with SAME session_id should fail (replay protection)
    resp2 = send_receive(ser, {
        "id": 42, "method": "frost_commit",
        "params": {"group": test_group, "session_id": session_id, "message": message}
    })
    assert resp2 is not None, "no response to second commit"
    assert "error" in resp2, f"second commit should fail but got: {resp2}"
    msg = resp2["error"]["message"].lower()
    assert "already" in msg or "duplicate" in msg, f"expected replay error: {resp2}"

    send_receive(ser, {
        "id": 43, "method": "delete_share",
        "params": {"group": test_group}
    })

    print("  PASS (replay blocked)")
    return True

def reset_device(ser):
    ser.dtr = False
    ser.rts = True
    time.sleep(0.1)
    ser.rts = False
    time.sleep(2)
    ser.reset_input_buffer()

def main():
    do_reset = "--reset" in sys.argv or "-r" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    device = args[0] if args else DEVICE

    print(f"\n=== Hardware Tests ({device}) ===\n")

    try:
        ser = serial.Serial(device, BAUD, timeout=TIMEOUT)
        time.sleep(2)
        ser.reset_input_buffer()
        if do_reset:
            print("Resetting device...")
            reset_device(ser)
    except Exception as e:
        print(f"Failed to open {device}: {e}")
        sys.exit(1)

    tests = [
        test_ping,
        test_import_list_delete,
        test_get_pubkey,
        test_frost_commit,
        test_frost_sign,
        test_session_replay_protection,
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
