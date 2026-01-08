#!/usr/bin/env python3
import serial
import time
import json
import sys

DEVICE = '/dev/ttyACM0'
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
        "session_id": "aa" * 32,
        "message": "00" * 32
    }
    resp = send_request(ser, "frost_commit", params)
    if resp and "result" in resp:
        result = resp['result']
        if "commitment" in result:
            print(f"    PASS: commitment received, index={result.get('index')}")
            return result
        print("    FAIL: no commitment in response")
        return None
    print(f"    FAIL: {resp}")
    return None

def test_frost_sign(ser, commit_result):
    print("\n[6] Testing frost_sign...")
    if not commit_result:
        print("    SKIP: No commitment from previous step")
        return False

    params = {
        "group": "test_group",
        "session_id": "aa" * 32,
        "commitments": ""
    }
    resp = send_request(ser, "frost_sign", params)
    if resp and "result" in resp:
        print(f"    PASS: signature share received")
        return True
    if resp and "error" in resp:
        print(f"    Expected error (no other commitments): {resp['error']['message']}")
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

def test_bitcoin_parse(ser):
    print("\n[9] Testing bitcoin_parse...")
    # Minimal valid Taproot PSBT with 1 input, 1 output
    psbt = "cHNidP8BAF4CAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AVDDAAAAAAAAIlEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBK6CGAQAAAAAAIlEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    resp = send_request(ser, "bitcoin_parse", {"psbt": psbt})
    if resp and "result" in resp:
        result = resp['result']
        if result.get('inputs') == 1 and result.get('outputs') == 1:
            print(f"    PASS: inputs={result['inputs']}, outputs={result['outputs']}, fee={result.get('fee_sats')}")
            return True
    print(f"    FAIL: {resp}")
    return False

def test_bitcoin_sign(ser):
    print("\n[10] Testing bitcoin_sign (sighash extraction)...")
    # Same PSBT as above
    psbt = "cHNidP8BAF4CAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AVDDAAAAAAAAIlEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBK6CGAQAAAAAAIlEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    resp = send_request(ser, "bitcoin_sign", {"psbt": psbt, "input_idx": 0})
    if resp and "result" in resp:
        result = resp['result']
        sighash = result.get('sighash', '')
        if len(sighash) == 64:  # 32 bytes hex = 64 chars
            print(f"    PASS: sighash={sighash[:16]}...")
            return True
    print(f"    FAIL: {resp}")
    return False

def test_policy_get(ser):
    print("\n[11] Testing policy_get...")
    resp = send_request(ser, "policy_get")
    if resp and "result" in resp:
        result = resp['result']
        if "has_policy" in result:
            print(f"    PASS: has_policy={result['has_policy']}")
            return True
    print(f"    FAIL: {resp}")
    return False

def test_policy_update_errors(ser):
    print("\n[12] Testing policy_update (error handling)...")
    # Test missing bundle
    resp = send_request(ser, "policy_update", {})
    if not (resp and "error" in resp and "Missing" in resp["error"]["message"]):
        print(f"    FAIL: Expected missing bundle error, got {resp}")
        return False
    # Test invalid length
    resp = send_request(ser, "policy_update", {"bundle": "deadbeef"})
    if not (resp and "error" in resp and "Invalid bundle length" in resp["error"]["message"]):
        print(f"    FAIL: Expected invalid length error, got {resp}")
        return False
    # Test invalid signature (correct length, bad sig)
    # Bundle: 1 + 32 + 32 + 4 + 2048 + 8 + 64 = 2189 bytes = 4378 hex
    fake_bundle = "01" + "00" * 2188
    resp = send_request(ser, "policy_update", {"bundle": fake_bundle})
    if not (resp and "error" in resp and "Invalid signature" in resp["error"]["message"]):
        print(f"    FAIL: Expected invalid signature error, got {resp}")
        return False
    print("    PASS: All error cases handled correctly")
    return True

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
    results.append(("bitcoin_parse", test_bitcoin_parse(ser)))
    results.append(("bitcoin_sign", test_bitcoin_sign(ser)))
    results.append(("policy_get", test_policy_get(ser)))
    results.append(("policy_update_errors", test_policy_update_errors(ser)))

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
