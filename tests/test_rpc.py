#!/usr/bin/env python3
import serial
import json
import sys
import time

def send_rpc(ser, method, params=None, req_id=1):
    msg = {"id": req_id, "method": method}
    if params:
        msg["params"] = params
    line = json.dumps(msg) + "\n"
    ser.write(line.encode())
    ser.flush()
    time.sleep(0.1)
    resp_line = ser.readline().decode().strip()
    if resp_line:
        return json.loads(resp_line)
    return None

def test_ping(ser):
    resp = send_rpc(ser, "ping", req_id=1)
    assert resp and resp.get("id") == 1
    assert "result" in resp
    assert resp["result"].get("pong") == True
    print(f"  ping: OK (version={resp['result'].get('version')})")

def test_list_shares_empty(ser):
    resp = send_rpc(ser, "list_shares", req_id=2)
    assert resp and resp.get("id") == 2
    assert "result" in resp
    shares = resp["result"].get("shares", [])
    print(f"  list_shares: OK ({len(shares)} shares)")
    return shares

def test_import_share(ser, group, share_hex):
    resp = send_rpc(ser, "import_share", {"group": group, "share": share_hex}, req_id=3)
    assert resp and resp.get("id") == 3
    if "error" in resp:
        print(f"  import_share: FAIL ({resp['error']['message']})")
        return False
    assert resp["result"].get("ok") == True
    print(f"  import_share: OK")
    return True

def test_get_pubkey(ser, group):
    resp = send_rpc(ser, "get_share_pubkey", {"group": group}, req_id=4)
    assert resp and resp.get("id") == 4
    if "error" in resp:
        print(f"  get_share_pubkey: FAIL ({resp['error']['message']})")
        return None
    pubkey = resp["result"].get("pubkey")
    index = resp["result"].get("index")
    print(f"  get_share_pubkey: OK (index={index}, pubkey={pubkey[:16]}...)")
    return pubkey

def test_frost_commit(ser, group, session_id, message):
    resp = send_rpc(ser, "frost_commit", {
        "group": group,
        "session_id": session_id,
        "message": message
    }, req_id=5)
    assert resp and resp.get("id") == 5
    if "error" in resp:
        print(f"  frost_commit: FAIL ({resp['error']['message']})")
        return None
    commitment = resp["result"].get("commitment")
    index = resp["result"].get("index")
    print(f"  frost_commit: OK (index={index}, commitment={commitment[:32]}...)")
    return commitment

def test_frost_sign(ser, group, session_id, commitments=""):
    resp = send_rpc(ser, "frost_sign", {
        "group": group,
        "session_id": session_id,
        "commitments": commitments
    }, req_id=6)
    assert resp and resp.get("id") == 6
    if "error" in resp:
        print(f"  frost_sign: FAIL ({resp['error']['message']})")
        return None
    sig_share = resp["result"].get("signature_share")
    index = resp["result"].get("index")
    print(f"  frost_sign: OK (index={index}, sig_share={sig_share[:32]}...)")
    return sig_share

def test_delete_share(ser, group):
    resp = send_rpc(ser, "delete_share", {"group": group}, req_id=7)
    assert resp and resp.get("id") == 7
    assert resp["result"].get("ok") == True
    print(f"  delete_share: OK")

def generate_test_share():
    return "ae0b3900b19a1f5de719ac0b14311770b5fbe499be512f80144e092e1740ac9d02930950a722fc8b79610e9d5f00ed8a1407fee195b8914d97233c5c8767c81bdd03dd00fe90614f9628d8db944334a6e82867d69896c5995470e17f39273332188e0100030002000000"

def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
    print(f"Connecting to {port}...")

    try:
        ser = serial.Serial(port, 115200, timeout=2)
        time.sleep(0.5)
        ser.reset_input_buffer()
    except Exception as e:
        print(f"Failed to open {port}: {e}")
        sys.exit(1)

    print("\n=== Phase 3 RPC Tests ===\n")

    try:
        test_ping(ser)

        initial_shares = test_list_shares_empty(ser)

        test_group = "npub1test123"
        test_share = generate_test_share()

        if test_import_share(ser, test_group, test_share):
            test_get_pubkey(ser, test_group)

            session_id = "a" * 64
            message = "b" * 64

            commitment = test_frost_commit(ser, test_group, session_id, message)
            if commitment:
                sig_share = test_frost_sign(ser, test_group, session_id, "")

            test_delete_share(ser, test_group)

        final_shares = test_list_shares_empty(ser)

        print("\n=== All Tests Passed ===\n")

    except AssertionError as e:
        print(f"\nTest failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
    finally:
        ser.close()

if __name__ == "__main__":
    main()
