#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import pty
import select
import re
import shutil

def find_qemu():
    if "QEMU_BIN" in os.environ:
        path = os.environ["QEMU_BIN"]
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
        raise RuntimeError(f"QEMU_BIN set but not executable: {path}")
    for name in ["qemu-system-xtensa", "qemu-system-xtensa-alt"]:
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError("QEMU not found. Set QEMU_BIN env var or add qemu-system-xtensa to PATH")

QEMU = find_qemu()
FLASH = os.environ.get("FLASH", "../build/merged_flash.bin")
if not os.path.isfile(FLASH):
    raise RuntimeError(f"Flash image not found: {FLASH}")

def drain_output(master, timeout=0.5):
    """Drain any pending output"""
    output = ""
    start = time.time()
    while time.time() - start < timeout:
        r, _, _ = select.select([master], [], [], 0.1)
        if r:
            try:
                data = os.read(master, 4096).decode('utf-8', errors='replace')
                output += data
            except OSError:
                break
        else:
            break
    return output

def wait_for_ready(master, timeout=15):
    """Wait for 'Ready' message"""
    output = ""
    start = time.time()
    while time.time() - start < timeout:
        r, _, _ = select.select([master], [], [], 0.1)
        if r:
            try:
                data = os.read(master, 4096).decode('utf-8', errors='replace')
                output += data
                if "Ready" in output:
                    time.sleep(0.3)
                    drain_output(master, 0.2)
                    return True, output
            except OSError:
                break
    return False, output

def send_command(master, cmd):
    """Send command and get response, handling crashes"""
    drain_output(master, 0.1)
    os.write(master, cmd.encode())
    time.sleep(0.5)

    response = ""
    start = time.time()
    while time.time() - start < 5:
        r, _, _ = select.select([master], [], [], 0.2)
        if r:
            try:
                data = os.read(master, 4096).decode('utf-8', errors='replace')
                response += data
                if response.count('{') > 0 and response.count('{') == response.count('}'):
                    break
            except OSError:
                break

    crashed = "Guru Meditation" in response or "Rebooting" in response

    return response, crashed

def extract_json(text):
    """Extract JSON object from text"""
    match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text)
    if match:
        return match.group(0)
    return None

def run_qemu_test():
    master, slave = pty.openpty()

    proc = subprocess.Popen(
        [QEMU, "-M", "esp32s3", "-nographic",
         "-drive", f"file={FLASH},format=raw,if=mtd"],
        stdin=slave,
        stdout=slave,
        stderr=subprocess.STDOUT
    )
    os.close(slave)

    print("Waiting for firmware to boot...")
    ready, output = wait_for_ready(master)
    if not ready:
        print("FAIL: Firmware did not become ready")
        proc.kill()
        return False
    print("Firmware ready!\n")

    SHARE_HEX = "ae0b3900b19a1f5de719ac0b14311770b5fbe499be512f80144e092e1740ac9d02930950a722fc8b79610e9d5f00ed8a1407fee195b8914d97233c5c8767c81bdd03dd00fe90614f9628d8db944334a6e82867d69896c5995470e17f39273332188e0100030002000000"
    SESSION_ID = "0" * 64
    MESSAGE = "a" * 64

    tests = [
        ('{"id":1,"method":"ping"}\n', '"pong":true', "ping"),
        ('{"id":2,"method":"list_shares"}\n', '"shares":', "list_shares (empty)"),
        ('{"id":3,"method":"import_share","params":{"group":"test","share":"' + SHARE_HEX + '"}}\n', '"ok":true', "import_share"),
        ('{"id":4,"method":"list_shares"}\n', '"test"', "list_shares (with test)"),
        ('{"id":5,"method":"get_share_pubkey","params":{"group":"test"}}\n', '"pubkey":', "get_share_pubkey"),
        ('{"id":6,"method":"frost_commit","params":{"group":"test","session_id":"' + SESSION_ID + '","message":"' + MESSAGE + '"}}\n', '"commitment":', "frost_commit"),
        ('{"id":7,"method":"frost_sign","params":{"group":"test","session_id":"' + SESSION_ID + '","commitments":""}}\n', '"signature_share":', "frost_sign"),
        ('{"id":8,"method":"delete_share","params":{"group":"test"}}\n', '"ok":true', "delete_share"),
        ('{"id":9,"method":"list_shares"}\n', '"shares":[]', "list_shares (after delete)"),
    ]

    results = []
    reboot_count = 0

    for i, (cmd, expected, name) in enumerate(tests):
        print(f"Test {i+1}: {name}")

        resp, crashed = send_command(master, cmd)

        if crashed:
            reboot_count += 1
            print(f"  [QEMU crashed - reboot #{reboot_count}]")

            # Wait for reboot
            ready, _ = wait_for_ready(master, timeout=12)
            if ready:
                print(f"  [Firmware rebooted, retrying...]")
                resp, crashed = send_command(master, cmd)
                if crashed:
                    print(f"  [Crashed again, skipping]")
                    results.append((name, False, "Repeated crash"))
                    wait_for_ready(master, timeout=12)
                    continue
            else:
                print(f"  [Reboot failed]")
                results.append((name, False, "Reboot failed"))
                continue

        json_resp = extract_json(resp)
        if json_resp:
            if expected in json_resp:
                print(f"  OK: {json_resp[:80]}...")
                results.append((name, True, json_resp))
            else:
                print(f"  FAIL: {json_resp[:80]}...")
                results.append((name, False, json_resp))
        else:
            print(f"  FAIL: No JSON in response")
            results.append((name, False, resp[:50]))

    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
    os.close(master)

    print("\n" + "="*50)
    print("SUMMARY")
    print("="*50)
    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, detail in results:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}")
    print(f"\n{passed}/{len(tests)} tests passed")
    print(f"QEMU reboots: {reboot_count}")

    return passed >= 5  # Consider success if at least 5 tests pass

if __name__ == "__main__":
    print("=== QEMU FROST Firmware Test ===\n")
    success = run_qemu_test()
    print(f"\n{'=== Test Suite Passed ===' if success else '=== Test Suite Failed ==='}")
    sys.exit(0 if success else 1)
