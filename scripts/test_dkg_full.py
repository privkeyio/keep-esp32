#!/usr/bin/env python3
"""
Full 3-participant DKG test using a single hardware device.

This script simulates a 2-of-3 DKG by running each participant's role
sequentially on the same device, collecting cryptographic data, and
completing the full protocol.
"""

import serial
import json
import time
import sys

DEVICE = "/dev/ttyUSB0"
BAUD = 115200
TIMEOUT = 5

def open_serial():
    ser = serial.Serial(DEVICE, BAUD, timeout=TIMEOUT)
    time.sleep(0.5)
    ser.reset_input_buffer()
    return ser

def rpc(ser, method, params=None):
    if params is None:
        params = {}
    cmd = json.dumps({'id': 1, 'method': method, 'params': params})
    ser.write((cmd + '\n').encode())
    ser.flush()
    time.sleep(0.3)

    for _ in range(10):
        line = ser.readline().decode().strip()
        if line.startswith('{') and '"id"' in line:
            resp = json.loads(line)
            if 'error' in resp:
                raise Exception(f"RPC error: {resp['error']}")
            return resp.get('result', {})
    raise Exception(f"No response for {method}")

def collect_round1(participant_index, threshold=2, participant_count=3):
    """Run Round 1 for a single participant and return the data."""
    print(f"\n=== Participant {participant_index}: Generating Round 1 ===")
    ser = open_serial()

    try:
        rpc(ser, 'dkg_init', {
            'group': 'dkg_test_full',
            'threshold': threshold,
            'participant_count': participant_count,
            'our_index': participant_index
        })
        print(f"  Initialized DKG session")

        r1 = rpc(ser, 'dkg_round1')
        print(f"  Generated {r1['num_coefficients']} coefficient commitments")

        r2 = rpc(ser, 'dkg_round2')
        shares = r2.get('shares', [])
        print(f"  Generated {len(shares)} shares for other participants")

        return {
            'participant_index': participant_index,
            'round1': r1,
            'round2_shares': {s['recipient_index']: s['share'] for s in shares}
        }
    finally:
        ser.close()

def complete_dkg(participant_index, all_data, threshold=2, participant_count=3):
    """Complete DKG for a participant given all other participants' data."""
    print(f"\n=== Participant {participant_index}: Completing DKG ===")
    ser = open_serial()

    try:
        rpc(ser, 'dkg_init', {
            'group': 'dkg_test_full',
            'threshold': threshold,
            'participant_count': participant_count,
            'our_index': participant_index
        })

        rpc(ser, 'dkg_round1')
        print(f"  Re-generated our Round 1")

        for p_data in all_data:
            if p_data['participant_index'] == participant_index:
                continue

            peer_idx = p_data['participant_index']
            # Use compact JSON with no spaces (C parser expects this)
            r1_json = json.dumps(p_data['round1'], separators=(',', ':'))

            try:
                result = rpc(ser, 'dkg_round1_peer', {
                    'peer_index': peer_idx,
                    'dkg_data': r1_json
                })
                validated = result.get('validated', False)
                print(f"  Received Round 1 from peer {peer_idx}: validated={validated}")
            except Exception as e:
                print(f"  Warning: Failed to validate peer {peer_idx}: {e}")

        rpc(ser, 'dkg_round2')
        print(f"  Generated our Round 2 shares")

        for p_data in all_data:
            if p_data['participant_index'] == participant_index:
                continue

            peer_idx = p_data['participant_index']
            share = p_data['round2_shares'].get(participant_index)

            if share:
                rpc(ser, 'dkg_receive_share', {
                    'peer_index': peer_idx,
                    'share': share
                })
                print(f"  Received share from peer {peer_idx}")

        result = rpc(ser, 'dkg_finalize')
        print(f"  DKG finalized!")
        print(f"  Group public key: {result.get('group_pubkey', 'N/A')}")
        return result

    finally:
        ser.close()

def main():
    print("=" * 60)
    print("FROST DKG Full Test - 2-of-3 Threshold")
    print("=" * 60)

    print("\nPhase 1: Collect Round 1 and Round 2 data from all participants")
    print("-" * 60)

    all_data = []
    for i in range(1, 4):
        data = collect_round1(i)
        all_data.append(data)
        time.sleep(0.5)

    print("\n" + "=" * 60)
    print("Phase 2: Complete DKG for each participant")
    print("-" * 60)

    results = []
    for i in range(1, 4):
        result = complete_dkg(i, all_data)
        results.append(result)
        time.sleep(0.5)

    print("\n" + "=" * 60)
    print("DKG TEST RESULTS")
    print("=" * 60)

    pubkeys = [r.get('group_pubkey', '') for r in results]
    if len(set(pubkeys)) == 1 and pubkeys[0]:
        print(f"\n✓ SUCCESS: All participants derived the same group public key")
        print(f"  Group pubkey: {pubkeys[0]}")
    else:
        print(f"\n✗ FAILURE: Group public keys don't match")
        for i, pk in enumerate(pubkeys):
            print(f"  Participant {i+1}: {pk}")
        sys.exit(1)

    ser = open_serial()
    try:
        shares = rpc(ser, 'list_shares')
        print(f"\n  Shares stored on device: {shares.get('shares', [])}")
    finally:
        ser.close()

    print("\n" + "=" * 60)
    print("Phase 5.5 DKG verification complete!")
    print("=" * 60)

if __name__ == '__main__':
    main()
