#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: MIT
"""End-to-end signing tests against the native device harness.

Runs two keep_device processes holding shares 1 and 3 of a 2-of-3 group and drives
them over JSON-RPC like the host does. Signatures are checked with BIP340.

  e2e.py <build-dir>                        offline checks (what CI runs)
  KNOTS_BIN=<dir> e2e.py <build-dir>        also spend on a regtest node built from
                                            Bitcoin Knots v29.4.2.knots20260508
"""

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P) % P
    x3 = (lam * lam - p1[0] - p2[0]) % P
    return x3, (lam * (p1[0] - x3) - p1[1]) % P


def point_mul(pt, n):
    r = None
    for i in range(256):
        if (n >> i) & 1:
            r = point_add(r, pt)
        pt = point_add(pt, pt)
    return r


def tagged_hash(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def lift_x(x):
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return x, y if y % 2 == 0 else P - y


def bip340_verify(pubkey, msg, sig):
    pt = lift_x(int.from_bytes(pubkey, "big"))
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if pt is None or r >= P or s >= N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", sig[:32] + pubkey + msg), "big") % N
    R = point_add(point_mul(G, s), point_mul(pt, N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


class RpcError(Exception):
    pass


class Device:
    def __init__(self, binary, name):
        self.name = name
        self.proc = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True)
        self.next_id = 1

    def rpc(self, method, params=None):
        rid = self.next_id
        self.next_id += 1
        req = {"id": rid, "method": method}
        if params is not None:
            req["params"] = params
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(f"{self.name} exited")
            if not line.startswith("{"):
                continue
            resp = json.loads(line)
            if resp.get("id") != rid:
                continue
            if "error" in resp:
                raise RpcError(resp["error"]["message"])
            return resp["result"]

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def frost_sign(build, devices, group, message):
    session = secrets.token_hex(32)
    commits = {}
    for d in devices:
        r = d.rpc("frost_commit", {"group": group, "session_id": session, "message": message.hex()})
        commits[d] = r["commitment"]
    shares = {}
    for d in devices:
        others = "".join(c for o, c in commits.items() if o is not d)
        shares[d] = d.rpc("frost_sign", {"group": group, "session_id": session,
                                         "commitments": others})["signature_share"]
    args = [os.path.join(build, "keep_device_aggregate"), message.hex()]
    for d in sorted(devices, key=lambda d: d.index):
        args += [d.share, commits[d], shares[d]]
    return bytes.fromhex(subprocess.check_output(args, text=True).strip())


def check(label, cond):
    print(f"{'PASS' if cond else 'FAIL'}: {label}")
    if not cond:
        raise SystemExit(1)


def setup(build, parity="even"):
    keys = json.loads(subprocess.check_output([os.path.join(build, "keep_device_keygen"), parity]))
    group33 = bytes.fromhex(keys["group33"])
    devices = []
    for share in (keys["shares"][0], keys["shares"][2]):
        d = Device(os.path.join(build, "keep_device"), f"device{share['index']}")
        d.index, d.share = share["index"], share["share"]
        d.rpc("import_share", {"group": "g", "share": share["share"]})
        check(f"device {share['index']} reports the group key",
              d.rpc("get_share_pubkey", {"group": "g"})["pubkey"] == keys["group33"])
        devices.append(d)
    return devices, group33


def offline(build):
    devices, group33 = setup(build)
    xonly = group33[1:]
    msg = secrets.token_bytes(32)
    sig = frost_sign(build, devices, "g", msg)
    check("2-of-3 signature over a raw message verifies as BIP340", bip340_verify(xonly, msg, sig))
    check("the verifier rejects that signature for a different message",
          not bip340_verify(xonly, bytes([msg[0] ^ 1]) + msg[1:], sig))

    psbt = devices[0].rpc("test_make_psbt", {"xonly": xonly.hex(), "amount": 100000})["psbt"]
    r = devices[0].rpc("bitcoin_sign", {"psbt": psbt, "input_idx": 0})
    sighash = bytes.fromhex(r["sighash"])
    sig = frost_sign(build, devices, "g", sighash)
    check("2-of-3 signature over the device's PSBT sighash verifies as BIP340",
          bip340_verify(xonly, sighash, sig))
    for d in devices:
        d.close()


def regtest(build, knots_bin):
    datadir = tempfile.mkdtemp(prefix="keep-e2e-")
    cli_base = [os.path.join(knots_bin, "bitcoin-cli"), "-regtest", f"-datadir={datadir}"]

    def cli(*args):
        out = subprocess.run(cli_base + list(args), capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError(f"{args[0]}: {out.stderr.strip()}")
        try:
            return json.loads(out.stdout)
        except json.JSONDecodeError:
            return out.stdout.strip()

    mocktime = [1700000000]

    def mine(n, addr):
        for _ in range(n):
            mocktime[0] += 600
            cli("setmocktime", str(mocktime[0]))
            cli("generatetoaddress", "1", addr)

    subprocess.run([os.path.join(knots_bin, "bitcoind"), "-regtest", f"-datadir={datadir}", "-daemon",
                    "-testactivationheight=blake2b@150", "-corepolicy=0", "-txindex",
                    "-fallbackfee=0.0001", f"-mocktime={mocktime[0]}"], check=True,
                   stdout=subprocess.DEVNULL)
    devices = []
    try:
        for _ in range(100):
            try:
                cli("getblockcount")
                break
            except RuntimeError:
                time.sleep(0.2)
        cli("createwallet", "w")
        waddr = cli("getnewaddress", "", "bech32m")
        mine(155, waddr)
        devices, group33 = setup(build)
        xonly = group33[1:].hex()
        addr = cli("deriveaddresses", cli("getdescriptorinfo", f"rawtr({xonly})")["descriptor"])[0]
        for sighash_type in (None, 0x21):
            txid = cli("sendtoaddress", addr, "1.0")
            mine(1, waddr)
            vout = next(o["n"] for o in cli("getrawtransaction", txid, "true")["vout"]
                        if o["scriptPubKey"].get("address") == addr)
            dest = cli("getnewaddress", "", "bech32m")
            psbt = cli("createpsbt", json.dumps([{"txid": txid, "vout": vout}]),
                       json.dumps([{dest: 0.9999}]))
            psbt = cli("utxoupdatepsbt", psbt, json.dumps([f"rawtr({xonly})"]))
            if sighash_type is not None:
                psbt = devices[0].rpc("test_set_sighash", {"psbt": psbt, "sighash": sighash_type})["psbt"]
            r = devices[0].rpc("bitcoin_sign", {"psbt": psbt, "input_idx": 0})
            sig = frost_sign(build, devices, "g", bytes.fromhex(r["sighash"]))
            if r["sighash_type"]:
                sig += bytes([r["sighash_type"]])
            final = devices[0].rpc("test_finalize", {"psbt": psbt, "witness_sig": sig.hex()})["hex"]
            spend = cli("sendrawtransaction", final)
            mine(1, waddr)
            conf = cli("getrawtransaction", spend, "true")["confirmations"]
            check(f"regtest: FROST spend with sighash type {r['sighash_type']:#x} mined", conf == 1)
    finally:
        for d in devices:
            d.close()
        try:
            cli("stop")
        except RuntimeError:
            pass
        time.sleep(1)
        shutil.rmtree(datadir, ignore_errors=True)


def main():
    build = sys.argv[1]
    offline(build)
    if os.environ.get("KNOTS_BIN"):
        regtest(build, os.environ["KNOTS_BIN"])
    print("e2e: all checks passed")


if __name__ == "__main__":
    main()
