#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: MIT
"""End-to-end signing tests against the native device harness.

Runs keep_device processes holding shares of dealer-generated groups and drives them
over JSON-RPC like the host does, with frost_tool (frost-secp256k1-tr, as keep uses it)
building signing packages, standing in for other signers and aggregating. Signatures
are checked with BIP340.

  e2e.py <build-dir>                        offline checks (what CI runs)
  KNOTS_BIN=<dir> e2e.py <build-dir>        also spend on a regtest node built from
                                            Bitcoin Knots v29.4.2.knots20260508
"""

import hashlib
import json
import os
import secrets
import shutil
import socket
import struct
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


def bip340_sign(seckey, msg):
    d0 = int.from_bytes(seckey, "big")
    pt = point_mul(G, d0)
    d = d0 if pt[1] % 2 == 0 else N - d0
    pub = pt[0].to_bytes(32, "big")
    aux = secrets.token_bytes(32)
    t = (d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", t + pub + msg), "big") % N
    R = point_mul(G, k0)
    k = k0 if R[1] % 2 == 0 else N - k0
    r = R[0].to_bytes(32, "big")
    e = int.from_bytes(tagged_hash("BIP0340/challenge", r + pub + msg), "big") % N
    return r + ((k + e * d) % N).to_bytes(32, "big")


class Warden:
    """Builds policy_bundle_t (main/policy.h, packed, little endian) signed by one key."""

    RULES_MAX = 2048

    def __init__(self):
        self.seckey = secrets.token_bytes(32)
        self.pubkey = point_mul(G, int.from_bytes(self.seckey, "big"))[0].to_bytes(32, "big")

    def bundle(self, rules, created_at, rules_len=None, tamper=False):
        body = rules if isinstance(rules, bytes) else json.dumps(rules).encode()
        head = struct.pack("<B32s32sI", 1, self.pubkey, hashlib.sha256(body).digest(),
                           len(body) if rules_len is None else rules_len)
        unsigned = head + body.ljust(self.RULES_MAX, b"\0") + struct.pack("<Q", created_at)
        sig = bip340_sign(self.seckey, hashlib.sha256(unsigned).digest())
        if tamper:
            sig = sig[:-1] + bytes([sig[-1] ^ 1])
        return (unsigned + sig).hex()


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


class Group:
    """A dealer-generated group from frost_tool; signers are 1-based indices."""

    def __init__(self, build, min_signers, participants, parity="even"):
        self.tool = os.path.join(build, "frost_tool", "release", "frost_tool")
        keys = json.loads(self.run("keygen", str(min_signers), str(participants), parity))
        self.min, self.n = min_signers, participants
        self.group33 = bytes.fromhex(keys["group_key"])
        self.pubkeys = keys["public_key_package"]
        self.kp = {p["index"]: p["key_package"] for p in keys["participants"]}

    def run(self, *args):
        return subprocess.check_output([self.tool, *args], text=True).strip()

    def package(self, message, commitments):
        return self.run("package", message.hex(), *[f"{i}:{c}" for i, c in sorted(commitments.items())])

    def device(self, build, index, name=None, group="g"):
        d = Device(os.path.join(build, "keep_device"), name or f"device{index}")
        d.index = index
        r = d.rpc("import_share", {"group": group, "key_package": self.kp[index], "participants": self.n})
        check(f"{d.name} import reports index {index}, {self.min}-of-{self.n} and the group key",
              r["index"] == index and r["threshold"] == self.min and r["participants"] == self.n
              and r["pubkey"] == self.group33.hex())
        return d


def frost_sign(group, devices, message, psbt=None, peers=(), name="g"):
    """Signs as the host does: every device commits, the full set of commitments goes back
    to each as one signing package. `peers` are signer indices played by frost_tool. With a
    PSBT, every device approves it with bitcoin_sign first, since each enforces its own
    policy."""
    if psbt is not None:
        for d in devices:
            r = d.rpc("bitcoin_sign", {"psbt": psbt, "input_idx": 0})
            if bytes.fromhex(r["sighash"]) != message:
                raise RuntimeError("device computed a different sighash")
    session = secrets.token_hex(32)
    commits, nonces = {}, {}
    for d in devices:
        r = d.rpc("frost_commit", {"group": name, "session_id": session, "message": message.hex()})
        if r["index"] != d.index:
            raise RuntimeError("commitment from the wrong index")
        commits[d.index] = r["commitment"]
    for i in peers:
        r = json.loads(group.run("commit", group.kp[i]))
        commits[i], nonces[i] = r["commitment"], r["nonces"]
    package = group.package(message, commits)
    shares = {}
    for d in devices:
        shares[d.index] = d.rpc("frost_sign", {"group": name, "session_id": session,
                                               "signing_package": package})["signature_share"]
    for i in peers:
        shares[i] = group.run("sign", group.kp[i], nonces[i], package)
    return bytes.fromhex(group.run("aggregate", group.pubkeys, package,
                                   *[f"{i}:{s}" for i, s in sorted(shares.items())]))


def check(label, cond):
    print(f"{'PASS' if cond else 'FAIL'}: {label}")
    if not cond:
        raise SystemExit(1)


def setup(build, parity="even"):
    group = Group(build, 2, 3, parity)
    devices = [group.device(build, 1), group.device(build, 3)]
    for d in devices:
        check(f"{d.name} reports the group key",
              d.rpc("get_share_pubkey", {"group": "g"})["pubkey"] == group.group33.hex())
    return devices, group


def offline(build):
    for parity in ("even", "odd"):
        devices, group = setup(build, parity)
        xonly = group.group33[1:]
        msg = secrets.token_bytes(32)
        sig = frost_sign(group, devices, msg)
        check(f"2-of-3 ({parity} group key) signature over a raw message verifies as BIP340",
              bip340_verify(xonly, msg, sig))
        check("the verifier rejects that signature for a different message",
              not bip340_verify(xonly, bytes([msg[0] ^ 1]) + msg[1:], sig))
        msg = secrets.token_bytes(32)
        check(f"a device signs with a peer that is not a device ({parity})",
              bip340_verify(xonly, msg, frost_sign(group, devices[:1], msg, peers=[2])))
        msg = secrets.token_bytes(32)
        check(f"three of a 2-of-3 group sign together ({parity})",
              bip340_verify(xonly, msg, frost_sign(group, devices, msg, peers=[2])))

        psbt = devices[0].rpc("test_make_psbt", {"xonly": xonly.hex(), "amount": 100000})["psbt"]
        r = devices[0].rpc("bitcoin_sign", {"psbt": psbt, "input_idx": 0})
        sighash = bytes.fromhex(r["sighash"])
        sig = frost_sign(group, devices, sighash)
        check(f"2-of-3 signature over the device's PSBT sighash verifies as BIP340 ({parity})",
              bip340_verify(xonly, sighash, sig))
        for d in devices:
            d.close()

    group = Group(build, 3, 5, "odd")
    devices = [group.device(build, i) for i in (2, 4, 5)]
    msg = secrets.token_bytes(32)
    check("3-of-5 with three devices verifies as BIP340",
          bip340_verify(group.group33[1:], msg, frost_sign(group, devices, msg)))
    msg = secrets.token_bytes(32)
    check("3-of-5 with two devices and a peer verifies as BIP340",
          bip340_verify(group.group33[1:], msg, frost_sign(group, devices[1:], msg, peers=[1])))
    for d in devices:
        d.close()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def expect_error(label, fn, fragment):
    try:
        fn()
    except RpcError as e:
        check(f"{label} ({e})", fragment in str(e))
        return
    check(f"{label}: unexpectedly accepted", False)


def succeeds(fn):
    try:
        fn()
        return True
    except RpcError:
        return False


def in_force(d, created_at):
    """The bundle from created_at loads and verifies, not just the pin reporting it."""
    got = d.rpc("policy_get")
    return got["created_at"] == created_at and "rules_len" in got and "bundle_valid" not in got


def policy_pinning(build):
    d = Device(os.path.join(build, "keep_device"), "device")
    warden, other = Warden(), Warden()
    update = lambda b: d.rpc("policy_update", {"bundle": b})
    prompts = lambda: d.rpc("test_confirm_log")["prompts"]

    expect_error("first policy without on-device confirmation is refused",
                 lambda: update(warden.bundle({"max_amount": 50000}, 100)), "not confirmed")
    check("the device asked about the bundle's Warden key",
          d.rpc("test_confirm_log")["last_key"] == warden.pubkey.hex())
    check("nothing was installed", d.rpc("policy_get")["has_policy"] is False)

    d.rpc("test_set_confirm", {"approve": True})
    expect_error("a bundle with a bad signature is refused before asking",
                 lambda: update(warden.bundle({}, 100, tamper=True)), "Invalid signature")
    check("no prompt for an invalid bundle", prompts() == 1)
    update(warden.bundle({"max_amount": 50000}, 100))
    got = d.rpc("policy_get")
    log = d.rpc("test_confirm_log")
    check("the screen reports the pin only after it is saved, and nothing for refusals",
          log["saved"] == 1 and log["save_failed"] == 0)
    check("first policy installs once confirmed and pins its key",
          got["has_policy"] and got["warden_pubkey"] == warden.pubkey.hex() and in_force(d, 100))
    check("the confirmation was asked once more", prompts() == 2)

    expect_error("a newer bundle from another key is refused",
                 lambda: update(other.bundle({}, 500)), "pinned Warden key")
    expect_error("the same created_at is refused as a rollback",
                 lambda: update(warden.bundle({"max_amount": 999999}, 100)), "not newer")
    expect_error("an older bundle is refused as a rollback",
                 lambda: update(warden.bundle({}, 50)), "not newer")
    expect_error("rules_len past the buffer is refused",
                 lambda: update(warden.bundle({}, 300, rules_len=Warden.RULES_MAX + 1)), "Malformed")
    update(warden.bundle({"max_amount": 70000}, 200))
    got = d.rpc("policy_get")
    check("a newer bundle from the pinned key replaces it without asking",
          in_force(d, 200) and got["warden_pubkey"] == warden.pubkey.hex() and prompts() == 2)

    group = Group(build, 2, 3)
    d.rpc("import_share", {"group": "g", "key_package": group.kp[1], "participants": 3})
    psbt = d.rpc("test_make_psbt", {"xonly": group.group33[1:].hex(), "amount": 20000})["psbt"]
    commit = lambda: d.rpc("frost_commit", {"group": "g", "session_id": secrets.token_hex(32),
                                            "message": secrets.token_bytes(32).hex()})
    approve = lambda: d.rpc("bitcoin_sign", {"psbt": psbt, "input_idx": 0})
    check("under the pinned policy, bitcoin_sign approves a spend within it", succeeds(approve))

    def fails_closed(label):
        got = d.rpc("policy_get")
        check(f"{label}: still pinned to the Warden key with no valid bundle",
              got["has_policy"] and got.get("bundle_valid") is False
              and got["warden_pubkey"] == warden.pubkey.hex())
        expect_error(f"{label}: frost_commit is refused", commit, "Policy")
        expect_error(f"{label}: bitcoin_sign is refused", approve, "Policy evaluation failed")
        expect_error(f"{label}: an older bundle is still a rollback",
                     lambda: update(warden.bundle({}, 150)), "not newer")

    d.rpc("test_corrupt_policy")
    fails_closed("corrupted bundle")
    update(warden.bundle({"max_amount": 70000}, 300))
    check("a corrupted bundle is replaced by a newer one from the pinned key without asking",
          in_force(d, 300) and prompts() == 2)

    d.rpc("test_cut_during_policy_write")
    expect_error("power lost while writing an update", lambda: update(warden.bundle({}, 400)),
                 "Storage error")
    fails_closed("after a cut write")
    update(warden.bundle({"max_amount": 70000}, 400))
    check("the interrupted update can be sent again without asking",
          in_force(d, 400) and prompts() == 2)

    d.rpc("test_cut_before_pin_raise")
    expect_error("power lost before the pin record is raised",
                 lambda: update(warden.bundle({}, 450)), "Storage error")
    check("the new bundle is already in force", in_force(d, 450))
    expect_error("an older bundle than the installed one is refused even though the pin lags",
                 lambda: update(warden.bundle({}, 420)), "not newer")
    d.rpc("test_boot_policy")
    d.rpc("test_install_legacy_bundle", {"bundle": warden.bundle({"max_amount": 999999}, 420)})
    fails_closed("after a reboot raised the lagging pin, an older bundle put back in flash")
    check("the reboot raised the pin to the installed bundle's created_at",
          d.rpc("policy_get")["created_at"] == 450)

    d.rpc("test_erase_policy_sector")
    fails_closed("after an erase with no write")
    update(warden.bundle({"max_amount": 70000}, 500))
    check("recovers with a newer bundle", in_force(d, 500))

    d.rpc("test_install_legacy_bundle", {"bundle": warden.bundle({"max_amount": 999999}, 450)})
    fails_closed("an older bundle from the pinned key put back in flash")
    d.rpc("test_install_legacy_bundle", {"bundle": other.bundle({}, 900)})
    fails_closed("a bundle from another key put back in flash")
    update(warden.bundle({"max_amount": 70000}, 600))
    check("recovers from a restored sector with a newer bundle",
          in_force(d, 600) and prompts() == 2)

    d.rpc("test_fail_pin_read", {"fail": True})
    expect_error("with the pin unreadable, frost_commit is refused", commit, "Policy")
    expect_error("with the pin unreadable, bitcoin_sign is refused", approve,
                 "Policy evaluation failed")
    d.rpc("test_fail_pin_read", {"fail": False})
    check("the bundle is in force again once the pin reads", in_force(d, 600))
    check("and bitcoin_sign approves under it again", succeeds(approve))

    d.rpc("test_install_legacy_bundle", {"bundle": warden.bundle({}, 2**62, tamper=True)})
    d.rpc("test_boot_policy")
    check("a forged bundle in flash cannot raise the pin at boot and lock out updates",
          succeeds(lambda: update(warden.bundle({"max_amount": 70000}, 700))) and in_force(d, 700))
    d.close()

    d = Device(os.path.join(build, "keep_device"), "fresh")
    d.rpc("test_set_confirm", {"approve": True})
    d.rpc("test_cut_during_policy_write")
    expect_error("power lost during the first install",
                 lambda: d.rpc("policy_update", {"bundle": warden.bundle({}, 100)}), "Storage error")
    got = d.rpc("policy_get")
    check("a confirmed first install that could not be written is reported as not saved",
          d.rpc("test_confirm_log")["save_failed"] == 1 and d.rpc("test_confirm_log")["saved"] == 0)
    check("the key confirmed for the first install stays pinned",
          got["has_policy"] and got["bundle_valid"] is False and got["warden_pubkey"] == warden.pubkey.hex())
    expect_error("another key cannot take over after the cut",
                 lambda: d.rpc("policy_update", {"bundle": other.bundle({}, 900)}), "pinned Warden key")
    d.rpc("policy_update", {"bundle": warden.bundle({}, 100)})
    check("resending the first bundle completes it without a second prompt",
          in_force(d, 100) and d.rpc("test_confirm_log")["prompts"] == 1)
    d.close()

    d = Device(os.path.join(build, "keep_device"), "legacy")
    d.rpc("test_install_legacy_bundle", {"bundle": warden.bundle({"max_amount": 1}, 100)})
    check("a bundle from before pinning is in force", in_force(d, 100))
    expect_error("updating it still needs the key confirmed on the device",
                 lambda: d.rpc("policy_update", {"bundle": warden.bundle({}, 200)}), "not confirmed")
    d.rpc("test_set_confirm", {"approve": True})
    expect_error("and is still refused as a rollback for the same key",
                 lambda: d.rpc("policy_update", {"bundle": warden.bundle({}, 100)}), "not newer")
    d.rpc("policy_update", {"bundle": other.bundle({}, 50)})
    got = d.rpc("policy_get")
    check("a confirmed key can replace a legacy bundle and becomes pinned",
          got["warden_pubkey"] == other.pubkey.hex() and in_force(d, 50))
    expect_error("after which the old key is refused",
                 lambda: d.rpc("policy_update", {"bundle": warden.bundle({}, 999)}), "pinned Warden key")
    d.close()


def signing_gate(build):
    devices, group = setup(build)
    xonly = group.group33[1:]
    a, b = devices
    warden = Warden()
    for d in devices:
        d.rpc("test_set_confirm", {"approve": True})
        d.rpc("policy_update", {"bundle": warden.bundle({"max_amount": 50000}, 100)})

    def psbt_for(amount):
        p = a.rpc("test_make_psbt", {"xonly": xonly.hex(), "amount": amount})["psbt"]
        return p, bytes.fromhex(a.rpc("bitcoin_sign", {"psbt": p, "input_idx": 0})["sighash"])

    def commit(d, message):
        return d.rpc("frost_commit", {"group": "g", "session_id": secrets.token_hex(32),
                                      "message": message.hex()})

    expect_error("with a policy, a raw message is refused",
                 lambda: commit(a, secrets.token_bytes(32)), "not approved")

    psbt, sighash = psbt_for(40000)
    sig = frost_sign(group, devices, sighash, psbt)
    check("a PSBT within policy is signed by both devices and verifies",
          bip340_verify(xonly, sighash, sig))
    expect_error("the same sighash cannot be signed twice from one approval",
                 lambda: commit(a, sighash), "not approved")

    unpolicied = Device(os.path.join(build, "keep_device"), "plain")
    over = unpolicied.rpc("test_make_psbt", {"xonly": xonly.hex(), "amount": 100000})["psbt"]
    over_sighash = bytes.fromhex(unpolicied.rpc("bitcoin_sign", {"psbt": over, "input_idx": 0})["sighash"])
    unpolicied.close()
    expect_error("bitcoin_sign refuses a PSBT over the policy limit",
                 lambda: a.rpc("bitcoin_sign", {"psbt": over, "input_idx": 0}), "Policy denied")
    expect_error("its sighash sent straight to frost_commit is refused",
                 lambda: commit(a, over_sighash), "not approved")

    psbt, sighash = psbt_for(40500)
    expect_error("a commit that fails before the commitment",
                 lambda: a.rpc("frost_commit", {"group": "missing", "session_id": secrets.token_hex(32),
                                                "message": sighash.hex()}), "Share not found")
    check("does not use up the approval", "commitment" in commit(a, sighash))

    psbt, sighash = psbt_for(41000)
    a.rpc("test_advance_clock", {"ms": 120001})
    expect_error("an approval expires after two minutes", lambda: commit(a, sighash), "not approved")

    psbt, sighash = psbt_for(42000)
    a.rpc("policy_update", {"bundle": warden.bundle({"max_amount": 50000}, 200)})
    expect_error("installing a policy drops earlier approvals", lambda: commit(a, sighash), "not approved")

    session = secrets.token_hex(32)
    raw = secrets.token_bytes(32)
    plain = group.device(build, 1, "open-session")
    c = plain.rpc("frost_commit", {"group": "g", "session_id": session, "message": raw.hex()})
    peer = json.loads(group.run("commit", group.kp[2]))
    package = group.package(raw, {1: c["commitment"], 2: peer["commitment"]})
    plain.rpc("test_set_confirm", {"approve": True})
    plain.rpc("policy_update", {"bundle": warden.bundle({"max_amount": 50000}, 100)})
    expect_error("the open session cannot be signed once a policy is installed",
                 lambda: plain.rpc("frost_sign", {"group": "g", "session_id": session,
                                                  "signing_package": package}), "Session not found")
    plain.close()

    a.rpc("policy_update", {"bundle": warden.bundle({"max_amount": 50000, "ALLOW_RAW": True}, 210)})
    expect_error("allow_raw is matched case-sensitively",
                 lambda: commit(a, secrets.token_bytes(32)), "not approved")
    a.rpc("policy_update", {"bundle": warden.bundle(b'{"max_amount": 50000, "allow_raw": true} x', 220)})
    expect_error("rules with trailing data are refused rather than partly read",
                 lambda: commit(a, secrets.token_bytes(32)), "not approved")
    expect_error("and deny bitcoin_sign", lambda: psbt_for(30000), "Policy denied")

    b_psbt = b.rpc("test_make_psbt", {"xonly": xonly.hex(), "amount": 30000})["psbt"]
    b_sign = lambda: b.rpc("bitcoin_sign", {"psbt": b_psbt, "input_idx": 0})
    b.rpc("policy_update", {"bundle": warden.bundle({"max_amount": 999999}, 225)})
    check("the PSBT used below passes a sane limit", "sighash" in b_sign())
    for i, (label, rules) in enumerate([("a non-number limit", {"max_amount": "999999"}),
                                        ("a negative limit", {"max_amount": -1}),
                                        ("a fractional limit", {"max_amount": 999999.5})]):
        b.rpc("policy_update", {"bundle": warden.bundle(rules, 230 + i)})
        expect_error(f"{label} denies instead of being ignored", b_sign, "Policy denied")
    b.rpc("policy_update", {"bundle": warden.bundle({"MAX_AMOUNT": 1}, 280)})
    expect_error("a mis-cased limit key still restricts", b_sign, "Policy denied")
    b.rpc("policy_update", {"bundle": warden.bundle({"max_amount": 50000}, 290)})

    for d in devices:
        d.rpc("policy_update", {"bundle": warden.bundle({"max_amount": 50000, "allow_raw": True}, 300)})
    msg = secrets.token_bytes(32)
    check("a policy with allow_raw lets a raw message through",
          bip340_verify(xonly, msg, frost_sign(group, devices, msg)))
    for d in devices:
        d.close()


def protocol(build):
    group = Group(build, 2, 3)
    d = Device(os.path.join(build, "keep_device"), "protocol")
    check("ping reports protocol 2", d.rpc("ping")["protocol_version"] == 2)
    for method in ("dkg_init", "dkg_round1", "frost_session_resume", "frost_session_list"):
        expect_error(f"{method} is retired", lambda: d.rpc(method, {"group": "g"}),
                     "not available in protocol 2")
    imp = lambda kp, n=3: d.rpc("import_share", {"group": "g", "key_package": kp, "participants": n})
    expect_error("the pre-protocol-2 share field is refused",
                 lambda: d.rpc("import_share", {"group": "g", "share": group.kp[1]}), "retired")
    bad = bytearray.fromhex(group.kp[1])
    bad[40] ^= 1
    expect_error("a key package whose share does not match its verifying share is refused",
                 lambda: imp(bad.hex()), "Invalid key_package (-5)")
    expect_error("trailing bytes are refused", lambda: imp(group.kp[1] + "00"), "Invalid key_package (-4)")
    expect_error("an empty key package is refused", lambda: imp(""), "Invalid key_package hex")
    expect_error("a participant count below 2 is refused", lambda: imp(group.kp[1], 1), "participants")
    expect_error("an index above the participant count is refused",
                 lambda: d.rpc("import_share", {"group": "g", "key_package": group.kp[3],
                                                "participants": 2}), "does not fit")
    expect_error("nothing was stored", lambda: d.rpc("get_share_pubkey", {"group": "g"}), "Share not found")
    r = imp(group.kp[2])
    info = d.rpc("get_share_info", {"group": "g"})
    check("get_share_info reports what import did",
          info == {"pubkey": r["pubkey"], "index": 2, "threshold": 2, "participants": 3,
                   "verifying_share": r["verifying_share"]})
    d.close()


def session_safety(build):
    group = Group(build, 2, 3)
    warden = Warden()

    def round_on(d, message, session=None):
        session = session or secrets.token_hex(32)
        c = d.rpc("frost_commit", {"group": "g", "session_id": session, "message": message.hex()})
        peer = json.loads(group.run("commit", group.kp[2]))
        return session, c["commitment"], peer

    def sign(d, session, package):
        return d.rpc("frost_sign", {"group": "g", "session_id": session, "signing_package": package})

    d = group.device(build, 1, "discard")
    d.rpc("test_set_confirm", {"approve": True})
    msg = secrets.token_bytes(32)
    session, mine, peer = round_on(d, msg)
    d.rpc("policy_update", {"bundle": warden.bundle({}, 100)})
    expect_error("installing a policy ends open sessions",
                 lambda: sign(d, session, group.package(msg, {1: mine, 2: peer["commitment"]})),
                 "Session not found")
    d.close()

    d = group.device(build, 1, "cut")
    d.rpc("test_set_confirm", {"approve": True})
    d.rpc("policy_update", {"bundle": warden.bundle({"allow_raw": True}, 100)})
    msg = secrets.token_bytes(32)
    session, mine, peer = round_on(d, msg)
    d.rpc("test_cut_before_pin_raise")
    expect_error("power lost before the pin is raised", lambda: d.rpc(
        "policy_update", {"bundle": warden.bundle({"max_amount": 1}, 200)}), "Storage error")
    check("the stricter policy is already in force", d.rpc("policy_get")["created_at"] == 200)
    expect_error("a session from the looser policy cannot sign after the cut",
                 lambda: sign(d, session, group.package(msg, {1: mine, 2: peer["commitment"]})),
                 "Session not found")
    d.close()

    d = group.device(build, 1, "reboot")
    msg = secrets.token_bytes(32)
    session, mine, peer = round_on(d, msg)
    d.rpc("test_reboot_signer")
    expect_error("a reboot ends the round: nonces are never kept in flash",
                 lambda: sign(d, session, group.package(msg, {1: mine, 2: peer["commitment"]})),
                 "Session not found")
    session, mine, peer = round_on(d, msg)
    package = group.package(msg, {1: mine, 2: peer["commitment"]})
    share = sign(d, session, package)["signature_share"]
    sig = group.run("aggregate", group.pubkeys, package,
                    f"1:{share}", f"2:{group.run('sign', group.kp[2], peer['nonces'], package)}")
    check("a fresh commit after the reboot signs a valid BIP340 signature",
          bip340_verify(group.group33[1:], msg, bytes.fromhex(sig)))
    check("an identical retry returns the same share", sign(d, session, package)["signature_share"] == share)
    other = group.package(msg, {1: mine, 3: json.loads(group.run("commit", group.kp[3]))["commitment"]})
    expect_error("a retry with a different package gets nothing", lambda: sign(d, session, other),
                 "already consumed")
    expect_error("the session id cannot be committed again",
                 lambda: d.rpc("frost_commit", {"group": "g", "session_id": session, "message": msg.hex()}),
                 "already")

    def refused(label, build_package, code):
        msg = secrets.token_bytes(32)
        session, mine, peer = round_on(d, msg)
        expect_error(label, lambda: sign(d, session, build_package(msg, mine, peer)),
                     f"Signing refused ({code})")
        expect_error(f"{label}: the nonces are spent", lambda: sign(
            d, session, group.package(msg, {1: mine, 2: peer["commitment"]})), "Session not found")

    refused("a package for another message is refused",
            lambda m, mine, peer: group.package(secrets.token_bytes(32), {1: mine, 2: peer["commitment"]}), -8)
    refused("a package with this device's commitment altered is refused",
            lambda m, mine, peer: group.package(m, {1: json.loads(group.run("commit", group.kp[1]))["commitment"],
                                                    2: peer["commitment"]}), -10)
    refused("a package without this device is refused",
            lambda m, mine, peer: group.package(m, {2: peer["commitment"],
                                                    3: json.loads(group.run("commit", group.kp[3]))["commitment"]}), -10)
    refused("a package below the threshold is refused",
            lambda m, mine, peer: group.package(m, {1: mine}), -9)
    refused("a package with trailing bytes is refused",
            lambda m, mine, peer: group.package(m, {1: mine, 2: peer["commitment"]}) + "00", -4)
    d.close()


def legacy_shares(build):
    group = Group(build, 2, 3, "odd")
    d = Device(os.path.join(build, "keep_device"), "legacy")
    d.index = 3
    d.rpc("test_plant_share", {"group": "g", "share": group.run("legacy", group.kp[3], "3")})
    good = bytearray.fromhex(group.run("legacy", group.kp[1], "3"))
    good[0] ^= 1
    d.rpc("test_plant_share", {"group": "bad", "share": good.hex()})
    expect_error("a share stored before protocol 2 is not used as it is",
                 lambda: d.rpc("get_share_pubkey", {"group": "g"}), "predates protocol 2")
    r = d.rpc("test_migrate_shares")
    check("migration rebuilds the valid share and removes the one that does not check out",
          r == {"status": 0, "migrated": 1, "removed": 1})
    expect_error("the invalid share is gone", lambda: d.rpc("get_share_pubkey", {"group": "bad"}),
                 "Share not found")
    stored = d.rpc("test_read_share", {"group": "g"})["share"]
    check("the migrated share is the protocol 2 payload of keep's own key package",
          stored == "020003" + group.kp[3])
    check("a second migration finds nothing to do",
          d.rpc("test_migrate_shares") == {"status": 0, "migrated": 0, "removed": 0})
    msg = secrets.token_bytes(32)
    check("the migrated share signs with keep",
          bip340_verify(group.group33[1:], msg, frost_sign(group, [d], msg, peers=[1])))
    d.close()


def regtest(build, knots_bin):
    datadir = tempfile.mkdtemp(prefix="keep-e2e-")
    rpcport, p2pport = free_port(), free_port()
    cli_base = [os.path.join(knots_bin, "bitcoin-cli"), "-regtest", f"-datadir={datadir}",
                f"-rpcport={rpcport}"]

    def cli(*args):
        out = subprocess.run(cli_base + list(args), capture_output=True, text=True, timeout=120)
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
                    "-fallbackfee=0.0001", f"-mocktime={mocktime[0]}", f"-rpcport={rpcport}",
                    f"-port={p2pport}", "-listen=0"], check=True,
                   stdout=subprocess.DEVNULL)
    devices = []
    try:
        cookie = os.path.join(datadir, "regtest", ".cookie")
        deadline = time.time() + 60
        while not os.path.exists(cookie):
            if time.time() > deadline:
                raise RuntimeError("regtest node did not start")
            time.sleep(0.2)
        cli("-rpcwait", "-rpcwaittimeout=60", "getblockcount")
        cli("createwallet", "w")
        waddr = cli("getnewaddress", "", "bech32m")
        mine(155, waddr)
        devices, group = setup(build)
        xonly = group.group33[1:].hex()
        warden = Warden()
        for d in devices:
            d.rpc("test_set_confirm", {"approve": True})
            d.rpc("policy_update", {"bundle": warden.bundle({"max_amount": 200000000}, 100)})
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
            sig = frost_sign(group, devices, bytes.fromhex(r["sighash"]), psbt)
            if r["sighash_type"]:
                sig += bytes([r["sighash_type"]])
            final = devices[0].rpc("test_finalize", {"psbt": psbt, "witness_sig": sig.hex()})["hex"]
            spend = cli("sendrawtransaction", final)
            mine(1, waddr)
            conf = cli("getrawtransaction", spend, "true")["confirmations"]
            check(f"regtest: FROST spend under a policy, sighash type {r['sighash_type']:#x}, mined", conf == 1)
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
    protocol(build)
    policy_pinning(build)
    signing_gate(build)
    session_safety(build)
    legacy_shares(build)
    if os.environ.get("KNOTS_BIN"):
        regtest(build, os.environ["KNOTS_BIN"])
    print("e2e: all checks passed")


if __name__ == "__main__":
    main()
