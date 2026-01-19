import json
import os
import secrets
from typing import Optional

import pytest
import serial

DEFAULT_PORT = os.environ.get("KEEP_DEVICE_PORT", "/dev/ttyUSB0")
DEFAULT_BAUD = int(os.environ.get("KEEP_DEVICE_BAUD", "115200"))
DEFAULT_TIMEOUT = float(os.environ.get("KEEP_DEVICE_TIMEOUT", "5.0"))


class DeviceConnection:
    def __init__(
        self,
        port: str = DEFAULT_PORT,
        baud: int = DEFAULT_BAUD,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.port = port
        self.baud = baud
        self.timeout = timeout
        self._serial: Optional[serial.Serial] = None
        self._request_id = 0

    def connect(self):
        self._serial = serial.Serial(
            port=self.port,
            baudrate=self.baud,
            timeout=self.timeout,
        )
        self._serial.reset_input_buffer()

    def disconnect(self):
        if self._serial and self._serial.is_open:
            self._serial.close()
        self._serial = None

    def rpc(self, method: str, params: Optional[dict] = None) -> dict:
        if not self._serial or not self._serial.is_open:
            raise RuntimeError("Device not connected")

        self._request_id += 1
        request = {"id": self._request_id, "method": method}
        if params:
            request["params"] = params

        line = json.dumps(request) + "\n"
        self._serial.write(line.encode("utf-8"))
        self._serial.flush()

        response_line = self._serial.readline()
        if not response_line:
            raise TimeoutError(f"No response for {method}")

        return json.loads(response_line.decode("utf-8"))

    def ping(self) -> dict:
        return self.rpc("ping")

    def import_share(self, group: str, share_hex: str) -> dict:
        return self.rpc("import_share", {"group": group, "share": share_hex})

    def delete_share(self, group: str) -> dict:
        return self.rpc("delete_share", {"group": group})

    def list_shares(self) -> dict:
        return self.rpc("list_shares")

    def get_share_info(self, group: str) -> dict:
        return self.rpc("get_share_info", {"group": group})

    def get_share_pubkey(self, group: str) -> dict:
        return self.rpc("get_share_pubkey", {"group": group})

    def frost_commit(self, group: str, session_id: str, message: str) -> dict:
        return self.rpc(
            "frost_commit",
            {"group": group, "session_id": session_id, "message": message},
        )

    def frost_sign(self, group: str, session_id: str, commitments: str) -> dict:
        return self.rpc(
            "frost_sign",
            {"group": group, "session_id": session_id, "commitments": commitments},
        )

    def dkg_init(
        self, group: str, threshold: int, participant_count: int, our_index: int
    ) -> dict:
        return self.rpc(
            "dkg_init",
            {
                "group": group,
                "threshold": threshold,
                "participant_count": participant_count,
                "our_index": our_index,
            },
        )

    def dkg_round1(self, group: str) -> dict:
        return self.rpc("dkg_round1", {"group": group})

    def dkg_round1_peer(self, group: str, peer_index: int, dkg_data: str) -> dict:
        return self.rpc(
            "dkg_round1_peer",
            {"group": group, "peer_index": peer_index, "dkg_data": dkg_data},
        )

    def dkg_round2(self, group: str) -> dict:
        return self.rpc("dkg_round2", {"group": group})

    def dkg_receive_share(self, group: str, peer_index: int, dkg_data: str) -> dict:
        return self.rpc(
            "dkg_receive_share",
            {"group": group, "peer_index": peer_index, "dkg_data": dkg_data},
        )

    def dkg_finalize(self, group: str) -> dict:
        return self.rpc("dkg_finalize", {"group": group})

    def get_status(self) -> dict:
        return self.rpc("get_status")


class MockDeviceConnection:
    MAX_SESSIONS = 4

    def __init__(self):
        self._request_id = 0
        self._shares: dict = {}
        self._sessions: dict = {}
        self._consumed_sessions: set = set()

    def connect(self):
        pass

    def disconnect(self):
        pass

    def _is_valid_hex(self, s: str) -> bool:
        if len(s) % 2 != 0:
            return False
        return all(c in "0123456789abcdefABCDEF" for c in s)

    def _is_valid_session_id(self, session_id: str) -> bool:
        if len(session_id) != 64 or not self._is_valid_hex(session_id):
            return False
        return session_id not in ("00" * 32, "ff" * 32)

    def _error(self, rid: int, code: int, message: str) -> dict:
        return {"id": rid, "error": {"code": code, "message": message}}

    def _ok(self, rid: int, result: dict) -> dict:
        return {"id": rid, "result": result}

    def _get_dkg_session(self, rid: int, group: str):
        dkg_key = f"dkg_{group}"
        if dkg_key not in self._sessions:
            return None, self._error(rid, -2, "DKG not initialized")
        return self._sessions[dkg_key], None

    def rpc(self, method: str, params: Optional[dict] = None) -> dict:
        self._request_id += 1
        rid = self._request_id
        params = params or {}
        handler = getattr(self, f"_rpc_{method}", None)
        if handler:
            return handler(rid, params)
        return self._error(rid, -32601, "Method not found")

    def _rpc_ping(self, rid: int, params: dict) -> dict:
        return self._ok(rid, {"pong": True, "version": "0.1.2"})

    def _rpc_list_shares(self, rid: int, params: dict) -> dict:
        return self._ok(rid, {"shares": list(self._shares.keys())})

    def _rpc_import_share(self, rid: int, params: dict) -> dict:
        group = params.get("group", "")
        share = params.get("share", "")
        if not group:
            return self._error(rid, -32602, "Invalid group name")
        if not share:
            return self._error(rid, -32602, "Invalid share data")
        if not self._is_valid_hex(share):
            return self._error(rid, -32602, "Invalid hex")
        self._shares[group] = share
        return self._ok(rid, {"ok": True})

    def _rpc_delete_share(self, rid: int, params: dict) -> dict:
        group = params.get("group", "")
        if group in self._shares:
            del self._shares[group]
            return self._ok(rid, {"ok": True})
        return self._error(rid, -3, "Share not found")

    def _rpc_get_share_info(self, rid: int, params: dict) -> dict:
        group = params.get("group", "")
        if group not in self._shares:
            return self._error(rid, -1, "Share not found")
        return self._ok(rid, {"pubkey": "02" + "00" * 32, "index": 1, "threshold": 2, "participants": 3})

    def _rpc_get_status(self, rid: int, params: dict) -> dict:
        return self._ok(rid, {
            "version": "0.1.2",
            "rng_healthy": True,
            "rng_total_calls": 100,
            "rng_failed_checks": 0,
            "rng_retries": 0,
        })

    def _rpc_frost_commit(self, rid: int, params: dict) -> dict:
        group = params.get("group", "")
        session_id = params.get("session_id", "")
        message = params.get("message", "")

        if group not in self._shares:
            return self._error(rid, -1, "Share not found")
        if not self._is_valid_session_id(session_id):
            return self._error(rid, -32602, "Invalid session_id")
        if len(message) != 64 or not self._is_valid_hex(message):
            return self._error(rid, -32602, "message must be 32 bytes")
        if session_id in self._consumed_sessions:
            return self._error(rid, -2, "Session ID already used")
        if session_id in self._sessions:
            return self._error(rid, -2, "Session ID already active")

        active = sum(1 for s in self._sessions.values() if s.get("state") == "committed")
        if active >= self.MAX_SESSIONS:
            return self._error(rid, -2, "No free session slots")

        self._sessions[session_id] = {"group": group, "state": "committed"}
        return self._ok(rid, {"commitment": "0001" + "aa" * 130, "index": 1})

    def _rpc_frost_sign(self, rid: int, params: dict) -> dict:
        group = params.get("group", "")
        session_id = params.get("session_id", "")
        commitments = params.get("commitments", "")

        if session_id not in self._sessions:
            return self._error(rid, -2, "Session not found")
        session = self._sessions[session_id]
        if session.get("group") != group:
            return self._error(rid, -32602, "Group mismatch")
        if commitments and (len(commitments) % 264 != 0 or not self._is_valid_hex(commitments)):
            return self._error(rid, -32602, "Invalid commitments format")

        self._consumed_sessions.add(session_id)
        session["state"] = "signed"
        return self._ok(rid, {"signature_share": "bb" * 36, "index": 1})

    def _rpc_dkg_init(self, rid: int, params: dict) -> dict:
        group = params.get("group", "")
        threshold = params.get("threshold", 0)
        participant_count = params.get("participant_count", 0)
        our_index = params.get("our_index", 0)

        if participant_count == 0 or threshold == 0:
            return self._error(rid, -32602, "Invalid params")
        if threshold > participant_count:
            return self._error(rid, -32602, "Threshold exceeds participants")
        if participant_count > 16:
            return self._error(rid, -32602, "Too many participants")
        if our_index < 1 or our_index > participant_count:
            return self._error(rid, -32602, "Invalid our_index")

        self._sessions[f"dkg_{group}"] = {
            "group": group,
            "state": "init",
            "threshold": threshold,
            "participant_count": participant_count,
            "our_index": our_index,
            "peers": {},
        }
        return self._ok(rid, {"ok": True})

    def _rpc_dkg_round1(self, rid: int, params: dict) -> dict:
        session, err = self._get_dkg_session(rid, params.get("group", ""))
        if err:
            return err
        if session.get("state") != "init":
            return self._error(rid, -2, "Wrong DKG state")
        session["state"] = "round1"
        return self._ok(rid, {"vss_commitment": "aa" * 64})

    def _rpc_dkg_round1_peer(self, rid: int, params: dict) -> dict:
        session, err = self._get_dkg_session(rid, params.get("group", ""))
        if err:
            return err
        peer_index = params.get("peer_index", 0)
        dkg_data = params.get("dkg_data", "")

        if session.get("state") not in ("round1",):
            return self._error(rid, -2, "Wrong DKG state")
        if peer_index < 1 or peer_index > session.get("participant_count", 0):
            return self._error(rid, -32602, "Invalid peer_index")
        if not dkg_data or not self._is_valid_hex(dkg_data):
            return self._error(rid, -32602, "Invalid dkg_data")

        session["peers"][peer_index] = dkg_data
        return self._ok(rid, {"ok": True})

    def _rpc_dkg_round2(self, rid: int, params: dict) -> dict:
        session, err = self._get_dkg_session(rid, params.get("group", ""))
        if err:
            return err
        if session.get("state") != "round1":
            return self._error(rid, -2, "Not in round1 state")
        required_peers = session.get("participant_count", 0) - 1
        if len(session.get("peers", {})) < required_peers:
            return self._error(rid, -2, "Missing peer data")
        session["state"] = "round2"
        return self._ok(rid, {"share_package": "bb" * 64})

    def _rpc_dkg_receive_share(self, rid: int, params: dict) -> dict:
        _, err = self._get_dkg_session(rid, params.get("group", ""))
        if err:
            return err
        return self._ok(rid, {"ok": True})

    def _rpc_dkg_finalize(self, rid: int, params: dict) -> dict:
        session, err = self._get_dkg_session(rid, params.get("group", ""))
        if err:
            return err
        if session.get("state") != "round2":
            return self._error(rid, -2, "DKG not complete")
        session["state"] = "complete"
        return self._ok(rid, {"group_pubkey": "02" + "cc" * 32})

    def _rpc_get_share_pubkey(self, rid: int, params: dict) -> dict:
        group = params.get("group", "")
        if group not in self._shares:
            return self._error(rid, -1, "Share not found")
        return self._ok(rid, {"pubkey": "02" + "00" * 32})

    def ping(self) -> dict:
        return self.rpc("ping")

    def import_share(self, group: str, share_hex: str) -> dict:
        return self.rpc("import_share", {"group": group, "share": share_hex})

    def delete_share(self, group: str) -> dict:
        return self.rpc("delete_share", {"group": group})

    def list_shares(self) -> dict:
        return self.rpc("list_shares")

    def get_share_info(self, group: str) -> dict:
        return self.rpc("get_share_info", {"group": group})

    def get_share_pubkey(self, group: str) -> dict:
        return self.rpc("get_share_pubkey", {"group": group})

    def frost_commit(self, group: str, session_id: str, message: str) -> dict:
        return self.rpc(
            "frost_commit",
            {"group": group, "session_id": session_id, "message": message},
        )

    def frost_sign(self, group: str, session_id: str, commitments: str) -> dict:
        return self.rpc(
            "frost_sign",
            {"group": group, "session_id": session_id, "commitments": commitments},
        )

    def get_status(self) -> dict:
        return self.rpc("get_status")

    def dkg_init(
        self, group: str, threshold: int, participant_count: int, our_index: int
    ) -> dict:
        return self.rpc(
            "dkg_init",
            {
                "group": group,
                "threshold": threshold,
                "participant_count": participant_count,
                "our_index": our_index,
            },
        )

    def dkg_round1(self, group: str) -> dict:
        return self.rpc("dkg_round1", {"group": group})

    def dkg_round1_peer(self, group: str, peer_index: int, dkg_data: str) -> dict:
        return self.rpc(
            "dkg_round1_peer",
            {"group": group, "peer_index": peer_index, "dkg_data": dkg_data},
        )

    def dkg_round2(self, group: str) -> dict:
        return self.rpc("dkg_round2", {"group": group})

    def dkg_receive_share(self, group: str, peer_index: int, dkg_data: str) -> dict:
        return self.rpc(
            "dkg_receive_share",
            {"group": group, "peer_index": peer_index, "dkg_data": dkg_data},
        )

    def dkg_finalize(self, group: str) -> dict:
        return self.rpc("dkg_finalize", {"group": group})


def is_hardware_available() -> bool:
    if os.environ.get("KEEP_MOCK_DEVICE", "0") == "1":
        return False
    try:
        s = serial.Serial(DEFAULT_PORT, DEFAULT_BAUD, timeout=0.5)
        s.close()
        return True
    except (serial.SerialException, OSError):
        return False


@pytest.fixture
def device():
    if is_hardware_available():
        conn = DeviceConnection()
    else:
        conn = MockDeviceConnection()
    conn.connect()
    yield conn
    conn.disconnect()


@pytest.fixture
def clean_device(device):
    resp = device.list_shares()
    if "result" in resp and "shares" in resp["result"]:
        for group in resp["result"]["shares"]:
            device.delete_share(group)
    yield device


def random_hex(length: int) -> str:
    return secrets.token_hex(length)


def random_session_id() -> str:
    return secrets.token_hex(32)


def random_message() -> str:
    return secrets.token_hex(32)
