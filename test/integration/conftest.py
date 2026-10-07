import json
import os
import secrets
from typing import Optional

import pytest
import serial

DEFAULT_PORT = os.environ.get("KEEP_DEVICE_PORT", "/dev/ttyUSB0")
DEFAULT_BAUD = int(os.environ.get("KEEP_DEVICE_BAUD", "115200"))
DEFAULT_TIMEOUT = float(os.environ.get("KEEP_DEVICE_TIMEOUT", "30.0"))


class DeviceRPCMixin:
    def ping(self) -> dict:
        return self.rpc("ping")

    def import_share(self, group: str, key_package_hex: str, participants: int = 3) -> dict:
        return self.rpc(
            "import_share",
            {"group": group, "key_package": key_package_hex, "participants": participants},
        )

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

    def frost_sign(self, group: str, session_id: str, signing_package: str) -> dict:
        return self.rpc(
            "frost_sign",
            {"group": group, "session_id": session_id, "signing_package": signing_package},
        )

    def get_status(self) -> dict:
        return self.rpc("get_status")


class DeviceConnection(DeviceRPCMixin):
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


class MockDeviceConnection(DeviceRPCMixin):
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
        return len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s)

    def _is_valid_session_id(self, session_id: str) -> bool:
        if len(session_id) != 64 or not self._is_valid_hex(session_id):
            return False
        return session_id not in ("00" * 32, "ff" * 32)

    def _error(self, rid: int, code: int, message: str) -> dict:
        return {"id": rid, "error": {"code": code, "message": message}}

    def _ok(self, rid: int, result: dict) -> dict:
        return {"id": rid, "result": result}

    def rpc(self, method: str, params: Optional[dict] = None) -> dict:
        self._request_id += 1
        rid = self._request_id
        params = params or {}
        handler = getattr(self, f"_rpc_{method}", None)
        if handler:
            return handler(rid, params)
        return self._error(rid, -32601, "Method not found")

    def _rpc_ping(self, rid: int, params: dict) -> dict:
        return self._ok(rid, {"pong": True, "version": "0.1.2", "protocol_version": 2})

    def _rpc_list_shares(self, rid: int, params: dict) -> dict:
        return self._ok(rid, {"shares": list(self._shares.keys())})

    def _rpc_import_share(self, rid: int, params: dict) -> dict:
        group = params.get("group", "")
        key_package = params.get("key_package", "")
        participants = params.get("participants", 0)
        if "share" in params:
            return self._error(rid, -32602, "The share field is retired in protocol 2")
        if not 2 <= participants <= 16:
            return self._error(rid, -32602, "participants must be 2 to 16")
        if not key_package or not self._is_valid_hex(key_package):
            return self._error(rid, -32602, "Invalid key_package hex")
        if not group:
            return self._error(rid, -32602, "Invalid group name")
        self._shares[group] = key_package
        return self._ok(rid, {"ok": True, "index": int(key_package[72:74], 16), "threshold": 2,
                              "participants": participants, "pubkey": key_package[204:270],
                              "verifying_share": key_package[138:204]})

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
        kp = self._shares[group]
        return self._ok(rid, {"pubkey": kp[204:270], "index": int(kp[72:74], 16), "threshold": 2,
                              "participants": 3, "verifying_share": kp[138:204]})

    def _rpc_get_status(self, rid: int, params: dict) -> dict:
        return self._ok(rid, {
            "version": "0.1.2",
            "rng_healthy": True,
            "rng_entropy_source": True,
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
        return self._ok(rid, {"commitment": "00230f8ab3" + "02" + "aa" * 32 + "03" + "bb" * 32, "index": 1})

    def _rpc_frost_sign(self, rid: int, params: dict) -> dict:
        group = params.get("group", "")
        session_id = params.get("session_id", "")
        signing_package = params.get("signing_package", "")

        if session_id not in self._sessions:
            return self._error(rid, -2, "Session not found")
        session = self._sessions[session_id]
        if session.get("group") != group:
            return self._error(rid, -32602, "Group mismatch")
        if not signing_package or not self._is_valid_hex(signing_package):
            return self._error(rid, -32602, "Invalid signing_package hex")

        self._consumed_sessions.add(session_id)
        session["state"] = "signed"
        return self._ok(rid, {"signature_share": "bb" * 32, "index": 1})

    def _rpc_get_share_pubkey(self, rid: int, params: dict) -> dict:
        group = params.get("group", "")
        if group not in self._shares:
            return self._error(rid, -1, "Share not found")
        return self._ok(rid, {"pubkey": self._shares[group][204:270]})


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


def signing_package(message_hex: str, commitments: dict) -> str:
    """frost-core's SigningPackage serialization: the 5-byte header every serialization
    carries, the commitment count, each 32-byte identifier with its commitment in
    identifier order, then the message with its length."""
    header = bytes.fromhex(next(iter(commitments.values())))[:5]
    out = header + bytes([len(commitments)])
    for index in sorted(commitments):
        out += index.to_bytes(32, "big") + bytes.fromhex(commitments[index])
    message = bytes.fromhex(message_hex)
    return (out + bytes([len(message)]) + message).hex()
