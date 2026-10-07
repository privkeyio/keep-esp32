from conftest import random_message, random_session_id, signing_package

# A public test group (2-of-3, frost-secp256k1-tr key packages) and a commitment from
# participant 3, so a device holding participant 1 can complete a round.
GROUP_KEY = "02a80c99f8a5ea6af8f238cb68f258125bea2c0d46b6a3ce1eb75ef95ca899ac3d"
KEY_PACKAGE_1 = (
    "00230f8ab30000000000000000000000000000000000000000000000000000000000000001f9806efa"
    "60670799c2f4accc8e28c108ba4655d23568c98f2995583874bd8b3302032ee7b831c0fd1f879e089f"
    "08ed286249afe84edd191284a90b7dcab416b5c002a80c99f8a5ea6af8f238cb68f258125bea2c0d46"
    "b6a3ce1eb75ef95ca899ac3d02"
)
KEY_PACKAGE_2 = (
    "00230f8ab30000000000000000000000000000000000000000000000000000000000000002860456b8"
    "94e79c8ca7e648bc33c21f5e882b3940011888ec4c837e44fa874c510286a817acec8f264ed53635db"
    "b43019356a7d101f0f9061b79116a185b0130d5a02a80c99f8a5ea6af8f238cb68f258125bea2c0d46"
    "b6a3ce1eb75ef95ca899ac3d02"
)
PEER_COMMITMENT = (
    "00230f8ab302536c15dc7ffdcf7903717514864a043e130e1da4b56f77897648716d91c8861b03e422"
    "e3fdb39dd5a3267f56229ebef45ebac6e541e03353ec265fc880624ea1f7"
)


class TestPing:
    def test_ping_response(self, device):
        resp = device.ping()
        assert "result" in resp
        assert resp["result"].get("pong") is True
        assert "version" in resp["result"]
        assert resp["result"]["protocol_version"] == 2

    def test_get_status(self, device):
        resp = device.get_status()
        assert "result" in resp
        assert "version" in resp["result"]
        assert "rng_healthy" in resp["result"]
        # On a real board this is the one assertion that proves the SAR ADC
        # entropy source actually came up. "we called bootloader_random_enable()"
        # is not the same claim, so the device reports a register readback.
        assert resp["result"]["rng_entropy_source"] is True


class TestShareManagement:
    def test_import_and_list(self, clean_device):
        resp = clean_device.import_share("test_group", KEY_PACKAGE_1)
        assert "result" in resp
        assert resp["result"].get("ok") is True

        resp = clean_device.list_shares()
        assert "result" in resp
        assert "test_group" in resp["result"]["shares"]

    def test_import_and_delete(self, clean_device):
        clean_device.import_share("delete_test", KEY_PACKAGE_1)

        resp = clean_device.delete_share("delete_test")
        assert "result" in resp
        assert resp["result"].get("ok") is True

        resp = clean_device.list_shares()
        assert "delete_test" not in resp["result"]["shares"]

    def test_delete_nonexistent(self, clean_device):
        resp = clean_device.delete_share("nonexistent_group_xyz")
        assert "error" in resp
        assert resp["error"]["message"] == "Share not found"

    def test_get_share_info(self, clean_device):
        clean_device.import_share("info_test", KEY_PACKAGE_1)

        resp = clean_device.get_share_info("info_test")
        assert "result" in resp
        assert "pubkey" in resp["result"]
        assert "index" in resp["result"]
        assert "threshold" in resp["result"]
        assert "participants" in resp["result"]
        assert resp["result"]["pubkey"] == GROUP_KEY
        assert resp["result"]["index"] == 1

    def test_get_share_info_not_found(self, clean_device):
        resp = clean_device.get_share_info("missing_share")
        assert "error" in resp
        assert resp["error"]["message"] == "Share not found"


class TestSigningFlow:
    def test_commit_requires_share(self, clean_device):
        resp = clean_device.frost_commit("no_such_group", random_session_id(), random_message())
        assert "error" in resp
        assert resp["error"]["message"] == "Share not found"

    def test_commit_success(self, clean_device):
        clean_device.import_share("commit_test", KEY_PACKAGE_1)

        resp = clean_device.frost_commit("commit_test", random_session_id(), random_message())
        assert "result" in resp
        assert "commitment" in resp["result"]
        assert "index" in resp["result"]
        assert len(resp["result"]["commitment"]) == 142

    def test_sign_requires_session(self, clean_device):
        clean_device.import_share("sign_test", KEY_PACKAGE_1)

        package = signing_package(random_message(), {3: PEER_COMMITMENT})
        resp = clean_device.frost_sign("sign_test", random_session_id(), package)
        assert "error" in resp
        assert resp["error"]["message"] == "Session not found"

    def test_complete_signing_flow(self, clean_device):
        clean_device.import_share("flow_test", KEY_PACKAGE_1)

        session_id = random_session_id()
        message = random_message()
        commit_resp = clean_device.frost_commit("flow_test", session_id, message)
        assert "result" in commit_resp
        mine = commit_resp["result"]["commitment"]

        package = signing_package(message, {1: mine, 3: PEER_COMMITMENT})
        sign_resp = clean_device.frost_sign("flow_test", session_id, package)
        assert "result" in sign_resp
        assert len(sign_resp["result"]["signature_share"]) == 64
        assert sign_resp["result"]["index"] == 1

    def test_session_id_reuse_rejected(self, clean_device):
        clean_device.import_share("reuse_test", KEY_PACKAGE_1)

        session_id = random_session_id()
        message = random_message()

        resp1 = clean_device.frost_commit("reuse_test", session_id, message)
        assert "result" in resp1

        resp2 = clean_device.frost_commit("reuse_test", session_id, message)
        assert "error" in resp2

    def test_invalid_session_id_all_zeros(self, clean_device):
        clean_device.import_share("zeros_test", KEY_PACKAGE_1)

        resp = clean_device.frost_commit("zeros_test", "00" * 32, random_message())
        assert "error" in resp

    def test_invalid_session_id_all_ones(self, clean_device):
        clean_device.import_share("ones_test", KEY_PACKAGE_1)

        resp = clean_device.frost_commit("ones_test", "ff" * 32, random_message())
        assert "error" in resp

    def test_invalid_message_length(self, clean_device):
        clean_device.import_share("msglen_test", KEY_PACKAGE_1)

        resp = clean_device.frost_commit("msglen_test", random_session_id(), "aa" * 16)
        assert "error" in resp

    def test_group_mismatch_on_sign(self, clean_device):
        clean_device.import_share("group_a", KEY_PACKAGE_1)
        clean_device.import_share("group_b", KEY_PACKAGE_2)

        session_id = random_session_id()
        commit_resp = clean_device.frost_commit("group_a", session_id, random_message())
        assert "result" in commit_resp

        sign_resp = clean_device.frost_sign(
            "group_b", session_id, signing_package(random_message(), {3: PEER_COMMITMENT}))
        assert "error" in sign_resp


class TestConcurrentSessions:
    def test_multiple_sessions(self, clean_device):
        clean_device.import_share("concurrent", KEY_PACKAGE_1)

        sessions = []
        for _ in range(4):
            resp = clean_device.frost_commit("concurrent", random_session_id(), random_message())
            if "result" in resp:
                sessions.append(resp)

        assert len(sessions) == 4

    def test_session_overflow(self, clean_device):
        clean_device.import_share("overflow", KEY_PACKAGE_1)

        for i in range(4):
            resp = clean_device.frost_commit("overflow", random_session_id(), random_message())
            assert "result" in resp, f"Session {i+1} should succeed"

        resp = clean_device.frost_commit("overflow", random_session_id(), random_message())
        assert "error" in resp
        assert resp["error"]["message"] == "No free session slots"


class TestInputValidation:
    def test_empty_group(self, clean_device):
        resp = clean_device.import_share("", KEY_PACKAGE_1)
        assert "error" in resp

    def test_empty_share(self, clean_device):
        resp = clean_device.import_share("empty_share", "")
        assert "error" in resp

    def test_invalid_hex_in_share(self, clean_device):
        resp = clean_device.import_share("bad_hex", "not_valid_hex_string!")
        assert "error" in resp

    def test_retired_share_field(self, clean_device):
        resp = clean_device.rpc("import_share", {"group": "old", "share": "00" * 104})
        assert "error" in resp

    def test_participants_required(self, clean_device):
        resp = clean_device.import_share("no_count", KEY_PACKAGE_1, participants=0)
        assert "error" in resp

    def test_malformed_signing_package(self, clean_device):
        clean_device.import_share("malformed", KEY_PACKAGE_1)

        session_id = random_session_id()
        commit_resp = clean_device.frost_commit("malformed", session_id, random_message())
        assert "result" in commit_resp

        sign_resp = clean_device.frost_sign("malformed", session_id, "invalid_package")
        assert "error" in sign_resp
