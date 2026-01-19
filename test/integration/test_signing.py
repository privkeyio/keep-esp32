from conftest import random_message, random_session_id

TEST_SHARE_2OF3_P1 = "00" * 102
TEST_SHARE_2OF3_P2 = "01" * 102


class TestPing:
    def test_ping_response(self, device):
        resp = device.ping()
        assert "result" in resp
        assert resp["result"].get("pong") is True
        assert "version" in resp["result"]

    def test_get_status(self, device):
        resp = device.get_status()
        assert "result" in resp
        assert "version" in resp["result"]
        assert "rng_healthy" in resp["result"]


class TestShareManagement:
    def test_import_and_list(self, clean_device):
        resp = clean_device.import_share("test_group", TEST_SHARE_2OF3_P1)
        assert "result" in resp
        assert resp["result"].get("ok") is True

        resp = clean_device.list_shares()
        assert "result" in resp
        assert "test_group" in resp["result"]["shares"]

    def test_import_and_delete(self, clean_device):
        clean_device.import_share("delete_test", TEST_SHARE_2OF3_P1)

        resp = clean_device.delete_share("delete_test")
        assert "result" in resp
        assert resp["result"].get("ok") is True

        resp = clean_device.list_shares()
        assert "delete_test" not in resp["result"]["shares"]

    def test_delete_nonexistent(self, clean_device):
        resp = clean_device.delete_share("nonexistent_group_xyz")
        assert "error" in resp
        assert resp["error"]["code"] == -3

    def test_get_share_info(self, clean_device):
        clean_device.import_share("info_test", TEST_SHARE_2OF3_P1)

        resp = clean_device.get_share_info("info_test")
        assert "result" in resp
        assert "pubkey" in resp["result"]
        assert "index" in resp["result"]
        assert "threshold" in resp["result"]
        assert "participants" in resp["result"]

    def test_get_share_info_not_found(self, clean_device):
        resp = clean_device.get_share_info("missing_share")
        assert "error" in resp
        assert resp["error"]["code"] == -1


class TestSigningFlow:
    def test_commit_requires_share(self, clean_device):
        resp = clean_device.frost_commit("no_such_group", random_session_id(), random_message())
        assert "error" in resp
        assert resp["error"]["code"] == -1

    def test_commit_success(self, clean_device):
        clean_device.import_share("commit_test", TEST_SHARE_2OF3_P1)

        resp = clean_device.frost_commit("commit_test", random_session_id(), random_message())
        assert "result" in resp
        assert "commitment" in resp["result"]
        assert "index" in resp["result"]
        assert len(resp["result"]["commitment"]) == 264

    def test_sign_requires_session(self, clean_device):
        clean_device.import_share("sign_test", TEST_SHARE_2OF3_P1)

        resp = clean_device.frost_sign("sign_test", random_session_id(), "0002" + "cc" * 130)
        assert "error" in resp
        assert resp["error"]["code"] == -2

    def test_complete_signing_flow(self, clean_device):
        clean_device.import_share("flow_test", TEST_SHARE_2OF3_P1)

        session_id = random_session_id()
        commit_resp = clean_device.frost_commit("flow_test", session_id, random_message())
        assert "result" in commit_resp
        assert "commitment" in commit_resp["result"]

        sign_resp = clean_device.frost_sign("flow_test", session_id, "0002" + "dd" * 130)
        assert "result" in sign_resp
        assert "signature_share" in sign_resp["result"]
        assert "index" in sign_resp["result"]

    def test_session_id_reuse_rejected(self, clean_device):
        clean_device.import_share("reuse_test", TEST_SHARE_2OF3_P1)

        session_id = random_session_id()
        message = random_message()

        resp1 = clean_device.frost_commit("reuse_test", session_id, message)
        assert "result" in resp1

        resp2 = clean_device.frost_commit("reuse_test", session_id, message)
        assert "error" in resp2

    def test_invalid_session_id_all_zeros(self, clean_device):
        clean_device.import_share("zeros_test", TEST_SHARE_2OF3_P1)

        resp = clean_device.frost_commit("zeros_test", "00" * 32, random_message())
        assert "error" in resp

    def test_invalid_session_id_all_ones(self, clean_device):
        clean_device.import_share("ones_test", TEST_SHARE_2OF3_P1)

        resp = clean_device.frost_commit("ones_test", "ff" * 32, random_message())
        assert "error" in resp

    def test_invalid_message_length(self, clean_device):
        clean_device.import_share("msglen_test", TEST_SHARE_2OF3_P1)

        resp = clean_device.frost_commit("msglen_test", random_session_id(), "aa" * 16)
        assert "error" in resp

    def test_group_mismatch_on_sign(self, clean_device):
        clean_device.import_share("group_a", TEST_SHARE_2OF3_P1)
        clean_device.import_share("group_b", TEST_SHARE_2OF3_P2)

        session_id = random_session_id()
        commit_resp = clean_device.frost_commit("group_a", session_id, random_message())
        assert "result" in commit_resp

        sign_resp = clean_device.frost_sign("group_b", session_id, "0002" + "ee" * 130)
        assert "error" in sign_resp


class TestConcurrentSessions:
    def test_multiple_sessions(self, clean_device):
        clean_device.import_share("concurrent", TEST_SHARE_2OF3_P1)

        sessions = []
        for _ in range(4):
            resp = clean_device.frost_commit("concurrent", random_session_id(), random_message())
            if "result" in resp:
                sessions.append(resp)

        assert len(sessions) == 4

    def test_session_overflow(self, clean_device):
        clean_device.import_share("overflow", TEST_SHARE_2OF3_P1)

        for i in range(4):
            resp = clean_device.frost_commit("overflow", random_session_id(), random_message())
            assert "result" in resp, f"Session {i+1} should succeed"

        resp = clean_device.frost_commit("overflow", random_session_id(), random_message())
        assert "error" in resp
        assert resp["error"]["message"] == "No free session slots"


class TestInputValidation:
    def test_empty_group(self, clean_device):
        resp = clean_device.import_share("", TEST_SHARE_2OF3_P1)
        assert "error" in resp

    def test_empty_share(self, clean_device):
        resp = clean_device.import_share("empty_share", "")
        assert "error" in resp

    def test_invalid_hex_in_share(self, clean_device):
        resp = clean_device.import_share("bad_hex", "not_valid_hex_string!")
        assert "error" in resp

    def test_malformed_commitments(self, clean_device):
        clean_device.import_share("malformed", TEST_SHARE_2OF3_P1)

        session_id = random_session_id()
        commit_resp = clean_device.frost_commit("malformed", session_id, random_message())
        assert "result" in commit_resp

        sign_resp = clean_device.frost_sign("malformed", session_id, "invalid_commitment")
        assert "error" in sign_resp
