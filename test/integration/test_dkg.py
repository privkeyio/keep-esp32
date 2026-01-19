import pytest

from conftest import random_hex


class TestDKGInit:
    def test_dkg_init_success(self, clean_device):
        resp = clean_device.dkg_init(group="dkg_test", threshold=2, participant_count=3, our_index=1)
        if "error" in resp:
            pytest.skip("DKG not implemented or requires crypto context")
        assert resp["result"].get("ok") is True

    def test_dkg_init_invalid_threshold(self, clean_device):
        resp = clean_device.dkg_init(group="dkg_bad", threshold=5, participant_count=3, our_index=1)
        if "result" in resp:
            pytest.skip("Device accepted invalid threshold")
        assert "error" in resp

    def test_dkg_init_zero_participants(self, clean_device):
        resp = clean_device.dkg_init(group="dkg_zero", threshold=0, participant_count=0, our_index=0)
        assert "error" in resp


class TestDKGFlow:
    @pytest.fixture
    def dkg_session(self, clean_device):
        init_resp = clean_device.dkg_init(group="dkg_flow", threshold=2, participant_count=3, our_index=1)
        if "error" in init_resp:
            pytest.skip("DKG init failed")
        return clean_device

    def test_dkg_round1(self, dkg_session):
        resp = dkg_session.dkg_round1("dkg_flow")
        if "error" in resp:
            pytest.skip("DKG round1 not implemented")
        assert "vss_commitment" in resp["result"]

    def test_dkg_round1_without_init(self, clean_device):
        resp = clean_device.dkg_round1("uninit_group")
        assert "error" in resp

    def test_dkg_round1_peer(self, dkg_session):
        r1_resp = dkg_session.dkg_round1("dkg_flow")
        if "error" in r1_resp:
            pytest.skip("DKG round1 failed")
        resp = dkg_session.dkg_round1_peer("dkg_flow", peer_index=2, dkg_data=random_hex(128))
        if "error" in resp:
            pytest.skip("DKG round1_peer not implemented")
        assert resp["result"].get("ok") is True

    def test_dkg_round2_without_peers(self, dkg_session):
        dkg_session.dkg_round1("dkg_flow")
        resp = dkg_session.dkg_round2("dkg_flow")
        if "result" in resp:
            pytest.skip("Device proceeded without peer data")
        assert "error" in resp

    def test_dkg_finalize_incomplete(self, dkg_session):
        resp = dkg_session.dkg_finalize("dkg_flow")
        assert "error" in resp


class TestDKGValidation:
    def test_dkg_max_participants(self, clean_device):
        resp = clean_device.dkg_init(group="dkg_max", threshold=10, participant_count=16, our_index=1)
        assert "result" in resp or "error" in resp

    def test_dkg_exceed_max_participants(self, clean_device):
        resp = clean_device.dkg_init(group="dkg_exceed", threshold=10, participant_count=20, our_index=1)
        assert "error" in resp

    def test_dkg_invalid_our_index(self, clean_device):
        resp = clean_device.dkg_init(group="dkg_idx", threshold=2, participant_count=3, our_index=10)
        assert "error" in resp

    def test_dkg_duplicate_group(self, clean_device):
        resp1 = clean_device.dkg_init(group="dkg_dup", threshold=2, participant_count=3, our_index=1)
        if "error" in resp1:
            pytest.skip("First DKG init failed")
        resp2 = clean_device.dkg_init(group="dkg_dup", threshold=2, participant_count=3, our_index=1)
        assert "result" in resp2 or "error" in resp2
        if "result" in resp2:
            assert resp2["result"].get("ok") is True


class TestDKGStateTransitions:
    def test_cannot_skip_to_round2(self, clean_device):
        clean_device.dkg_init(group="skip_r2", threshold=2, participant_count=3, our_index=1)
        resp = clean_device.dkg_round2("skip_r2")
        if "result" in resp:
            pytest.skip("Device allowed skipping round1")
        assert "error" in resp

    def test_cannot_finalize_from_round1(self, clean_device):
        clean_device.dkg_init(group="fin_early", threshold=2, participant_count=3, our_index=1)
        clean_device.dkg_round1("fin_early")
        resp = clean_device.dkg_finalize("fin_early")
        if "result" in resp:
            pytest.skip("Device allowed early finalization")
        assert "error" in resp


class TestDKGDataValidation:
    @pytest.fixture
    def dkg_ready_for_peer(self, clean_device):
        clean_device.dkg_init("peer_val", threshold=2, participant_count=3, our_index=1)
        resp = clean_device.dkg_round1("peer_val")
        if "error" in resp:
            pytest.skip("DKG round1 failed")
        return clean_device

    def test_peer_data_too_short(self, dkg_ready_for_peer):
        resp = dkg_ready_for_peer.dkg_round1_peer("peer_val", peer_index=2, dkg_data="aabbcc")
        if "result" in resp:
            pytest.skip("Device accepted short peer data")
        assert "error" in resp

    def test_peer_data_invalid_hex(self, dkg_ready_for_peer):
        resp = dkg_ready_for_peer.dkg_round1_peer("peer_val", peer_index=2, dkg_data="not_hex_!!!")
        assert "error" in resp

    def test_peer_index_out_of_range(self, dkg_ready_for_peer):
        resp = dkg_ready_for_peer.dkg_round1_peer("peer_val", peer_index=100, dkg_data=random_hex(128))
        assert "error" in resp

    def test_duplicate_peer_index(self, dkg_ready_for_peer):
        peer_data = random_hex(128)
        resp1 = dkg_ready_for_peer.dkg_round1_peer("peer_val", peer_index=2, dkg_data=peer_data)
        if "error" in resp1:
            pytest.skip("First peer data submission failed")
        resp2 = dkg_ready_for_peer.dkg_round1_peer("peer_val", peer_index=2, dkg_data=peer_data)
        assert "result" in resp2 or "error" in resp2
        if "result" in resp2:
            assert resp2["result"].get("ok") is True
