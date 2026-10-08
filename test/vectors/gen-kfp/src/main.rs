// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Writes the KFP v2 vectors frost_tr is checked against, from keep's own code
//! (keep-core and keep-frost-net at the commit pinned in Cargo.toml, and the
//! nostr crate keep uses): transport keys, announce proofs and the announces a
//! running keep node publishes, rendezvous addresses, NIP-44 v2 payloads, keep
//! events sealed to a member, NIP-01 serializations and salted session ids.
//! Groups come from keep's dealer, so each run writes a fresh, equally valid set.
//! The lockfile is not tracked (the RNG hygiene check bans getrandom in any);
//! seed it from keep's at the pinned commit, which resolves under keep's MSRV:
//!
//!   git -C <keep> show cdc47ddb120a50a2c31d7a2abd4279845c4dddd2:Cargo.lock > Cargo.lock
//!   cargo run --release > ../../../components/frost_tr/rust/vectors/kfp.json
use std::time::Duration;

use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::{derive_session_id_salted, proof::sign_proof, KfpEventBuilder, KfpNode};
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::*;
use serde_json::{json, Value};

struct FixedNonce([u8; 32]);
impl nostr_sdk::nostr::secp256k1::rand::RngCore for FixedNonce {
    fn next_u32(&mut self) -> u32 {
        unreachable!()
    }
    fn next_u64(&mut self) -> u64 {
        unreachable!()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.copy_from_slice(&self.0[..dest.len()]);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), nostr_sdk::nostr::secp256k1::rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn seeded(label: &str) -> [u8; 32] {
    use nostr_sdk::hashes::{sha256, Hash};
    sha256::Hash::hash(label.as_bytes()).to_byte_array()
}

async fn capture_announce(relay: &str, node: &KfpNode) -> Event {
    let client = Client::default();
    client.add_relay(relay).await.unwrap();
    client.connect().await;
    let mut rx = client.notifications();
    client
        .subscribe(Filter::new().kind(Kind::Custom(24242)).author(node.pubkey()), None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    node.announce().await.unwrap();
    loop {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("announce").unwrap() {
            RelayPoolNotification::Event { event, .. } => {
                client.disconnect().await;
                return *event;
            }
            _ => continue,
        }
    }
}

#[tokio::main]
async fn main() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();
    let mock = MockRelay::run().await.unwrap();
    let relay = mock.url().await.to_string();
    let lengths = [1usize, 16, 31, 32, 33, 64, 65, 255, 256, 257, 300, 1000, 4096, 16385, 65408];

    let mut groups = Vec::new();
    for (g, config) in [ThresholdConfig::two_of_three(), ThresholdConfig::two_of_three(), ThresholdConfig::new(3, 5).unwrap()]
        .into_iter()
        .enumerate()
    {
        let dealer = TrustedDealer::new(config);
        let (shares, pkp) = dealer.generate(&format!("kfp-vectors-{g}")).unwrap();
        let group_key = pkp.verifying_key().serialize().unwrap();
        let mut members = Vec::new();
        let mut key_packages = Vec::new();
        let mut nodes = Vec::new();
        for share in shares {
            let kp = share.key_package().unwrap();
            key_packages.push(hex::encode(kp.serialize().unwrap()));
            nodes.push((kp, KfpNode::new(share, vec![relay.clone()]).await.unwrap()));
        }
        for (kp, node) in &nodes {
            let index = share_index(kp);
            let transport = node.pubkey().to_bytes();
            let announce = capture_announce(&relay, node).await;
            let share32: [u8; 32] = kp.signing_share().serialize().try_into().unwrap();
            let vs: [u8; 33] = kp.verifying_share().serialize().unwrap().try_into().unwrap();
            let group32: [u8; 32] = group_key[1..33].try_into().unwrap();
            let proofs: Vec<Value> = [0u64, 1_700_000_000, u64::MAX]
                .iter()
                .map(|ts| json!({"timestamp": ts, "proof": hex::encode(sign_proof(&share32, &group32, index, &vs, &transport, *ts).unwrap())}))
                .collect();

            // NIP-44 between the device (this member's transport key) and a peer key.
            let peer = Keys::new(SecretKey::from_slice(&seeded(&format!("peer {g} {index}"))).unwrap());
            let nip44: Vec<Value> = lengths
                .iter()
                .enumerate()
                .map(|(i, len)| {
                    let nonce = seeded(&format!("nonce {g} {index} {i}"));
                    let plaintext: Vec<u8> = (0..*len).map(|b| (b * 7 + i) as u8).collect();
                    let payload = nip44::encrypt_with_rng(&mut FixedNonce(nonce), peer.secret_key(), &node.pubkey(), &plaintext, nip44::Version::V2).unwrap();
                    // plaintext byte b is (b * 7 + i) mod 256; long payloads are recorded by hash.
                    if *len <= 1000 {
                        json!({"nonce": hex::encode(nonce), "length": len, "payload": payload})
                    } else {
                        use nostr_sdk::hashes::{sha256, Hash};
                        json!({"nonce": hex::encode(nonce), "length": len,
                               "payload_sha256": sha256::Hash::hash(payload.as_bytes()).to_string()})
                    }
                })
                .collect();

            // keep events a peer seals to this member's transport key.
            let events: Vec<Value> = [
                KfpEventBuilder::pong(&peer, &node.pubkey(), seeded("challenge")).unwrap(),
                KfpEventBuilder::ping(&peer, &node.pubkey()).unwrap(),
            ]
            .into_iter()
            .map(|e| {
                let plaintext = nip44::decrypt(peer.secret_key(), &node.pubkey(), &e.content).unwrap();
                json!({"event": serde_json::from_str::<Value>(&e.as_json()).unwrap(), "plaintext": plaintext})
            })
            .collect();

            members.push(json!({
                "index": index,
                "transport_pubkey": hex::encode(transport),
                "proofs": proofs,
                "announce": serde_json::from_str::<Value>(&announce.as_json()).unwrap(),
                "peer_secret": peer.secret_key().to_secret_hex(),
                "peer_pubkey": peer.public_key().to_hex(),
                "nip44": nip44,
                "events": events,
            }));
        }
        groups.push(json!({
            "min_signers": *nodes[0].0.min_signers(),
            "group_key": hex::encode(&group_key),
            "key_packages": key_packages,
            "members": members,
        }));
    }

    // NIP-01 serialization: keep events and their ids.
    let keys = Keys::new(SecretKey::from_slice(&seeded("event author")).unwrap());
    let to = Keys::new(SecretKey::from_slice(&seeded("event recipient")).unwrap()).public_key();
    let serializations: Vec<Value> = [
        KfpEventBuilder::pong(&keys, &to, seeded("c1")).unwrap(),
        EventBuilder::new(Kind::Custom(24242), "line\nbreak \"quote\" back\\slash \t tab \u{8} \u{c} \r é ✓")
            .tag(Tag::public_key(to))
            .tag(Tag::custom(TagKind::custom("t"), ["x\"y"]))
            .sign_with_keys(&keys)
            .unwrap(),
    ]
    .into_iter()
    .map(|e| {
        let serialized = serde_json::to_string(&json!([0, e.pubkey.to_hex(), e.created_at.as_u64(), e.kind.as_u16(), e.tags, e.content])).unwrap();
        json!({"serialized": serialized, "id": e.id.to_hex()})
    })
    .collect();

    let sessions: Vec<Value> = [
        (vec![0x11u8; 32], vec![1u16, 2], 2u16, vec![]),
        (vec![0x22u8; 32], vec![3u16, 1], 2u16, vec![]),
        (vec![0x33u8; 32], vec![1u16, 2, 3], 3u16, [0u64.to_be_bytes().to_vec(), 0u32.to_be_bytes().to_vec(), 7u32.to_be_bytes().to_vec()].concat()),
        (vec![0x44u8; 32], vec![1u16, 2], 2u16, [1u64.to_be_bytes().to_vec(), vec![0xff, b'T', b'R', 0]].concat()),
        (vec![0x55u8; 32], vec![2u16, 5, 4], 3u16, [2u64.to_be_bytes().to_vec(), 1u32.to_be_bytes().to_vec(), vec![0xff, b'T', b'R', 1], vec![0xab; 32]].concat()),
        (vec![], vec![1u16, 2], 2u16, vec![]),
        (vec![0x66u8; 300], vec![1u16, 2], 2u16, 5u64.to_be_bytes().to_vec()),
    ]
    .into_iter()
    .map(|(message, participants, threshold, salt)| {
        json!({
            "message": hex::encode(&message),
            "participants": participants,
            "threshold": threshold,
            "salt": hex::encode(&salt),
            "id": hex::encode(derive_session_id_salted(&message, &participants, threshold, &salt)),
        })
    })
    .collect();

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "source": "keep-core/keep-frost-net cdc47ddb and nostr 0.44.7 (test/vectors/gen-kfp)",
            "groups": groups,
            "serializations": serializations,
            "sessions": sessions,
        }))
        .unwrap()
    );
}

fn share_index(kp: &frost_secp256k1_tr::keys::KeyPackage) -> u16 {
    let b = kp.identifier().serialize();
    u16::from_be_bytes([b[30], b[31]])
}
