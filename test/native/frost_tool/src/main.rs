// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The host side of a FROST round for the native tests, on frost-secp256k1-tr
//! 3.0.0 as keep uses it. Prints JSON or hex on stdout.
//!
//!   keygen <min> <max> <even|odd>         dealer-generated group
//!   commit <key_package>                  a peer's nonces and commitment
//!   package <message> <idx:commitment>... SigningPackage serialization
//!   sign <key_package> <nonces> <package> a peer's signature share
//!   aggregate <pubkeys> <package> <idx:share>...
//!                                         verified 64-byte BIP-340 signature
//!   legacy <key_package> <participants>   the 104-byte pre-protocol-2 share
//!   tweak-key-package <key_package> <path>
//!   tweak-public-key-package <pubkeys> <path>
//!                                         keep's BIP-32 tweak for a path like 0,5
//!   taptweak-key-package <key_package> <merkle_root|->
//!   taptweak-public-key-package <pubkeys> <merkle_root|->
//!                                         the BIP-341 TapTweak as keep applies it
//!   key-spend-sighash <psbt_hex>          input 0's BIP-341 SIGHASH_DEFAULT key-spend sighash
//!   key-spend-finalize <psbt_hex> <sig>   the transaction with input 0's key-path witness

use std::collections::BTreeMap;
use std::io::Read;
use std::process::exit;

use bitcoin::hashes::{sha256, sha512, Hash as _, HashEngine as _, Hmac, HmacEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use frost_secp256k1_tr as frost;
use frost::keys::{IdentifierList, KeyPackage, PublicKeyPackage, SigningShare, Tweak, VerifyingShare};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage, VerifyingKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn die(msg: &str) -> ! {
    eprintln!("frost_tool: {msg}");
    exit(1)
}

fn rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .unwrap_or_else(|e| die(&format!("/dev/urandom: {e}")));
    ChaCha20Rng::from_seed(seed)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    if s.len() % 2 != 0 {
        die("odd-length hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| die("bad hex")))
        .collect()
}

fn index(s: &str) -> Identifier {
    let i: u16 = s.parse().unwrap_or_else(|_| die("bad index"));
    Identifier::try_from(i).unwrap_or_else(|_| die("bad index"))
}

fn pairs(args: &[String]) -> Vec<(Identifier, Vec<u8>)> {
    args.iter()
        .map(|a| {
            let (i, h) = a.split_once(':').unwrap_or_else(|| die("expected idx:hex"));
            (index(i), unhex(h))
        })
        .collect()
}

fn key_package(s: &str) -> KeyPackage {
    KeyPackage::deserialize(&unhex(s)).unwrap_or_else(|e| die(&format!("key package: {e}")))
}

/// keep-core v0.10.0's `frost_bip32::derive_path_composite` with its
/// deterministic chain code, written against rust-bitcoin as keep is.
fn composite_tweak(group_xonly: &[u8], path: &[u32]) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(b"keep-frost-bip32-chaincode-v1");
    engine.input(group_xonly);
    let mut chaincode = sha256::Hash::from_engine(engine).to_byte_array();
    let secp = Secp256k1::verification_only();
    let mut lift = vec![0x02];
    lift.extend_from_slice(group_xonly);
    let mut parent = PublicKey::from_slice(&lift).unwrap_or_else(|_| die("group key not on curve"));
    let mut acc: Option<SecretKey> = None;
    for &index in path {
        if index >= 0x8000_0000 {
            die("hardened index");
        }
        let mut engine = HmacEngine::<sha512::Hash>::new(&chaincode);
        engine.input(&parent.serialize());
        engine.input(&index.to_be_bytes());
        let i = Hmac::<sha512::Hash>::from_engine(engine).to_byte_array();
        let t: [u8; 32] = i[..32].try_into().unwrap();
        let scalar = Scalar::from_be_bytes(t).unwrap_or_else(|_| die("tweak >= n"));
        parent = parent.add_exp_tweak(&secp, &scalar).unwrap_or_else(|_| die("bad child"));
        acc = Some(match acc {
            None => SecretKey::from_slice(&t).unwrap_or_else(|_| die("zero tweak")),
            Some(a) => a.add_tweak(&scalar).unwrap_or_else(|_| die("zero sum")),
        });
        chaincode.copy_from_slice(&i[32..]);
    }
    acc.unwrap_or_else(|| die("empty path")).secret_bytes()
}

/// The tweak as keep applies it: negated for an odd-y group key.
fn effective_tweak(vk: &[u8], path: &[u32]) -> Scalar {
    let mut t = composite_tweak(&vk[1..33], path);
    if vk[0] == 0x03 {
        t = SecretKey::from_slice(&t).unwrap().negate().secret_bytes();
    }
    Scalar::from_be_bytes(t).unwrap()
}

fn shift(point: &[u8], t: &Scalar) -> Vec<u8> {
    let secp = Secp256k1::verification_only();
    PublicKey::from_slice(point).unwrap().add_exp_tweak(&secp, t).unwrap().serialize().to_vec()
}

fn path_arg(s: &str) -> Vec<u32> {
    s.split(',').map(|i| i.parse().unwrap_or_else(|_| die("bad path"))).collect()
}

fn merkle_root_arg(s: &str) -> Option<[u8; 32]> {
    (s != "-").then(|| unhex(s).try_into().unwrap_or_else(|_| die("merkle root must be 32 bytes")))
}

fn psbt_arg(s: &str) -> bitcoin::Psbt {
    bitcoin::Psbt::deserialize(&unhex(s)).unwrap_or_else(|e| die(&format!("psbt: {e}")))
}

fn participant_index(id: &Identifier) -> u16 {
    let b = id.serialize();
    u16::from_be_bytes([b[30], b[31]])
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| args.get(i).map(String::as_str).unwrap_or_else(|| die("missing argument"));
    match arg(0) {
        "keygen" => {
            let min: u16 = arg(1).parse().unwrap_or_else(|_| die("bad min"));
            let max: u16 = arg(2).parse().unwrap_or_else(|_| die("bad max"));
            let odd = match arg(3) {
                "even" => false,
                "odd" => true,
                _ => die("parity must be even or odd"),
            };
            let mut rng = rng();
            let (shares, pubkeys) = loop {
                let (s, p) = frost::keys::generate_with_dealer(max, min, IdentifierList::Default, &mut rng)
                    .unwrap_or_else(|e| die(&format!("keygen: {e}")));
                if (p.verifying_key().serialize().unwrap()[0] == 3) == odd {
                    break (s, p);
                }
            };
            let participants: Vec<String> = shares
                .into_iter()
                .map(|(id, s)| {
                    let kp = KeyPackage::try_from(s).unwrap();
                    format!(
                        "{{\"index\":{},\"key_package\":\"{}\"}}",
                        participant_index(&id),
                        hex(&kp.serialize().unwrap())
                    )
                })
                .collect();
            println!(
                "{{\"group_key\":\"{}\",\"public_key_package\":\"{}\",\"participants\":[{}]}}",
                hex(&pubkeys.verifying_key().serialize().unwrap()),
                hex(&pubkeys.serialize().unwrap()),
                participants.join(",")
            );
        }
        "commit" => {
            let kp = key_package(arg(1));
            let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng());
            println!(
                "{{\"nonces\":\"{}\",\"commitment\":\"{}\"}}",
                hex(&nonces.serialize().unwrap()),
                hex(&commitments.serialize().unwrap())
            );
        }
        "package" => {
            let message = unhex(arg(1));
            let commitments: BTreeMap<_, _> = pairs(&args[2..])
                .into_iter()
                .map(|(id, c)| {
                    (id, SigningCommitments::deserialize(&c).unwrap_or_else(|e| die(&format!("commitment: {e}"))))
                })
                .collect();
            println!("{}", hex(&SigningPackage::new(commitments, &message).serialize().unwrap()));
        }
        "sign" => {
            let kp = key_package(arg(1));
            let nonces = SigningNonces::deserialize(&unhex(arg(2))).unwrap_or_else(|e| die(&format!("nonces: {e}")));
            let package = SigningPackage::deserialize(&unhex(arg(3))).unwrap_or_else(|e| die(&format!("package: {e}")));
            let share = frost::round2::sign(&package, &nonces, &kp).unwrap_or_else(|e| die(&format!("sign: {e}")));
            println!("{}", hex(&share.serialize()));
        }
        "aggregate" => {
            let pubkeys =
                PublicKeyPackage::deserialize(&unhex(arg(1))).unwrap_or_else(|e| die(&format!("pubkeys: {e}")));
            let package = SigningPackage::deserialize(&unhex(arg(2))).unwrap_or_else(|e| die(&format!("package: {e}")));
            let shares: BTreeMap<_, _> = pairs(&args[3..])
                .into_iter()
                .map(|(id, s)| (id, SignatureShare::deserialize(&s).unwrap_or_else(|e| die(&format!("share: {e}")))))
                .collect();
            let sig = frost::aggregate(&package, &shares, &pubkeys).unwrap_or_else(|e| die(&format!("aggregate: {e}")));
            pubkeys
                .verifying_key()
                .verify(package.message(), &sig)
                .unwrap_or_else(|e| die(&format!("verify: {e}")));
            println!("{}", hex(&sig.serialize().unwrap()));
        }
        "legacy" => {
            let kp = key_package(arg(1));
            let participants: u16 = arg(2).parse().unwrap_or_else(|_| die("bad participants"));
            let mut out = kp.signing_share().serialize();
            out.extend(kp.verifying_share().serialize().unwrap());
            out.extend(kp.verifying_key().serialize().unwrap());
            out.extend(participant_index(kp.identifier()).to_le_bytes());
            out.extend(participants.to_le_bytes());
            out.extend(kp.min_signers().to_le_bytes());
            println!("{}", hex(&out));
        }
        "tweak-key-package" => {
            let kp = key_package(arg(1));
            let vk = kp.verifying_key().serialize().unwrap();
            let t = effective_tweak(&vk, &path_arg(arg(2)));
            let share = SecretKey::from_slice(&kp.signing_share().serialize()).unwrap().add_tweak(&t).unwrap();
            let tweaked = KeyPackage::new(
                *kp.identifier(),
                SigningShare::deserialize(&share.secret_bytes()).unwrap(),
                VerifyingShare::deserialize(&shift(&kp.verifying_share().serialize().unwrap(), &t)).unwrap(),
                VerifyingKey::deserialize(&shift(&vk, &t)).unwrap(),
                *kp.min_signers(),
            );
            println!("{}", hex(&tweaked.serialize().unwrap()));
        }
        "tweak-public-key-package" => {
            let pkp = PublicKeyPackage::deserialize(&unhex(arg(1))).unwrap_or_else(|e| die(&format!("pubkeys: {e}")));
            let vk = pkp.verifying_key().serialize().unwrap();
            let t = effective_tweak(&vk, &path_arg(arg(2)));
            let shares: BTreeMap<_, _> = pkp
                .verifying_shares()
                .iter()
                .map(|(id, vs)| (*id, VerifyingShare::deserialize(&shift(&vs.serialize().unwrap(), &t)).unwrap()))
                .collect();
            let tweaked = PublicKeyPackage::new(shares, VerifyingKey::deserialize(&shift(&vk, &t)).unwrap(), pkp.min_signers());
            println!("{}", hex(&tweaked.serialize().unwrap()));
        }
        "taptweak-key-package" => {
            println!("{}", hex(&key_package(arg(1)).tweak(merkle_root_arg(arg(2))).serialize().unwrap()));
        }
        "taptweak-public-key-package" => {
            let pkp = PublicKeyPackage::deserialize(&unhex(arg(1))).unwrap_or_else(|e| die(&format!("pubkeys: {e}")));
            println!("{}", hex(&pkp.tweak(merkle_root_arg(arg(2))).serialize().unwrap()));
        }
        "key-spend-sighash" => {
            use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
            let psbt = psbt_arg(arg(1));
            let prevouts: Vec<bitcoin::TxOut> = psbt
                .inputs
                .iter()
                .map(|i| i.witness_utxo.clone().unwrap_or_else(|| die("an input has no witness_utxo")))
                .collect();
            let sighash = SighashCache::new(&psbt.unsigned_tx)
                .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
                .unwrap_or_else(|e| die(&format!("sighash: {e}")));
            println!("{}", hex(sighash.as_ref()));
        }
        "key-spend-finalize" => {
            let mut psbt = psbt_arg(arg(1));
            let sig = unhex(arg(2));
            if sig.len() != 64 {
                die("signature must be 64 bytes");
            }
            psbt.inputs[0].final_script_witness = Some(bitcoin::Witness::from_slice(&[sig]));
            let tx = psbt.extract_tx_unchecked_fee_rate();
            println!("{}", hex(&bitcoin::consensus::serialize(&tx)));
        }
        _ => die("unknown command"),
    }
}
