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

use std::collections::BTreeMap;
use std::io::Read;
use std::process::exit;

use frost_secp256k1_tr as frost;
use frost::keys::{IdentifierList, KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};
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
        _ => die("unknown command"),
    }
}
