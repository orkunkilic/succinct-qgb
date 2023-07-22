/* 
    Create a set of functions for all operations

    1- 
        Create 4 random secret keys
        Create 4 public keys from the secret keys
        Create 4 Goldilocks points from the public keys
        Create a random message
        Create a signature from the message and the secret key for each of the 4 secret keys
        Create the QGB from the 4 public keys
        Create the QGB root from the QGB
        Create the message hash from the message

        Dump all of the above to a file as a JSON object

    2- 
        Read the JSON object from the file
        Create a proof from the JSON object
        Verify the proof
        Dump the proof to a file as a JSON object
*/

use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;
use std::thread;

use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::Field;
use plonky2::field::types::Sample;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::curve::curve_types::CurveScalar;
use plonky2_ecdsa::curve::ecdsa::ECDSAPublicKey;
use plonky2_ecdsa::curve::ecdsa::ECDSASecretKey;
use plonky2_ecdsa::curve::ecdsa::ECDSASignature;
use plonky2_ecdsa::curve::ecdsa::sign_message;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;

use crate::F;
use crate::innerproof::QGBTree;


/* 
        Create 4 random secret keys
        Create 4 public keys from the secret keys
        Create 4 Goldilocks points from the public keys
        Create a random message
        Create a signature from the message and the secret key for each of the 4 secret keys
        Create the QGB from the 4 public keys
        Create the QGB root from the QGB
        Create the message hash from the message

        Dump all of the above to a file as a JSON object
*/
pub fn generate_step_1() {
    let sks = (0..4)
    .map(|_| ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand()))
    .collect::<Vec<ECDSASecretKey<Secp256K1>>>();

    let pks_ecdsa = sks
        .iter()
        .map(|sk| ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine()))
        .collect::<Vec<ECDSAPublicKey<Secp256K1>>>();

    let pks = pks_ecdsa
        .iter()
        .map(|pk| {
            pk.0
                .x
                .0
                .iter()
                .map(|x| F::from_canonical_u64(*x))
                .collect::<Vec<F>>()
        })
        .collect::<Vec<Vec<F>>>();

    // build tree from pks
    let qgb_tree = QGBTree::new(pks.clone());

    let qgb_root = qgb_tree.root();

    let msg = Secp256K1Scalar::rand();

    let msg_hash = PoseidonHash::hash_no_pad(&msg.0.into_iter().map(|x| F::from_canonical_u64(x)).collect::<Vec<F>>());

    let signatures = sks
        .iter()
        .map(|sk| sign_message(msg, sk.clone()))
        .collect::<Vec<ECDSASignature<Secp256K1>>>();

    let data = serde_json::json!({
        "sks": sks,
        "pks_ecdsa": pks_ecdsa,
        "pks": pks,
        "msg": msg,
        "msg_hash": msg_hash,
        "signatures": signatures,
    });
    
    let path = Path::new("data.json");
    let mut file = File::create(&path).unwrap();
    file.write_all(data.to_string().as_bytes()).unwrap();

}

#[test]
fn test_generate_step_1() {
    generate_step_1();
}

/* 
        Read the JSON object from the file
        Create a proof from the JSON object
        Verify the proof
        Dump the proof to a file as a JSON object
*/
pub fn generate_step_2(i: u8) {

    let path = Path::new("data.json");
    let file = File::open(&path).unwrap();
    let reader = BufReader::new(file);
    let data: serde_json::Value = serde_json::from_reader(reader).unwrap();

    let pks = data["pks"].clone();
    let pks: Vec<Vec<F>> = serde_json::from_value(pks).unwrap();

    let pk = data["pks"][i as usize].clone();
    let pk: Vec<F> = serde_json::from_value(pk).unwrap();

    let pk_ecdsa = data["pks_ecdsa"][i as usize].clone();
    let pk_ecdsa: ECDSAPublicKey<Secp256K1> = serde_json::from_value(pk_ecdsa).unwrap();

    let r = data["signatures"][i as usize]["r"].clone();
    let r: Secp256K1Scalar = serde_json::from_value(r).unwrap();

    let s = data["signatures"][i as usize]["s"].clone();
    let s: Secp256K1Scalar = serde_json::from_value(s).unwrap();

    let msg = data["msg"].clone();
    let msg: Secp256K1Scalar = serde_json::from_value(msg).unwrap();

    let tree = QGBTree::new(pks.clone());

    let (proof, vd) = tree.gen_proof(pk.try_into().unwrap(), i as usize, r, s, pk_ecdsa, msg).unwrap();

    let data = serde_json::json!({
        "proof": proof
    });

    // save as proof_{i}.json
    let name = format!("proof_{}.json", i);
    let path = Path::new(&name);
    let mut file = File::create(&path).unwrap();
    file.write_all(data.to_string().as_bytes()).unwrap();
}

#[test]
fn test_generate_step_2() {
    // go 0..4 in multiple threads
    let mut handlers = vec![];
    for i in 0..4 {
        handlers.push(
            thread::spawn(move || {
                generate_step_2(i);
            })
        );
    }

    for handler in handlers {
        handler.join().unwrap();
    }
}

// TODO: NOT COMPLETE!