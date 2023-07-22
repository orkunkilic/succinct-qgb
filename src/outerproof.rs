use crate::innerproof::*;
use crate::{Digest, C, F};

use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;

impl QGBTree {
    pub fn aggregate_proofs(
        proof0: ProofPackage,
        proof1: ProofPackage,
        verifier_data0: &VerifierCircuitData<F, C, 2>,
        verifier_data1: &VerifierCircuitData<F, C, 2>,
    ) -> (ProofPackage, VerifierCircuitData<F, C, 2>) {
        let config = CircuitConfig {
            zero_knowledge: true,
            num_wires: 136,
            ..CircuitConfig::standard_recursion_zk_config()
        };
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();

        let proof_target0 = builder.add_virtual_proof_with_pis(&verifier_data0.common);
        pw.set_proof_with_pis_target(
            &proof_target0,
            &ProofWithPublicInputs {
                proof: proof0.proof.clone(),
                public_inputs: proof0.public_inputs.clone(),
            },
        );
        
        let vd_target0 =
            builder.add_virtual_verifier_data(verifier_data0.common.fri_params.config.cap_height);
        pw.set_verifier_data_target(&vd_target0, &verifier_data0.verifier_only);

        pw.set_cap_target(
            &vd_target0.constants_sigmas_cap,
            &verifier_data0.verifier_only.constants_sigmas_cap,
        );

        builder.verify_proof::<C>(&proof_target0, &vd_target0, &verifier_data0.common);
        println!("proof0 verified");
        
        let proof_target1 = builder.add_virtual_proof_with_pis(&verifier_data1.common);
        pw.set_proof_with_pis_target(
            &proof_target1,
            &ProofWithPublicInputs {
                proof: proof1.proof.clone(),
                public_inputs: proof1.public_inputs.clone(),
            },
        );

        let vd_target =
            builder.add_virtual_verifier_data(verifier_data1.common.fri_params.config.cap_height);
        pw.set_verifier_data_target(&vd_target, &verifier_data1.verifier_only);

        pw.set_cap_target(
            &vd_target.constants_sigmas_cap,
            &verifier_data1.verifier_only.constants_sigmas_cap,
        );

        builder.verify_proof::<C>(&proof_target1, &vd_target, &verifier_data1.common);
        println!("proof1 verified");

        // msg_hash is last 4 elements of public_inputs
        let msg_hash0: Digest = proof0.public_inputs[8..12].try_into().unwrap();
        let msg_hash1: Digest = proof1.public_inputs[8..12].try_into().unwrap();

        let msg_hash0_out = HashOut {
            elements: msg_hash0,
        };
        let msg_hash1_out = HashOut {
            elements: msg_hash1,
        };

        let msg_hash0_target = builder.constant_hash(msg_hash0_out);
        let msg_hash1_target = builder.constant_hash(msg_hash1_out);

        // assert all msg_hash are equal
        builder.connect_hashes(msg_hash0_target, msg_hash1_target);

        // make hash public input
        builder.register_public_inputs(&msg_hash0_target.elements);

        // pubkey is first 4 elements of public_inputs
        let pub_key0: Digest = proof0.public_inputs[0..4].try_into().unwrap();
        let pub_key1: Digest = proof1.public_inputs[0..4].try_into().unwrap();
        // concat
        let pub_keys = pub_key0
            .iter()
            .chain(pub_key1.iter())
            .cloned()
            .collect::<Vec<F>>();
        // hash
        let pub_keys_hash = PoseidonHash::hash_no_pad(&pub_keys);
        // make hash target
        let pub_keys_hash_target = builder.constant_hash(pub_keys_hash);
        // make hash public input
        builder.register_public_inputs(&pub_keys_hash_target.elements);

        let data = builder.build();
        let recursive_proof = data.prove(pw).unwrap();

        data.verify(recursive_proof.clone()).unwrap();

        println!("recursive_proof public inputs at the end: {:?}", recursive_proof.public_inputs);

        (
            ProofPackage {
                proof: recursive_proof.proof,
                public_inputs: recursive_proof.public_inputs,
            },
            data.verifier_data(),
        )
    }

    pub fn aggregate_outer_proofs(
        proof0: ProofPackage,
        proof1: ProofPackage,
        verifier_data0: &VerifierCircuitData<F, C, 2>,
        verifier_data1: &VerifierCircuitData<F, C, 2>,
    ) -> (ProofPackage, VerifierCircuitData<F, C, 2>) {
        let config = CircuitConfig {
            zero_knowledge: true,
            num_wires: 136,
            ..CircuitConfig::standard_recursion_zk_config()
        };
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();

        let proof_target0 = builder.add_virtual_proof_with_pis(&verifier_data0.common);
        pw.set_proof_with_pis_target(
            &proof_target0,
            &ProofWithPublicInputs {
                proof: proof0.proof.clone(),
                public_inputs: proof0.public_inputs.clone(),
            },
        );
        
        let vd_target0 =
            builder.add_virtual_verifier_data(verifier_data0.common.fri_params.config.cap_height);
        pw.set_verifier_data_target(&vd_target0, &verifier_data0.verifier_only);

        pw.set_cap_target(
            &vd_target0.constants_sigmas_cap,
            &verifier_data0.verifier_only.constants_sigmas_cap,
        );

        builder.verify_proof::<C>(&proof_target0, &vd_target0, &verifier_data0.common);
        println!("proof0 verified");
        
        let proof_target1 = builder.add_virtual_proof_with_pis(&verifier_data1.common);
        pw.set_proof_with_pis_target(
            &proof_target1,
            &ProofWithPublicInputs {
                proof: proof1.proof.clone(),
                public_inputs: proof1.public_inputs.clone(),
            },
        );

        let vd_target =
            builder.add_virtual_verifier_data(verifier_data1.common.fri_params.config.cap_height);
        pw.set_verifier_data_target(&vd_target, &verifier_data1.verifier_only);

        pw.set_cap_target(
            &vd_target.constants_sigmas_cap,
            &verifier_data1.verifier_only.constants_sigmas_cap,
        );

        builder.verify_proof::<C>(&proof_target1, &vd_target, &verifier_data1.common);
        println!("proof1 verified");

        // msg_hash is first 4 elements of public_inputs
        let msg_hash0: Digest = proof0.public_inputs[0..4].try_into().unwrap();
        let msg_hash1: Digest = proof1.public_inputs[0..4].try_into().unwrap();

        let msg_hash0_out = HashOut {
            elements: msg_hash0,
        };
        let msg_hash1_out = HashOut {
            elements: msg_hash1,
        };

        let msg_hash0_target = builder.constant_hash(msg_hash0_out);
        let msg_hash1_target = builder.constant_hash(msg_hash1_out);

        // assert all msg_hash are equal
        builder.connect_hashes(msg_hash0_target, msg_hash1_target);

        // make hash public input
        builder.register_public_inputs(&msg_hash0_target.elements);

        // pubkey is last 4 elements of public_inputs
        let pub_key0: Digest = proof0.public_inputs[4..8].try_into().unwrap();
        let pub_key1: Digest = proof1.public_inputs[4..8].try_into().unwrap();

        // concat
        let pub_keys = pub_key0
            .iter()
            .chain(pub_key1.iter())
            .cloned()
            .collect::<Vec<F>>();

        // hash
        let pub_keys_hash = PoseidonHash::hash_no_pad(&pub_keys);

        // make hash target
        let pub_keys_hash_target = builder.constant_hash(pub_keys_hash);

        // make hash public input
        builder.register_public_inputs(&pub_keys_hash_target.elements);

        let data = builder.build();
        let recursive_proof = data.prove(pw).unwrap();

        data.verify(recursive_proof.clone()).unwrap();

        println!("recursive_proof public inputs at the end: {:?}", recursive_proof.public_inputs);

        (
            ProofPackage {
                proof: recursive_proof.proof,
                public_inputs: recursive_proof.public_inputs,
            },
            data.verifier_data(),
        )

    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use plonky2::field::{secp256k1_scalar::Secp256K1Scalar, types::Sample};
    use plonky2_ecdsa::curve::{secp256k1::Secp256K1, ecdsa::{ECDSASecretKey, ECDSAPublicKey, sign_message, ECDSASignature}, curve_types::{CurveScalar, Curve}};

    use super::*;

    #[test]
    fn test_aggregate_proofs() {
        type Curve = Secp256K1;

        // generate 4 random sk and pk
        let sks = (0..4)
            .map(|_| ECDSASecretKey::<Curve>(Secp256K1Scalar::rand()))
            .collect::<Vec<ECDSASecretKey<Curve>>>(); 

        let pks_ecdsa = sks
            .iter()
            .map(|sk| ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine()))
            .collect::<Vec<ECDSAPublicKey<Curve>>>();

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

        let msg = Secp256K1Scalar::rand();

        let msg_hash = PoseidonHash::hash_no_pad(&msg.0.into_iter().map(|x| F::from_canonical_u64(x)).collect::<Vec<F>>());
        println!("msg_hash: {:?}", msg_hash);

        fn generate_proof(
            tree: QGBTree,
            pks_i: Vec<F>,
            i: usize,
            r_i: Secp256K1Scalar,
            s_i: Secp256K1Scalar,
            pk_i: ECDSAPublicKey<Secp256K1>,
            msg: Secp256K1Scalar,
            msg_hash: HashOut<GoldilocksField>
        ) -> (ProofPackage, VerifierCircuitData<F, C, 2>) {
            println!("create proof for pk_i: {:?}", pk_i);

            let (proof, vd) = tree.gen_proof(pks_i.clone().try_into().unwrap(), i, r_i, s_i, pk_i, msg).unwrap();

            let package = ProofPackage {
                proof: proof.proof,
                public_inputs: proof.public_inputs,
            };

            // verify proof0
            QGBTree::verify_proof(
                msg_hash.elements,
                pks_i.clone().try_into().unwrap(),
                tree.root(),
                package.clone(),
                &vd,
            ).unwrap();
            println!("proof verified for pk_i: {:?}", pk_i);

            (package, vd)
        }

        let mut handlers = vec![];
        // loop twice
        for k in 0..4 {
            let pks_k = pks[k].clone();
            let sk_k = sks[k].clone();
            let pk_k = pks_ecdsa[k].clone();
            let sig_k = sign_message(msg, sk_k);
            let ECDSASignature { r: r_k, s: s_k } = sig_k;

            let tree = qgb_tree.clone();

            handlers.push(thread::spawn(move || {
                generate_proof(
                    tree,
                    pks_k.clone(),
                    k,
                    r_k,
                    s_k,
                    pk_k,
                    msg,
                    msg_hash,
                )
            }));
        }

        let mut proofs = vec![];
        let mut vds = vec![];

        for handler in handlers {
            let (proof, vd) = handler.join().unwrap();
            proofs.push(proof);
            vds.push(vd);
        }

        println!("all inner proofs generated");

        let (proof0, vd0) = QGBTree::aggregate_proofs(
            proofs[0].clone(),
            proofs[1].clone(),
            &vds[0],
            &vds[1],
        );

        vd0.verify(ProofWithPublicInputs {
            proof: proof0.proof.clone(),
            public_inputs: proof0.public_inputs.clone(),
        }).unwrap();

        println!("first batch of proofs aggregated");

        let (proof1, vd1) = QGBTree::aggregate_proofs(
            proofs[2].clone(),
            proofs[3].clone(),
            &vds[2],
            &vds[3],
        );

        vd1.verify(ProofWithPublicInputs {
            proof: proof1.proof.clone(),
            public_inputs: proof1.public_inputs.clone(),
        }).unwrap();

        println!("second batch of proofs aggregated");

        // wait for keyboard input to continue
        println!("press enter to continue for the last step");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        let (proof, vd) = QGBTree::aggregate_outer_proofs(
            proof0,
            proof1,
            &vd0,
            &vd1,
        );

        vd.verify(ProofWithPublicInputs {
            proof: proof.proof.clone(),
            public_inputs: proof.public_inputs.clone(),
        }).unwrap();

        println!("outer recursive proofs aggregated");

        // first 4 elements of public_inputs are the msg_hash
        let msg_hash: Digest = proof.public_inputs[0..4].try_into().unwrap();

        // last 4 elements of public_inputs are the pub_keys_hash
        let pub_keys_hash: Digest = proof.public_inputs[4..8].try_into().unwrap();

        println!("msg_hash of aggregated proof: {:?}", msg_hash);

        println!("pub_keys_hash of aggregated proof: {:?}", pub_keys_hash);
    }
}
