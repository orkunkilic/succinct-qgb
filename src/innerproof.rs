use anyhow::Result;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ecdsa::curve::ecdsa::ECDSAPublicKey;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::ecdsa::{ECDSAPublicKeyTarget, ECDSASignatureTarget, verify_message_circuit};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

use crate::{Digest, PlonkyProof, C, F};

pub struct QGBTargets {
    qgb_root: HashOutTarget,
    merkle_proof: MerkleProofTarget,
    pub_key: [Target; 4],
    pk_i: Target,
}

#[derive(Debug, Clone)]
pub struct QGBTree(pub MerkleTree<F, PoseidonHash>);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofPackage {
    pub proof: PlonkyProof,
    pub public_inputs: Vec<F>,
}

impl QGBTree {
    pub fn new(pks: Vec<Vec<F>>) -> Self {
        QGBTree(MerkleTree::new(pks, 0))
    }

    pub fn tree_height(&self) -> usize {
        self.0.leaves.len().trailing_zeros() as usize
    }

    pub fn root(&self) -> Digest {
        self.0
            .cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .collect::<Vec<F>>()
            .try_into()
            .unwrap()
    }

    pub fn circuit(&self, builder: &mut CircuitBuilder<F, 2>) -> QGBTargets {
        // Register public inputs.
        let pub_key: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        builder.register_public_inputs(&pub_key);
        let qgb_root = builder.add_virtual_hash();
        builder.register_public_inputs(&qgb_root.elements);

        // Merkle proof
        let merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(self.tree_height()),
        };

        // Verify public key Merkle proof.
        let pk_i = builder.add_virtual_target();
        let pk_i_bits = builder.split_le(pk_i, self.tree_height());
        builder.verify_merkle_proof::<PoseidonHash>(
            pub_key.to_vec(),
            &pk_i_bits,
            qgb_root,
            &merkle_proof,
        );


        QGBTargets {
            qgb_root,
            merkle_proof,
            pub_key,
            pk_i,
        }
    }
    pub fn fill_qgb_targets(
        &self,
        pw: &mut PartialWitness<F>,
        pub_key: Digest,
        pk_i: usize,
        targets: QGBTargets,
    ) {
        let QGBTargets {
            pub_key: pub_key_target,
            qgb_root,
            merkle_proof: merkle_proof_target,
            pk_i: pk_i_target,
        } = targets;

        pw.set_target_arr(pub_key_target, pub_key);
        pw.set_hash_target(qgb_root, self.0.cap.0[0]);
        pw.set_target(pk_i_target, F::from_canonical_usize(pk_i));

        let merkle_proof = self.0.prove(pk_i);
        for (ht, h) in merkle_proof_target
            .siblings
            .into_iter()
            .zip(merkle_proof.siblings)
        {
            pw.set_hash_target(ht, h);
        }
    }
}

// proof related
impl QGBTree {
    pub fn gen_proof(
        &self,
        pub_key: Digest,
        pk_i: usize,
        r: Secp256K1Scalar,
        s: Secp256K1Scalar,
        pk: ECDSAPublicKey<Secp256K1>,
        msg: Secp256K1Scalar,
    ) -> Result<(ProofPackage, VerifierCircuitData<F, C, 2>)> {
        let config = CircuitConfig {
            zero_knowledge: true,
            num_wires: 136,
            ..CircuitConfig::standard_recursion_zk_config()
        };
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();

        // build merkle tree related circuit
        let targets = self.circuit(&mut builder);
        self.fill_qgb_targets(&mut pw, pub_key, pk_i, targets);

        println!("pub key: {:?}", pub_key);

        // build msg_hash for public input
        let msg_hash = PoseidonHash::hash_no_pad(&msg.0.into_iter().map(|x| F::from_canonical_u64(x)).collect::<Vec<F>>());
        let msg_hash_target = builder.constant_hash(msg_hash);
        builder.register_public_inputs(&msg_hash_target.elements);
        
        // public_key target
        let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));
        
        // signature target
        let r_target = builder.constant_nonnative(r);
        let s_target = builder.constant_nonnative(s);
        let sig_target = ECDSASignatureTarget {
            r: r_target,
            s: s_target,
        };

        // msg target
        let msg_target = builder.constant_nonnative(msg);

        // verify message circuit
        verify_message_circuit(&mut builder, msg_target, sig_target, pk_target);

        // build proof
        let data = builder.build();
        let proof = data.prove(pw)?;

        // return proof and verifier data
        Ok((
            ProofPackage {
                proof: proof.proof,
                public_inputs: proof.public_inputs,
            },
            data.verifier_data(),
        ))
    }

    pub fn verify_proof(
        msg_hash: Digest,
        pub_key: Digest,
        qgb_root: Digest,
        proof: ProofPackage,
        verifier_data: &VerifierCircuitData<F, C, 2>,
    ) -> Result<()> {
        let public_inputs = pub_key.into_iter()
            .chain(qgb_root.into_iter())
            .chain(msg_hash.into_iter())
            .collect::<Vec<F>>();

        verifier_data.verify(ProofWithPublicInputs {
            proof: proof.proof,
            public_inputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::hash::Hash;

    use super::*;
    use plonky2::field::types::Sample;

    
    #[test]
    fn test_inner_proof() {
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

        let qgb_root = qgb_tree.root();

        let i = 0;

        let pks_i = pks[i].clone();

        let msg = Secp256K1Scalar::rand();

        let sk = sks[i].clone();
        let pk = pks_ecdsa[i].clone();

        let sig = sign_message(msg, sk);

        let ECDSASignature { r, s } = sig;

        println!("create proof...");

        let (proof, vd) = qgb_tree
            .gen_proof(pks_i.clone().try_into().unwrap(), i, r, s, pk, msg)
            .unwrap();

        println!("verify proof...");

        let msg_hash = PoseidonHash::hash_no_pad(&msg.0.into_iter().map(|x| F::from_canonical_u64(x)).collect::<Vec<F>>());
        println!("msg_hash: {:?}", msg_hash);

        QGBTree::verify_proof(
            msg_hash.elements,
            pks_i.try_into().unwrap(), 
            qgb_root, proof, &vd
        ).unwrap();
    }
}
