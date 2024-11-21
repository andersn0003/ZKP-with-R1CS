use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

mod utils;
use utils::to_scalar;
pub use utils::{encrypt_with_g1, encrypt_with_g2};

pub struct LRO {
    left: Vec<Vec<Scalar>>,
    right: Vec<Vec<Scalar>>,
    output: Vec<Vec<Scalar>>,
}

impl LRO {
    pub fn new(left: &[Vec<i64>], right: &[Vec<i64>], output: &[Vec<i64>]) -> Self {
        if left.len() == 0
            || left[0].len() == 0
            || left.len() != right.len()
            || right.len() != output.len()
            || left
                .iter()
                .zip(right.iter())
                .enumerate()
                .any(|(index, (l, r))| l.len() != r.len() || r.len() != output[index].len())
        {
            panic!("LRO mismatch");
        }

        LRO {
            left: to_scalar(left),
            right: to_scalar(right),
            output: to_scalar(output),
        }
    }

    fn verify_witness_equality(witness_g1: &[G1Affine], witness_g2: &[G2Affine]) {
        if witness_g1.len() != witness_g2.len()
            || witness_g1.iter().zip(witness_g2.iter()).any(|(g1, g2)| {
                pairing(&g1, &G2Affine::generator()) != pairing(&G1Affine::generator(), &g2)
            })
        {
            panic!("Witness mismatch");
        }
    }

    pub fn verify(&self, witness_g1: &[G1Affine], witness_g2: &[G2Affine]) {
        LRO::verify_witness_equality(witness_g1, witness_g2);

        if witness_g1.len() != self.left[0].len() {
            panic!("Witness LRO mismatch");
        }

        if self
            .left
            .iter()
            .zip(self.right.iter())
            .enumerate()
            .any(|(step, (left, right))| {
                let mut g1 = G1Projective::identity();
                left.iter()
                    .enumerate()
                    .for_each(|(index, val)| g1 += val * witness_g1[index]);

                let mut g2 = G2Projective::identity();
                right
                    .iter()
                    .enumerate()
                    .for_each(|(index, val)| g2 += val * witness_g2[index]);

                let mut g1_out = G1Projective::identity();
                self.output[step]
                    .iter()
                    .enumerate()
                    .for_each(|(index, val)| g1_out += val * witness_g1[index]);

                pairing(&G1Affine::from(g1), &G2Affine::from(g2))
                    != pairing(&G1Affine::from(g1_out), &G2Affine::generator())
            })
        {
            panic!("Verification failed");
        }
    }
}
