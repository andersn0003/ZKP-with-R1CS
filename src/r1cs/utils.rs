use bls12_381::{G1Affine, G2Affine, Scalar};

pub fn to_scalar(input: &[Vec<i64>]) -> Vec<Vec<Scalar>> {
    input
        .iter()
        .map(|row| {
            row.iter()
                .map(|col| {
                    let abs = col.abs();
                    if abs > *col {
                        Scalar::from(abs as u64).neg()
                    } else {
                        Scalar::from(abs as u64)
                    }
                })
                .collect()
        })
        .collect()
}

pub fn encrypt_with_g1(witness: &[i64]) -> Vec<G1Affine> {
    let g1 = G1Affine::generator();

    witness
        .iter()
        .map(|col| {
            let abs = col.abs();
            let scalar = if abs > *col {
                Scalar::from(abs as u64).neg()
            } else {
                Scalar::from(abs as u64)
            };
            G1Affine::from(scalar * g1)
        })
        .collect()
}

pub fn encrypt_with_g2(witness: &[i64]) -> Vec<G2Affine> {
    let g2 = G2Affine::generator();

    witness
        .iter()
        .map(|col| {
            let abs = col.abs();
            let scalar = if abs > *col {
                Scalar::from(abs as u64).neg()
            } else {
                Scalar::from(abs as u64)
            };
            G2Affine::from(scalar * g2)
        })
        .collect()
}
