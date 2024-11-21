mod r1cs;
use r1cs::{encrypt_with_g1, encrypt_with_g2, LRO};

// y^2 = 4x^3 + 2z + 9
//
// Constraints:
// v1 = y*y
// v2 = x*x
// v1 - 2z - 9 = v2*4x
//
// Witness:
// [1, y, x, z, v1, v2]
//
// Example witnesses:
// [1, 5, 1, 6, 25, 1]
// [1, 7, 1, 18, 49, 1]
//
fn main() {
    let witness = [1, 5, 1, 6, 25, 1];
    let witness_g1 = encrypt_with_g1(&witness);
    let witness_g2 = encrypt_with_g2(&witness);

    let lro = LRO::new(
        &[
            vec![0, 1, 0, 0, 0, 0],
            vec![0, 0, 1, 0, 0, 0],
            vec![0, 0, 0, 0, 0, 1],
        ],
        &[
            vec![0, 1, 0, 0, 0, 0],
            vec![0, 0, 1, 0, 0, 0],
            vec![0, 0, 4, 0, 0, 0],
        ],
        &[
            vec![0, 0, 0, 0, 1, 0],
            vec![0, 0, 0, 0, 0, 1],
            vec![-9, 0, 0, -2, 1, 0],
        ],
    );
    lro.verify(&witness_g1, &witness_g2);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_lro() -> LRO {
        LRO::new(
            &[
                vec![0, 1, 0, 0, 0, 0],
                vec![0, 0, 1, 0, 0, 0],
                vec![0, 0, 0, 0, 0, 1],
            ],
            &[
                vec![0, 1, 0, 0, 0, 0],
                vec![0, 0, 1, 0, 0, 0],
                vec![0, 0, 4, 0, 0, 0],
            ],
            &[
                vec![0, 0, 0, 0, 1, 0],
                vec![0, 0, 0, 0, 0, 1],
                vec![-9, 0, 0, -2, 1, 0],
            ],
        )
    }

    #[test]
    #[should_panic(expected = "LRO mismatch")]
    fn fail_lro_mismatch_empty_rows() {
        LRO::new(&[], &[], &[]);
    }

    #[test]
    #[should_panic(expected = "LRO mismatch")]
    fn fail_lro_mismatch_empty_columns() {
        LRO::new(&[vec![]], &[vec![]], &[vec![]]);
    }

    #[test]
    #[should_panic(expected = "LRO mismatch")]
    fn fail_lro_mismatch_rows() {
        LRO::new(&[vec![1], vec![2]], &[vec![1]], &[vec![1]]);
    }

    #[test]
    #[should_panic(expected = "LRO mismatch")]
    fn fail_lro_mismatch_columns() {
        LRO::new(&[vec![1, 2]], &[vec![1]], &[vec![1]]);
    }

    #[test]
    #[should_panic(expected = "Witness mismatch")]
    fn fail_witness_mismatch_content() {
        let witness = [1, 5, 1, 6, 25, 1];
        let witness_g1 = encrypt_with_g1(&witness);

        let witness = [1, 7, 1, 18, 49, 1];
        let witness_g2 = encrypt_with_g2(&witness);

        let lro = get_lro();
        lro.verify(&witness_g1, &witness_g2);
    }

    #[test]
    #[should_panic(expected = "Witness mismatch")]
    fn fail_witness_mismatch_length() {
        let witness = [1, 5, 1, 6, 25, 1];
        let witness_g1 = encrypt_with_g1(&witness);

        let witness = [1, 5, 1, 6, 25, 1, 2];
        let witness_g2 = encrypt_with_g2(&witness);

        let lro = get_lro();
        lro.verify(&witness_g1, &witness_g2);
    }

    #[test]
    #[should_panic(expected = "Witness LRO mismatch")]
    fn fail_witness_lro_mismatch() {
        let witness = [1, 5, 1, 6, 25, 1, 2];
        let witness_g1 = encrypt_with_g1(&witness);

        let witness = [1, 5, 1, 6, 25, 1, 2];
        let witness_g2 = encrypt_with_g2(&witness);

        let lro = get_lro();
        lro.verify(&witness_g1, &witness_g2);
    }

    #[test]
    #[should_panic(expected = "Verification failed")]
    fn fail_bad_witness() {
        let witness = [1, 6, 2, 6, 36, 4];
        let witness_g1 = encrypt_with_g1(&witness);
        let witness_g2 = encrypt_with_g2(&witness);

        let lro = get_lro();
        lro.verify(&witness_g1, &witness_g2);
    }

    #[test]
    fn pass() {
        let lro = get_lro();

        let witness = [1, 5, 1, 6, 25, 1];
        let witness_g1 = encrypt_with_g1(&witness);
        let witness_g2 = encrypt_with_g2(&witness);
        lro.verify(&witness_g1, &witness_g2);

        let witness = [1, 7, 1, 18, 49, 1];
        let witness_g1 = encrypt_with_g1(&witness);
        let witness_g2 = encrypt_with_g2(&witness);
        lro.verify(&witness_g1, &witness_g2);
    }

    #[test]
    fn pass_2() {
        // 529 = x^3 + 4x^2 - xz + 4
        //
        // Constraints:
        // v1 = x*x
        // v2 = x*v1
        // 529 - v2 - 4v1 - 4 = -x*z
        //
        // Witness:
        // [1, x, z, v1, v2]
        //
        // Example witness:
        // [1, 7, 2, 49, 343]
        //
        let witness = [1, 7, 2, 49, 343];
        let witness_g1 = encrypt_with_g1(&witness);
        let witness_g2 = encrypt_with_g2(&witness);

        let lro = LRO::new(
            &[
                vec![0, 1, 0, 0, 0],
                vec![0, 1, 0, 0, 0],
                vec![0, -1, 0, 0, 0],
            ],
            &[
                vec![0, 1, 0, 0, 0],
                vec![0, 0, 0, 1, 0],
                vec![0, 0, 1, 0, 0],
            ],
            &[
                vec![0, 0, 0, 1, 0],
                vec![0, 0, 0, 0, 1],
                vec![525, 0, 0, -4, -1],
            ],
        );
        lro.verify(&witness_g1, &witness_g2);
    }
}
