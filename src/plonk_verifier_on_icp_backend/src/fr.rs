use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

pub fn fr_to_gnark_bytes(fr: &Fr) -> Vec<u8> {
    fr.into_bigint().to_bytes_be()
}

pub fn fr_from_gnark_bytes(bytes: &[u8]) -> Fr {
    Fr::from(BigUint::from_bytes_be(bytes))
}

#[cfg(test)]
mod tests {
    #[test]
    fn hello() {
        println!("hello");
    }
}