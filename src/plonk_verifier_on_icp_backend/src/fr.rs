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
mod test {
    use super::*;
    use ark_serialize::{
        CanonicalDeserialize, CanonicalSerialize,
    };

    use ark_ff::{BigInteger256, Field};
    use num_bigint::BigUint;
    use num_traits::Num;
    use std::ops::{Add, Div, Mul, Sub};
    use std::str::FromStr;

    #[test]
    fn test_bigint_from_string() {
        let v1 = BigUint::from_str("1024").unwrap();
        assert_eq!(v1, BigUint::new([1024].to_vec()));

        //with "num_bigint::BigUint + num_traits::Num" traits to get value from decimal/hex string
        let v2 = BigUint::from_str_radix(
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
            16,
        )
        .unwrap();
        let v3 = BigUint::from_str_radix(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap();
        assert_eq!(v2, v3);

        let v2_1 = BigInteger256::try_from(v2).unwrap();
        let v3_1 = BigInteger256::try_from(v3).unwrap();
        assert_eq!(v2_1, v3_1);
    }

    #[test]
    fn test_biginteger256_serde_from_be_bytes() {
        // big-endian bytes
        let s = String::from("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
        let mut bytes_vec = hex::decode(&s.clone()).unwrap();

        //since igInteger256::deserialize_uncompressed is treat bytes as little-endian, reverse bytes first
        bytes_vec.reverse();
        let v1 = BigInteger256::deserialize_uncompressed::<&[u8]>(bytes_vec.as_ref()).unwrap();
        let v1str = v1.to_string();
        assert_eq!(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            v1str
        );
    }

    #[test]
    fn test_fr_from_biguint() {
        let input = vec![
            "7de9a1d1961df40980e97e12f4dd1def0e535bf858ddcdf3d2a64fee726ec744",
            "fc7a5eefddf5b9e5fc06e8f8b37e7172dfd5cb598a96d7d26cbe972517016510",
            "05d7127126089b5e8b7af6ad46959fea9e94582d9eb8caabb9205ed8a1c36c91",
            "921fb8f9e9efd865706e6f017259386c10070861f29e1151c3bb83a48934646e",
        ];

        let output = vec![
            "13175412526922964177080897496541576850519188848052084205935292988061649913666",
            "4757834056648670749114983047853294034164989321973894378345768017701699151115",
            "2641563643757307952281786817189485924276511397256432725904865976110150806673",
            "428996195638157125664800467491845848268572530814052950149558609155640812651",
        ];

        for (i, s) in input.iter().enumerate(){
            let bytes = hex::decode(s).unwrap();
            let v = BigUint::from_bytes_be(&bytes);
            let fr = Fr::from(v);
            assert_eq!(output[i], fr.to_string());
        }
    }

    #[test]
    fn test_fr_operations() {
        //derive Fr from u8 and &str
        let one = Fr::from(1u8);
        let two = Fr::from(2u8);
        let three = Fr::from_str("3").unwrap();

        let is_geq = one.is_geq_modulus();
        assert_eq!(false, is_geq);
       
        let double = one.double();
        assert_eq!(two, double);
        assert_eq!(three, two.add(&one));
        assert_eq!(two, three.sub(&one));
        
        let four = two.square();
        assert_eq!(four, three.add(&one));

        let four_inverse = four.inverse().unwrap();
        assert_eq!(one, four.mul(&four_inverse));
        assert_eq!(four_inverse, one.div(&four))
    }

    #[test]
    fn test_fr_serde() {
        let v = Fr::from_str("23").unwrap();

        let mut bytes_vec = vec![];
        v.serialize_uncompressed(&mut bytes_vec).unwrap();

        let v1 = Fr::deserialize_uncompressed::<&[u8]>(bytes_vec.clone().as_ref()).unwrap();
        assert_eq!(v, v1);
    }

    #[test]
    fn test_fr_to_gnark_bytes() {
        let v = Fr::from_str("23").unwrap();

        let res = fr_to_gnark_bytes(&v);
        assert_eq!(
            "0000000000000000000000000000000000000000000000000000000000000017",
            hex::encode(res)
        );
    }  

    #[test]
    fn test_fr_mul(){
        let five = Fr::from(5u8);
        let seven = Fr::from(7u8);

        let thirty_five = five.mul(&seven);
        println!("thirty_five: {:?}", thirty_five.to_string());
        println!("five: {:?}", five.to_string());

    }
}