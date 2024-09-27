use ark_bn254::Fr;
use std::error::Error;
use ark_std::io::Read;
use crate::fr::*;

pub struct PublicWitness{}
/*
    in gnark@BN254, witness is composited as the flollowing
    | number of public |  4 bytes  |
    | number of sceret |  4 bytes  |
    | number of vector |  4 bytes  |
    | vector of fr     |  32 bytes for each |
*/

impl PublicWitness {
    pub fn from_gnark_bytes(data: &[u8]) -> Result<Vec<Fr>, Box<dyn Error>> {
        let mut reader = data; // Using slice directly
        
        let mut public_len_bytes = [0u8; 4];
        reader.read_exact(&mut public_len_bytes)?;
        let public_len = u32::from_be_bytes(public_len_bytes);

        let mut secret_len_bytes = [0u8; 4];
        reader.read_exact(&mut secret_len_bytes)?;
        let _secret_len = u32::from_be_bytes(secret_len_bytes);

        let mut vector_len_bytes = [0u8; 4];
        reader.read_exact(&mut vector_len_bytes)?;
        let vector_len = u32::from_be_bytes(vector_len_bytes);
        if public_len != vector_len {
            return Err("public_len != vector_len".into());
        }

        let mut witnesses = Vec::with_capacity(vector_len as usize);
        for _i in 0..(vector_len as usize) {
            let mut v_bytes = [0u8; 32];
            reader.read_exact(&mut v_bytes)?;
            let v = fr_from_gnark_bytes(&v_bytes);
            witnesses.push(v);
        }
        Ok(witnesses)
    }
}
