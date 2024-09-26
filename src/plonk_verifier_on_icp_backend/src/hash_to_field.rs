
use sha2::Sha256;
use std::io::{self, Write};
use ark_bn254::Fr;
use digest::Digest;
use digest::core_api::BlockSizeUser;
use std::error::Error;

use crate::fr::{fr_from_gnark_bytes, fr_to_gnark_bytes};

const BYTE_SIZE:usize = 32;

pub struct HashToField {
    domain: Vec<u8>,
    to_hash: Vec<u8>,
}


impl HashToField {
    pub fn new(domain_separator: &[u8]) -> Self {
        HashToField {
            domain: domain_separator.to_vec(),
            to_hash: Vec::new(),
        }
    }

    pub fn sum(&mut self) -> Vec<u8> {
        let fr = hash_to_field(&self.to_hash, &self.domain, 1).unwrap();
        fr_to_gnark_bytes(&fr[0])
    }

    pub fn reset(&mut self) {
        self.to_hash.clear();
    }
}

impl Write for HashToField {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.to_hash.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn hash_to_field(msg: &[u8], dst: &[u8], count: usize) -> Result<Vec<Fr>, Box<dyn Error>> {
    let len = BYTE_SIZE + 16;
    let pseduo_random_bytes = expand_msg_xmd(msg, dst, len*count)?;

    let mut res = Vec::with_capacity(count);
    for i in 0..count {
       let fr = fr_from_gnark_bytes(&pseduo_random_bytes[i*len..(i+1)*len]);
       res.push(fr);
    }
    Ok(res)    
}


fn expand_msg_xmd(msg: &[u8], dst: &[u8], n: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut hasher = Sha256::new();

     // output size of the hash function, e.g. 32 bytes = 256 bits for sha2::Sha256
    let b_len = Sha256::output_size();
    let ell = (n + b_len - 1) / b_len; //
    if ell > 255 {
        return Err("invalid len_in_bytes".into());
    }
    if dst.len() > 255 {
        return Err("invalid domain size (>255 bytes)".into());
    }
    let size_domain = dst.len() as u8;


    // Z_pad = I2OSP(0, r_in_bytes)
    // l_i_b_str = I2OSP(len_in_bytes, 2)
    // DST_prime = DST ∥ I2OSP(len(DST), 1)
    // b₀ = H(Z_pad ∥ msg ∥ l_i_b_str ∥ I2OSP(0, 1) ∥ DST_prime)
    hasher.reset();
    hasher.update(&vec![0; Sha256::block_size()]);
    hasher.update(msg);
    hasher.update(&[(n >> 8) as u8, n as u8, 0]);
    hasher.update(dst);
    hasher.update(&[size_domain]);
    let b0 = hasher.finalize_reset();

    // b₁ = H(b₀ ∥ I2OSP(1, 1) ∥ DST_prime)
    hasher.update(&b0);
    hasher.update(&[1]);
    hasher.update(dst);
    hasher.update(&[size_domain]);
    let mut b1 = hasher.finalize_reset();

    let mut uniform_bytes: Vec<u8> = Vec::with_capacity(n);
    uniform_bytes.extend_from_slice(&b1);
    for i in 2..=ell {
        // update the hasher with xor of b_0 and b_i elements
        for (l, r) in b0.iter().zip(b1.iter()) {
            hasher.update(&[*l ^ *r]);
        }
        hasher.update(&[i as u8]);
        hasher.update(&dst);
        hasher.update(&[size_domain]);
        b1 = hasher.finalize_reset();
        uniform_bytes.extend_from_slice(&b1);
    }
    let res = uniform_bytes[0..n].to_vec();
    Ok(res)
}



#[cfg(test)]
mod test{
    use super::*;
    
    #[test]
    fn test_hash_to_field_1() {
        let mut hasher = HashToField::new(b"BSB22-Plonk");
        let bytes = hex::decode("19fcec892a59a9032fcbacc2aea4576819e265dd54ae49d57d17200bb33134e301f3ba06fdccf993b19c56b49875cac18d385eb53c651d53587e4548279b5c2a").unwrap();
        hasher.write(&bytes).unwrap();
        let res = hasher.sum();
        let fr = fr_from_gnark_bytes(&res);
        assert_eq!("2161252824825955644621487721081736561973572532081413859751628043458274122616", fr.to_string());
    }

    #[test]
    fn test_hash_to_field_2() {
        let mut hasher = HashToField::new(b"BSB22-Plonk");
        let bytes = hex::decode("22312c83811c0d51c0a0655b0412909d605dabd8650dfb965f5d94a4db5edbe106799e4bff042d46d2ebb3c8404a15b34ce0ccf5b39ae3e67b947c457373c76e").unwrap();
        hasher.write(&bytes).unwrap();
        let res = hasher.sum();
        let fr = fr_from_gnark_bytes(&res);
        assert_eq!("11593280986460652115679837107476641214342495810443230158187475124137133584283", fr.to_string());
    }
}