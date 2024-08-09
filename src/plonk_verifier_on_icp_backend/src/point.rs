use ark_bn254::{Config, Fq, G1Affine, G2Affine};
use ark_ec::{
    bn::{self, Bn, BnConfig, TwistType},
    short_weierstrass::SWFlags,
    AffineRepr,
};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use std::cmp::{Ord, Ordering, PartialOrd};
use std::error::Error;
use std::ops::{Add, Div, Mul, Neg, Sub};
use std::{any::Any, str::FromStr};

//reference github.com/consensys/gnark-crypto/ecc/bn254/marshal.go
const GNARK_MASK: u8 = 0b11 << 6;
const GNARK_UNCOMPRESSED: u8 = 0b00 << 6;
const GNARK_COMPRESSED_POSTIVE: u8 = 0b10 << 6;
const GNARK_COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const GNARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

const ARK_MASK: u8 = 0b11 << 6;
const ARK_COMPRESSED_POSTIVE: u8 = 0b00 << 6;
const ARK_COMPRESSED_NEGATIVE: u8 = 0b10 << 6;
const ARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

/*
    In gnark, G1Affine
    compressed bytes is big-endian，
    MSB byte:
    bit7 = 1 : compressed format
    bit6 = 1 : y > -y
    bit6 = 0 : y < -y
    uncompressed bytes =  x big-endian bytes | y big endian bytes

    In arkworks, G1Affine
    compressed bytes i  little-endian,
    MSB byte:
    bit7 = 0 : y<-y
    bit7 = 1 : y > -y
    uncompressed bytes =  x le bytes | y le bytes + negative flag in y's MSB byte

*/
fn gnark_flag_to_ark_flag(msb: u8) -> u8 {
    let gnark_flag = msb & GNARK_MASK;

    let mut ark_flag = ARK_COMPRESSED_POSTIVE;
    match gnark_flag {
        GNARK_COMPRESSED_POSTIVE => ark_flag = ARK_COMPRESSED_POSTIVE,
        GNARK_COMPRESSED_NEGATIVE => ark_flag = ARK_COMPRESSED_NEGATIVE,
        GNARK_COMPRESSED_INFINITY => ark_flag = ARK_COMPRESSED_INFINITY,
        _ => panic!("Unexpected gnark_flag value: {}", gnark_flag),
    }

    msb & !ARK_MASK | ark_flag
}

//convert big-endian gnark compressed x bytes to litte-endian ark compressed x for g1 and g2 point
pub fn ganrk_commpressed_x_to_ark_commpressed_x(x: &Vec<u8>) -> Vec<u8> {
    if x.len() != 32 && x.len() != 64 {
        panic!("Invalid x length: {}", x.len());
    }
    let mut x_copy = x.clone();

    let msb = gnark_flag_to_ark_flag(x_copy[0]);
    x_copy[0] = msb;

    x_copy.reverse();
    x_copy
}

// get the G1Affine to gnark uncompressed bytes
// ark uncompressed   | x bytes in le | y bytes in le | (d88ec7e93cdf5ddabe594fc8b62c1913c1ee19a029bc4a6b2a56ecae808a7c09 06a2261cf69efc2413ce2db397a8c0fccf0849f81979b2c2fc9457cdf2bd5300)
// gnark uncompressed | x bytes in be | y bytes in be | (097c8a80aeec562a6b4abc29a019eec113192cb6c84f59beda5ddf3ce9c78ed8 0053bdf2cd5794fcc2b27919f84908cffcc0a897b32dce1324fc9ef61c26a206)
// Note: in ark works, a negative flag is tagged if y is negative, this flag is not exist in gnark.
// in production, use only 1 mthod 
pub fn ark_g1_to_gnark_unompressed_bytes(point: &G1Affine) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = vec![];
    
    let x_bytes = point.x().unwrap().into_bigint().to_bytes_be();
    let y_bytes = point.y().unwrap().into_bigint().to_bytes_be();

    bytes.extend_from_slice(&x_bytes);
    bytes.extend_from_slice(&y_bytes);

    Ok(bytes)
}

pub fn gnark_compressed_x_to_g1_point(buf: &[u8]) -> Result<G1Affine, Box<dyn Error>> {
    if buf.len() != 32 {
        return Err(SerializationError::InvalidData.into())
    };

    let m_data = buf[0] & GNARK_MASK;
    if m_data == GNARK_COMPRESSED_INFINITY {
        if !is_zeroed(buf[0] & !GNARK_MASK, &buf[1..32]) {
            return Err(SerializationError::InvalidData.into())
        }
        Ok(G1Affine::identity())
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !GNARK_MASK;

        let x = Fq::from_be_bytes_mod_order(&x_bytes.to_vec());
        let (y, neg_y) =
            G1Affine::get_ys_from_x_unchecked(x).ok_or(SerializationError::InvalidData)?;

        let mut final_y = y;
        if y.cmp(&neg_y) == Ordering::Greater {
            if m_data == GNARK_COMPRESSED_POSTIVE {
                final_y = y.neg();
            }
        } else {
            if m_data == GNARK_COMPRESSED_NEGATIVE {
                final_y = y.neg();
            }
        }

        let p = G1Affine::new_unchecked(x, final_y);
        if !p.is_on_curve() {
            return Err(SerializationError::InvalidData.into())
        }
        Ok(p)
    }
}

fn is_zeroed(first_byte: u8, buf: &[u8]) -> bool {
    if first_byte != 0 {
        return false;
    }
    for &b in buf {
        if b != 0 {
            return false;
        }
    }
    true
}

pub fn gnark_uncompressed_bytes_to_g1_point(buf: &[u8]) -> Result<G1Affine, Box<dyn Error>>{
    if buf.len() != 64 {
        return Err(SerializationError::InvalidData.into());
    };

    let (x_bytes, y_bytes) = buf.split_at(32);

    let x = Fq::from_be_bytes_mod_order(&x_bytes.to_vec());
    let y = Fq::from_be_bytes_mod_order(&y_bytes.to_vec());
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(SerializationError::InvalidData.into());
    }
    Ok(p)
}

pub fn gnark_compressed_x_to_g2_point(buf: &[u8]) -> Result<G2Affine, Box<dyn Error>> {
    if buf.len() != 64 {
        return Err(SerializationError::InvalidData.into());
    };

    let bytes = ganrk_commpressed_x_to_ark_commpressed_x(&buf.to_vec());
    let p = G2Affine::deserialize_compressed::<&[u8]>(&bytes)?;
    Ok(p)
}
