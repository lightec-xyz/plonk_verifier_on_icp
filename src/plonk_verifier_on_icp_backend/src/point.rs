use ark_bn254::{Fq, G1Affine, G2Affine};
use ark_ec::{
    AffineRepr,
};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, SerializationError};
use std::cmp::{Ord, Ordering};
use std::error::Error;
use std::ops::Neg;


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


#[cfg(test)]
mod test {
    use super::*;
    use std::{str::FromStr};
    use ark_serialize::CanonicalSerialize;


    #[test]
    fn test_g1_generator() {
        let generator = G1Affine::generator();

        let x = Fq::from(1u8);
        let y = Fq::from(2u8);

        let p1 = G1Affine::new(x, y);
        assert_eq!(p1, generator);

        let p2 = G1Affine::new(Fq::from_str("1").unwrap(), Fq::from_str("2").unwrap());
        assert_eq!(p2, generator);
    }


    #[test]
    fn test_g1point_from_string() {
        //Note: 
        //1 Fq::from_str is only applied without leading zeros
        //2. arkworks g1 point is marshal in little-endian
        
        let x = Fq::from_str("1").unwrap();
        let y = Fq::from_str("2").unwrap();
        let p1 = G1Affine::new(x, y);
        println!("{:?}", p1);
        assert_eq!(p1.is_on_curve(), true);

        let mut bytes_vec = vec![];
        p1.serialize_compressed(&mut bytes_vec).unwrap();
        // println!("bytes_vec: {:?}", bytes_vec); //little-endian

        let s = String::from("0000000000000000000000000000000000000000000000000000000000000001");
        let mut bytes_vec = hex::decode(&s.clone()).unwrap();

        bytes_vec.reverse();
        let p2 = G1Affine::deserialize_compressed::<&[u8]>(bytes_vec.as_ref()).unwrap();

        assert_eq!(p1, p2);
    }

    #[test]
    fn test_g1point_serde() {
        //step1, rebuild G1Affine from x and y coordinates
        let xs = String::from("097c8a80aeec562a6b4abc29a019eec113192cb6c84f59beda5ddf3ce9c78ed8");
        let mut bytes_vec = hex::decode(&xs.clone()).unwrap();
        bytes_vec.reverse();
        let x = Fq::deserialize_compressed::<&[u8]>(bytes_vec.as_ref()).unwrap();

        let ys = String::from("0053bdf2cd5794fcc2b27919f84908cffcc0a897b32dce1324fc9ef61c26a206");
        let mut bytes_vec = hex::decode(&ys.clone()).unwrap();
        bytes_vec.reverse();
        let y = Fq::deserialize_compressed::<&[u8]>(bytes_vec.as_ref()).unwrap();
        let p1 = G1Affine::new_unchecked(x, y);
        assert_eq!(p1.is_on_curve(), true);

        //step2. get G1Affine compressed bytes, and rebuild
        let mut compressed_bytes: Vec<u8> = vec![];
        p1.serialize_compressed(&mut compressed_bytes).unwrap();
        println!("p1 compressed: {:?}", hex::encode(compressed_bytes.clone()));
        let p2 = G1Affine::deserialize_compressed::<&[u8]>(compressed_bytes.as_ref()).unwrap();
        assert_eq!(p2.is_on_curve(), true);
        assert_eq!(p1, p2);

        //step3. get G1Affine uncompressed bytes, and rebuild
        //gnark 097c8a80aeec562a6b4abc29a019eec113192cb6c84f59beda5ddf3ce9c78ed80053bdf2cd5794fcc2b27919f84908cffcc0a897b32dce1324fc9ef61c26a206
        let mut uncompressed_bytes = vec![];
        p1.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
        println!(
            "p1 uncompressed: {:?}",
            hex::encode(uncompressed_bytes.clone())
        );
        println!("p1 uncompressed: {:?}", uncompressed_bytes.clone());
        let p3 = G1Affine::deserialize_uncompressed::<&[u8]>(uncompressed_bytes.as_ref()).unwrap();
        assert_eq!(p3.is_on_curve(), true);
        assert_eq!(p1, p3);
    }

    #[test]
    fn test_ganrk_flag_to_ark_flag() {
        let b: u8 = 255;

        let gnark_positive = b & !GNARK_MASK | GNARK_COMPRESSED_POSTIVE;
        let ark_positive = gnark_flag_to_ark_flag(gnark_positive);
        assert_eq!(ark_positive & ARK_MASK, ARK_COMPRESSED_POSTIVE);
        assert_eq!(ark_positive & !ARK_MASK, 63);
        // println!("gnark_positive {:?}, ark_positive: {:?}", gnark_positive, ark_positive);

        let gnark_negative = b & !GNARK_MASK | GNARK_COMPRESSED_NEGATIVE;
        let ark_negative = gnark_flag_to_ark_flag(gnark_negative);
        assert_eq!(ark_negative & ARK_MASK, ARK_COMPRESSED_NEGATIVE);
        assert_eq!(ark_negative & !ARK_MASK, 63);
        // println!("gnark_negative {:?},ark_negative: {:?}", gnark_negative, ark_negative);

        let gnark_infinity = b & !GNARK_MASK | GNARK_COMPRESSED_INFINITY;
        let ark_infinity = gnark_flag_to_ark_flag(gnark_infinity);
        assert_eq!(ark_infinity & ARK_MASK, ARK_COMPRESSED_INFINITY);
        assert_eq!(ark_infinity & !ARK_MASK, 63);
        // println!("gnark_infinity {:?},ark_infinity: {:?}", gnark_infinity, ark_infinity);
    }

    #[test]
    #[should_panic(expected = "Unexpected gnark_flag value")]
    fn test_gnark_flag_to_ark_flag_panic() {
        let b: u8 = 255;

        let ganrk_invalid = b & !GNARK_MASK;
        gnark_flag_to_ark_flag(ganrk_invalid);
    }

    #[test]
    fn test_g1point_gnark_compressed_x_to_ark_compressed_x() {
        {
            let xs = String::from("897c8a80aeec562a6b4abc29a019eec113192cb6c84f59beda5ddf3ce9c78ed8");
            let ganrk_x_bytes_vec = hex::decode(&xs).unwrap();

            let ark_x_bytes_vec = ganrk_commpressed_x_to_ark_commpressed_x(&ganrk_x_bytes_vec);
            assert_eq!(
                "d88ec7e93cdf5ddabe594fc8b62c1913c1ee19a029bc4a6b2a56ecae808a7c09",
                hex::encode(ark_x_bytes_vec.clone())
            );

            let p1 = G1Affine::deserialize_compressed::<&[u8]>(ark_x_bytes_vec.as_ref()).unwrap();
            assert_eq!(p1.is_on_curve(), true);

            let mut compressed = vec![];
            p1.serialize_compressed(&mut compressed).unwrap();
            println!("compressed: {:?}", hex::encode(compressed.clone()));
            assert_eq!("d88ec7e93cdf5ddabe594fc8b62c1913c1ee19a029bc4a6b2a56ecae808a7c09", hex::encode(compressed));
        }


        {
            let xs = String::from("d934a10bcf7f1b4a365e8be1c1063fe8f919f03021c2ffe4f80b29267ec93e5b");
            let ganrk_x_bytes_vec = hex::decode(&xs).unwrap();

            let ark_x_bytes_vec = ganrk_commpressed_x_to_ark_commpressed_x(&ganrk_x_bytes_vec);
            assert_eq!(
                "5b3ec97e26290bf8e4ffc22130f019f9e83f06c1e18b5e364a1b7fcf0ba13499",
                hex::encode(ark_x_bytes_vec.clone())
            );

            let p1 = G1Affine::deserialize_compressed::<&[u8]>(ark_x_bytes_vec.as_ref()).unwrap();
            assert_eq!(p1.is_on_curve(), true);

            let mut compressed = vec![];
            p1.serialize_compressed(&mut compressed).unwrap();
            println!("compressed: {:?}", hex::encode(compressed.clone()));
            assert_eq!("5b3ec97e26290bf8e4ffc22130f019f9e83f06c1e18b5e364a1b7fcf0ba13499", hex::encode(compressed));
        }

    }


    #[test]
    fn test_g2point_gnark_compressed_x_to_ark_compressed_x() {
        //bn254 g2 generator
        //998e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed, x:10857046999023057135944570762232829481370756359578518086990519993285655852781+11559732032986387107991004021392285783925812861821192530917403151452391805634*u, y:8495653923123431417604973247489272438418190587263600148770280649306958101930+4082367875863433681332203403145435568316851327593401208105741076214120093531*u
        let xs = String::from("998e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed");
        let ganrk_x_bytes_vec = hex::decode(&xs).unwrap();

        let ark_x_bytes_vec = ganrk_commpressed_x_to_ark_commpressed_x(&ganrk_x_bytes_vec);
        assert_eq!("edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19", hex::encode(ark_x_bytes_vec.clone()));

        let p1 = G2Affine::deserialize_compressed::<&[u8]>(ark_x_bytes_vec.as_ref()).unwrap();
        assert_eq!(p1.is_on_curve(), true);
        assert_eq!(p1, G2Affine::generator());

        let mut compressed = vec![];
        p1.serialize_compressed(&mut compressed).unwrap();
        // println!("compressed: {:?}", hex::encode(compressed.clone()));

        let mut x_compressed = vec![];
        p1.x()
            .unwrap()
            .serialize_compressed(&mut x_compressed)
            .unwrap();
        // println!("x compressed: {:?}", hex::encode(x_compressed.clone()));
        assert_eq!(x_compressed, compressed);

        assert_eq!(
            "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            p1.x().unwrap().c0.into_bigint().to_string()
        );
        assert_eq!(
            "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            p1.x().unwrap().c1.into_bigint().to_string()
        );
        assert_eq!(
            "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            p1.y().unwrap().c0.into_bigint().to_string()
        );
        assert_eq!(
            "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            p1.y().unwrap().c1.into_bigint().to_string()
        );
    }

    
    //"test_gnark_compressed_x_to_g1_point_to_gnark_uncompressed_bytes"  checks "ganrk compressed bytes"  -> "ark g1 point" -> "ganrk uncompressed bytes" 
    #[test]
    fn test_gnark_compressed_x_to_g1_point_to_gnark_uncompressed_bytes() {
        let input :Vec<Vec<&str>> = vec![
            vec![
                "897c8a80aeec562a6b4abc29a019eec113192cb6c84f59beda5ddf3ce9c78ed8",
                "4290860583572509627464577404645192107154708027355374043132381799101413953240",
                "147959282368291695976176804501251963707900737478195501167604460443637555718",
                "097c8a80aeec562a6b4abc29a019eec113192cb6c84f59beda5ddf3ce9c78ed80053bdf2cd5794fcc2b27919f84908cffcc0a897b32dce1324fc9ef61c26a206"
            ],

            vec![
                "9ae06afadef57a6e844f9a0fe62711abfa53d9132e4656fb3002d8c9ac0e7e64",
                "12156646154255023419676968282873543092370571330830097518462231970884835245668",
                "10610570566006993286673885485482428354276799132634670696393883549563563114542",
                "1ae06afadef57a6e844f9a0fe62711abfa53d9132e4656fb3002d8c9ac0e7e6417755ec00eaf2e18a5c0aee47f6c8c5bfb57564edad465fbc67c3367bf25802e"
                ],

            vec![
                "a18e3b9acf719e44cd60e7dfa40090b17d5953b3ad2690caa81f8cdd3db06ef7",
                "15177627663158952982807952306112893181866930449069439546056404874076953276151",
                "7675477345262433228488919372071568693727865880846220056364591300950269074530",
                "218e3b9acf719e44cd60e7dfa40090b17d5953b3ad2690caa81f8cdd3db06ef710f82a8dc8fbe7ec03c2c5dd52d35592989ec5d8ab6f9c0fe348fa4299539c62",
            ],

            vec![
                "d934a10bcf7f1b4a365e8be1c1063fe8f919f03021c2ffe4f80b29267ec93e5b",
                "11400808761523315312150391456108391824881486602921942128186819160643908222555",
                "14980586638432349385711836194138269947324138751709684934997845089363323103380",
                "1934a10bcf7f1b4a365e8be1c1063fe8f919f03021c2ffe4f80b29267ec93e5b211eb62900755b59dbf5639c244c35d67b6ce817aa42ca6cc6c6bed00089a894",
            ],

            vec![
                "d61ef0d2f2254d8d1ee93abe691d96323a8ab0dc5a1c2934037da03eac86cc05",
                "10005550186988162032048721443837032170272580553919687041827156787249065413637",
                "16376521367536559124828317734052134974913043704637475549164230961661511192633",
                "161ef0d2f2254d8d1ee93abe691d96323a8ab0dc5a1c2934037da03eac86cc052434c859d553887c5913ab671095676644a40e7ee5f2e54704365d3afb4bd039",
            ],
            vec![
                "8fb7db4e47b0995390599785192ba54e65829b07971e4ed36a01c414ee4e43c8",
                "7109539334479048624182317947995219539766831889007440199000543598409453290440",
                "4413846126710758906053453389321321603238671860249222822443566118923545149251",
                "0fb7db4e47b0995390599785192ba54e65829b07971e4ed36a01c414ee4e43c809c225fc038a9fbdfbfa7e34d012de4f3d6e3f9532cd186f3f39d8392054ff43"
            ],
            vec![
                "cd12a1664917226af9d25a901300586a7cac148ff581e9aa384fd425dc0be54d",
                "5912984217522181547321919931909111727452726340902940929497961681194012370253",
                "12767209704703130149983783570663400149257021280411218688944404931158804890156",
                "0d12a1664917226af9d25a901300586a7cac148ff581e9aa384fd425dc0be54d1c39fc0fa3549d71805220ab6cbb191a0c7ed1d510423363b6f510b977cd822c",
            ],
            vec![
                "c311ece454bb1e18c2a378c2d60e27ff82fa2a8ff8517c8352ce97b6d6bac30c",
                "1388609913779922583900459447884538405377718501450649920562588669940227293964",
                "12508873470735545293429820256324879951329215393474081826349261773964943369183",
                "0311ece454bb1e18c2a378c2d60e27ff82fa2a8ff8517c8352ce97b6d6bac30c1ba7c5802881c25823e5c10598a463d72818e514892023be4612dc6c047923df",
            ],
            vec![
                "d0d698747655e00f02190b3ef20dca8317e1985a877a28c50fc186ef888eb5d1",
                "7616163054455539452736620785012755174875059344681555096751105810121928652241",
                "14562734697196328782354506992978459207419803494491793716092475567906547331970",
                "10d698747655e00f02190b3ef20dca8317e1985a877a28c50fc186ef888eb5d12032373b18c12a213f66863525b99a6040b5ddc95582172c32a8fc76c8c47382",
            ],
            vec![
                "abf34c316357989d9b9b20547e14e9873ed4a80572a8b63a5c8f984ca4db5f64",
                "19879322190043296708582919785736258573140911595006192878624239043535181668196",
                "10449011793699482830321119601220150320160275840828850796168644595904516908791",
                "2bf34c316357989d9b9b20547e14e9873ed4a80572a8b63a5c8f984ca4db5f641719ee5c23510962aa1d3830a077d5317e5fa90f703cacac83f492145d86e6f7",
            ],
            vec![
                "a9b3336af06fe046fbc3aaf7e29c5dd98d6e62d9bf307e661b1f5d964d9883ff",
                "18861447288648258906634345342100325158933534415574228792951256245503008474111",
                "3163695761448065902054863622200721956109485238216706705093442391973155411044",
                "29b3336af06fe046fbc3aaf7e29c5dd98d6e62d9bf307e661b1f5d964d9883ff06fe969dc5cda1364246d8ee1646c54eadc9bd37c51ba7b330518699035d9464",
            ],
            vec![
                "a25c32944760bed330a03b4b21399c7b3cb0cc4fe5ab34bfffbe77b5e2bcce6f",
                "15541535866697086291231194455468647410411301339620703478171306216787130764911",
                "5174345319566430319092950513106968068288626244842479652923360805975555509851",
                "225c32944760bed330a03b4b21399c7b3cb0cc4fe5ab34bfffbe77b5e2bcce6f0b70935ed9e5eebed1fb7509119f0abe76c633779fc42990d1410b7b59df0e5b",
            ],
            vec![
                "ce55b5c3bc4cb98229dc81d4f52a4af3e3fb4de67d750bb5b9bb7c640432ee0f",
                "6483816373780534812527109172946783617870137517548716896634445093989680082447",
                "16873421593701870459631693102122369604746493025952787281783196599501713638138",
                "0e55b5c3bc4cb98229dc81d4f52a4af3e3fb4de67d750bb5b9bb7c640432ee0f254e04a795c32b649dc71d7578bc921c0ecc0936c0e5971a8d02f1a9d22502fa",
            ],
            vec![
                "9e6302260081e9b2bd900965001d614ef48e4988debdf4344693e96a14bcd604",
                "13744318144935161693190450953918669878086347740304012988199673721994918811140",
                "8017544429189956401020077156363607526684643606184425783179080668089754142490",
                "1e6302260081e9b2bd900965001d614ef48e4988debdf4344693e96a14bcd60411b9c4f31a03268812cb88e1a49d9509c095abb29858963cad1f49adc1cd471a",
            ],
            vec![
                "dd6f11900c7bb689f8c689d52480a5e63696dc759cb5eb6a9a715181ed14ca4f",
                "13313313846339981526633928209142145374688569890311291351000148367537832512079",
                "20022614083977039352161292715590359101776858046014637921326972925925505082084",
                "1d6f11900c7bb689f8c689d52480a5e63696dc759cb5eb6a9a715181ed14ca4f2c4465e1219bb67cea3e423ca8b9bffbd36768845cec8512ae3fefd85a77a2e4",
            ],
            vec![
                "955ac825aab4b66ff5a82115888871efa5a3c79c49799beb1cd7997d46f3ae87",
                "9658967420843463997073473369217766259251647053822486475370453919130992225927",
                "3806338303893399425410339875867392698853877980195854963607733549053042773226",
                "155ac825aab4b66ff5a82115888871efa5a3c79c49799beb1cd7997d46f3ae87086a4fa67be674fca3ff974d70896a226c6cbbe5f8405624886fc8b353ec4cea",
            ],
            vec![
                "998c557e5aa8607f8c98cd3be948a1636b54af253c125e5dc4a23bb65b577365",
                "11555769858590763282646543957253077115202963431416684734763398411247630644069",
                "7690460246604018776678897640066239189831105958277038558087530903350136488067",
                "198c557e5aa8607f8c98cd3be948a1636b54af253c125e5dc4a23bb65b5773651100a5707bb3793a6d9edf8b92e2197b002054a7f03fa502ec0e26744caf4083",
            ],
            vec![
                "d4e1623fba1a1c7a72f7aa883d0ec93c08fde7028ce895f184711002f9d21e90",
                "9444475650457917540229069915672437841828921609201717016890970255475141123728",
                "13924535695077918174914475852137629336324009285381430712469938824352623635154",
                "14e1623fba1a1c7a72f7aa883d0ec93c08fde7028ce895f184711002f9d21e901ec9020674dce5b1db1d1b10c61d0384450af6026855ce1f3b2d346819d22ad2",
            ],
            vec![
                "8ab931bc73d9aba75bd4793c84e93ab11d461bd13813de70f6eca474e96aa306",
                "4850338459058089147703991768276496132962089856653120749127982533251114377990",
                "1444583867675554940376321329106704621814680904092298607083160694611705671053",
                "0ab931bc73d9aba75bd4793c84e93ab11d461bd13813de70f6eca474e96aa30603319b01abf1e7a10ee8f0c9970006655663f1c03c84836fc6b49cf2ccd52d8d",
            ],
            vec![
                "efdb5ddfca8ebc04c952f1cf3b33f16375332fd6d53df220effe5ff7ee782415",
                "21646291286410145181980515654580999613597211554159218773972885129071575966741",
                "16912486491368578605495096826785097379083119983946176306455419259615770226981",
                "2fdb5ddfca8ebc04c952f1cf3b33f16375332fd6d53df220effe5ff7ee782415256420cd2c09ac1432c95781ee6225f743938eb42e8bb1b1c88f3c7a90a2b125",
            ],
            vec![
                "ab7f1439812a6ed0a8fb41ccfd0002c1b56939fb04b351d19c3a7c4bf8e11401",
                "19673981651553946844833427515366261405271850429848033446086872503864581493761",
                "5225687683774711331131527010261691238757047655259802488949717930504233572759",
                "2b7f1439812a6ed0a8fb41ccfd0002c1b56939fb04b351d19c3a7c4bf8e114010b8da268fb77232013080aad3513f52e8c0e939297236efc0710a3ba26f65997",
            ],
            vec![
                "c9344b1ad661953f2a4286dea46580067f2d8ab30f61421189f60f2b521a6d6f",
                "4163210039129469851547431306883056469073058617963481854877612324767496039791",
                "16310619230803877614718320258219543513649758714385649489454125794497183061526",
                "09344b1ad661953f2a4286dea46580067f2d8ab30f61421189f60f2b521a6d6f240f7bbbb9640b633b34d6605b2f695db2f17ddd9c77008d268d6e076b439616",
            ],
            vec![
                "8c23cf5f37d66766280038bf754816eae6b9ac11674a3dba1f18039e21dc5127",
                "5491025058835535829481168677776787492644057312799263080707109445871815381287",
                "1067152714132902145414979520121934461401429562937981854848997489821648352208",
                "0c23cf5f37d66766280038bf754816eae6b9ac11674a3dba1f18039e21dc5127025bfcae1c1ed35b5fbbdbaea8ad71ae4194714f82fab2f982579afdf86af3d0",
            ],
            vec![
                "a4f09de230602fd14bbc31434cbb7408531f4ad77fb028352e3c7eb3e5d6b258",
                "16708395516763354064424698696391292198118222372999035995160323169280733917784",
                "10018582827580318238325617745960677648234642777782529788529217292449528764769",
                "24f09de230602fd14bbc31434cbb7408531f4ad77fb028352e3c7eb3e5d6b2581626512273cb6fafa3c862e4c7d361d9b581e8ccfbec3ec2f8755169adad5961",
            ],
            vec![
                "cfb32ff6d0ee5a0671c5f8a534ed2db7dd752ef4ca9f7c00d5fd49e9d91a3801",
                "7101289389572514749247485709715397842062408538543057283140535385994745755649",
                "15778053196969410359247369167907963465491609581591289587555720543902799054005",
                "0fb32ff6d0ee5a0671c5f8a534ed2db7dd752ef4ca9f7c00d5fd49e9d91a380122e20fc7a406670b13eaa65b82ee52ae1ed2fa8e3761a7d349c11989a31544b5",
            ],
            vec![
                "d4fbb5905302ac95deed78ef679abfef0bfd4a296d2a9ff5f4d1519a019e8ed8",
                "9490988691987811690796394715817941247263748794389228161213712738399446535896",
                "19928091924393372252077692383493373435073336376633629217105199163078447599151",
                "14fbb5905302ac95deed78ef679abfef0bfd4a296d2a9ff5f4d1519a019e8ed82c0ee67b5fce578ee700de213e7f2467c2488d022ee6b451599b00e159e20e2f",
            ],
            vec![
                "a7022a370507a113c0d58f142b8b592f66fbb02c94bd8f099c60c1c86b7ae438",
                "17644026145550277744519507703253841873934091334117783574154265319137647191096",
                "10668466420867175741369437409156504563991959415309467739709593788736162862759",
                "27022a370507a113c0d58f142b8b592f66fbb02c94bd8f099c60c1c86b7ae43817962354aab534c2e254f11bae7e4e85dd24e4ea58c8b1d09161e41a5d7196a7",
            ],
            vec![
                "9f1a5d277594d28784f1903862436fbb4bae4a05ff3936c6f764ae6b10e968d5",
                "14068279255996427674949270013194292364149894868004128622262355087871684733141",
                "7451128128318131936762233515197157410571880768995847921686416842764558274929",
                "1f1a5d277594d28784f1903862436fbb4bae4a05ff3936c6f764ae6b10e968d510793066d4c7fedb02fa89b0e9d6c9312d86030188bdfb7f1b3b18530f481171",
            ],
            vec![
                "9891e7ba820a2046b51a4ba10398ae45658d576342b6b14c7126efe19cd116a2",
                "11113300522042211303164157957187661991242506026662495272227402097101265508002",
                "4979503913346007996340789014441625770019107535564486684687820685132982180343",
                "1891e7ba820a2046b51a4ba10398ae45658d576342b6b14c7126efe19cd116a20b024ca16d73fb0b7da9d720d4d72e875ac3653da24f34045b0853cd4eb4d9f7",
            ],
            vec![
                "96a66db015ad98f19cf127d6c5fd9a7eb2bdb9ac675634c1229087fdfb859f07",
                "10244936319170457901245688825392087797895179376248208704316032770426859265799",
                "9213038207046178664381095142582664795289613466472997112874165243514571759847",
                "16a66db015ad98f19cf127d6c5fd9a7eb2bdb9ac675634c1229087fdfb859f07145e6513d747c70841a11d1f9692522e9a417fdcff8ba6ff6eb6c5af01e4a0e7",
            ],
            vec![
                "c9f87d71b58dda7b87e3dc431cf61bd61261f9a9aa8cbb6ad357258d18c193e9",
                "4509859493201638933155901640116864347392610614785994755132661227889769944041",
                "15008468452030836280846267318616752992394752360339436166296591116047807314349",
                "09f87d71b58dda7b87e3dc431cf61bd61261f9a9aa8cbb6ad357258d18c193e9212e7dfaf25b856646e3a85223f1106c1f7bbc5a1c18eb22e02d91b935f679ad",
            ],
            vec![
                "cb2a5d665f3fea654bd1ac625974c7dc4778222f70cd9a72aed0218bb6a5398d",
                "5050293533492395050386005723318966310059138596920688843210927167186751797645",
                "16148153065389174850473751790365478880862917234068053967046896824302796311318",
                "0b2a5d665f3fea654bd1ac625974c7dc4778222f70cd9a72aed0218bb6a5398d23b387deb94d3a507525aa2a89d624e604cee7e4d47a0e5e58f03bd821748b16",
            ],
            vec![
                "9b408dd9901eff58e7397090e017da837856b105768c11cf026f65f18eb34bea",
                "12326504135615054936063934945181170345330148188270731226213072075264946818026",
                "10577006410852743690076474721031331785218309918367053914924722095460093777739",
                "1b408dd9901eff58e7397090e017da837856b105768c11cf026f65f18eb34bea17625f9c59968264cef0e810a26e09dc6057bcbb924aab5bde3f6e9a31ffd74b",
            ],
            vec![
                "e26df64543ecb1cce20401fabb369d0693837408bb4af39e614938dd3a2422fa",
                "15572922878882825633483213921667698085698316642522077472653231852031802876666",
                "17098079040282229312359299614838067282292223320815471456974451471490771894132",
                "226df64543ecb1cce20401fabb369d0693837408bb4af39e614938dd3a2422fa25cd2b77695b0809a08f2ea0c65fb2ee8343977ca32657986832bbc90424bf74",
            ],
            vec![
                "ed59ff307e6bbd6ba1ac884fec0490235acb35046b02b1ce60daa57df34655f2",
                "20513088827721805683180038954770278191025460074525065783794236774437561456114",
                "20339086310583852304300441321551179882784677397535786913435123599134666314700",
                "2d59ff307e6bbd6ba1ac884fec0490235acb35046b02b1ce60daa57df34655f22cf783d06d013384c5b8c3098695a03b1a09e11dd7050ba6beef274ee5e0d3cc",
            ],
            vec![
                "a0e0d4b01cd97734121befe8a10314cbed629b067be8cc84e81e3d862c059a94",
                "14871252815389219877243440073667023061667689598059517702830380490645376965268",
                "6427726117762068082502345819817179435050290368333210123934235967319376755689",
                "20e0d4b01cd97734121befe8a10314cbed629b067be8cc84e81e3d862c059a940e35f6cc82663b608733ea42d074298ddbd2558d7248ec645aee896561c57be9",
            ],
            vec![
                "d1cceb8a11b7f114d0ce2044e638d6cbec97cc977ca525e248d7bbed8ff8cc8c",
                "8051380859860433049453348833151857291472458093389236650740269390915442363532",
                "20258577904776240037536936948280325378594596406749408042353891315072728177047",
                "11cceb8a11b7f114d0ce2044e638d6cbec97cc977ca525e248d7bbed8ff8cc8c2cc9f2e1af8e2df02a36f14d02987065a071dd85384d76751812585b4c0e1997",
            ],
            vec![
                "abeb4162c5a746cf0b3d9c74c09d7cffbca95d8aab3262143b363d08ffdd883b",
                "19865112825706024844186600815068351228044155853897897136120467965707909171259",
                "487367251174680962210963824584695963009500685198911166202270811565068879252",
                "2beb4162c5a746cf0b3d9c74c09d7cffbca95d8aab3262143b363d08ffdd883b0113d7100e980acf1b6d5e86fb9f8bcd2a8332661d598b1cb961c8e010a78594",
            ],
            vec![
                "849b43b273679931822f439c899aab642e271fbb1ed8e01343057e62f3da2236",
                "2083579917402988301692321245161200246415355188444520833137486646314192740918",
                "9357194365971837591584259920168735767090423181296588119460987250992011941677",
                "049b43b273679931822f439c899aab642e271fbb1ed8e01343057e62f3da223614affbfcf453d67622227bede6ac4e1c7e5d0f01068bea82984acad67b16172d",
            ],
            vec![
                "e100deb91201f58800586071201af38837ea48caefe3ca814fa9aa381ea77f61",
                "14927861180423338924037373751426522313037245423349135324363325279803737079649",
                "21308415614219333463038157993891585530568622638027893863695932104910748788692",
                "2100deb91201f58800586071201af38837ea48caefe3ca814fa9aa381ea77f612f1c22c693a02598c6a01dc13b38ce0e2023784b4950558fc95eb42dd57027d4",
            ],
            vec![
                "d54c0549eb3fa1584a5a56a2f59190b7241d199afac160e6ffe03f99ee46c32e",
                "9632886698754156529825733861546595940869856422761696491573111557520921903918",
                "17726089211653005056394112802971251267069340159033698669600626581771379020690",
                "154c0549eb3fa1584a5a56a2f59190b7241d199afac160e6ffe03f99ee46c32e27309c6750a20d294ef3c608e6f27d977cd3c13159073925b93ddc4cde481392",
            ],
            vec![
                "ea2c9aa070c28aa3bbec683dcf2a22f24f5292d67f01a1db38f7562f61d00da6",
                "19075948105751316136240955897896481549005337875743687669562122150897007988134",
                "16769857563639304933161021424288772151488366304727479215153777724093513037468",
                "2a2c9aa070c28aa3bbec683dcf2a22f24f5292d67f01a1db38f7562f61d00da62513672c364785cf0b245f2d239481eea318e45716da497e9fb6428d613f769c",
            ],
            vec![
                "c147fd06fb1bc75ddc990af3257175c12e866c7687c2276766b3e9f8fb0089d3",
                "579505320212762425735881865226607024753196548216059657745815150457291573715",
                "21192636644898461092213758635836200065219098403495160987430895125182192828334",
                "0147fd06fb1bc75ddc990af3257175c12e866c7687c2276766b3e9f8fb0089d32eda9b75ece7ad1438bdc65de81130804448d2173f2ce3425a131050c6f43fae",
            ],
            vec![
                "e4ec006089c4e743a3c04440a528e7b0fc9c47c9d3f827868dc39eb022c47f65",
                "16700241058948954038853025889765270762927358564672586074368818957391638069093",
                "18037830251620119344296599345768437474870634883908239282811761339810030390774",
                "24ec006089c4e743a3c04440a528e7b0fc9c47c9d3f827868dc39eb022c47f6527e10cd524c63c762c921ae47f1827830bc6b0881c1b9e626d45369f77458df6",
            ],
            vec![
                "e7c2b3eaea06f9c9d5c99f65e9165c4197233df3f1136ab643268135b03a522e",
                "17984211171183937232457353950027878763756910657988933281146516560430258344494",
                "13209548080179662994674278564018056272656150008587256009767116978569835339671",
                "27c2b3eaea06f9c9d5c99f65e9165c4197233df3f1136ab643268135b03a522e1d3456d9de379fa686c180bc8013fb52e989acbc9d48a98804007912059a5f97",
            ],
            vec![
                "e9e390237ee2209ab0dcbb7c17006910d189ee6d5683bba51ffbfdac543c8c6e",
                "18946895884053058508334069124342243674223835680504415921065654816658840915054",
                "14135696183930184670319737589747119120223570964279541269832761925625709964456",
                "29e390237ee2209ab0dcbb7c17006910d189ee6d5683bba51ffbfdac543c8c6e1f4085404bfcc1dd65b2ba0b17d1ef173fa4bea7cfcc3e1a1aceadf7e1d5aca8",
            ],
            vec![
                "cd72cc714fd646288df54a3f7d4945e15dfd611bcb0b3571712a45e31f173d05",
                "6082898608103735801321317359942901231204066663709182555254515597881655115013",
                "19829644683116579624010162991267763422459581720461023270679746228069425623443",
                "0d72cc714fd646288df54a3f7d4945e15dfd611bcb0b3571712a45e31f173d052bd72e603ee10b4dfebb2ae281872c9fdae83f9e5c09585c46ea4be8bd863193",
            ],
            vec![
                "a94fc19db5526ab2fed3e5440c5872446ae477c3143f3567bd6b035a32e74c0f",
                "18685743998883400701243887050493594486560297074943858249916186714636609342479",
                "322840156185117108609925249519487847188962456830902308172916825601921191478",
                "294fc19db5526ab2fed3e5440c5872446ae477c3143f3567bd6b035a32e74c0f00b6b896ee1b8217cfcd43f1f044e09a8d3f3b4f437f03ae7024df9ec92f0e36",
            ],
            vec![
                "981c2abf328c54aa2ed49dac22798da8367fbe49dc4a5a83810633abe371bc68",
                "10905275111831910005624780809264263886118289956115314391949237391383619288168",
                "1521066763227176018684520131445292724380846461426629520183069078387711838628",
                "181c2abf328c54aa2ed49dac22798da8367fbe49dc4a5a83810633abe371bc68035ce4adf00c1738b445adeae8d6ffa708f79274eb412e3d24f31f9e3bb489a4",
            ],
            vec![
                "da9fcfd254177b064dabc88b5ae109e06645b8407be438f57ede2b8c0a84fd20",
                "12042497078403166798758471312582296835645204997925211816726949269241434799392",
                "20792989959392256743038140061344614760183269738366891842623727540117733781411",
                "1a9fcfd254177b064dabc88b5ae109e06645b8407be438f57ede2b8c0a84fd202df86a4e7c4ffd6bf912b72b1129226d5fa36808e1dec922da4c5f4606fa2fa3",
            ],
            vec![
                "a60222dfec201018987e417294e91c330d1a9c4326fc36b67c47678e8b534a68",
                "17191662636604467916243269221461641857967120679749846239769453682400364284520",
                "871596776800465699414059010192931117303728440295216780458445362032383340545",
                "260222dfec201018987e417294e91c330d1a9c4326fc36b67c47678e8b534a6801ed4e6941183e8e7365fc7af853c923a2d015665a4f6f408cfb08e1a10fb001",
            ],
            vec![
                "8c3fd723e29362bb74008949a0bd6d34127f834d61fd85694be5a0af7371d95b",
                "5540550391004137060896532454059739069653611284384083993215886371114598914395",
                "262373690529415321785885421900032233169566436878239425780531802912764176247",
                "0c3fd723e29362bb74008949a0bd6d34127f834d61fd85694be5a0af7371d95b00947f8d11208844f1a7ad54b5628df7106603a916c3b2a4abf8daad1523a777",
            ],
            vec![
                "d022ab70a7cbc52a2503d74a6e7f51fcc9267dc53262d840f05633ebedc0dfde",
                "7298261613345034084732025569481528479978652667074434594152712664126247198686",
                "13395622358307626583684433808820510939691601922309751018482236272127382180084",
                "1022ab70a7cbc52a2503d74a6e7f51fcc9267dc53262d840f05633ebedc0dfde1d9da7506fecb9b85d84b5006e9da7bd2fd710385de6c6b7f65284de2778d0f4",
            ],
            vec![
                "ce74f0fb55b2f204a6217ca42b1e3025ee78b6af0f00d1684ab1d8f9082483d4",
                "6538997334775023862394561273402105006321855066995800173747430610383703147476",
                "19302614919898333769777039322763951981075044747701249635198355066692704823372",
                "0e74f0fb55b2f204a6217ca42b1e3025ee78b6af0f00d1684ab1d8f9082483d42aace493da355ee8f9e8f9b6ca254203d3d9c83d04812e4487f61462e976684c",
            ],
            vec![
                "c2c0086ab768ba3b768f1e5182e4f5c3ae3c7172233c645687855fdecd31cc83",
                "1243918424644335368073369839606725362144714884509485329213749881245778693251",
                "19658218267379285937622527860215114746708707357337498310882970019952223348755",
                "02c0086ab768ba3b768f1e5182e4f5c3ae3c7172233c645687855fdecd31cc832b76284116d533e0cd81cc4e3bfc4b092554242b0e5a502abcb7a48dfb986813",
            ],
            vec![
                "90f1239e7d06a097e08119917f6f5013085749bbd27a560ca633d618a2bdfba5",
                "7663061553904326695776311992718786429615318081909696503090206166520268979109",
                "7328967761344556390880159816253133876284913512223127032836441949720721325845",
                "10f1239e7d06a097e08119917f6f5013085749bbd27a560ca633d618a2bdfba510340c7afc56366dd8787370293164b36bd998937f506c79513164335dbd7f15",
            ],
            vec![
                "a6eaf2217793d6b5f4e7790e3976c2f286e96577c17ecd6fdc7653b3323bcf6d",
                "17603001584209408051658260493516231014748598664236966289667834896254605447021",
                "5440654969555880032133289257097540488923396761037241413743846679384497296557",
                "26eaf2217793d6b5f4e7790e3976c2f286e96577c17ecd6fdc7653b3323bcf6d0c074d34c4b8faa017a866a9e5f2e00ae47a9736f359974ff5c9160f63f794ad",
            ],
            vec![
                "d9aeb32420dfc9c093518f155af643249274745385085323a4c37f916b7060c2",
                "11616488990469308526848738966322423004477968995131160962203072409192977424578",
                "18176030844620255149179276986495573200872639858232864307987636607401041494281",
                "19aeb32420dfc9c093518f155af643249274745385085323a4c37f916b7060c2282f44d60a1c7fedc358b233e5ab418c485dd8351b5429bb13230ac168e28109",
            ],
            vec![
                "af42f0e27b1878c135186d4514c19f96a2d99c5564d6dd20717c2df63a6589e0",
                "21376978314723549078576614153368855436846090523963050159558689636779179739616",
                "3255796666647592701034825637247998495248396106541991756345121475535616423101",
                "2f42f0e27b1878c135186d4514c19f96a2d99c5564d6dd20717c2df63a6589e00732b732369236ce2b0d6a11a6c139bb87202fa5fb6b640259b929dc329534bd",
            ],
            vec![
                "a744a7bbbdc72c8048c08c9fe3c752ed2a25395df354b7a25447de769893388d",
                "17761504348288218549904334919465339906863588253377546641711963850730521180301",
                "3975222010704740305076402840808486392933293457462397857304520144966363127687",
                "2744a7bbbdc72c8048c08c9fe3c752ed2a25395df354b7a25447de769893388d08c9e55b53151497a37ba978cca5e3ffc8e31a9671f3c6cb5b8bc32ff9281f87",
            ],
            vec![
                "ce500a472e8baba79b2fdb6189b2123a3d8bcd68cc5028d9c71dd15390356e05",
                "6473798581869503995533775133798921993453989999591952097698378177744836324869",
                "13584038641839168851190850211646922388594138055280511841898231854754587462376",
                "0e500a472e8baba79b2fdb6189b2123a3d8bcd68cc5028d9c71dd15390356e051e084b1cd09a4e22ea5f8b8573c65dd96509082ee66054be69c60eaf2613cae8",
            ],
            vec![
                "8d9c285ba2fd593e878164b5095fbac99f6b68411fb2f9160c28a3627f47edec",
                "6155973714061722161073588161454723937151765225306487162699537738232209337836",
                "9623372823876366796050251281391437715726911899861611493740488270339219730905",
                "0d9c285ba2fd593e878164b5095fbac99f6b68411fb2f9160c28a3627f47edec1546a2d0afd262dd01f80fb0f1201bf102d87e437a8644ce4be295bb3dbd31d9",
            ],
            vec![
                "cc57c8dcfbc0a0356712fe38b5810042139b673d6f4c49f5d2ee5c021e538124",
                "5582856184605167855911995572294905414340454994400952197270355039870357045540",
                "17908806332326729077184515842514025703851224752153847206756468916543148688452",
                "0c57c8dcfbc0a0356712fe38b5810042139b673d6f4c49f5d2ee5c021e53812427980671fe4cef67f42609f20badbb5afcb3eadb5d8c086954df500a5ebe8444",
            ],
            vec![
                "d9d6c865f78803f45e868f55191c99622828c95441e3cb65beacde8977bc06e8",
                "11687309584736295002663299784234586846346047730439418807470138202083827648232",
                "17203355563710658931613019178692470507306841312830560772744214536555219003204",
                "19d6c865f78803f45e868f55191c99622828c95441e3cb65beacde8977bc06e82608c112b19bba6e89d18e356edc200ab4b3cfc8e23761538eb4d1ee724a2744",
            ],
            vec![
                "d066695f6b00137aaf8e76cc2efb777e25f73561161dc9050ad384dc07ea42b9",
                "7417951233769450314568648525323951277611646480809762441868220830234268287673",
                "21758608515947036137808405617666357299985220855024668544075293397231986358149",
                "1066695f6b00137aaf8e76cc2efb777e25f73561161dc9050ad384dc07ea42b9301aef9d60a422edd933878bb581ce417431beff4815dd111347fe1f18ed3785",
            ],
            vec![
                "a186ba4a7f6266d9e88c067015d893c90de34471cf3c35c626cbea02ec142476",
                "15164367243199791909570425268267616894453076053892232630979272667538044232822",
                "1545488723805141852797004331333690908748637147399347347121650270828596196639",
                "2186ba4a7f6266d9e88c067015d893c90de34471cf3c35c626cbea02ec142476036ab732cd33179ca61db82083ddc5870a8c97dec912cb5019c8232a066a751f",
            ],
            vec![
                "84586872f42ee1c5d6630da67d7c78aa932ede260c57dc5d12178c48d82d4896",
                "1965454816803034920746356350527442060801822442607898329096163453431284844694",
                "6679383344872851415176404035259525383812625731573903569058833045890030130448",
                "04586872f42ee1c5d6630da67d7c78aa932ede260c57dc5d12178c48d82d48960ec465a1db23ccf49eb5d5646b910ecfb15ce7b5b44ddc4eaa2f1a6772205510",
            ],
            vec![
                "8ec50c81b6f67d8c75191654083556e295c62e834f70407527f895cdb0143c7c",
                "6680535069984590062226102588731397095659553447675705272085841810956007783548",
                "1731886729458121635366073884687782071139211435799290844895507087108153704865",
                "0ec50c81b6f67d8c75191654083556e295c62e834f70407527f895cdb0143c7c03d43691178d4dad24928e34f2ccf625571124f494332764c26c143b2fca81a1",
            ],
            vec![
                "a50cc39a8a6d307a662b7281554c62160563702a4d3b74b96a73020dee49a9fb",
                "16758127569305622033690696576772666948369570687337655194316309407204222020091",
                "996381977260576916306052948741250441861090512190329094196817061979425454614",
                "250cc39a8a6d307a662b7281554c62160563702a4d3b74b96a73020dee49a9fb0233eea595bb5e489fb936153b4e53c38020e18b0c5153ed84089daa9371ba16",
            ],
            vec![
                "e1cc64c66b8454fe8a04b0c223027056024b1a857c2954e908c01ad46dfa92fd",
                "15287456328489553811251089526817405774794364456572262388563076064707199275773",
                "16045075511148081081180974221437774610890399755993978595202690039156356992884",
                "21cc64c66b8454fe8a04b0c223027056024b1a857c2954e908c01ad46dfa92fd237930dfbdf0299c03ed8cc974814cd0a4ed0de344dc2f0bf2b400bd288ccf74",
            ],
            vec![
                "e4cc85ab25e959618b7a3a014096769e52e53facce52c88d233f4b843c42045a",
                "16644621896619932674403156773599989254062908433680748614707665313524218987610",
                "13005385132933128008170911714502134831890364747549772156388645207959659156890",
                "24cc85ab25e959618b7a3a014096769e52e53facce52c88d233f4b843c42045a1cc0c9814576bd18d2ec2cf89934c09d167607333b9f4b211f83952db2cd159a",
            ],
            vec![
                "c374162b30dd32546ab82ca133255fb78b3d5fa3868d81f6b0c8d10838a52098",
                "1562045808107412830910722877268151167079969129726893823398063505190913646744",
                "21165873820784950133588246139903004626425028930311294151546173511136645683756",
                "0374162b30dd32546ab82ca133255fb78b3d5fa3868d81f6b0c8d10838a520982ecb75c59b77a0271f678fca039c22194f9771b29e4d2d093c7a85e031ff1a2c",
            ],
            vec![
                "ceead133ab604a2e28205201315e4f56ee018cd6d940de56e89351cd76525362",
                "6747265951315643810708068932074472329661514340538740628164568819602390405986",
                "20686829957075510408803791739126670303462736905667498894331787598576996546491",
                "0eead133ab604a2e28205201315e4f56ee018cd6d940de56e89351cd765253622dbc54b1266c7cc2141c0ed3805e9b70058ab89c3c0ad6a97085ab346a8777bb",
            ],
            vec![
                "87587c6024d0d18bff242b706a08366324dbb4c3518bbe4849848ee3288c463a",
                "3322530890362390081860860456393697429296580689901957489759399885206333441594",
                "9133463464185787809937546684779172784190437769194249621052436464239035321248",
                "07587c6024d0d18bff242b706a08366324dbb4c3518bbe4849848ee3288c463a14315b6c95991e9f6aa26557a29fa929a5725dba0ac24fecc35ae34a684c8ba0",
            ],
            vec![
                "e656fe46e6aa463847c3f2efcd38a6724f41c47db9b86135cf6a599bf7c804b1",
                "17341592048795289180672058352505106498850275508462818513070744665196228773041",
                "20310608686472840815255571426662881554734153462034293023974485571583878290716",
                "2656fe46e6aa463847c3f2efcd38a6724f41c47db9b86135cf6a599bf7c804b12ce765aaa40532633be89d26a69a327a65252ceea5208bbd5badd3bfddeedd1c",
            ],
            vec![
                "c34163625ca2728ff43a31580a63a63df9a23d0eec931bfaab75bfdf0122b9b5",
                "1472469529679057655750342792043254765435160336026413462914303763637759818165",
                "11346969455120439979832582013613395463933703122314462619184454303581259298523",
                "034163625ca2728ff43a31580a63a63df9a23d0eec931bfaab75bfdf0122b9b519162838f229cd406f1b94e2d18bc09217ce7105550bb09429d915ba77e5f6db",
            ],
            vec![
                "d9f2a3701a23e44c0ab6de34ef62e50dfe65a83ccfc2d998063da89a1f0ee88b",
                "11736526211179466907316855774772675857387806383025459551008174430332765792395",
                "20439395959332227638375735447595769385696108139242324664394056588463910575991",
                "19f2a3701a23e44c0ab6de34ef62e50dfe65a83ccfc2d998063da89a1f0ee88b2d3049c4163f8df6d250e4611382b26669e8cdc3eb28285a46f76f5d5cae5f77",
            ],
            vec![
                "dba86a33ad37e40b3a40a5b8dac85021b78ed7cb38d358eee2cace5db2fd2c06",
                "12510010196943019476567961786336293139594463462647652433484569825671158508550",
                "18923025791792437758612128255526572998539821313164661930095555788446721452304",
                "1ba86a33ad37e40b3a40a5b8dac85021b78ed7cb38d358eee2cace5db2fd2c0629d60d9490b99ccfdc8bdf78125d14eaf9c7459002a0b807106114e33d752910",
            ],
            vec![
                "d748768acb8f5b1a52188b94b85fe08dfe11ec5d61e7602991003ecb70eeb3b5",
                "10531226654058100350852661889877241555758465688704768270345944990691961516981",
                "13693440937494681284486055235161553320577958053791741188458253051221424160470",
                "1748768acb8f5b1a52188b94b85fe08dfe11ec5d61e7602991003ecb70eeb3b51e4636817e8a93af3ca8a27ea755c9288f0de8dbcf505a04bdd59f76d65f3ed6",
            ],
            vec![
                "82931be9b93ddc7f045858687cdf70a35e17ccd09fdcb4e104966dbc6dcb0f60",
                "1164544864016114291367152769547287780089375910760868117525032757145453137760",
                "8568198002944974885160598414939896135009725128289109705861922465805986203386",
                "02931be9b93ddc7f045858687cdf70a35e17ccd09fdcb4e104966dbc6dcb0f6012f16d9f540c3e3c51332c43de6d532b7a7555ae24dccfc0113d2d58e23486fa",
            ],
            vec![
                "e4d7eaf4edbb23410337d53e16a04f57bbc9e6293a4a8325cba5a3a59d32c511",
                "16664756279833075503407337378687973447885521673154091977127004282902312830225",
                "18657381484354910461191908921477663785644893893903193836304398489118489482048",
                "24d7eaf4edbb23410337d53e16a04f57bbc9e6293a4a8325cba5a3a59d32c511293fb425932d335cfc3f2d0bd46d1cc2acdf01493d23f19902fa77ffb4ac9340",
            ],
            vec![
                "a5edd2c63d992644ddfd1bb792dafe89ef24fe3a4f133149863c4ab9eab0639d",
                "17155772863222651407177547633557489192665693895572093121434076707017678939037",
                "47059014839761416665545835115274607080590892973869815693956073114110130381",
                "25edd2c63d992644ddfd1bb792dafe89ef24fe3a4f133149863c4ab9eab0639d001aa26bdf75acf2c5e39dadd11e6778868953d47ac8e31a7dfe0296b7e9f8cd",
            ],
            vec![
                "de6a6b57701ce08be230e57417d3943720e44d06b12d755a99f41fcf76055ad4",
                "13757412090545823053531367791860044986176154844941876581978262561267965582036",
                "17817147976374216009408142567124629680965717592589532494961532221488033720149",
                "1e6a6b57701ce08be230e57417d3943720e44d06b12d755a99f41fcf76055ad4276425fc9de3730d5190540dd9d77302b82946d67e4b5db0b78f22d4f3386755",
            ],
            vec![
                "e3f712519e8eec187c9cebae5698d5865768f184e14aa4635b989f588cbd4120",
                "16267487357302643678324743530062243979625902349511133738733084915667365085472",
                "20584984375678589585254318204395276317892856898285006957170801746381989429228",
                "23f712519e8eec187c9cebae5698d5865768f184e14aa4635b989f588cbd41202d82b03294a9bbe1bb64b54eba05beb46dd78a1d5cd5ebbb28bfe2d91cf73fec",
            ],
            vec![
                "8c901c87e13a11287ae9bc02daf1d20924d18a35c801e9baa1ab1b6b8a70eda4",
                "5682377072536947218613470133952956558720833405018917996334813071899632922020",
                "2378162733337801039853862165326067670255480592480678166290465245007182375928",
                "0c901c87e13a11287ae9bc02daf1d20924d18a35c801e9baa1ab1b6b8a70eda40541fe0e60d9b2d1a122f13ea024dfc1d181aa8d1ae9dae0865dd79fdba92bf8",
            ],
            vec![
                "85b0d843d441231d5fc00230f17d9c9d1901e15d9326d130bd92627924f4b73a",
                "2574021932197662754750109868481104913126775855326588200980541271739253176122",
                "1576455848937333889778887064607292783444815084945806053024711413134386658993",
                "05b0d843d441231d5fc00230f17d9c9d1901e15d9326d130bd92627924f4b73a037c3e0d4fc8a27d41072c7f18e5dffe0d78a0448644932246b7e9391229feb1",
            ],
            vec![
                "d40e91d754e2f43755243841fc0d8305c15c5d37632bf4571fa68d16ad293ed7",
                "9071999389120639165075892824792565169365919935317012254800373498620079062743",
                "15160936210130268693001253302637524319077291857758020184901323956758070938729",
                "140e91d754e2f43755243841fc0d8305c15c5d37632bf4571fa68d16ad293ed72184c92a686f4ddf665a9617d1dd70e1382e4b53c248fdfe9377f33e695bcc69",
            ],
            vec![
                "ef1ef2bedca3888526153e42d98cf42ba1dabeb7ca11ecffdc650f33a1c02ac0",
                "21313384663598639715647616884377354150182489492174942873552538593113967438528",
                "14258027050593447067861795286414467508154497763676785308982932983987850040282",
                "2f1ef2bedca3888526153e42d98cf42ba1dabeb7ca11ecffdc650f33a1c02ac01f85c1e053c92d7a3884d3e28260f34fd577c9236ef7bbfc679165e86c05d3da",
            ],
            vec![
                "91972ecfb9bd03233529a66dd1bfe5d43c4f72ba001a4f79c03dfbbc0fcdba59",
                "7956435413298506193062993687750920218074153586967800032118498906395160459865",
                "6874392527969784196004327283862171288447576276127868097038957854426852426859",
                "11972ecfb9bd03233529a66dd1bfe5d43c4f72ba001a4f79c03dfbbc0fcdba590f32c4ae7848344bdbe7c3223b94067583fc69a52ba74373262dd614ea8b046b",
            ],
            vec![
                "a2f537b12d4cdbed2675cef9bcc131320f839921e556db891f7cd732a14483c2",
                "15811898755432066051834503324734308626353432953904650456337893236479409554370",
                "2730950287282462389597829929525169558852040386470361233002279248696914796820",
                "22f537b12d4cdbed2675cef9bcc131320f839921e556db891f7cd732a14483c20609a9c007315bbee740713cf003d463ffd2285d919189fa91f29da33f00e114",
            ],
            vec![
                "8850fb5e6f1113775d3d2e0e04536bc3a1395bcd7152eb54cd3c990c642d4a56",
                "3761585438113122047686667420167080466940567227490538469642155991479545055830",
                "8613925027184975605332082999555589082554903168326253239431190347765086150646",
                "0850fb5e6f1113775d3d2e0e04536bc3a1395bcd7152eb54cd3c990c642d4a56130b4f0cec87df5c28cbb040456b87156db0f49219ee039bcd5e8c81df7bdff6",
            ],
            vec![
                "e9acbdbb75c7912d8003841f7bfb4238f4c39bdbdeb9edac90389a9c29cb94c7",
                "18850033971029009470292888643444394570121063810060697992702450320115113891015",
                "17734100987742137016281315404362521802677686987113422358697682198503183909177",
                "29acbdbb75c7912d8003841f7bfb4238f4c39bdbdeb9edac90389a9c29cb94c72735253c9b40503d2346df8cba83a726fa09702bae39b3e3de5ba59f39988139",
            ],
            vec![
                "e95d1103374765d467237c80ca83be76825e37f11f4f6388013f47df788114e3",
                "18709260985327594488673929313324330137518143649576471750054531006634414642403",
                "16700486695844484502471015762615996092278077213453456988131615089532405383647",
                "295d1103374765d467237c80ca83be76825e37f11f4f6388013f47df788114e324ec23f7b78d30828549b5e471bae9cff81c5ea8632d3fed76e8ec9825c181df",
            ],
            vec![
                "ef49f1fbacac3633c52d443b72b01a1437ad6703e4ce0855bd3129d7ee4bb9bf",
                "21389353825143090252867164563348605300841423309297308919011482821297384962495",
                "12585872222479734474736920219118319433139848591834517315374691738056653495848",
                "2f49f1fbacac3633c52d443b72b01a1437ad6703e4ce0855bd3129d7ee4bb9bf1bd359ea980862febd440fc176cd4ce85ec43e93470d828a6aac4474286b5e28",
            ],
            vec![
                "99b041a96fa46c175ae1c23310f5f571e0ec4314bd1186de0107112057d86442",
                "11619239479483487244414626934823736122667944672473758691159688222639350375490",
                "387006972101286032794559497497187798494704948481338322352073318714454908580",
                "19b041a96fa46c175ae1c23310f5f571e0ec4314bd1186de0107112057d8644200db09c669ab4c5c9f501bf0d522c888ad3a6fe29b2c1f897daeebe723391ea4",
            ],
            vec![
                "ce20eacb2a5462418167277dfdfc2fba360886deb3cfcf547732783575480dd9",
                "6390539472210789896175390174502862271057459525772372424906943213101398887897",
                "16893322800934261635339189594737551496440389038098937795446337174091677369877",
                "0e20eacb2a5462418167277dfdfc2fba360886deb3cfcf547732783575480dd92559482863428c7c8ef43a63827aef58d374be17aca02fa79535fc0f5dfd0615",
            ],
            vec![
                "c49d0393ec286cb44ac75ea3e9b46284d4d8f63f934b84e70ddbf495ba7f9969",
                "2086671076724802896446657473187808720373210290533355562114568073663274260841",
                "12688154126459329389694847024645067042366148882342019134367499142653666863925",
                "049d0393ec286cb44ac75ea3e9b46284d4d8f63f934b84e70ddbf495ba7f99691c0d3da1446fb18aa7b060b7bd85ab45d4b2964fcfe27d4c845e7072372b2b35",
            ],
            vec![
                "acffb1bde8b0f64bce72d4208506745f95fd66fe1b5c4990408ababf14760632",
                "20353538068220760763962322999858787008194165209108734503823615568807999178290",
                "1627513362726483672168461725184209080977484486928107462523834597654843370425",
                "2cffb1bde8b0f64bce72d4208506745f95fd66fe1b5c4990408ababf14760632039923d1c0e60efd70774f22c144143ae3d2198ede66bbda9356780cb45c2bb9",
            ],
            vec![
                "c71df5fae607048a384d4b20cfc2803f0cbcd6bb6eb52d469378614b9fca48d6",
                "3219126197027782352075255749402690645067572392675117602697162255957664352470",
                "15725265792009728688352354065337723451038816053886366923363403414691404044012",
                "071df5fae607048a384d4b20cfc2803f0cbcd6bb6eb52d469378614b9fca48d622c42f5df81b84d6c68603dd8a7905840935af2ab2e7f6a1a5339c74a5fbd6ec",
            ],
            vec![
                "cb8bc8eb156e4ef81a18d3afe8ee1879007362accfbc6bdaa2e54c7f8964b754",
                "5222419763533886985971095566446719772552958418394597651330807418042838202196",
                "11947711893500550826845827397851915846265888050063379381813984264165116844728",
                "0b8bc8eb156e4ef81a18d3afe8ee1879007362accfbc6bdaa2e54c7f8964b7541a6a2a506b8df7c82fe9efc8dd0c4b6d17d624dba5eab1f8ce0c2adcf6a39ab8",
            ],
            vec![
                "82fc141f032439feef11949f0101251959e56126e7dbeb46dd81981f4623191a",
                "1350010028506807732483094416039930749468408982178579445461486282763854354714",
                "1974920762264532138166754304942947895952221986597860261879968157099055883512",
                "02fc141f032439feef11949f0101251959e56126e7dbeb46dd81981f4623191a045dc3fa6297278657b82c5a086a424d930fa20157e0a27efccc9886a57ba4f8",
            ],
            vec![
                "ab57061277684f40b6aa39c1580b0274d2ede0a6ee65d52aa2a72352ff2307b0",
                "19603210092048368070188522171339250427277682037169306858628190864091925120944",
                "1486948181215089388364217912115585709047549264745841917176978251047988512114",
                "2b57061277684f40b6aa39c1580b0274d2ede0a6ee65d52aa2a72352ff2307b003499535652985e0d12c92f0059db0aed2ae2fbcfe11fe0cb3192bc7c1624572",
            ],
            vec![
                "c151f6ba19cdbd666784beae51793933d4c7bff6df8f8999dfd9648edca62aea",
                "597130307699149842149932533234382796524615995064550156791241004025328839402",
                "11669773498500920472095244929826391330491209050708395393463573482399616671952",
                "0151f6ba19cdbd666784beae51793933d4c7bff6df8f8999dfd9648edca62aea19ccdb9460b015563e62e78aad0eeabefe49415f185a449e9d565596469320d0",
            ],
            vec![
                "a719dc55d42c420e1df6aeca1e0db45c2c354550d7fad36f0699be9b7ebd403a",
                "17685892969503021917026550559542322584776856510818560466812359577188775575610",
                "2093197919280337533751124564966564981989138165843044614559742416595653110584",
                "2719dc55d42c420e1df6aeca1e0db45c2c354550d7fad36f0699be9b7ebd403a04a0b541f7cf5555b476f4dfec90e3c5101add77fc5b4ee0c4ed48eb2e5e2b38",
            ],
            vec![
                "9546df0c9c28abef1e49b767999d86225255d2dd1fd42d0a4198592253c2f866",
                "9623788544183224193686588396019175383666318932054497766059952279457848555622",
                "3148721943475073191301255609584837186448529800234875539277195731093534518838",
                "1546df0c9c28abef1e49b767999d86225255d2dd1fd42d0a4198592253c2f86606f61d0bfed3f8ac3be1451675d5dfda2bb084a282ba2f32d531dcf7b2b3ae36",
            ],
            vec![
                "99bffdbc3c1c192098bebcf5e8fa555ea7308b68ea30a53d93023198fa462f82",
                "11647040220580338963320356107811803045415891459571749755159545520616099950466",
                "4239867753083090923945735282993639511236348423568395938604650372852847353990",
                "19bffdbc3c1c192098bebcf5e8fa555ea7308b68ea30a53d93023198fa462f82095fae1b7a767e900052df5062a123293c928c9945a49f6aaf0aff3c82b62086",
            ],
            vec![
                "d2331ee433156d54fea18f1378620fba7396f27dba0786d5a82a258cebc6278f",
                "8231953679440477882577338284019588334275118654350354613701423902088688445327",
                "15353162843201831641849112365042690784079239212174519674290136891776533586163",
                "12331ee433156d54fea18f1378620fba7396f27dba0786d5a82a258cebc6278f21f1950c814e1c46b8169f842c2ffeca9075c12ab07acab861d53a3a487ce0f3",
            ],
            vec![
                "e1b7a1fc4e4e7a7cb9af18eaa151af14c8428ca69c1ea04601afed43e3323576",
                "15250774999417271469734642639035080836364513662248855624685826239065247331702",
                "12501021494486120427575615681433332418042849163205692918610506897849491474325",
                "21b7a1fc4e4e7a7cb9af18eaa151af14c8428ca69c1ea04601afed43e33235761ba353d22c17a4f7b519bb2846e19427ffa854e20bd8066b466109977a614795",
            ],

        ];

        struct GnarkPoint {
            compreesed_x: String,
            big_x: String,
            big_y: String,
            uncompressed: String,
        }

        let ganrk_points: Vec<GnarkPoint> = input
            .iter()
            .map(|vec| GnarkPoint {
                compreesed_x: vec[0].to_string(),
                big_x: vec[1].to_string(),
                big_y: vec[2].to_string(),
                uncompressed: vec[3].to_string(),
            })
            .collect();

        for (_, point) in ganrk_points.iter().enumerate() {
            let ganrk_x_bytes = hex::decode(&point.compreesed_x).unwrap();
            let p = gnark_compressed_x_to_g1_point(&ganrk_x_bytes).unwrap();
            let big_x = p.x().unwrap().into_bigint().to_string();
            let big_y = p.y().unwrap().into_bigint().to_string();

            assert_eq!(big_x, point.big_x);
            assert_eq!(big_y, point.big_y);

            let hex_x = p.x().unwrap().into_bigint().to_bytes_be();
            let hex_y = p.y().unwrap().into_bigint().to_bytes_be();
            let mut uncompressed = vec![];

 
            uncompressed.extend_from_slice(&hex_x);
            uncompressed.extend_from_slice(&hex_y);
            assert_eq!(point.uncompressed, hex::encode(uncompressed.clone()));

            let uncompressed_ark = hex::encode(ark_g1_to_gnark_unompressed_bytes(&p).unwrap());
            assert_eq!(uncompressed_ark, point.uncompressed);


            let p1 = gnark_uncompressed_bytes_to_g1_point(&uncompressed).unwrap();
            assert_eq!(p, p1);
        }
    }



}
