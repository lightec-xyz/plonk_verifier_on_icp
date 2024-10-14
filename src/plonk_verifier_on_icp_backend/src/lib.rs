use ic_cdk::query;

mod fr;
mod point;
mod proof;
mod vk;
mod fiat_shamir;
mod witness;
mod hash_to_field;
mod verifier;


fn verify(vk_bytes:Vec<u8>, proof_bytes: Vec<u8>, wit_bytes:Vec<u8>, vk_has_lines:bool) ->bool {
    let proof = match proof::Proof::from_compressed_gnark_bytes(&proof_bytes) {
        Ok(proof) => proof,
        Err(err) => {
        ic_cdk::eprintln!("Failed to decode proof: {}", err);
        return false
        }
    };

    let wit = match witness::PublicWitness::from_gnark_bytes(&wit_bytes) {
        Ok(wit) => wit,
        Err(err) => {
        ic_cdk::eprintln!("Failed to decode witness: {}", err);
        return false
        }
    };

    let vk = match vk::VerifyingKey::from_gnark_bytes(&vk_bytes, vk_has_lines) {
        Ok(vk) => vk,
        Err(err) => {
        ic_cdk::eprintln!("Failed to decode vk: {}", err);
        return false
        }
    };

    let result = match verifier::verify(&vk, &proof, &wit, true){
        Ok(result ) => result,
        Err(err) => {
        ic_cdk::eprintln!("Failed to verify proof: {}", err);
        return false
        }
    };
    return result
}


#[query]
pub fn verify_hex(vk_hex:String, proof_hex: String, wit_hex:String, vk_has_lines:bool) ->bool {
    let vk_bytes =  match hex::decode(vk_hex){
        Ok(bytes) => bytes,
        Err(e) => {
            ic_cdk::eprintln!("hex::decode vk hex error {:?}", e);
            return false
        }   
    };

    let proof_bytes =  match hex::decode(proof_hex){
        Ok(bytes) => bytes,
        Err(e) => {
            ic_cdk::eprintln!("hex::decode proof hex error {:?}", e);
            return false
        }   
    };

    let wit_bytes =  match hex::decode(wit_hex){
        Ok(bytes) => bytes,
        Err(e) => {
            ic_cdk::eprintln!("hex::decode wit hex error {:?}", e);
            return false
        }   
    };

    let result = verify(vk_bytes, proof_bytes, wit_bytes, vk_has_lines);
    if !result {
        ic_cdk::trap("verify fail");
    }
    
    return result
}


#[query]
pub fn verify_bytes(vk_bytes:Vec<u8>, proof_bytes: Vec<u8>, wit_bytes:Vec<u8>, vk_has_lines:bool) ->bool {
    let result = verify(vk_bytes, proof_bytes, wit_bytes, vk_has_lines);
    if !result {
        ic_cdk::trap("verify fail");
    }
    
    return result
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;


    #[test]
    fn test_verify_cubic() {
        let mut vk_file = File::open("src/test_data/cubic/cubic.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });

        let mut vk_bytes = vec![];
        vk_file.read_to_end(&mut vk_bytes).unwrap();
        let vk_bytes_wo_lines = vk::VerifyingKey::to_gnark_bytes_wo_lines(&vk_bytes, true).unwrap();
        let vk_hex = hex::encode(&vk_bytes);
        let vk_hex_wo_lines = hex::encode(&vk_bytes_wo_lines);
        println!("vk_hex: {:?}", vk_hex.clone());
        println!("vk_hex_wo_lines: {:?}", vk_hex_wo_lines.clone());



        let mut proof_file = File::open("src/test_data/cubic/cubic_compressed.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut proof_bytes = vec![];
        proof_file.read_to_end(&mut proof_bytes).unwrap();
        let proof_hex = hex::encode(&proof_bytes);
        println!("proof_hex: {:?}", proof_hex.clone());
   

        let mut wit_file = File::open("src/test_data/cubic/cubic.wtns").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut wit_bytes = vec![];
        wit_file.read_to_end(&mut wit_bytes).unwrap();
        let wit_hex = hex::encode(&wit_bytes);
        println!("wit_hex: {:?}", wit_hex.clone());

        let result = verify_bytes(vk_bytes, proof_bytes.clone(), wit_bytes.clone(), true);
        assert_eq!(true, result);

        let result = verify_bytes(vk_bytes_wo_lines, proof_bytes, wit_bytes, false); 
        assert_eq!(true, result);

        let result = verify_hex(vk_hex, proof_hex.clone(), wit_hex.clone(), true);
        assert_eq!(true, result);

        let result = verify_hex(vk_hex_wo_lines, proof_hex, wit_hex, false);
        assert_eq!(true, result);

    }

    #[test]
    fn test_verify_hasher() {
        let mut vk_file = File::open("src/test_data/hasher/hasher.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });

        let mut vk_bytes = vec![];
        vk_file.read_to_end(&mut vk_bytes).unwrap();
        let vk_bytes_wo_lines = vk::VerifyingKey::to_gnark_bytes_wo_lines(&vk_bytes, true).unwrap();
        let vk_hex = hex::encode(&vk_bytes);
        let vk_hex_wo_lines = hex::encode(&vk_bytes_wo_lines);
        println!("vk_hex: {:?}", vk_hex.clone());
        println!("vk_hex_wo_lines: {:?}", vk_hex_wo_lines.clone());

        let mut proof_file = File::open("src/test_data/hasher/hasher_compressed.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut proof_bytes = vec![];
        proof_file.read_to_end(&mut proof_bytes).unwrap();
        let proof_hex = hex::encode(&proof_bytes);
        println!("proof_hex: {:?}", proof_hex.clone());
   
        let mut wit_file = File::open("src/test_data/hasher/hasher.wtns").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut wit_bytes = vec![];
        wit_file.read_to_end(&mut wit_bytes).unwrap();
        let wit_hex = hex::encode(&wit_bytes);
        println!("wit_hex: {:?}", wit_hex.clone());

        let result = verify_bytes(vk_bytes, proof_bytes.clone(), wit_bytes.clone(), true);
        assert_eq!(true, result);

        let result = verify_bytes(vk_bytes_wo_lines, proof_bytes, wit_bytes, false); 
        assert_eq!(true, result);

        let result = verify_hex(vk_hex, proof_hex.clone(), wit_hex.clone(), true);
        assert_eq!(true, result);

        let result = verify_hex(vk_hex_wo_lines, proof_hex, wit_hex, false);
        assert_eq!(true, result);

    }


    #[test]
    fn test_verify_mimc() {
        let mut vk_file = File::open("src/test_data/mimc/mimc.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });

        let mut vk_bytes = vec![];
        vk_file.read_to_end(&mut vk_bytes).unwrap();
        let vk_bytes_wo_lines = vk::VerifyingKey::to_gnark_bytes_wo_lines(&vk_bytes, true).unwrap();
        let vk_hex = hex::encode(&vk_bytes);
        let vk_hex_wo_lines = hex::encode(&vk_bytes_wo_lines);
        println!("vk_hex: {:?}", vk_hex.clone());
        println!("vk_hex_wo_lines: {:?}", vk_hex_wo_lines.clone());

        let mut proof_file = File::open("src/test_data/mimc/mimc_compressed.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut proof_bytes = vec![];
        proof_file.read_to_end(&mut proof_bytes).unwrap();
        let proof_hex = hex::encode(&proof_bytes);
        println!("proof_hex: {:?}", proof_hex.clone());
   
        let mut wit_file = File::open("src/test_data/mimc/mimc.wtns").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut wit_bytes = vec![];
        wit_file.read_to_end(&mut wit_bytes).unwrap();
        let wit_hex = hex::encode(&wit_bytes);
        println!("wit_hex: {:?}", wit_hex.clone());

        let result = verify_bytes(vk_bytes, proof_bytes.clone(), wit_bytes.clone(), true);
        assert_eq!(true, result);

        let result = verify_bytes(vk_bytes_wo_lines, proof_bytes, wit_bytes, false); 
        assert_eq!(true, result);

        let result = verify_hex(vk_hex, proof_hex.clone(), wit_hex.clone(), true);
        assert_eq!(true, result);

        let result = verify_hex(vk_hex_wo_lines, proof_hex, wit_hex, false);
        assert_eq!(true, result);

    }

    #[test]
    fn test_compare_cubic_compressed_uncompressed_gnark_proof() {
        let mut compressed_file = File::open("src/test_data/hasher/hasher_compressed.proof").unwrap();
        let mut compressed_data = Vec::new();
        compressed_file.read_to_end(&mut compressed_data).unwrap();
        let compressed_proof = proof::Proof::from_compressed_gnark_bytes(&compressed_data).unwrap();

        let mut uncompressed_file = File::open("src/test_data/hasher/hasher_uncompressed.proof").unwrap();
        let mut uncompressed_data = Vec::new();
        uncompressed_file.read_to_end(&mut uncompressed_data).unwrap();
        let uncompressed_proof = proof::Proof::from_uncompressed_gnark_bytes(&uncompressed_data).unwrap();

        assert_eq!(compressed_proof, uncompressed_proof);
    }  
}