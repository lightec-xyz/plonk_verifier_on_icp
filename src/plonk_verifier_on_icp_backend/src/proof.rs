use crate::fr::*;
use crate::point::*;
use ark_bn254::{Fr, G1Affine};

pub use ark_std::io::Read;
use std::error::Error;
use ark_ff::Zero;

#[derive(Clone, Default, Debug)]
pub struct BatchOpeningProof {
    pub h: G1Affine,

    // ClaimedValues purported values
    pub claimed_values: Vec<Fr>,
}
impl PartialEq for BatchOpeningProof {
    fn eq(&self, other: &Self) -> bool {
        self.h == other.h &&
        self.claimed_values == other.claimed_values
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct OpeningProof {
    pub h: G1Affine,
    // ClaimedValues purported values
    pub claimed_value: Fr,
}

impl PartialEq for OpeningProof {
    fn eq(&self, other: &Self) -> bool {
        self.h == other.h &&
        self.claimed_value == other.claimed_value
    }
}



#[derive(Clone, Default, Debug)]
pub struct Proof {
    // Commitments to the solution vectors
    pub lro: [G1Affine; 3],

    // Commitment to Z, the permutation polynomial
    pub z: G1Affine,

    // Commitments to h1, h2, h3 such that h = h1 + Xh2 + X**2h3 is the quotient polynomial
    pub h: [G1Affine; 3],

    pub bsb22_commitments: Vec<G1Affine>,

    // Batch opening proof of linearizedPolynomial, l, r, o, s1, s2, qCPrime
    pub batched_proof: BatchOpeningProof,

    // Opening proof of Z at zeta*mu
    pub zshifted_proof: OpeningProof,
}

impl Proof {
    pub fn from_compressed_gnark_bytes(data: &[u8]) -> Result<Self, Box<dyn Error>> {
        let mut reader = data; // Using slice directly

        let mut l_bytes = [0u8; 32];
        let mut r_bytes = [0u8; 32];
        let mut o_bytes = [0u8; 32];
        let mut z_bytes = [0u8; 32];
        let mut h0_bytes = [0u8; 32];
        let mut h1_bytes = [0u8; 32];
        let mut h2_bytes = [0u8; 32];
        let mut batched_proof_h_bytes = [0u8; 32];

        reader.read_exact(&mut l_bytes)?;
        reader.read_exact(&mut r_bytes)?;
        reader.read_exact(&mut o_bytes)?;
        reader.read_exact(&mut z_bytes)?;
        reader.read_exact(&mut h0_bytes)?;
        reader.read_exact(&mut h1_bytes)?;
        reader.read_exact(&mut h2_bytes)?;
        reader.read_exact(&mut batched_proof_h_bytes)?;

        let l_commit = gnark_compressed_x_to_g1_point(&l_bytes)?;
        let r_commit = gnark_compressed_x_to_g1_point(&r_bytes)?;
        let o_commit = gnark_compressed_x_to_g1_point(&o_bytes)?;
        let z_commit = gnark_compressed_x_to_g1_point(&z_bytes)?;
        let h0_commit = gnark_compressed_x_to_g1_point(&h0_bytes)?;
        let h1_commit = gnark_compressed_x_to_g1_point(&h1_bytes)?;
        let h2_commit = gnark_compressed_x_to_g1_point(&h2_bytes)?;
        let batched_proof_h_commit = gnark_compressed_x_to_g1_point(&batched_proof_h_bytes)?;

        let mut batched_proof_values_len_bytes = [0u8; 4];
        reader
            .read_exact(&mut batched_proof_values_len_bytes)?;
        let batched_proof_values_len = u32::from_be_bytes(batched_proof_values_len_bytes);
        let mut batched_proof_values: Vec<Fr> = Vec::with_capacity(batched_proof_values_len as usize);
        for _i in 0..(batched_proof_values_len as usize) {
            let mut v_bytes = [0u8; 32];
            reader.read_exact(&mut v_bytes)?;
            let v = fr_from_gnark_bytes(&v_bytes);
            batched_proof_values.push(v);
        }
      
        let mut z_shifted_h_bytes = [0u8; 32];
        let mut z_shifted_value_bytes = [0u8; 32];
        reader.read_exact(&mut z_shifted_h_bytes)?;
        reader.read_exact(&mut z_shifted_value_bytes)?;
        let z_shifted_h_commit = gnark_compressed_x_to_g1_point(&z_shifted_h_bytes)?;
        let z_shifted_value = fr_from_gnark_bytes(&z_shifted_value_bytes);

        let mut bs22_commits_len_bytes = [0u8; 4];
        reader.read_exact(&mut bs22_commits_len_bytes)?;
        let bs22_commits_len = u32::from_be_bytes(bs22_commits_len_bytes);
        let mut bsb22_commits: Vec<G1Affine> = Vec::with_capacity(bs22_commits_len as usize);
        for _i in 0..(bs22_commits_len as usize) {
            let mut v_bytes = [0u8; 32];
            reader.read_exact(&mut v_bytes)?;
            let v = gnark_compressed_x_to_g1_point(&v_bytes)?;
            bsb22_commits.push(v);
        }

        let proof = Proof {
            lro: [l_commit, r_commit, o_commit],
            z: z_commit,
            h: [h0_commit, h1_commit, h2_commit],
            bsb22_commitments: bsb22_commits,
            batched_proof: BatchOpeningProof {
                h: batched_proof_h_commit,
                claimed_values: batched_proof_values,
            },
            zshifted_proof: OpeningProof {
                h: z_shifted_h_commit,
                claimed_value: z_shifted_value,
            },
        };

        Ok(proof)
    }


    pub fn from_uncompressed_gnark_bytes(data: &[u8]) ->  Result<Self, Box<dyn Error>> {
        let len = data.len();
        let bsb22_commit_len = (len - 768)/96;

        let mut reader = data; // Using slice directly

        let mut l_bytes = [0u8; 64];
        let mut r_bytes = [0u8; 64];
        let mut o_bytes = [0u8; 64];
        let mut h0_bytes = [0u8; 64];
        let mut h1_bytes = [0u8; 64];
        let mut h2_bytes = [0u8; 64];

        reader.read_exact(&mut l_bytes)?;
        reader.read_exact(&mut r_bytes)?;
        reader.read_exact(&mut o_bytes)?;
        reader.read_exact(&mut h0_bytes)?;
        reader.read_exact(&mut h1_bytes)?;
        reader.read_exact(&mut h2_bytes)?;

        let l_commit = gnark_uncompressed_bytes_to_g1_point(&l_bytes)?;
        let r_commit = gnark_uncompressed_bytes_to_g1_point(&r_bytes)?;
        let o_commit = gnark_uncompressed_bytes_to_g1_point(&o_bytes)?;
        let h0_commit = gnark_uncompressed_bytes_to_g1_point(&h0_bytes)?;
        let h1_commit = gnark_uncompressed_bytes_to_g1_point(&h1_bytes)?;
        let h2_commit = gnark_uncompressed_bytes_to_g1_point(&h2_bytes)?;


        let mut l_value_bytes = [0u8; 32];
        let mut r_value_bytes = [0u8; 32];
        let mut o_value_bytes = [0u8; 32];
        let mut s1_value_bytes = [0u8; 32];
        let mut s2_value_bytes = [0u8; 32];

        reader.read_exact(&mut l_value_bytes)?;
        reader.read_exact(&mut r_value_bytes)?;
        reader.read_exact(&mut o_value_bytes)?;
        reader.read_exact(&mut s1_value_bytes)?;
        reader.read_exact(&mut s2_value_bytes)?;

        let l_value = fr_from_gnark_bytes(&l_value_bytes);
        let r_value = fr_from_gnark_bytes(&r_value_bytes);
        let o_value = fr_from_gnark_bytes(&o_value_bytes);
        let s1_value = fr_from_gnark_bytes(&s1_value_bytes);
        let s2_value = fr_from_gnark_bytes(&s2_value_bytes);


        let mut z_bytes: [u8; 64] = [0u8; 64];
        reader.read_exact(&mut z_bytes)?;
        let z_commit = gnark_uncompressed_bytes_to_g1_point(&z_bytes)?;


        let mut z_shifted_value_bytes = [0u8; 32];
        reader.read_exact(&mut z_shifted_value_bytes)?;
        let z_shifted_value = fr_from_gnark_bytes(&z_shifted_value_bytes);

        // let mut linearization_polynomial_value_bytes = [0u8;32];
        // reader.read_exact(&mut linearization_polynomial_value_bytes)?;

        let linearization_polynomial_value = Fr::zero();

        let mut batched_proof_h_bytes = [0u8; 64];
        reader.read_exact(&mut batched_proof_h_bytes)?;
        let batched_proof_h_commit = gnark_uncompressed_bytes_to_g1_point(&batched_proof_h_bytes)?;

        let mut z_shifted_h_bytes = [0u8; 64];
        reader.read_exact(&mut z_shifted_h_bytes)?;
        let z_shifted_h_commit = gnark_uncompressed_bytes_to_g1_point(&z_shifted_h_bytes)?;

        let mut bsb22_commit_values = Vec::with_capacity(bsb22_commit_len);
        for _ in 0..bsb22_commit_len {
            let mut tmp32 = [0u8; 32];
            reader.read_exact(&mut tmp32)?;
            let value =fr_from_gnark_bytes(&tmp32);
            bsb22_commit_values.push(value);
        }

        let mut bsb22_commits  = Vec::with_capacity(bsb22_commit_len);
        for _i in 0..bsb22_commit_len {
            let mut tmp64 = [0u8; 64];
            reader.read_exact(&mut tmp64)?;
            let commit = gnark_uncompressed_bytes_to_g1_point(&tmp64)?;
            bsb22_commits.push(commit);
        }

        let mut batched_proof_values = vec![linearization_polynomial_value,l_value, r_value, o_value, s1_value, s2_value];
        batched_proof_values.extend_from_slice(&bsb22_commit_values);
    
        let proof = Proof {
            lro: [l_commit, r_commit, o_commit],
            z: z_commit,
            h: [h0_commit, h1_commit, h2_commit],
            bsb22_commitments: bsb22_commits,
            batched_proof: BatchOpeningProof {
                h: batched_proof_h_commit,
                claimed_values: batched_proof_values,
            },
            zshifted_proof: OpeningProof {
                h: z_shifted_h_commit,
                claimed_value: z_shifted_value,
            },
        };


        Ok(proof)
    }
}

//skip batched_proof.claimed_values[0]
impl PartialEq for Proof {
    fn eq(&self, other: &Self) -> bool {
        let eq1 = self.lro == other.lro &&
            self.z == other.z &&
            self.h == other.h &&
            self.bsb22_commitments == other.bsb22_commitments &&
            self.batched_proof.h == other.batched_proof.h &&
            self.zshifted_proof == other.zshifted_proof;

        let mut eq2 = true;        
        for i in 1..self.batched_proof.claimed_values.len() {
            eq2 = eq2 && self.batched_proof.claimed_values[i] == other.batched_proof.claimed_values[i];
        }

        eq1 && eq2
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;
    use std::fs::File;

    static COMPRESSED_PROOF_DATA1 :&str = "910cf23488c8938d62cd8c3aa077206268fb2e9c94753ff52bc201afe338c448d35fc52d00200b95837289edb922393211d5e901b79976f2a77626774b3b9c3793674935c867be7d1bc128768e45e8141b8c5b3b8d35510a355f0e5c7ba866f98160cf6d63bb6ef0e9d793c1646e83f143383d850efdf3c2340a289f42aa7713d87981d0580dc7d9994bab5c3d1eb5c6eb8fa0a38ff09a9f9495f28ace1fe92ce2d65055e54dd2513d0c6a10326dd75771fc0a862897a68a5b1aae2636815a27cffef9c74582533828fb7da2c506cc6670284aa5f9023901a46a692fc1741f84abc5ff7a81c9f7e274fa0711fca83d2abb1c423100e0de8dddfb3146b36a8186000000062e9f4ea0264a416444710e9bd9d5f80518a460ccf6aa7e6367a54e2c4bdf8afe1b18db168fe415408ec689d2b0d968a1d0675b6db6f3501af6a8cf17547828250262132daa2f1807b8232e9e4455b1b2bb9e979df8de8b6f35a82f08da1e77152b1860723558cab4e93d96370b0eec108bb9f546b279fa2ade09b0203d4a8e641a4f279fa501786e6a37ec1b18a77587531ffb25d08cd2de9e1652b0548bf2b80e52f355eacc837d4ea24d46036d9df42ebea1e1d5cffaeb9bc4d9da050bfca99d70b632f4c6ee28b16d393de8941ae2853ec25603968ebf36448f59cf4a3b931182127da3e810e886559a81f1fbff52c8bdf6aea163976f5518a09bb196f4bf00000000";

    #[test]
    fn test_read_compressed_gnark_proof() {
        let s = String::from(COMPRESSED_PROOF_DATA1);
        let data = hex::decode(&s.clone()).unwrap();

        let proof = Proof::from_compressed_gnark_bytes(&data).unwrap();

        assert_eq!(
            "7712192229631003224747667854059574530379724369086066549207106013525658092616",
            proof.lro[0].x().unwrap().into_bigint().to_string()
        );
        assert_eq!(
            "10312591011670878926845572221117025298358942749331148897798207649675722974229",
            proof.lro[0].y().unwrap().into_bigint().to_string()
        );

        assert_eq!(
            "8763155451477108304536784072552196458925426257546873453432181440630492994615",
            proof.lro[1].x().unwrap().into_bigint().to_string()
        );
        assert_eq!(
            "15352278484834761909830598059161884959228185986162789732449078173111362104867",
            proof.lro[1].y().unwrap().into_bigint().to_string()
        );

        assert_eq!(
            "8776434648219860214789754007538320450895193601249048053435788382727397992185",
            proof.lro[2].x().unwrap().into_bigint().to_string()
        );
        assert_eq!(
            "5366789569407776165329165130333405904091854154769943392511152890401215346861",
            proof.lro[2].y().unwrap().into_bigint().to_string()
        );

        assert_eq!(
            "623361777432986138802061747779180373125292332501458532718278869916133783315",
            proof.z.x().unwrap().into_bigint().to_string()
        );
        assert_eq!(
            "2842214882302059479524931775527971443202790645607931955168808545385344569735",
            proof.z.y().unwrap().into_bigint().to_string()
        );

        assert_eq!(
            "11070192803057371278106022453818369532577713881762071360188277642183743367468",
            proof.h[0].x().unwrap().into_bigint().to_string()
        );
        assert_eq!(
            "16357922835310160800926147174286546701389066101664824653312957708875387832974",
            proof.h[0].y().unwrap().into_bigint().to_string()
        );

        assert_eq!(
            "15757296579145370125890693065725441891660332688140904452995303562868808571431",
            proof.h[1].x().unwrap().into_bigint().to_string()
        );
        assert_eq!(
            "17063243144422272653196620799194402369359545185548876031251042487867389774254",
            proof.h[1].y().unwrap().into_bigint().to_string()
        );

        assert_eq!(
            "7235195790392603810298051293252575995708324941040923496381353096834784173956",
            proof.h[2].x().unwrap().into_bigint().to_string()
        );
        assert_eq!(
            "15893769207206256763553645789717162013616772033509441072093498880209964370912",
            proof.h[2].y().unwrap().into_bigint().to_string()
        );

        assert_eq!(
            "21087862371968947379731292372400839670278137824013268162884703276237603179262",
            proof.batched_proof.claimed_values[0]
                .into_bigint()
                .to_string()
        );
        assert_eq!(
            "12256363332025133140078548171985433799492892987172395418800827351467415840805",
            proof.batched_proof.claimed_values[1]
                .into_bigint()
                .to_string()
        );
        assert_eq!(
            "1077909073815466360707620417200489675413721467045839828484091180403960739605",
            proof.batched_proof.claimed_values[2]
                .into_bigint()
                .to_string()
        );
        assert_eq!(
            "19492522465336426169036360688059817435471374276390213211013902876415036657252",
            proof.batched_proof.claimed_values[3]
                .into_bigint()
                .to_string()
        );
        assert_eq!(
            "11899988453398596395785182781487035641326645562543154200917856943000412484280",
            proof.batched_proof.claimed_values[4]
                .into_bigint()
                .to_string()
        );
        assert_eq!(
            "6478940780162502045372475740415125988776847214177697900415400918754846833833",
            proof.batched_proof.claimed_values[5]
                .into_bigint()
                .to_string()
        );
  

        assert_eq!(
            "13316216971780387897285478047363428610211267989156277862255617893986646768531",
            proof
                .zshifted_proof
                .h
                .x()
                .unwrap()
                .into_bigint()
                .to_string()
        );
        assert_eq!(
            "9809333512433023052270103947243891539373029131799799789121070186056385283119",
            proof
                .zshifted_proof
                .h
                .y()
                .unwrap()
                .into_bigint()
                .to_string()
        );

        assert_eq!(
            "7919136163025664166060119323405203858873715190288630061770785596039186805951",
            proof.zshifted_proof.claimed_value.into_bigint().to_string()
        );

        assert_eq!(0, proof.bsb22_commitments.len());
    }


    static COMPRESSED_PROOF_DATA2 :&str = "910cf23488c8938d62cd8c3aa077206268fb2e9c94753ff52bc201afe338c448d35fc52d00200b95837289edb922393211d5e901b79976f2a77626774b3b9c3793674935c867be7d1bc128768e45e8141b8c5b3b8d35510a355f0e5c7ba866f98160cf6d63bb6ef0e9d793c1646e83f143383d850efdf3c2340a289f42aa7713d87981d0580dc7d9994bab5c3d1eb5c6eb8fa0a38ff09a9f9495f28ace1fe92ce2d65055e54dd2513d0c6a10326dd75771fc0a862897a68a5b1aae2636815a27cffef9c74582533828fb7da2c506cc6670284aa5f9023901a46a692fc1741f84abc5ff7a81c9f7e274fa0711fca83d2abb1c423100e0de8dddfb3146b36a8186000000062e9f4ea0264a416444710e9bd9d5f80518a460ccf6aa7e6367a54e2c4bdf8afe1b18db168fe415408ec689d2b0d968a1d0675b6db6f3501af6a8cf17547828250262132daa2f1807b8232e9e4455b1b2bb9e979df8de8b6f35a82f08da1e77152b1860723558cab4e93d96370b0eec108bb9f546b279fa2ade09b0203d4a8e641a4f279fa501786e6a37ec1b18a77587531ffb25d08cd2de9e1652b0548bf2b80e52f355eacc837d4ea24d46036d9df42ebea1e1d5cffaeb9bc4d9da050bfca99d70b632f4c6ee28b16d393de8941ae2853ec25603968ebf36448f59cf4a3b931182127da3e810e886559a81f1fbff52c8bdf6aea163976f5518a09bb196f4bf00000000";
    static UNCOMPRESSED_PROOF_DATA2 :&str = "110cf23488c8938d62cd8c3aa077206268fb2e9c94753ff52bc201afe338c44816ccb83c19a268b56b0b5261e2a4f2cfc841c313f99b1f0964510146cb896415135fc52d00200b95837289edb922393211d5e901b79976f2a77626774b3b9c3721f114e9d484e2594e554da115dbd089745953ac145e22f733da9209829dae2313674935c867be7d1bc128768e45e8141b8c5b3b8d35510a355f0e5c7ba866f90bdd7ec8cd8c70ecd42847804a4a8f6ce9a8dfd26df951c8fb35afda029df8ad187981d0580dc7d9994bab5c3d1eb5c6eb8fa0a38ff09a9f9495f28ace1fe92c242a4197ee994d8781a53e0de7a0aa877c71022d3f0de22086b88c79fbbb0a8e22d65055e54dd2513d0c6a10326dd75771fc0a862897a68a5b1aae2636815a2725b97410383baf0a00846f65a537341fde137875f66f99bac0b2a39e637409ae0ffef9c74582533828fb7da2c506cc6670284aa5f9023901a46a692fc1741f8423238df9027f7e3011362587bed47dee96b6002f55532e681c545ea0b1ba0be01b18db168fe415408ec689d2b0d968a1d0675b6db6f3501af6a8cf17547828250262132daa2f1807b8232e9e4455b1b2bb9e979df8de8b6f35a82f08da1e77152b1860723558cab4e93d96370b0eec108bb9f546b279fa2ade09b0203d4a8e641a4f279fa501786e6a37ec1b18a77587531ffb25d08cd2de9e1652b0548bf2b80e52f355eacc837d4ea24d46036d9df42ebea1e1d5cffaeb9bc4d9da050bfca90160cf6d63bb6ef0e9d793c1646e83f143383d850efdf3c2340a289f42aa77130648a2f93ae7ea48d8055c64e24dd25e311b7f16892691f2e70bc193b1be91871182127da3e810e886559a81f1fbff52c8bdf6aea163976f5518a09bb196f4bf2bc5ff7a81c9f7e274fa0711fca83d2abb1c423100e0de8dddfb3146b36a81860d14f318c5efa4c0389a6bf89a3a0e6dffcfb5fa2d99559b52a93ebf4c9e6e191d70b632f4c6ee28b16d393de8941ae2853ec25603968ebf36448f59cf4a3b9315afe2d1fc0f47cf5edc4fe32033330daed53bd2a65f8d851ec47c2c476bc42f";

    #[test]
    fn test_compare_compressed_uncompressed_gnark_proof() {
        let compressed_str = String::from(COMPRESSED_PROOF_DATA2);
        let compressed_data = hex::decode(&compressed_str).unwrap();
        let compressed_proof = Proof::from_compressed_gnark_bytes(&compressed_data).unwrap();

        let uncompressed_str = String::from(UNCOMPRESSED_PROOF_DATA2);
        let uncompressed_data = hex::decode(&uncompressed_str).unwrap();
        let uncompressed_proof = Proof::from_uncompressed_gnark_bytes(&uncompressed_data).unwrap();

        assert_eq!(compressed_proof, uncompressed_proof);
   }
    

    #[test]
    fn test_compare_compressed_uncompressed_gnark_proof_from_file() {
        let mut compressed_file = File::open("src/test_data/cubic/cubic_compressed.proof").unwrap();
        let mut compressed_data = Vec::new();
        compressed_file.read_to_end(&mut compressed_data).unwrap();
        let compressed_proof = Proof::from_compressed_gnark_bytes(&compressed_data).unwrap();

        let mut uncompressed_file = File::open("src/test_data/cubic/cubic_uncompressed.proof").unwrap();
        let mut uncompressed_data = Vec::new();
        uncompressed_file.read_to_end(&mut uncompressed_data).unwrap();
        let uncompressed_proof = Proof::from_uncompressed_gnark_bytes(&uncompressed_data).unwrap();

        assert_eq!(compressed_proof, uncompressed_proof);
    }

}
