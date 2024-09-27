use crate::fr::*;
use crate::fiat_shamir::*;
// use crate::hash_to_field;
use crate::point::*;
use crate::proof::*;
use crate::vk::*;
use crate::witness::*;
use crate::hash_to_field::*;
use ark_bn254::{Bn254,Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, VariableBaseMSM, CurveGroup, pairing::Pairing,};
use ark_ff::{BigInteger64, PrimeField, Field};
use ark_serialize::Valid;
use ark_std::io::Write;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::ops::{Add, Div, Mul, Sub, Neg};
use std::error::Error;
use ark_std::{One, Zero};


//verify the gnark proof generated in rust
pub fn verify(vk:&VerifyingKey, proof:&Proof, public_witness:&[Fr]) -> Result<bool, Box<dyn Error>> {
    if proof.bsb22_commitments.len() != vk.qcp.len() {
        return Err("bsb22_commitments.len() != qcp.len()".into())
    }

    if public_witness.len() != vk.nb_public_variables as usize {
        return Err("public_witness.len() != nb_public_variables".into());
    }

    let mut transcript = Transcript::new(
        Box::new(Sha256::new()),
        vec!["gamma", "beta", "alpha", "zeta"],
    );

    bind_public_data(&mut transcript, "gamma", &vk, public_witness.to_vec())?;

    let gamma = derive_randomness(&mut transcript, "gamma", Some(vec![proof.lro[0], proof.lro[1], proof.lro[2]]))?;

    let beta = derive_randomness(&mut transcript, "beta", None)?;

    let mut alpha_deps: Vec<G1Affine> = Vec::with_capacity(proof.bsb22_commitments.len()+1);
    for bsb22_commit in proof.bsb22_commitments.iter() {
        alpha_deps.push(*bsb22_commit);
    }
    alpha_deps.push(proof.z);
    let alpha = derive_randomness(&mut transcript, "alpha", Some(alpha_deps))?;

    let zeta = derive_randomness(&mut transcript, "zeta",Some(vec![proof.h[0], proof.h[1],  proof.h[2]]))?;

    // evaluation of Z=Xⁿ-1 at ζ
    let one = Fr::one();
    let b_expo = BigInteger64::from(vk.size);
    let zeta_power_m = zeta.pow(&b_expo);  //zeta_pow_m = ζ^n
    let z_zeta = zeta_power_m.sub(&one);   //z_zeta = ζ^n - 1

    // compute PI = ∑_{i<n} Lᵢ*wᵢ //计算PI 的方程 和PI(zeta)的值？
    let mut pi = Fr::zero();
    let mut xi_li = Fr::zero();
    let mut w_pow_i = Fr::one();
    let mut den = zeta.clone();
    den = den.sub(&w_pow_i);                    //den = zeta - w^0

    let mut lagrange = z_zeta.clone();
    lagrange = lagrange.div(&den).mul(&vk.size_inv);
    let lagrange_one = lagrange.clone();

    for i in 0..public_witness.len(){
        xi_li = lagrange.mul(&public_witness[i]);
        pi = pi.add(&xi_li);

        if i+1 != public_witness.len() {
            lagrange = lagrange.mul(&vk.generator).mul(&den);

            w_pow_i = w_pow_i.mul(&vk.generator);
            den = zeta.sub(&w_pow_i);
            lagrange = lagrange.div(&den);
        }
    }

    for i in 0..vk.commit_constraint_indexes.len() {
        let mut hasher = HashToField::new(b"BSB22-Plonk");
        let bytes = ark_g1_to_gnark_unompressed_bytes(&proof.bsb22_commitments[i])?;
        hasher.write(&bytes)?;
        let hash_bytes = hasher.sum();
        hasher.reset();
        let hash_commit = fr_from_gnark_bytes(&hash_bytes);

        //w_pow_i = w^{int64(vk.NbPublicVariables)+int64(vk.CommitmentConstraintIndexes[i]))}
        w_pow_i = vk.generator.pow(&BigInteger64::from(vk.nb_public_variables+ vk.commit_constraint_indexes[i])); 
        den = zeta.sub(&w_pow_i);

        lagrange = zeta.sub(&one).mul(w_pow_i).div(&den).mul(&lagrange_one);
        xi_li = lagrange.mul(&hash_commit);
        pi = pi.add(&xi_li);
    }
  

    let z_eval = proof.zshifted_proof.claimed_value; //z(w*zeta) evalution value 

    let claimed_quotient_eval = proof.batched_proof.claimed_values[0];
    let mut linearized_polynomial_zeta_eval = proof.batched_proof.claimed_values[1];
    let l_eval = proof.batched_proof.claimed_values[2];
    let r_eval = proof.batched_proof.claimed_values[3];
    let o_eval = proof.batched_proof.claimed_values[4];
    let s1_eval = proof.batched_proof.claimed_values[5];
    let s2_eval = proof.batched_proof.claimed_values[6];

    let mut s1_ = s1_eval.mul(&beta).add(&l_eval).add(&gamma); //_s1= (l(ζ)+β*s1(ζ)+γ) = (a(x)+β*s1(ζ)+γ))
    let mut s2_ = s2_eval.mul(&beta).add(&r_eval).add(&gamma); //_s2= (r(ζ)+β*s2(ζ)+γ) = (b(x)+β*s2(ζ)+γ))
    let o_ = o_eval.add(&gamma); //_o= (o(ζ)+γ) = (c(x)+γ)
    
    s1_= s1_.mul(&s2_).mul(&o_).mul(&alpha).mul(z_eval);
    let alpha_square_lagrange = lagrange_one.mul(&alpha).mul(&alpha);  //alpha_square_lagrange = α²*L₁(ζ)


    linearized_polynomial_zeta_eval = linearized_polynomial_zeta_eval.add(&pi).add(s1_).sub(&alpha_square_lagrange);
    
    let zeta_pow_m_minus_one = zeta_power_m.sub(&one);
    linearized_polynomial_zeta_eval = linearized_polynomial_zeta_eval.div(&zeta_pow_m_minus_one);
  
    if claimed_quotient_eval != linearized_polynomial_zeta_eval {
        return Err("claimed_quotient_eval != linearized_polynomial_zeta_eval".into())
    }

    let m_plus_two = BigInteger64::from(vk.size+2);
    let zeta_m_plus_two = zeta.pow(&m_plus_two);  //ζ^{n+2}
    let zeta_m_plus_two_big = zeta_m_plus_two.into_bigint();

    let mut fold_h = proof.h[2];
    fold_h = fold_h.mul_bigint(&zeta_m_plus_two_big).into();
    fold_h = fold_h.add(&proof.h[1]).into();
    fold_h = fold_h.mul_bigint(&zeta_m_plus_two_big).into();
    fold_h = fold_h.add(&proof.h[0]).into();

    let rl_eval = r_eval.mul(&l_eval);

    let u1 = z_eval.mul(&beta);                              //u = Z(μζ) * β
    let v1 = s1_eval.mul(&beta).add(&l_eval).add(&gamma);    //v = (l(ζ)+β*s₁(ζ)+γ)
    let w1 = s2_eval.mul(&beta).add(&r_eval).add(&gamma);    // w = (r(ζ)+β*s₂(ζ)+γ)
    s1_ = u1.mul(&v1).mul(&w1).mul(&alpha);                                                     // s1_ = α*Z(μζ)(l(ζ)+β*s₁(ζ)+γ)*(r(ζ)+β*s₂(ζ)+γ)*β

    let coset_square = vk.coset_shift.square();
    let u2 = zeta.mul(&beta).add(&l_eval).add(&gamma);    // u = (l(ζ)+β*ζ+γ)
    let v2 = zeta.mul(&beta).mul(&vk.coset_shift).add(&r_eval).add(&gamma);    // v = (r(ζ)+β*ζ*ξ+γ)
    let w2 = zeta.mul(&beta).mul(&coset_square).add(&o_eval).add(&gamma);    // w = (o(ζ)+β*ζ*ξ^2+γ)
    s2_= u2.mul(&v2).mul(&w2).neg();                                                     // s2_ = -β*ζ*(l(ζ)+β*ζ+γ)*(r(ζ)+β*ζ*ξ+γ)*(o(ζ)+β*ζ*ξ^2+γ

    s2_ = s2_.mul(&alpha).add(&alpha_square_lagrange);

    let mut points = proof.bsb22_commitments.clone();
    let mut appended_points = vec![vk.ql, vk.qr, vk.qm, vk.qo, vk.qk, vk.s[2], proof.z];
    points.append(&mut appended_points);

    let mut scalars = Vec::with_capacity(proof.bsb22_commitments.len()+7);
    scalars.extend_from_slice(&proof.batched_proof.claimed_values[7..]);
    let mut appended_scalars = vec![l_eval, r_eval, rl_eval, o_eval, one, s1_, s2_];
    scalars.append(&mut appended_scalars);

    let linearized_polynomial_digest = G1Projective::msm(&points, &scalars).unwrap().into_affine();

    let mut digests_to_fold: Vec<G1Affine> = Vec::with_capacity(vk.qcp.len()+7);
    digests_to_fold.push(fold_h);
    digests_to_fold.push(linearized_polynomial_digest);
    digests_to_fold.push(proof.lro[0]);
    digests_to_fold.push(proof.lro[1]);
    digests_to_fold.push(proof.lro[2]);
    digests_to_fold.push(vk.s[0]);
    digests_to_fold.push(vk.s[1]);
    for qcp in &vk.qcp {
        digests_to_fold.push(*qcp)
    }

    let z_eval_bytes = fr_to_gnark_bytes(&z_eval);

    let (folded_proof, folded_digest) = fold_proof(digests_to_fold.as_slice(), &proof.batched_proof, zeta, Some(vec![z_eval_bytes]))?;
    let shifted_zeta = zeta.mul(&vk.generator);

    let is_z_valid = kzg_verify_single_point(&proof.z, &proof.zshifted_proof, &shifted_zeta, &vk.kzg)?;
    let is_batch_valid = kzg_verify_single_point(&folded_digest, &folded_proof, &zeta, &vk.kzg)?;
   
    Ok(is_z_valid&&is_batch_valid)    
}

//bind_public_data prepare public data for derive randomess
fn bind_public_data(
    transcript: &mut Transcript,
    challenge: &str,
    vk: &VerifyingKey,
    public_inputs: Vec<Fr>,
) -> Result<(), Box<dyn Error>> {
    let s0_bytes = ark_g1_to_gnark_unompressed_bytes(&vk.s[0])?;
    let s1_bytes = ark_g1_to_gnark_unompressed_bytes(&vk.s[1])?;
    let s2_bytes = ark_g1_to_gnark_unompressed_bytes(&vk.s[2])?;
    let ql_bytes = ark_g1_to_gnark_unompressed_bytes(&vk.ql)?;
    let qr_bytes = ark_g1_to_gnark_unompressed_bytes(&vk.qr)?;
    let qm_bytes = ark_g1_to_gnark_unompressed_bytes(&vk.qm)?;
    let qo_bytes = ark_g1_to_gnark_unompressed_bytes(&vk.qo)?;
    let qk_bytes = ark_g1_to_gnark_unompressed_bytes(&vk.qk)?;

    let mut qcp_bytes: Vec<Vec<u8>> = Vec::with_capacity(vk.qcp.len());
    for qcp in &vk.qcp {
        let bytes = ark_g1_to_gnark_unompressed_bytes(qcp)?;
        qcp_bytes.push(bytes);
    }

    let mut public_inputs_bytes: Vec<Vec<u8>> = Vec::with_capacity(public_inputs.len());
    for input in &public_inputs {
        let bytes = fr_to_gnark_bytes(input);
        public_inputs_bytes.push(bytes);
    }

    transcript.bind(challenge, &s0_bytes)?;
    transcript.bind(challenge, &s1_bytes)?;
    transcript.bind(challenge, &s2_bytes)?;
    transcript.bind(challenge, &ql_bytes)?;
    transcript.bind(challenge, &qr_bytes)?;
    transcript.bind(challenge, &qm_bytes)?;
    transcript.bind(challenge, &qo_bytes)?;
    transcript.bind(challenge, &qk_bytes)?;

    for bytes in &qcp_bytes {
        transcript.bind(challenge, bytes)?;
    }

    for bytes in &public_inputs_bytes {
        transcript.bind(challenge, bytes)?;
    }
    Ok(())
}

// derive_randomness derives randomness from transcript
pub fn derive_randomness(
    transcript: &mut Transcript,
    challenge: &str,
    points: Option<Vec<G1Affine>>,
) -> Result<Fr, Box<dyn Error>> {
    if let Some(points_vec) = points {
        for p in points_vec {
            let bytes = ark_g1_to_gnark_unompressed_bytes(&p)?;
            transcript.bind(challenge, &bytes)?;
        }
    };

    let bytes: Vec<u8> = transcript.compute_challenge(challenge)?;
    let v = BigUint::from_bytes_be(&bytes);
    let fr = Fr::from(v);
    Ok(fr)
}


// fold_proof folds digests and BatchOpeningProof
pub fn fold_proof(digests: &[G1Affine], batch_opening_proof: &BatchOpeningProof, point:Fr, data_transcipt: Option<Vec<Vec<u8>>>) -> Result<(OpeningProof,G1Affine), Box<dyn Error>> {

    let nb_digests = digests.len();
    // check consistency between numbers of claims vs number of digests
    if nb_digests != batch_opening_proof.claimed_values.len() {
        panic!("Digests and claimed values have different lengths");
    };

    // derive the challenge γ, binded to the point and the commitments
    let gamma = kzg_derive_gamma(point, digests, &batch_opening_proof.claimed_values, data_transcipt)?;
    let mut gammas = Vec::with_capacity(nb_digests);
    gammas.push(Fr::one());
    if nb_digests > 1 {
        gammas.push(gamma);
    };

    for i in 2..nb_digests {
        gammas.push(gammas[i-1].mul(&gamma));
    };

    let (folded_digest, foled_eval) = kzg_fold(digests, &batch_opening_proof.claimed_values, &gammas)?;

    let res = OpeningProof {
        h: batch_opening_proof.h,
        claimed_value: foled_eval
    };

    Ok((res, folded_digest))

}

// fold folds digests and evaluations using the list of factors as random numbers.
// digests: digests list of digests to fold
// fai:evaluations list of evaluations to fold
// ci:factors list of multiplicative factors used for the folding (in Montgomery form)
// Returns ∑ᵢcᵢdᵢ, ∑ᵢcᵢf(aᵢ)
pub fn kzg_fold(digests :&[G1Affine], fai:&[Fr], ci :&[Fr]) -> Result<(G1Affine,Fr), Box<dyn Error>> {
    let nb_digests = digests.len();

    if nb_digests != fai.len() || nb_digests != ci.len() {
        return Err("Digests, evaluations and factors have different lengths".into());
    };

    // fold the claimed values ∑ᵢcᵢf(aᵢ)
    let mut foled_eval = Fr::zero();
    for i in 0..nb_digests {
        let tmp = fai[i].mul(&ci[i]);
        foled_eval = foled_eval.add(&tmp);
    };

    // fold the digests ∑ᵢ[cᵢ]([fᵢ(α)]G₁)
    let folded_digest = G1Projective::msm(digests, ci).unwrap().into_affine();

    Ok((folded_digest, foled_eval))    
}

// Verify verifies a KZG opening proof at a single point
// point = ζ, open point
// commitment = [f(x)]₁, f(x)'s commitment
// proof.h = [h(x)]₁, quotient polynomial h(x)'s commitment
// proof.claimed_value = f(ζ), value at open point 
pub fn kzg_verify_single_point(commit: &G1Affine, proof: &OpeningProof, point: &Fr, vk: &KzgVerifyingKey) -> Result<bool, Box<dyn Error>> {
    // [f(ζ)]G₁ = y * [1]₁ = f(ζ) *[1]₁
    let claimed_value_big  = proof.claimed_value.into_bigint();
    let claimed_value_g1_proj = G1Affine::generator().mul_bigint(claimed_value_big);

    // [f(x) - f(ζ)]G₁ = [f(x)]₁ - f(ζ)*[1]₁
    let mut f_minus_fa_g1_proj = G1Projective::from(*commit);
    f_minus_fa_g1_proj = f_minus_fa_g1_proj.sub(&claimed_value_g1_proj);

    // [-H(x)]G₁
    let neg_h = proof.h.neg();

    // [f(x)]₁ + ζ*[h(x)]₁- f(ζ) *[1]₁
    let point_big = point.into_bigint();
    let mut total_g1_proj = proof.h.mul_bigint(point_big);
    total_g1_proj = total_g1_proj.add(f_minus_fa_g1_proj);
    let total_g1_affine = total_g1_proj.into_affine();
    
    let pairing_result = Bn254::multi_pairing(vec![total_g1_affine, neg_h], vk.g2);
    pairing_result.check()?;
    Ok(true)
}

// kzg_derive_gamma derives a challenge using Fiat Shamir to fold proofs.
pub fn kzg_derive_gamma(fr : Fr, digests: &[G1Affine], claimed_values : &[Fr], data_transcript: Option<Vec<Vec<u8>>>) -> Result<Fr, Box<dyn Error>> {
    let mut transcript = Transcript::new(
        Box::new(Sha256::new()),
        vec!["gamma"],
    );

    let bytes = fr_to_gnark_bytes(&fr);
    transcript.bind("gamma", &bytes)?;

    for d in digests {
        let bytes = ark_g1_to_gnark_unompressed_bytes(d)?;
        transcript.bind("gamma", &bytes)?;
    };

    for v in claimed_values {
        let bytes = fr_to_gnark_bytes(v);
        transcript.bind("gamma", &bytes)?;
    };

    if let Some(data) = data_transcript {
        for d in data {
            transcript.bind("gamma", d.as_slice())?;
        };
    }
 
    let bytes: Vec<u8> = transcript.compute_challenge("gamma")?;
    let v = BigUint::from_bytes_be(&bytes);
    let fr = Fr::from(v);
    Ok(fr)
}

// kzg_divide_polynomial_by_x_minus_a computes (f-f(a))/(x-a), in canonical basis, in regular form
// f memory is re-used for the result
pub fn kzg_divide_polynomial_by_x_minus_a(f: &[Fr], fa: &Fr, a : &Fr) -> Result<Vec<Fr>, Box<dyn Error>> {
    let mut f_copy = vec![Fr::zero(); f.len()];
    f_copy.copy_from_slice(f);

    // first we compute f-f(a)
    f_copy[0] = f_copy[0].sub(fa);

    // now we use synthetic division to divide by x-a
    for i in (0..=f_copy.len()-2).rev() {
        let tmp = f_copy[i+1].mul(a);
        f_copy[i] = f_copy[i].add(&tmp);
    }

    Ok(f_copy[1..].to_vec())    
}



#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use ark_bn254::Fq;
    // use std::vec;
    use super::*;
    use std::fs::File;

    #[test]
    fn test_kzg_divide_polynomial_by_x_minus_a() {
        let size = 10;
        let mut coeffs = Vec::with_capacity(size);

        coeffs.push(Fr::from(567));
        for i in 1..size {
            coeffs.push(Fr::from((567+i) as u64));
        }

        let fa = Fr::from(581807978777675747367i128);
        let a = Fr::from(100);

        let result = kzg_divide_polynomial_by_x_minus_a(&coeffs, &fa, &a).unwrap();
        assert_eq!("5818079787776757468", result[0].to_string());
        assert_eq!("58180797877767569", result[1].to_string());
        assert_eq!("581807978777670", result[2].to_string());
        assert_eq!("5818079787771", result[3].to_string());
        assert_eq!("58180797872", result[4].to_string());
        assert_eq!("581807973", result[5].to_string());
        assert_eq!("5818074", result[6].to_string());
        assert_eq!("58175", result[7].to_string());
        assert_eq!("576", result[8].to_string());
    }

    #[test]
    fn test_fold_proof() {
        let digest_str :Vec<Vec<&str>> = vec![
            vec!["19439843421331868731048920761041485100311316113639113728763517607290880888561", "3962135465877614200711446361696500777806926945245380960178027903417523424360"],
            vec!["21371011874295022104212298179491547185152296099547976752666827902737047458623", "13078528585400863682104670653299997747955611433236040645936738688644282353393"],
            vec!["21331244228972098394430934304779976416162120107036581448523649300709636631486", "14797230170318974213844904900297672643450778206092542653116270742759988348307"],
            vec!["17732485047809477074325676591722341408702792534757986188827300216336432676968", "14269113617971571947582525955859337143953875150259695542094936085650706968805"],
            vec!["2513531450779741774381166738397529229903825310877217742340791263387573843764", "10514915900118247345163197169314344375635384431487090493437650563455935051211"],
            vec!["4290860583572509627464577404645192107154708027355374043132381799101413953240", "147959282368291695976176804501251963707900737478195501167604460443637555718"],
            vec!["12156646154255023419676968282873543092370571330830097518462231970884835245668", "10610570566006993286673885485482428354276799132634670696393883549563563114542"]
        ];

        let h_str = vec!["876707076371717127069125978328654668655341628655473206819622065236257595145", "460814277655693737205039146672204997651517943497740039146393067657050178594"];

        let claim_vals_str = vec![
            "15054180778610820829376937596011358865784096266639273490438236811742655217416", "205123322307186165413938191562039325076039399890843400056961877316720984660",
            "2657983629575768070030820300920548932958782609314604576267592987113419935400",
            "986081019562346864761624081500574543516391948406973761258846090957496445562",
            "10532170807698316814599792458239876118966025241330039635050142298206911770996",
            "11411724786298094112809192269724475809258068421681668314283962582687360626562",
            "13583614823749895836805239287126128354018130769216579522978891999424168496887"
        ];

        let point_str = "428996195638157125664800467491845848268572530814052950149558609155640812651";

        let data_transcript_str = vec!["05d2f29bf53fd8ce5361e6ea3784e801ac0c4a3a8362efc518d6361af4212e47"];

        struct GnarkPoint {
            big_x: String,
            big_y: String,
        }

        let ganrk_points: Vec<GnarkPoint> = digest_str
        .iter()
        .map(|vec| GnarkPoint {
            big_x: vec[0].to_string(),
            big_y: vec[1].to_string(),
        })
        .collect();
    
        let mut digests = Vec::with_capacity(ganrk_points.len());
        for (_, point) in ganrk_points.iter().enumerate() {
            let x = BigUint::from_str(&point.big_x).unwrap();
            let y = BigUint::from_str(&point.big_y).unwrap();

            let digest = G1Affine::new(Fq::from(x), Fq::from(y));
            digests.push(digest);
        }

        let h_x = BigUint::from_str(&h_str[0]).unwrap();
        let h_y = BigUint::from_str(&h_str[1]).unwrap();
        let h = G1Affine::new(Fq::from(h_x), Fq::from(h_y));

        let claim_vals = claim_vals_str
        .iter()
        .map(|x| Fr::from(BigUint::from_str(x).unwrap()))
        .collect::<Vec<Fr>>();

        let batch_opening_proof = BatchOpeningProof {
            h:h,
            claimed_values:claim_vals,
        };
        
        let point = Fr::from(BigUint::from_str(&point_str).unwrap());

        let data_transcript = data_transcript_str
        .iter()
        .map(|x| hex::decode(x).unwrap())
        .collect::<Vec<Vec<u8>>>();

       let(opening_proof, digest)  = fold_proof(&digests,  &batch_opening_proof, point, Some(data_transcript)).unwrap();
       assert_eq!("(20263577364888023503226768230526337280204089690127349362914132838218371276794, 16930668638835727420546454921753874079894058376243462449981829277079553144966)", digest.to_string());
       assert_eq!("(876707076371717127069125978328654668655341628655473206819622065236257595145, 460814277655693737205039146672204997651517943497740039146393067657050178594)", opening_proof.h.to_string());
       assert_eq!("19674270539144290625731309089172697973090844743107571163541639124063474299762", opening_proof.claimed_value.to_string());

    }

    #[test]
    fn test_derive_randomess() {
        let mut vk_file = File::open("src/test_data/cubic.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
    
        let mut buf = vec![];
        vk_file.read_to_end(&mut buf).unwrap();
        let vk = VerifyingKey::from_gnark_bytes(&buf, true).unwrap();

        let mut proof_file = File::open("src/test_data/cubic_compressed_proof.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        proof_file.read_to_end(&mut buf).unwrap();
        let proof = Proof::from_compressed_gnark_bytes(&buf).unwrap();

        let mut transcript = Transcript::new(
            Box::new(Sha256::new()),
            vec!["gamma", "beta", "alpha", "zeta"],
        );

        let public_inputs = vec![Fr::from(35)];

        bind_public_data(&mut transcript, "gamma", &vk, public_inputs).unwrap();
        let gamma = derive_randomness(&mut transcript, "gamma", Some(vec![proof.lro[0], proof.lro[1], proof.lro[2]])).unwrap();
        assert_eq!("13175412526922964177080897496541576850519188848052084205935292988061649913666", gamma.to_string());

        let beta = derive_randomness(&mut transcript, "beta", None).unwrap();
        assert_eq!("4757834056648670749114983047853294034164989321973894378345768017701699151115", beta.to_string());

        let mut alpha_deps: Vec<G1Affine> = Vec::with_capacity(proof.bsb22_commitments.len()+1);
        for i in 0..proof.bsb22_commitments.len() {
            alpha_deps.push(proof.bsb22_commitments[i]);
        }
        alpha_deps.push(proof.z);
        let alpha = derive_randomness(&mut transcript, "alpha", Some(alpha_deps)).unwrap();
        assert_eq!("2641563643757307952281786817189485924276511397256432725904865976110150806673", alpha.to_string());

        let zeta = derive_randomness(&mut transcript, "zeta",Some(vec![proof.h[0], proof.h[1],  proof.h[2]])).unwrap();
        assert_eq!("428996195638157125664800467491845848268572530814052950149558609155640812651", zeta.to_string());
    }


    #[test]
    fn test_verify_cubic_compressed_proof_pass() {
        let mut vk_file = File::open("src/test_data/cubic.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
    
        let mut buf = vec![];
        vk_file.read_to_end(&mut buf).unwrap();
        let vk = VerifyingKey::from_gnark_bytes(&buf, true).unwrap();

        let mut proof_file = File::open("src/test_data/cubic_compressed_proof.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        proof_file.read_to_end(&mut buf).unwrap();
        let proof = Proof::from_compressed_gnark_bytes(&buf).unwrap();

        let mut wit_file = File::open("src/test_data/cubic_public_witness.wtns").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        wit_file.read_to_end(&mut buf).unwrap();
        let public_witness = PublicWitness::from_gnark_bytes(&buf).unwrap();
   

        let result = verify(&vk, &proof, &public_witness).unwrap();
        assert_eq!(true, result);
    }


    #[test]
    #[should_panic(expected = "claimed_quotient_eval != linearized_polynomial_zeta_eval")]
    fn test_verify_cubic_compressed_proof_fail() {
        let mut vk_file = File::open("src/test_data/cubic.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
    
        let mut buf = vec![];
        vk_file.read_to_end(&mut buf).unwrap();
        let vk = VerifyingKey::from_gnark_bytes(&buf, true).unwrap();

        let mut proof_file = File::open("src/test_data/cubic_compressed_proof.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        proof_file.read_to_end(&mut buf).unwrap();
        let proof = Proof::from_compressed_gnark_bytes(&buf).unwrap();
        let public_inputs = vec![Fr::from(36)];  //ERROR here, SHOULD BE 35

        let result = verify(&vk, &proof, &public_inputs).unwrap();
        assert_eq!(true, result);
    }


    #[test]
    fn test_verify_cubic_uncompressed_proof_pass() {
        let mut vk_file = File::open("src/test_data/cubic.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
    
        let mut buf = vec![];
        vk_file.read_to_end(&mut buf).unwrap();
    
        let vk = VerifyingKey::from_gnark_bytes(&buf, true).unwrap();
        let mut proof_file = File::open("src/test_data/cubic_uncompressed_proof.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });

        let mut buf = vec![];
        proof_file.read_to_end(&mut buf).unwrap();
        let proof = Proof::from_uncompressed_gnark_bytes(&buf).unwrap();
        let public_inputs = vec![Fr::from(35)];

        let result = verify( &vk,  &proof,&public_inputs).unwrap();
        assert_eq!(true, result);
    }

}
