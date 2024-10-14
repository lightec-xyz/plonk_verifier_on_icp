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
//if proof is rebuild from uncompressed bytes, because gnark MarshalSolidity() skip pack the claimed value of the linearised polynomial at zeta, so proof.batched_proof.claimed_values[0] is zero, 
//so skip the proof.batched_proof.claimed_values[0] != const_lin check. please check "ganrk/backend/plonk/bn254/solidity.go" for detail
pub fn verify(vk:&VerifyingKey, proof:&Proof, public_witness:&[Fr], proof_is_from_compressed :bool) -> Result<bool, Box<dyn Error>> {
    if proof.bsb22_commitments.len() != vk.qcp.len() {
        return Err("bsb22_commitments.len() != qcp.len()".into())
    }

    if public_witness.len() != vk.nb_public_variables as usize {
        return Err("public_witness.len() != nb_public_variables".into());
    }

    //check the points in the proof are on the curve
    for i in 0..proof.lro.len() {
        if !proof.lro[i].is_on_curve() {
            return Err("lro[i] is not on curve".into());
        }
    }

    if !proof.z.is_on_curve() {
        return Err("z is not on curve".into());
    }

    for i in 0..proof.h.len() {
        if !proof.h[i].is_on_curve() {
            return Err("H[i] is not on curve".into());
        }
    } 

    for i in 0..proof.bsb22_commitments.len() {
        if !proof.bsb22_commitments[i].is_on_curve() {
            return Err("bsb22_commitments[i] is not on curve".into());
        }
    }

    if !proof.batched_proof.h.is_on_curve() {
        return Err("batched_proof.h is not on curve".into());
    }
    
    if !proof.zshifted_proof.h.is_on_curve() {
        return Err("zshifted_proof.h is not on curve".into());
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

    // evaluation of zh_zeta = ζ^n - 1
    let one = Fr::one();
    let b_expo = BigInteger64::from(vk.size);
    let zeta_power_m = zeta.pow(&b_expo);  //zeta_pow_m = ζ^n
    let zh_zeta = zeta_power_m.sub(&one);   //zh_zeta = ζ^n - 1
    let zeta_minus_one = zeta.sub(&one);    //zeta_minus_one = ζ - 1
    let inverse_zeta_minus_one = zeta_minus_one.inverse().unwrap();  //inverse_zeta_minus_one = 1/(ζ - 1)
    let lagrange_zero = zh_zeta.mul(&inverse_zeta_minus_one).mul(vk.size_inv);  //lagrange_zero = 1/n * (ζ^n-1)/(ζ-1)

    // compute PI = ∑_{i<n} Lᵢ*wᵢ //计算PI 的方程 和PI(zeta)的值？
    //TODO(keep), use batch inversion
    let mut pi = Fr::zero();
    let mut xi_li = Fr::zero();
    let mut w_pow_i = Fr::one();
    let mut den = zeta.clone();
    den = den.sub(&w_pow_i);                    //den = zeta - w^0

    let mut lagrange = zh_zeta.clone();
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
  
    let l_eval = proof.batched_proof.claimed_values[1];
    let r_eval = proof.batched_proof.claimed_values[2];
    let o_eval = proof.batched_proof.claimed_values[3];
    let s1_eval = proof.batched_proof.claimed_values[4];
    let s2_eval = proof.batched_proof.claimed_values[5];

    //z(wζ)
    let zu_eval = proof.zshifted_proof.claimed_value; 

    //alpha_square_lagrange_zero = α²*L₁(ζ)
    let alpha_square_lagrange_zero = lagrange_zero.mul(&alpha).mul(&alpha);   // α² * 1/n * (ζ^n-1)/(ζ-1)

    // computing the constant coefficient of the full algebraic relation
	// , corresponding to the value of the linearisation polynomiat at ζ
	// PI(ζ) - α²*L₁(ζ) + α(l(ζ)+β*s1(ζ)+γ)(r(ζ)+β*s2(ζ)+γ)(o(ζ)+γ)*z(ωζ)
    let mut s1_ = s1_eval.mul(&beta).add(&l_eval).add(&gamma); //s1_= (l(ζ)+β*s1(ζ)+γ) = (a(x)+β*s1(ζ)+γ))
    let mut s2_ = s2_eval.mul(&beta).add(&r_eval).add(&gamma); //s2_= (r(ζ)+β*s2(ζ)+γ) = (b(x)+β*s2(ζ)+γ))
    let o_ = o_eval.add(&gamma); //o_= (o(ζ)+γ) = (c(x)+γ)
    
    let mut const_lin = s1_.mul(&s2_).mul(&o_).mul(&alpha).mul(zu_eval); // α(l(ζ)+β*s1(ζ)+γ)(r(ζ)+β*s2(ζ)+γ)(o(ζ)+γ)*z(ωζ)
    const_lin = const_lin.sub(&alpha_square_lagrange_zero).add(&pi); // PI(ζ) - α²*L₁(ζ) + α(l(ζ)+β*s1(ζ)+γ)(r(ζ)+β*s2(ζ)+γ)(o(ζ)+γ)*z(ωζ)
    const_lin = const_lin.neg(); //-[PI(ζ) - α²*L₁(ζ) + α(l(ζ)+β*s1(ζ)+γ)(r(ζ)+β*s2(ζ)+γ)(o(ζ)+γ)*z(ωζ)]

    if proof_is_from_compressed {
        if proof.batched_proof.claimed_values[0] != const_lin {
            return Err("algebraic relation does not hold".into())
        } 
    }
  
  
    // computing the linearised polynomial digest
	// α²*L₁(ζ)*[Z] +
	// _s1*[s3]+_s2*[Z] + l(ζ)*[Ql] +
	// l(ζ)r(ζ)*[Qm] + r(ζ)*[Qr] + o(ζ)*[Qo] + [Qk] + ∑ᵢQcp_(ζ)[Pi_i] -
	// Z_{H}(ζ)*(([H₀] + ζᵐ⁺²*[H₁] + ζ²⁽ᵐ⁺²⁾*[H₂])
	// where
	// _s1 =  α*(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*β*Z(μζ)
	// _s2 = -α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)

	// _s1 = α*(l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(β)+γ)*β*Z(μζ)
    let mut _s1 = alpha.mul(&s1_).mul(&s2_).mul(&beta).mul(&zu_eval); // α*(l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(β)+γ)*β*Z(μζ)


    // _s2 = -α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
    let mut _s2 = beta.mul(&zeta).add(&l_eval).add(&gamma);  // (l(ζ)+β*ζ+γ)
    let tmp1 = beta.mul(&vk.coset_shift).mul(&zeta).add(&gamma).add(r_eval);  // (r(ζ)+β*u*ζ+γ)
    let tmp2 = beta.mul(&vk.coset_shift).mul(&vk.coset_shift).mul(&zeta).add(&o_eval).add(&gamma);  // (o(ζ)+β*u²*ζ+γ)
    _s2 = _s2.mul(&tmp1).mul(&tmp2).mul(&alpha).neg(); //  _s2 = -α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)

    // α²*L₁(ζ) - α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
    let coeff_z = alpha_square_lagrange_zero.add(_s2);

    // l(ζ)*r(ζ)
    let rl_eval = r_eval.mul(&l_eval);
  
    // -ζⁿ⁺²*(ζⁿ-1), -ζ²⁽ⁿ⁺²⁾*(ζⁿ-1), -(ζⁿ-1)
    let n_plus_two = BigInteger64::from(vk.size+2);
    let zeta_n_plus_two = zeta.pow(&n_plus_two);  //ζ⁽ⁿ⁺²⁾
    let zeta_n_plus_two_square = zeta_n_plus_two.mul(&zeta_n_plus_two);  // ζ²⁽ⁿ⁺²⁾
    let zeta_n_plus_two_zh = zeta_n_plus_two.mul(zh_zeta).neg();  //- ζ⁽ⁿ⁺²⁾ * (ζⁿ-1)
    let zeta_n_plus_two_square_zh = zeta_n_plus_two_square.mul(zh_zeta).neg();  // - ζ²⁽ⁿ⁺²⁾ * (ζⁿ-1)
    let zh = zh_zeta.neg();  // -(ζⁿ-1)

    let mut points = proof.bsb22_commitments.clone();
    let mut appended_points = vec![vk.ql, vk.qr, vk.qm, vk.qo, vk.qk, vk.s[2], proof.z, proof.h[0], proof.h[1], proof.h[2]];
    points.append(&mut appended_points);


    let mut appended_scalars = vec![l_eval, r_eval, rl_eval, o_eval, one, _s1, coeff_z, zh, zeta_n_plus_two_zh, zeta_n_plus_two_square_zh];
    let mut scalars = Vec::with_capacity(proof.bsb22_commitments.len()+appended_scalars.len());
    scalars.extend_from_slice(&proof.batched_proof.claimed_values[6..]);
    scalars.append(&mut appended_scalars);

    let linearized_polynomial_digest = G1Projective::msm(&points, &scalars).unwrap().into_affine();


    let mut digests_to_fold: Vec<G1Affine> = Vec::with_capacity(vk.qcp.len()+6);
    digests_to_fold.push(linearized_polynomial_digest);
    digests_to_fold.push(proof.lro[0]);
    digests_to_fold.push(proof.lro[1]);
    digests_to_fold.push(proof.lro[2]);
    digests_to_fold.push(vk.s[0]);
    digests_to_fold.push(vk.s[1]);
    for qcp in &vk.qcp {
        digests_to_fold.push(*qcp)
    }

    let zu_eval_bytes = fr_to_gnark_bytes(&zu_eval);

    let (folded_proof, folded_digest) = fold_proof(digests_to_fold.as_slice(), &proof.batched_proof, zeta, Some(vec![zu_eval_bytes]))?;
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
 
    let mut bytes: Vec<u8> = transcript.compute_challenge("gamma")?;
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
        let mut vk_file = File::open("src/test_data/cubic/cubic.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
    
        let mut buf = vec![];
        vk_file.read_to_end(&mut buf).unwrap();
        let vk = VerifyingKey::from_gnark_bytes(&buf, true).unwrap();

        let mut proof_file = File::open("src/test_data/cubic/cubic_compressed.proof").unwrap_or_else(|e| {
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
        assert_eq!("13705172354636085904875144654410498891411589938071787668402876935436031928286", gamma.to_string());

        let beta = derive_randomness(&mut transcript, "beta", None).unwrap();
        assert_eq!("502094640838906301389960030054321793321596228809244953660330047874664680226", beta.to_string());

        let mut alpha_deps: Vec<G1Affine> = Vec::with_capacity(proof.bsb22_commitments.len()+1);
        for i in 0..proof.bsb22_commitments.len() {
            alpha_deps.push(proof.bsb22_commitments[i]);
        }
        alpha_deps.push(proof.z);
        let alpha = derive_randomness(&mut transcript, "alpha", Some(alpha_deps)).unwrap();
        assert_eq!("2836954317178053921774550760313570552348377351550765650432083429178725888741", alpha.to_string());

        let zeta = derive_randomness(&mut transcript, "zeta",Some(vec![proof.h[0], proof.h[1],  proof.h[2]])).unwrap();
        assert_eq!("15802285496528275891841759887321678994127603663567429848560933560816697252136", zeta.to_string());
    }


    #[test]
    fn test_verify_cubic_compressed_proof_pass() {
        let mut vk_file = File::open("src/test_data/cubic/cubic.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
    
        let mut buf = vec![];
        vk_file.read_to_end(&mut buf).unwrap();
        let vk = VerifyingKey::from_gnark_bytes(&buf, true).unwrap();

        let mut proof_file = File::open("src/test_data/cubic/cubic_compressed.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        proof_file.read_to_end(&mut buf).unwrap();
        let proof = Proof::from_compressed_gnark_bytes(&buf).unwrap();

        let mut wit_file = File::open("src/test_data/cubic/cubic.wtns").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        wit_file.read_to_end(&mut buf).unwrap();
        let public_witness = PublicWitness::from_gnark_bytes(&buf).unwrap();
   

        let result = verify(&vk, &proof, &public_witness, true).unwrap();
        assert_eq!(true, result);
    }


    #[test]
    fn test_verify_cubic_uncompressed_proof_pass() {
        let mut vk_file = File::open("src/test_data/cubic/cubic.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
    
        let mut buf = vec![];
        vk_file.read_to_end(&mut buf).unwrap();
        let vk = VerifyingKey::from_gnark_bytes(&buf, true).unwrap();

        let mut proof_file = File::open("src/test_data/cubic/cubic_uncompressed.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });

        let mut buf = vec![];
        proof_file.read_to_end(&mut buf).unwrap();
        let proof = Proof::from_uncompressed_gnark_bytes(&buf).unwrap();
        let public_inputs = vec![Fr::from(35)];

        let result = verify( &vk, &proof, &public_inputs, false).unwrap();
        assert_eq!(true, result);
    }

    #[test]
    #[should_panic(expected = "algebraic relation does not hold")]
    fn test_verify_cubic_compressed_proof_fail() {
        let mut vk_file = File::open("src/test_data/cubic/cubic.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
    
        let mut buf = vec![];
        vk_file.read_to_end(&mut buf).unwrap();
        let vk = VerifyingKey::from_gnark_bytes(&buf, true).unwrap();

        let mut proof_file = File::open("src/test_data/cubic/cubic_compressed.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        proof_file.read_to_end(&mut buf).unwrap();
        let proof = Proof::from_compressed_gnark_bytes(&buf).unwrap();
        let public_inputs = vec![Fr::from(36)];

        let result = verify(&vk, &proof,&public_inputs, true).unwrap();
        assert_eq!(true, result);
    }

    #[test]
    fn test_verify_hasher_compressed_proof_pass() {
        let mut vk_file = File::open("src/test_data/hasher/hasher.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
    
        let mut buf = vec![];
        vk_file.read_to_end(&mut buf).unwrap();
        let vk = VerifyingKey::from_gnark_bytes(&buf, true).unwrap();

        let mut proof_file = File::open("src/test_data/hasher/hasher_compressed.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        proof_file.read_to_end(&mut buf).unwrap();
        let proof = Proof::from_compressed_gnark_bytes(&buf).unwrap();

        let mut wit_file = File::open("src/test_data/hasher/hasher.wtns").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        wit_file.read_to_end(&mut buf).unwrap();
        let public_witness = PublicWitness::from_gnark_bytes(&buf).unwrap();
   

        let result = verify( &vk, &proof,  &public_witness, true).unwrap();
        assert_eq!(true, result);
    }

    #[test]
    fn test_verify_hasher_uncompressed_proof_pass() {
        let mut vk_file = File::open("src/test_data/hasher/hasher.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
    
        let mut buf = vec![];
        vk_file.read_to_end(&mut buf).unwrap();
        let vk = VerifyingKey::from_gnark_bytes(&buf, true).unwrap();

        let mut proof_file = File::open("src/test_data/hasher/hasher_uncompressed.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        proof_file.read_to_end(&mut buf).unwrap();
        let proof = Proof::from_uncompressed_gnark_bytes(&buf).unwrap();

        let mut wit_file = File::open("src/test_data/hasher/hasher.wtns").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        wit_file.read_to_end(&mut buf).unwrap();
        let public_witness = PublicWitness::from_gnark_bytes(&buf).unwrap();
   

        let result = verify( &vk, &proof, &public_witness, false).unwrap();
        assert_eq!(true, result);
    }


    #[test]
    fn test_verify_mimc_compressed_proof_pass() {
        let mut vk_file = File::open("src/test_data/mimc/mimc.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
    
        let mut buf = vec![];
        vk_file.read_to_end(&mut buf).unwrap();
        let vk = VerifyingKey::from_gnark_bytes(&buf, true).unwrap();

        let mut proof_file = File::open("src/test_data/mimc/mimc_compressed.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        proof_file.read_to_end(&mut buf).unwrap();
        let proof = Proof::from_compressed_gnark_bytes(&buf).unwrap();

        let mut wit_file = File::open("src/test_data/mimc/mimc.wtns").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        wit_file.read_to_end(&mut buf).unwrap();
        let public_witness = PublicWitness::from_gnark_bytes(&buf).unwrap();
   

        let result = verify( &vk, &proof, &public_witness, true).unwrap();
        assert_eq!(true, result);
    }

    #[test]
    fn test_verify_mimc_uncompressed_proof_pass() {
        let mut vk_file = File::open("src/test_data/mimc/mimc.vk").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
    
        let mut buf = vec![];
        vk_file.read_to_end(&mut buf).unwrap();
        let vk = VerifyingKey::from_gnark_bytes(&buf, true).unwrap();

        let mut proof_file = File::open("src/test_data/mimc/mimc_uncompressed.proof").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        proof_file.read_to_end(&mut buf).unwrap();
        let proof = Proof::from_uncompressed_gnark_bytes(&buf).unwrap();

        let mut wit_file = File::open("src/test_data/mimc/mimc.wtns").unwrap_or_else(|e| {
            panic!("open file error: {}", e);
        });
        let mut buf = vec![];
        wit_file.read_to_end(&mut buf).unwrap();
        let public_witness = PublicWitness::from_gnark_bytes(&buf).unwrap();
   

        let result = verify(&vk, &proof, &public_witness, false).unwrap();
        assert_eq!(true, result);
    }

}
