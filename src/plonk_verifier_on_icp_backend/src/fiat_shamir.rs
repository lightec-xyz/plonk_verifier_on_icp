// This file is rust version of Consensys/ganrk/std/fiat-shamir/transcript.go 
use std::collections::HashMap;
use std::fmt;
use std::error::Error;

#[derive(Debug)]
pub enum TranscriptError {
    ChallengeNotFound,
    ChallengeAlreadyComputed,
    PreviousChallengeNotComputed,
}

impl fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TranscriptError::ChallengeNotFound => {
                write!(f, "challenge not recorded in the transcript")
            }
            TranscriptError::ChallengeAlreadyComputed => write!(
                f,
                "challenge already computed, cannot be bound to other values"
            ),
            TranscriptError::PreviousChallengeNotComputed => write!(
                f,
                "the previous challenge is needed and has not been computed"
            ),
        }
    }
}

impl std::error::Error for TranscriptError {}

pub struct Transcript {
    hasher: Box<dyn digest::DynDigest>,
    challenges: HashMap<String, Challenge>,
    previous: Option<Challenge>,
}

struct Challenge {
    position: usize,
    bindings: Vec<Vec<u8>>,
    value: Vec<u8>,
    is_computed: bool,
}

impl Transcript {
    pub fn new(hasher: Box<dyn digest::DynDigest>, challenge_ids: Vec<&str>) -> Self {
        let mut challenges = HashMap::new();
        for (i, id) in challenge_ids.iter().enumerate() {
            challenges.insert(
                id.to_string(),
                Challenge {
                    position: i,
                    bindings: Vec::new(),
                    value: Vec::new(),
                    is_computed: false,
                },
            );
        }

        Self {
            hasher,
            challenges,
            previous: None,
        }
    }

    pub fn bind(
        &mut self,
        challenge_id: &str,
        b_value: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let challenge = self.challenges.get_mut(challenge_id);
        match challenge {
            Some(challenge) => {
                if challenge.is_computed {
                    return Err(TranscriptError::ChallengeAlreadyComputed.into());
                }

                challenge.bindings.push(b_value.to_vec());
                Ok(())
            }
            None => Err(TranscriptError::ChallengeNotFound.into()),
        }
    }

    pub fn compute_challenge(
        &mut self,
        challenge_id: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let challenge = self.challenges.get_mut(challenge_id);
        match challenge {
            Some(challenge) => {
                if challenge.is_computed {
                    return Ok(challenge.value.clone());
                }

                self.hasher.reset();

                self.hasher.update(challenge_id.as_bytes());

                //if not the first challenge, write the previous value, then the bindings for current one.
                if challenge.position != 0 {
                    if let Some(previous) = &self.previous {
                        if previous.position != challenge.position - 1 {
                            return Err(TranscriptError::PreviousChallengeNotComputed.into());
                        }
                        self.hasher.update(&previous.value);
                    } else {
                        return Err(TranscriptError::PreviousChallengeNotComputed.into());
                    }
                }

                for binding in &challenge.bindings {
                    self.hasher.update(binding);
                }

                let result = self.hasher.finalize_reset().to_vec();

                challenge.value = result.clone();
                challenge.is_computed = true;

                self.previous = Some(challenge.clone()); //after computed, update the previous challenge

                Ok(result)
            }
            None => Err(TranscriptError::ChallengeNotFound.into()),
        }
    }
}

impl Clone for Challenge {
    fn clone(&self) -> Self {
        Self {
            position: self.position,
            bindings: self.bindings.clone(),
            value: self.value.clone(),
            is_computed: self.is_computed,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_fiat_shamir_1() {
        let mut transcript = Transcript::new(
            Box::new(Sha256::new()),
            vec!["gamma", "beta", "alpha", "zeta"],
        );
        transcript.bind("gamma", b"gamma").unwrap();
        transcript.bind("beta", b"beta").unwrap();
        transcript.bind("alpha", b"alpha").unwrap();
        transcript.bind("zeta", b"zeta").unwrap();
        let challenge = transcript.compute_challenge("gamma").unwrap();
        assert_eq!(
            "61ce95fb020d3a579ac4c2bbcce85a9c3e9bfd631846e515cf3654d35f96a081",
            hex::encode(challenge)
        );

        let challenge = transcript.compute_challenge("beta").unwrap();
        assert_eq!(
            "b8d5ffd7340937229a699b9d2b51f39186a4e2f0c8b3598c2fab03709772ef0b",
            hex::encode(challenge)
        );

        let challenge = transcript.compute_challenge("alpha").unwrap();
        assert_eq!(
            "0bda3425dbfcf9f6a1fc40e00826a87279f226b47dbc800215c18b8dff64f6d5",
            hex::encode(challenge)
        );

        let challenge = transcript.compute_challenge("zeta").unwrap();
        assert_eq!(
            "729616e95f88271cb3a99102adb605aaa46683ead82d1790379734df83b65a53",
            hex::encode(challenge)
        );
    }

    #[test]
    fn test_fiat_shamir_2() {
        /*
        vk.S0: 097c8a80aeec562a6b4abc29a019eec113192cb6c84f59beda5ddf3ce9c78ed80053bdf2cd5794fcc2b27919f84908cffcc0a897b32dce1324fc9ef61c26a206
        vk.S1: 1ae06afadef57a6e844f9a0fe62711abfa53d9132e4656fb3002d8c9ac0e7e6417755ec00eaf2e18a5c0aee47f6c8c5bfb57564edad465fbc67c3367bf25802e
        vk.S2: 218e3b9acf719e44cd60e7dfa40090b17d5953b3ad2690caa81f8cdd3db06ef710f82a8dc8fbe7ec03c2c5dd52d35592989ec5d8ab6f9c0fe348fa4299539c62
        vk.Ql: 1934a10bcf7f1b4a365e8be1c1063fe8f919f03021c2ffe4f80b29267ec93e5b211eb62900755b59dbf5639c244c35d67b6ce817aa42ca6cc6c6bed00089a894
        vk.Qr: 161ef0d2f2254d8d1ee93abe691d96323a8ab0dc5a1c2934037da03eac86cc052434c859d553887c5913ab671095676644a40e7ee5f2e54704365d3afb4bd039
        vk.Qm: 0fb7db4e47b0995390599785192ba54e65829b07971e4ed36a01c414ee4e43c809c225fc038a9fbdfbfa7e34d012de4f3d6e3f9532cd186f3f39d8392054ff43
        vk.Qo: 0d12a1664917226af9d25a901300586a7cac148ff581e9aa384fd425dc0be54d1c39fc0fa3549d71805220ab6cbb191a0c7ed1d510423363b6f510b977cd822c
        vk.Qk: 0311ece454bb1e18c2a378c2d60e27ff82fa2a8ff8517c8352ce97b6d6bac30c1ba7c5802881c25823e5c10598a463d72818e514892023be4612dc6c047923df
        publicInputs[0]: 0000000000000000000000000000000000000000000000000000000000000023
        deriveRandomness:gamma:1a4119176997c03bd903efca6b4f5f6c57a24dc38ecdc2ee1298dc4ed6acd4c12e0d805572fde3d4bbf876079ec28789b6a8b05fc1a5bb4d00c801ca2756aa24
        deriveRandomness:gamma:07265bc20793a05dbe9be18427a1219aa05553dcf409d11bf2890a15a214de102b0da24ae451264b96cf2dc9d234d89e956c814d436ee38ffcbc9bb638e37931
        deriveRandomness:gamma:1438e60b866fc158cda025337e0e555a90b3fc6ddd833e30969c70d96f19018400091cade6828d83535efa0c27b48c1abd777aa37ada3f6072d1a2e62753e892
        deriveRandomness:alpha:15a4a0b144fe7b786aa16e3ccd4a44a2d13d6f9b85288876bb56c536a3b4c673029dc4456b9b964ed897037f737b09b60a742eb33faed1ce4327e98f2d6d82b0
        deriveRandomness:zeta:1ef95a05e7dd52604ce0bde0f5213adca1ec7edf8c432ca6a9f4fea0c78efb8a01b060910be62ae5747a1319c287edd3dd39106b946480bdd0fd9c96c56d5d42
        deriveRandomness:zeta:11aceef82dbe6f7f8acb33ef615d5d9424ac4857ea08bdf46df381168edfffa303e52d8d7109c92bcbc9eefa6859ec6364155e931dd84ac7ccbdc9df124986da
        deriveRandomness:zeta:298ecd894c7ba3d5b69c7199b7094fbe00303ce532cabfdf089b5634fac3f85a21829d363477e532987a5ce136db670901ea92acd88867a345b9f581622f7599
        deriveRandomness reuslt, gamma:78b3acae712a2bf283aff6e1853fb48c0c7946d98739e86fb15854150d233ba9
        deriveRandomness reuslt, beta:f655ba4e354572edf457f869e3fd1c56e771f5d23fd34123dd74199033d59cf0
        deriveRandomness reuslt, alpha:69813d04b2b9bbe872a3721324dca475bcfe8c2b1d9b634242e3628cf4330c0b
        deriveRandomness reuslt, zeta:2656adcc7a9148fd7526f0d41b86b7e7758caeb7b2673ff5afd8d52bef948f04
         */

        let mut transcript = Transcript::new(
            Box::new(Sha256::new()),
            vec!["gamma", "beta", "alpha", "zeta"],
        );

        let s0_bytes = hex::decode("097c8a80aeec562a6b4abc29a019eec113192cb6c84f59beda5ddf3ce9c78ed80053bdf2cd5794fcc2b27919f84908cffcc0a897b32dce1324fc9ef61c26a206").unwrap();
        let s1_bytes = hex::decode("1ae06afadef57a6e844f9a0fe62711abfa53d9132e4656fb3002d8c9ac0e7e6417755ec00eaf2e18a5c0aee47f6c8c5bfb57564edad465fbc67c3367bf25802e").unwrap();
        let s2_bytes = hex::decode("218e3b9acf719e44cd60e7dfa40090b17d5953b3ad2690caa81f8cdd3db06ef710f82a8dc8fbe7ec03c2c5dd52d35592989ec5d8ab6f9c0fe348fa4299539c62").unwrap();
        let ql_bytes = hex::decode("1934a10bcf7f1b4a365e8be1c1063fe8f919f03021c2ffe4f80b29267ec93e5b211eb62900755b59dbf5639c244c35d67b6ce817aa42ca6cc6c6bed00089a894").unwrap();
        let qr_bytes = hex::decode("161ef0d2f2254d8d1ee93abe691d96323a8ab0dc5a1c2934037da03eac86cc052434c859d553887c5913ab671095676644a40e7ee5f2e54704365d3afb4bd039").unwrap();
        let qm_bytes = hex::decode("0fb7db4e47b0995390599785192ba54e65829b07971e4ed36a01c414ee4e43c809c225fc038a9fbdfbfa7e34d012de4f3d6e3f9532cd186f3f39d8392054ff43").unwrap();
        let qo_bytes = hex::decode("0d12a1664917226af9d25a901300586a7cac148ff581e9aa384fd425dc0be54d1c39fc0fa3549d71805220ab6cbb191a0c7ed1d510423363b6f510b977cd822c").unwrap();
        let qk_bytes = hex::decode("0311ece454bb1e18c2a378c2d60e27ff82fa2a8ff8517c8352ce97b6d6bac30c1ba7c5802881c25823e5c10598a463d72818e514892023be4612dc6c047923df").unwrap();
        let public_input_bytes =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000023")
                .unwrap();
        let l_bytes = hex::decode("1a4119176997c03bd903efca6b4f5f6c57a24dc38ecdc2ee1298dc4ed6acd4c12e0d805572fde3d4bbf876079ec28789b6a8b05fc1a5bb4d00c801ca2756aa24").unwrap();
        let r_bytes = hex::decode("07265bc20793a05dbe9be18427a1219aa05553dcf409d11bf2890a15a214de102b0da24ae451264b96cf2dc9d234d89e956c814d436ee38ffcbc9bb638e37931").unwrap();
        let o_bytes = hex::decode("1438e60b866fc158cda025337e0e555a90b3fc6ddd833e30969c70d96f19018400091cade6828d83535efa0c27b48c1abd777aa37ada3f6072d1a2e62753e892").unwrap();
        let z_bytes = hex::decode("15a4a0b144fe7b786aa16e3ccd4a44a2d13d6f9b85288876bb56c536a3b4c673029dc4456b9b964ed897037f737b09b60a742eb33faed1ce4327e98f2d6d82b0").unwrap();
        let h0_bytes = hex::decode("1ef95a05e7dd52604ce0bde0f5213adca1ec7edf8c432ca6a9f4fea0c78efb8a01b060910be62ae5747a1319c287edd3dd39106b946480bdd0fd9c96c56d5d42").unwrap();
        let h1_bytes = hex::decode("11aceef82dbe6f7f8acb33ef615d5d9424ac4857ea08bdf46df381168edfffa303e52d8d7109c92bcbc9eefa6859ec6364155e931dd84ac7ccbdc9df124986da").unwrap();
        let h2_bytes = hex::decode("298ecd894c7ba3d5b69c7199b7094fbe00303ce532cabfdf089b5634fac3f85a21829d363477e532987a5ce136db670901ea92acd88867a345b9f581622f7599").unwrap();

        transcript.bind("gamma", &s0_bytes).unwrap();
        transcript.bind("gamma", &s1_bytes).unwrap();
        transcript.bind("gamma", &s2_bytes).unwrap();
        transcript.bind("gamma", &ql_bytes).unwrap();
        transcript.bind("gamma", &qr_bytes).unwrap();
        transcript.bind("gamma", &qm_bytes).unwrap();
        transcript.bind("gamma", &qo_bytes).unwrap();
        transcript.bind("gamma", &qk_bytes).unwrap();
        transcript.bind("gamma", &public_input_bytes).unwrap();
        transcript.bind("gamma", &l_bytes).unwrap();
        transcript.bind("gamma", &r_bytes).unwrap();
        transcript.bind("gamma", &o_bytes).unwrap();
        let challenge = transcript.compute_challenge("gamma").unwrap();
        assert_eq!(
            "78b3acae712a2bf283aff6e1853fb48c0c7946d98739e86fb15854150d233ba9",
            hex::encode(challenge)
        );

        let challenge = transcript.compute_challenge("beta").unwrap();
        assert_eq!(
            "f655ba4e354572edf457f869e3fd1c56e771f5d23fd34123dd74199033d59cf0",
            hex::encode(challenge)
        );

        transcript.bind("alpha", &z_bytes).unwrap();
        let challenge = transcript.compute_challenge("alpha").unwrap();
        assert_eq!(
            "69813d04b2b9bbe872a3721324dca475bcfe8c2b1d9b634242e3628cf4330c0b",
            hex::encode(challenge)
        );

        transcript.bind("zeta", &h0_bytes).unwrap();
        transcript.bind("zeta", &h1_bytes).unwrap();
        transcript.bind("zeta", &h2_bytes).unwrap();
        let challenge = transcript.compute_challenge("zeta").unwrap();
        assert_eq!(
            "2656adcc7a9148fd7526f0d41b86b7e7758caeb7b2673ff5afd8d52bef948f04",
            hex::encode(challenge)
        );
    }

    #[test]
    fn test_fiat_shamir_3() {
        /*
        vk.S0: 097c8a80aeec562a6b4abc29a019eec113192cb6c84f59beda5ddf3ce9c78ed80053bdf2cd5794fcc2b27919f84908cffcc0a897b32dce1324fc9ef61c26a206
        vk.S1: 1ae06afadef57a6e844f9a0fe62711abfa53d9132e4656fb3002d8c9ac0e7e6417755ec00eaf2e18a5c0aee47f6c8c5bfb57564edad465fbc67c3367bf25802e
        vk.S2: 218e3b9acf719e44cd60e7dfa40090b17d5953b3ad2690caa81f8cdd3db06ef710f82a8dc8fbe7ec03c2c5dd52d35592989ec5d8ab6f9c0fe348fa4299539c62
        vk.Ql: 1934a10bcf7f1b4a365e8be1c1063fe8f919f03021c2ffe4f80b29267ec93e5b211eb62900755b59dbf5639c244c35d67b6ce817aa42ca6cc6c6bed00089a894
        vk.Qr: 161ef0d2f2254d8d1ee93abe691d96323a8ab0dc5a1c2934037da03eac86cc052434c859d553887c5913ab671095676644a40e7ee5f2e54704365d3afb4bd039
        vk.Qm: 0fb7db4e47b0995390599785192ba54e65829b07971e4ed36a01c414ee4e43c809c225fc038a9fbdfbfa7e34d012de4f3d6e3f9532cd186f3f39d8392054ff43
        vk.Qo: 0d12a1664917226af9d25a901300586a7cac148ff581e9aa384fd425dc0be54d1c39fc0fa3549d71805220ab6cbb191a0c7ed1d510423363b6f510b977cd822c
        vk.Qk: 0311ece454bb1e18c2a378c2d60e27ff82fa2a8ff8517c8352ce97b6d6bac30c1ba7c5802881c25823e5c10598a463d72818e514892023be4612dc6c047923df
        publicInputs[0]: 0000000000000000000000000000000000000000000000000000000000000023
        deriveRandomness:gamma:2f290e6ef58d63d6af5f9df935f5913c4b662fddea046781e7ecb8727c98ebbe20b6ef7b9bdd580df7a19d894a327f17fe71e3387fd071de23dafbbd880d4593
        deriveRandomness:gamma:27343b1a1025c75dd23467de117413c08c9d7ff4b5d0c6c1f00dd3a1b862c0681f8c0837f7648c48c0d4324a4263c8f7493216ba3e34da7e5729c513ae32b0e5
        deriveRandomness:gamma:058e9bbf2bfa1956bf5b8adfb049de451d05bb20d85724d78aadace129ac7734173f3b434e8a2932480d79021f289c67c6152da3f89f9e2551b8c8b858aff5cb
        deriveRandomness reuslt, gamma:7de9a1d1961df40980e97e12f4dd1def0e535bf858ddcdf3d2a64fee726ec744
        deriveRandomness reuslt, beta:fc7a5eefddf5b9e5fc06e8f8b37e7172dfd5cb598a96d7d26cbe972517016510
        deriveRandomness:alpha:1eae1edd67a6c1d4c37c5a130a80286e074a2d57aade34989de556e2b3844cf32c1d9e12ef2d46d5f81f63b457a757888fd7453801163b900bbeefdda01ddd62
        deriveRandomness reuslt, alpha:05d7127126089b5e8b7af6ad46959fea9e94582d9eb8caabb9205ed8a1c36c91
        deriveRandomness:zeta:050476606aa495222cf68e107742ff5e26d73b835d5a9374276918b773bcc38f08ee9f942cc524ef2532647cd143cde1f3aaf3c3380252410f32d74816710283
        deriveRandomness:zeta:176c1803d47c580accf151f149868e58b5c3e8bf8ada2b16718ffb175c29e2661b7e54df7887a038fff54df7e8c2bbffb2f694ff95a1a0967646b2efef83fa54
        deriveRandomness:zeta:268adeb6036f20da8576d6f3f9a61aa11035765e5c80f0afd2b67694691386ae1017aa6a2391778904f8b2d045c6c4b2f70f2dbb5eb599d676b0d0e33962870c
        deriveRandomness reuslt, zeta:921fb8f9e9efd865706e6f017259386c10070861f29e1151c3bb83a48934646e
         */

        let mut transcript = Transcript::new(
            Box::new(Sha256::new()),
            vec!["gamma", "beta", "alpha", "zeta"],
        );

        let s0_bytes = hex::decode("097c8a80aeec562a6b4abc29a019eec113192cb6c84f59beda5ddf3ce9c78ed80053bdf2cd5794fcc2b27919f84908cffcc0a897b32dce1324fc9ef61c26a206").unwrap();
        let s1_bytes = hex::decode("1ae06afadef57a6e844f9a0fe62711abfa53d9132e4656fb3002d8c9ac0e7e6417755ec00eaf2e18a5c0aee47f6c8c5bfb57564edad465fbc67c3367bf25802e").unwrap();
        let s2_bytes = hex::decode("218e3b9acf719e44cd60e7dfa40090b17d5953b3ad2690caa81f8cdd3db06ef710f82a8dc8fbe7ec03c2c5dd52d35592989ec5d8ab6f9c0fe348fa4299539c62").unwrap();
        let ql_bytes = hex::decode("1934a10bcf7f1b4a365e8be1c1063fe8f919f03021c2ffe4f80b29267ec93e5b211eb62900755b59dbf5639c244c35d67b6ce817aa42ca6cc6c6bed00089a894").unwrap();
        let qr_bytes = hex::decode("161ef0d2f2254d8d1ee93abe691d96323a8ab0dc5a1c2934037da03eac86cc052434c859d553887c5913ab671095676644a40e7ee5f2e54704365d3afb4bd039").unwrap();
        let qm_bytes = hex::decode("0fb7db4e47b0995390599785192ba54e65829b07971e4ed36a01c414ee4e43c809c225fc038a9fbdfbfa7e34d012de4f3d6e3f9532cd186f3f39d8392054ff43").unwrap();
        let qo_bytes = hex::decode("0d12a1664917226af9d25a901300586a7cac148ff581e9aa384fd425dc0be54d1c39fc0fa3549d71805220ab6cbb191a0c7ed1d510423363b6f510b977cd822c").unwrap();
        let qk_bytes = hex::decode("0311ece454bb1e18c2a378c2d60e27ff82fa2a8ff8517c8352ce97b6d6bac30c1ba7c5802881c25823e5c10598a463d72818e514892023be4612dc6c047923df").unwrap();
        let public_input_bytes =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000023")
                .unwrap();
        let l_bytes = hex::decode("2f290e6ef58d63d6af5f9df935f5913c4b662fddea046781e7ecb8727c98ebbe20b6ef7b9bdd580df7a19d894a327f17fe71e3387fd071de23dafbbd880d4593").unwrap();
        let r_bytes = hex::decode("27343b1a1025c75dd23467de117413c08c9d7ff4b5d0c6c1f00dd3a1b862c0681f8c0837f7648c48c0d4324a4263c8f7493216ba3e34da7e5729c513ae32b0e5").unwrap();
        let o_bytes = hex::decode("058e9bbf2bfa1956bf5b8adfb049de451d05bb20d85724d78aadace129ac7734173f3b434e8a2932480d79021f289c67c6152da3f89f9e2551b8c8b858aff5cb").unwrap();
        let z_bytes = hex::decode("1eae1edd67a6c1d4c37c5a130a80286e074a2d57aade34989de556e2b3844cf32c1d9e12ef2d46d5f81f63b457a757888fd7453801163b900bbeefdda01ddd62").unwrap();
        let h0_bytes = hex::decode("050476606aa495222cf68e107742ff5e26d73b835d5a9374276918b773bcc38f08ee9f942cc524ef2532647cd143cde1f3aaf3c3380252410f32d74816710283").unwrap();
        let h1_bytes = hex::decode("176c1803d47c580accf151f149868e58b5c3e8bf8ada2b16718ffb175c29e2661b7e54df7887a038fff54df7e8c2bbffb2f694ff95a1a0967646b2efef83fa54").unwrap();
        let h2_bytes = hex::decode("268adeb6036f20da8576d6f3f9a61aa11035765e5c80f0afd2b67694691386ae1017aa6a2391778904f8b2d045c6c4b2f70f2dbb5eb599d676b0d0e33962870c").unwrap();

        transcript.bind("gamma", &s0_bytes).unwrap();
        transcript.bind("gamma", &s1_bytes).unwrap();
        transcript.bind("gamma", &s2_bytes).unwrap();
        transcript.bind("gamma", &ql_bytes).unwrap();
        transcript.bind("gamma", &qr_bytes).unwrap();
        transcript.bind("gamma", &qm_bytes).unwrap();
        transcript.bind("gamma", &qo_bytes).unwrap();
        transcript.bind("gamma", &qk_bytes).unwrap();
        transcript.bind("gamma", &public_input_bytes).unwrap();
        transcript.bind("gamma", &l_bytes).unwrap();
        transcript.bind("gamma", &r_bytes).unwrap();
        transcript.bind("gamma", &o_bytes).unwrap();
        let challenge = transcript.compute_challenge("gamma").unwrap();
        assert_eq!(
            "7de9a1d1961df40980e97e12f4dd1def0e535bf858ddcdf3d2a64fee726ec744",
            hex::encode(challenge)
        );

        let challenge = transcript.compute_challenge("beta").unwrap();
        assert_eq!(
            "fc7a5eefddf5b9e5fc06e8f8b37e7172dfd5cb598a96d7d26cbe972517016510",
            hex::encode(challenge)
        );

        transcript.bind("alpha", &z_bytes).unwrap();
        let challenge = transcript.compute_challenge("alpha").unwrap();
        assert_eq!(
            "05d7127126089b5e8b7af6ad46959fea9e94582d9eb8caabb9205ed8a1c36c91",
            hex::encode(challenge)
        );

        transcript.bind("zeta", &h0_bytes).unwrap();
        transcript.bind("zeta", &h1_bytes).unwrap();
        transcript.bind("zeta", &h2_bytes).unwrap();
        let challenge = transcript.compute_challenge("zeta").unwrap();
        assert_eq!(
            "921fb8f9e9efd865706e6f017259386c10070861f29e1151c3bb83a48934646e",
            hex::encode(challenge)
        );
    }

    #[test]
    fn test_sha256() {
        let mut hasher = Sha256::new();
        let data = b"0";
        hasher.update(data);
        let result = hasher.finalize_reset().to_vec();
        assert_eq!(
            "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9",
            hex::encode(result)
        );

        hasher.reset();
        let data = hex::decode("0800").unwrap();
        hasher.update(data);
        let result = hasher.finalize_reset().to_vec();
        assert_eq!(
            "e545d395bb3fd971f91bf9a2b6722831df704efae6c1aa9da0989ed0970b77bb",
            hex::encode(result)
        );

        hasher.reset();
        let data = hex::decode("0800aef67890").unwrap();
        hasher.update(data);
        let result = hasher.finalize_reset().to_vec();
        assert_eq!(
            "166b273d4333cda4a7a5e633029dceda2bcfd497132b6295768c1fcd704af49b",
            hex::encode(result)
        );
    }
}
