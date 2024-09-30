# `plonk_verifier_on_icp`

Welcome to your new `plonk_verifier_on_icp` project and to the Internet Computer development community. By default, creating a new project adds this README and some template files to your project directory. You can edit these template files to customize your project and to include your own code to speed up the development cycle.

To get started, you might want to explore the project directory structure and the default configuration file. Working with this project in your development environment will not affect any production deployment or identity tokens.

To learn more before you start working with `plonk_verifier_on_icp`, see the following documentation available online:

- [Quick Start](https://internetcomputer.org/docs/current/developer-docs/setup/deploy-locally)
- [SDK Developer Tools](https://internetcomputer.org/docs/current/developer-docs/setup/install)
- [Rust Canister Development Guide](https://internetcomputer.org/docs/current/developer-docs/backend/rust/)
- [ic-cdk](https://docs.rs/ic-cdk)
- [ic-cdk-macros](https://docs.rs/ic-cdk-macros)
- [Candid Introduction](https://internetcomputer.org/docs/current/developer-docs/backend/candid/)


# Architecture 

![plonk_verifier_arch drawio](https://github.com/user-attachments/assets/77413f83-62f0-46af-a6b3-80b08460ad62)

- lib.rs: the entrance for user on ICP, provides verify_bytes() and verify_hex() two functions.
- verifer.rs: plonk verifier
- vk.rs: build verification key from bytes.
- proof.rs: build proof from bytes 
- witness.rs: build witness from bytes 
- fiat_shamir.rs: implement fiat_shamir function  
- hash_to_field.rs: implement hash_to_field function
- fr.rs: build fr from bytes 
- point.rs: build BN254 G1/G2 point from bytes


## proof.rs 
thre are 2 types proof
- compressed, where g1 points are compressed, it is the result of proof.WriteTo
- uncompressed, where g1 points are uncompressed, it is the result of proof.MarshalSolidity()

## gnark version
This repo is based on ganrk v0.9.1.


# How to run locally 
1. start ICP locally in one terminal, 
```bash
dfx start --clean
```

2. download repo and deploy plonk verifer in another terminal,
```bash
git clone https://github.com/lightec-xyz/plonk_verifier_on_icp.git
cd plonk_verifier_on_icp
dfx deploy plonk_verifier_on_icp_backend 
```
after deployed, get the cansiter id(e.g. bkyz2-fmaaa-aaaaa-qaaaq-cai) for later use
```bash
Installing canisters...
Creating UI canister on the local network.
The UI canister on the "local" network is "bd3sg-teaaa-aaaaa-qaaba-cai"
Installing code for canister plonk_verifier_on_icp_backend, with canister ID bkyz2-fmaaa-aaaaa-qaaaq-cai
Deployed canisters.
URLs:
  Backend canister via Candid interface:
    plonk_verifier_on_icp_backend: http://127.0.0.1:4943/?canisterId=bd3sg-teaaa-aaaaa-qaaba-cai&id=bkyz2-fmaaa-aaaaa-qaaaq-cai
```

3. build the one circuit(e.g. hasher) in examples directory, and execute it, which will generate verifyingkey, proof, and witness and then call verify_bytes() to verify the proof/witness.
```bash
cd examples 
go mod tidy
cd hasher
go build
./hasher -canister bkyz2-fmaaa-aaaaa-qaaaq-cai
```

# How to run in ICP mainnet 
plonk_verifer is deployed at https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=3luut-nqaaa-aaaao-qbcwa-cai. you can run the example on ICP mainnet with the following command.

```bash
cd examples 
go mod tidy
cd hasher
go build
./hasher -canister 3luut-nqaaa-aaaao-qbcwa-cai -network ic 
```
Or, build circuit and retrieve verifyingkey, proof, and witness and take them as input parameters in verify_hex().
<img width="1325" alt="image" src="https://github.com/user-attachments/assets/2a0ac97d-0503-4a65-9cce-b282195636e4">

Any modification in verifyingkey, proof, and witness will cause verify fail as shown below.
<img width="1198" alt="image" src="https://github.com/user-attachments/assets/a6d0d759-e660-42fe-b7f4-5a5e724a0d61">






